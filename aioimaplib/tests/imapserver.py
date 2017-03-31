#    aioimaplib : an IMAPrev4 lib using python asyncio 
#    Copyright (C) 2016  Bruno Thomas
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
import asyncio
import email
import logging
import uuid
from datetime import datetime, timedelta
from email.header import Header
import email.mime.nonmultipart
from math import ceil

import re
from copy import deepcopy
from functools import update_wrapper
from pytz import utc

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
sh = logging.StreamHandler()
sh.setLevel(logging.INFO)
sh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s " +
                                  "[%(module)s:%(lineno)d] %(message)s"))
log.addHandler(sh)

NONAUTH, AUTH, SELECTED, IDLE, LOGOUT = 'NONAUTH', 'AUTH', 'SELECTED', 'IDLE', 'LOGOUT'


class ServerState(object):
    def __init__(self):
        self.mailboxes = dict()
        self.connections = dict()
        self.subcriptions = dict()

    def reset(self):
        self.mailboxes = dict()
        for connection in self.connections.values():
            connection.transport.close()
        self.connections = dict()

    def add_mail(self, to, mail, mailbox='INBOX'):
        if to not in self.mailboxes:
            self.mailboxes[to] = dict()
        if mailbox not in self.mailboxes[to]:
            self.mailboxes[to][mailbox] = list()
        m = deepcopy(mail)
        m.id = self.max_id(to, mailbox) + 1
        m.uid = self.max_uid(to) + 1
        self.mailboxes[to][mailbox].append(m)
        return m.uid

    def max_uid(self, user):
        if user not in self.mailboxes: return 0
        return max(map(lambda mailbox: max(mailbox, default=Mail(user), key=lambda msg: msg.uid).uid,
                       self.mailboxes[user].values()))

    def max_id(self, user, mailbox):
        if user not in self.mailboxes or \
                mailbox not in self.mailboxes[user] or \
                len(self.mailboxes[user][mailbox]) == 0:
            return 0
        return max(self.mailboxes[user][mailbox], key=lambda msg: msg.id).id

    def login(self, user_login, protocol):
        if user_login not in self.mailboxes:
            self.mailboxes[user_login] = dict()
            self.mailboxes[user_login]['INBOX'] = list()
        if user_login not in self.connections:
            self.connections[user_login] = protocol
        if user_login not in self.subcriptions:
            self.subcriptions[user_login] = set()

    def create_mailbox_if_not_exists(self, user_login, user_mailbox):
        if user_mailbox not in self.mailboxes[user_login]:
            self.mailboxes[user_login][user_mailbox] = list()

    def get_mailbox_messages(self, user_login, user_mailbox):
        return self.mailboxes[user_login].get(user_mailbox)

    def imap_receive(self, user, mail, mailbox):
        uid = self.add_mail(user, mail, mailbox)
        if user in self.connections:
            self.connections[user].notify_new_mail(uid)
        return uid

    def get_connection(self, user):
        return self.connections.get(user)

    def subscribe(self, user, mailbox):
        self.subcriptions[user].add(mailbox)

    def unsubscribe(self, user, mailbox):
        self.subcriptions[user].remove(mailbox)

    def lsub(self, user, mailbox_search):
        mb_re = re.compile(mailbox_search)
        return [mb for mb in self.subcriptions[user] if mb_re.match(mb)]

    def list(self, user, mailbox_pattern):
        mb_re = re.compile(mailbox_pattern)
        return sorted([mb for mb in self.mailboxes[user].keys() if mb_re.match(mb)])

    def remove(self, message, user, mailbox):
        self.mailboxes[user][mailbox].remove(message)

    def delete_mailbox(self, user, mailbox):
        if mailbox in self.mailboxes[user]:
            del self.mailboxes[user][mailbox]

    def rename_mailbox(self, user, old_mb, new_mb):
        if old_mb in self.mailboxes[user]:
            mb = self.mailboxes[user].pop(old_mb)
            self.mailboxes[user][new_mb] = mb

    def copy(self, user, src_mailbox, dest_mailbox, message_set):
        to_copy = [msg for msg in self.mailboxes[user][src_mailbox] if str(msg.id) in message_set]
        if dest_mailbox not in self.mailboxes[user]:
            self.mailboxes[user][dest_mailbox] = list()
        self.mailboxes[user][dest_mailbox] += to_copy


def critical_section(next_state):
    @asyncio.coroutine
    def execute_section(self, state, critical_func, *args, **kwargs):
        with (yield from self.state_condition):
            critical_func(self, *args, **kwargs)
            self.state = state
            log.debug('state -> %s' % state)
            self.state_condition.notify_all()

    def decorator(func):
        def wrapper(self, *args, **kwargs):
            asyncio.async(execute_section(self, next_state, func, *args, **kwargs))

        return update_wrapper(wrapper, func)

    return decorator


command_re = re.compile(br'((DONE)|(?P<tag>\w+) (?P<cmd>[\w]+)([\w \.#@:\*"\(\)\{\}\+\-]+)?$)')


class ImapProtocol(asyncio.Protocol):
    IDLE_STILL_HERE_PERIOD_SECONDS = 10

    def __init__(self, server_state, fetch_chunk_size=0, loop=asyncio.get_event_loop()):
        self.delay_seconds = 0
        self.loop = loop
        self.fetch_chunk_size = fetch_chunk_size
        self.transport = None
        self.server_state = server_state
        self.user_login = None
        self.user_mailbox = None
        self.idle_tag = None
        self.idle_task = None
        self.state = NONAUTH
        self.state_condition = asyncio.Condition()
        self.append_literal_command = None

    def connection_made(self, transport):
        self.transport = transport
        transport.write('* OK IMAP4rev1 MockIMAP Server ready\r\n'.encode())

    def data_received(self, data):
        if self.append_literal_command is not None:
            self.append_literal(data)
            return
        for cmd_line in data.splitlines():
            if command_re.match(cmd_line) is None:
                self.send_untagged_line('BAD Error in IMAP command : Unknown command (%r).' % cmd_line)
            else:
                command_array = cmd_line.decode().rstrip().split()
                if self.state is not IDLE:
                    tag = command_array[0]
                    self.exec_command(tag, command_array[1:])
                else:
                    self.exec_command(None, command_array)

    def connection_lost(self, error):
        if error:
            log.error(error)

        if self.idle_task is not None:
            self.idle_task.cancel()
        self.transport.close()

    def exec_command(self, tag, command_array):
        command = command_array[0].lower()
        parameters = command_array[1:]
        if command == 'uid':
            command = command_array[1].lower()
            parameters = ['uid'] + command_array[2:]
        if not hasattr(self, command):
            return self.error(tag, 'Command "%s" not implemented' % command)
        self.loop.call_later(self.delay_seconds, lambda: getattr(self, command)(tag, *parameters))

    def send_untagged_line(self, response, encoding='utf-8', continuation=False, max_chunk_size=0):
        self.send_raw_untagged_line(response.encode(encoding=encoding), continuation, max_chunk_size)

    def send_raw_untagged_line(self, raw_response, continuation=False, max_chunk_size=0):
        prefix = b'+ ' if continuation else b'* '
        raw_line = prefix + raw_response + b'\r\n'
        if max_chunk_size:
            for nb_chunk in range(ceil(len(raw_line) / max_chunk_size)):
                chunk_start_index = nb_chunk * max_chunk_size
                self.send(raw_line[chunk_start_index:chunk_start_index + max_chunk_size])
        else:
            self.send(raw_line)

    def send_tagged_line(self, tag, response):
        self.send('{tag} {response}\r\n'.format(tag=tag, response=response).encode())

    def send(self, _bytes):
        log.debug("Sending %r", _bytes)
        self.transport.write(_bytes)

    @critical_section(next_state=AUTH)
    def login(self, tag, *args):
        self.user_login = args[0]
        self.server_state.login(self.user_login, self)
        self.send_untagged_line('CAPABILITY IMAP4rev1')
        self.send_tagged_line(tag, 'OK LOGIN completed')

    @critical_section(next_state=LOGOUT)
    def logout(self, tag, *args):
        self.server_state.login(self.user_login, self)
        self.send_untagged_line('BYE Logging out')
        self.send_tagged_line(tag, 'OK LOGOUT completed')
        self.transport.close()

    @critical_section(next_state=SELECTED)
    def select(self, tag, *args):
        self.user_mailbox = args[0]
        self.examine(tag, *args)

    @critical_section(next_state=IDLE)
    def idle(self, tag, *args):
        log.debug("Entering idle for '%s'", self.user_login)
        self.idle_tag = tag

        def still_here():
            self.send_untagged_line('OK Still here')
            self.idle_task = self.loop.call_later(self.IDLE_STILL_HERE_PERIOD_SECONDS, still_here)

        self.idle_task = self.loop.call_later(self.IDLE_STILL_HERE_PERIOD_SECONDS, still_here)
        self.send_untagged_line('idling', continuation=True)

    @critical_section(next_state=SELECTED)
    def done(self, _, *args):
        self.send_tagged_line(self.idle_tag, 'OK IDLE terminated')
        self.idle_task.cancel()
        self.idle_task = None
        self.idle_tag = None

    @critical_section(next_state=AUTH)
    def close(self, tag, *args):
        self.user_mailbox = None
        self.send_tagged_line(tag, 'OK CLOSE completed.')

    @asyncio.coroutine
    def wait(self, state):
        with (yield from self.state_condition):
            yield from self.state_condition.wait_for(lambda: self.state == state)

    def examine(self, tag, *args):
        mailbox_name = args[0]
        self.server_state.create_mailbox_if_not_exists(self.user_login, mailbox_name)
        mailbox = self.server_state.get_mailbox_messages(self.user_login, mailbox_name)
        self.send_untagged_line('FLAGS (\Answered \Flagged \Deleted \Seen \Draft)')
        self.send_untagged_line('OK [PERMANENTFLAGS (\Answered \Flagged \Deleted \Seen \Draft \*)] Flags permitted.')
        self.send_untagged_line('{nb_messages} EXISTS'.format(nb_messages=len(mailbox)))
        self.send_untagged_line('{nb_messages} RECENT'.format(nb_messages=0))
        self.send_untagged_line('OK [UIDVALIDITY 1400426466] UIDs valid')
        self.send_untagged_line('OK [UIDNEXT {next_uid}] Predicted next UID'.format(next_uid=len(mailbox) + 1))
        self.send_tagged_line(tag, 'OK [READ] Select completed (0.000 secs).')

    def search(self, tag, *args_param):
        args = list(args_param)
        by_uid = False
        args.reverse()

        if args[-1] == 'uid':
            args.pop()
            by_uid = True

        charset, keyword, unkeyword, older, younger = None, None, None, None, None
        if args and 'CHARSET' == args[-1].upper():
            args.pop()
            charset = args.pop()
        if args and 'KEYWORD' == args[-1].upper():
            args.pop()
            keyword = args.pop()
        if args and 'UNKEYWORD' == args[-1].upper():
            args.pop()
            unkeyword = args.pop()
        if args and 'OLDER' == args[-1].upper():
            args.pop()
            older = int(args.pop())
        if args and 'YOUNGER' == args[-1].upper():
            args.pop()
            younger = int(args.pop())
        all = 'ALL' in args

        self.send_untagged_line(
            'SEARCH {msg_uids}'.format(msg_uids=' '.join(
                self.memory_search(all, keyword, unkeyword, older, younger, by_uid=by_uid))))
        self.send_tagged_line(tag, 'OK %sSEARCH completed' % ('UID ' if by_uid else ''))

    def memory_search(self, all, keyword, unkeyword, older, younger, by_uid=False):
        def item_match(msg):
            return all or \
                   (keyword is not None and keyword in msg.flags) or \
                   (unkeyword is not None and unkeyword not in msg.flags) or \
                   (older is not None and datetime.now(tz=utc) - timedelta(seconds=older) > msg.date) or \
                   (younger is not None and datetime.now(tz=utc) - timedelta(seconds=younger) < msg.date)

        return [str(msg.uid if by_uid else msg.id)
                for msg in self.server_state.get_mailbox_messages(self.user_login, self.user_mailbox)
                if item_match(msg)]

    def store(self, tag, *args):
        arg_list = list(args)
        if arg_list[0] == 'uid':
            arg_list = list(args[1:])
        uid = int(arg_list[0])  # args = ['12', '+FLAGS', 'FOO']
        flag = arg_list[2]  # only support one flag and do not handle replacement (without + sign)
        for message in self.server_state.get_mailbox_messages(self.user_login, self.user_mailbox):
            if message.uid == uid:
                message.flags.append(flag)
                self.send_untagged_line('{uid} FETCH (UID {uid} FLAGS ({flags}))'.format(
                    uid=uid, flags=' '.join(message.flags)))
        self.send_tagged_line(tag, 'OK Store completed.')

    def fetch(self, tag, *args):
        arg_list = list(args)
        if arg_list[0] == 'uid':
            arg_list = list(args[1:])
        uid = int(arg_list[0])
        parts = arg_list[1:]
        for message in self.server_state.get_mailbox_messages(self.user_login, self.user_mailbox):
            if message.uid == uid:
                message_body = message.as_bytes()
                uid_bytes = ('%d' % message.uid).encode()
                if 'RFC822' in ' '.join(parts):
                    self.send_raw_untagged_line(uid_bytes + b' FETCH (UID ' + uid_bytes + b' RFC822 {' +
                                            ('%d' % len(message_body)).encode() + b'}\r\n' + message_body + b')',
                                            max_chunk_size=self.fetch_chunk_size)
                else:
                    self.send_untagged_line('{uid} FETCH (UID {uid} FLAGS ({flags}))'.format(
                        uid=uid, flags=' '.join(message.flags)))
        self.send_tagged_line(tag, 'OK FETCH completed.')

    def append(self, tag, *args):
        mailbox_name = args[0]
        size = args[-1].strip('{}')
        self.append_literal_command = (tag, mailbox_name, int(size))
        self.send_untagged_line('Ready for literal data', continuation=True)

    def append_literal(self, data):
        tag, mailbox_name, size = self.append_literal_command
        if data == b'\r\n':
            self.send_tagged_line(tag, 'OK APPEND completed.')
            self.append_literal_command = None
            return

        if len(data) != size:
            self.send_tagged_line(self.append_literal_command[0],
                                  'BAD literal length : expected %s but was %s' % (size, len(data)))
            self.append_literal_command = None
        else:
            m = email.message_from_bytes(data)
            self.server_state.add_mail(m.get('To'), Mail(m), mailbox_name)

    def expunge(self, tag, *args):
        for message in self.server_state.get_mailbox_messages(self.user_login, self.user_mailbox).copy():
            self.server_state.remove(message, self.user_login, self.user_mailbox)
            self.send_untagged_line('{msg_uid} EXPUNGE'.format(msg_uid=message.uid))
        self.send_tagged_line(tag, 'OK EXPUNGE completed.')

    def capability(self, tag, *args):
        self.send_untagged_line('CAPABILITY IMAP4rev1 LITERAL+ IDLE')
        self.send_tagged_line(tag, 'OK Pre-login capabilities listed, post-login capabilities have more')

    def copy(self, tag, *args):
        message_set, mailbox = args[0:-1], args[-1]
        self.server_state.copy(self.user_login, self.user_mailbox, mailbox, message_set)
        self.send_tagged_line(tag, 'OK COPY completed.')

    def noop(self, tag, *args):
        self.send_tagged_line(tag, 'OK NOOP completed.')

    def check(self, tag, *args):
        self.send_tagged_line(tag, 'OK CHECK completed.')

    def status(self, tag, *args):
        mailbox_name = args[0]
        data_items = ' '.join(args[1:])
        mailbox = self.server_state.get_mailbox_messages(self.user_login, mailbox_name)
        if mailbox is None:
            self.send_tagged_line(tag, 'NO STATUS completed.')
            return
        status_response = 'STATUS %s (' % mailbox_name
        if 'MESSAGES' in data_items:
            status_response += 'MESSAGES %s' % len(mailbox)
        if 'RECENT' in data_items:
            status_response += ' RECENT %s' % len([m for m in mailbox if 'RECENT' in m.flags])
        if 'UIDNEXT' in data_items:
            status_response += ' UIDNEXT %s' % (self.server_state.max_uid(self.user_login) + 1)
        if 'UIDVALIDITY' in data_items:
            status_response += ' UIDVALIDITY %s' % (self.server_state.max_uid(self.user_login) + 1)
        if 'UNSEEN' in data_items:
            status_response += ' UNSEEN %s' % len([m for m in mailbox if 'UNSEEN' in m.flags])
        status_response += ')'
        self.send_untagged_line(status_response)
        self.send_tagged_line(tag, 'OK STATUS completed.')

    def subscribe(self, tag, *args):
        mailbox_name = args[0]
        self.server_state.subscribe(self.user_login, mailbox_name)
        self.send_tagged_line(tag, 'OK SUBSCRIBE completed.')

    def unsubscribe(self, tag, *args):
        mailbox_name = args[0]
        self.server_state.unsubscribe(self.user_login, mailbox_name)
        self.send_tagged_line(tag, 'OK UNSUBSCRIBE completed.')

    def lsub(self, tag, *args):
        reference_name, mailbox_name = args

        if not reference_name.endswith('.') and not mailbox_name.startswith('.'):
            mailbox_search = '%s.%s' % (reference_name, mailbox_name)
        else:
            mailbox_search = reference_name + mailbox_name

        for found_mb_name in self.server_state.lsub(self.user_login, mailbox_search):
            self.send_untagged_line('LSUB () "." %s' % found_mb_name)
        self.send_tagged_line(tag, 'OK LSUB completed.')

    def create(self, tag, *args):
        mailbox_name = args[0]
        self.server_state.create_mailbox_if_not_exists(self.user_login, mailbox_name)
        self.send_tagged_line(tag, 'OK CREATE completed.')

    def delete(self, tag, *args):
        mailbox_name = args[0]
        self.server_state.delete_mailbox(self.user_login, mailbox_name)
        self.send_tagged_line(tag, 'OK DELETE completed.')

    def rename(self, tag, *args):
        old_mb, new_mb = args
        self.server_state.rename_mailbox(self.user_login, old_mb, new_mb)
        self.send_tagged_line(tag, 'OK RENAME completed.')

    def list(self, tag, *args):
        mailbox_pattern = args[0]

        for mb in self.server_state.list(self.user_login, mailbox_pattern):
            self.send_untagged_line('LIST () "/" %s' % mb)
        self.send_tagged_line(tag, 'OK LIST completed.')

    def error(self, tag, msg):
        self.send_tagged_line(tag, 'BAD %s' % msg)

    def notify_new_mail(self, uid):
        if self.idle_tag:
            self.send_untagged_line('{uid} EXISTS'.format(uid=uid))
            self.send_untagged_line('{uid} RECENT'.format(uid=uid))

    def delay(self, tag, *args):
        self.delay_seconds = int(args[0])
        self.send_tagged_line(tag, 'OK DELAY completed.')


_SERVER_STATE = ServerState()


def imap_receive(mail, imap_user=None, mailbox='INBOX'):
    """
    :param imap_user: str
    :type mail: Mail
    :type mailbox: str
    :type to_list: list
    """
    global _SERVER_STATE
    if imap_user is not None:
        return [_SERVER_STATE.imap_receive(imap_user, mail, mailbox)]
    else:
        uids = list()
        for to in mail.to:
            uids.append(_SERVER_STATE.imap_receive(to, mail, mailbox))
        return uids


def get_imapconnection(user):
    return _SERVER_STATE.get_connection(user)


def create_imap_protocol(fetch_chunk_size=0, loop=asyncio.get_event_loop()):
    protocol = ImapProtocol(_SERVER_STATE, fetch_chunk_size, loop)
    return protocol


def reset():
    global _SERVER_STATE
    _SERVER_STATE.reset()


class Mail(object):
    def __init__(self, email, date=datetime.now()):
        self.date = date
        self.email = email
        self.uid = 0
        self.id = 0
        self.flags = []

    def as_bytes(self):
        return self.email.as_bytes()

    def as_string(self):
        return self.email.as_string()

    @property
    def to(self):
        return self.email.get('To').split(', ')

    @staticmethod
    def create(to, mail_from='', subject='', content='',
               encoding='utf-8',
               date=None,
               in_reply_to=None,
               message_id=None,
               quoted_printable=False,
               cc=None
               ):
        """
        :param quoted_printable: boolean
        :type to: list
        :type cc: list
        :type mail_from: str
        :type subject: unicode
        :type content: unicode
        :type encoding: str
        :type date: datetime
        :param in_reply_to: str
        :param message_id: str
        """
        charset = email.charset.Charset(encoding)
        msg = email.mime.nonmultipart.MIMENonMultipart('text', 'plain', charset=encoding)
        if quoted_printable:
            charset.body_encoding = email.charset.QP
        msg.set_payload(content, charset=charset)
        date = date or datetime.now(tz=utc)
        msg['Return-Path'] = '<%s>' % mail_from
        msg['Delivered-To'] = '<%s>' % ', '.join(to)
        msg['Message-ID'] = '<%s>' % (message_id or '%s@mockimap' % str(uuid.uuid1()))
        msg['Date'] = date.strftime('%a, %d %b %Y %H:%M:%S %z')
        if '<' in mail_from  and '>' in mail_from or mail_from == '':
            msg['From'] = mail_from
        else:
            msg['From'] = '<%s>' % mail_from
        msg['User-Agent'] = 'python3'
        msg['MIME-Version'] = '1.0'
        msg['To'] = ', '.join(to)
        msg['Subject'] = Header(subject, encoding)
        if in_reply_to is not None:
            msg['In-Reply-To'] = '<%s>' % in_reply_to
        if cc is not None:
            msg['Cc'] = ', '.join(cc)
        return Mail(msg, date=date)

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    factory = loop.create_server(create_imap_protocol, 'localhost', 1143)
    server = loop.run_until_complete(factory)
    loop.run_forever()
