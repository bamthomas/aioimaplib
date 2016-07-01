import asyncio
import logging
import quopri
import uuid
from datetime import datetime
from email._encoded_words import encode

import re

from functools import wraps, update_wrapper

import tzlocal

from copy import deepcopy

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

    def create_mailbox_if_not_exists(self, user_login, user_mailbox):
        if user_mailbox not in self.mailboxes[user_login]:
            self.mailboxes[user_login][user_mailbox] = list()

    def get_mailbox_messages(self, user_login, user_mailbox):
        return self.mailboxes[user_login][user_mailbox]

    def imap_receive(self, user, mail, mailbox):
        uid = self.add_mail(user, mail, mailbox)
        if user in self.connections:
            self.connections[user].notify_new_mail(uid)

    def get_connection(self, user):
        return self.connections.get(user)

    def remove(self, message, user, mailbox):
        self.mailboxes[user][mailbox].remove(message)

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
            asyncio.wait(asyncio.async(execute_section(self, next_state, func, *args, **kwargs)))

        return update_wrapper(wrapper, func)

    return decorator

command_re = re.compile(br'((DONE)|(?P<tag>\w+) (?P<cmd>[\w]+)([\w "\(\)\+\-]+)?$)')


class ImapProtocol(asyncio.Protocol):
    def __init__(self, server_state):
        self.transport = None
        self.server_state = server_state
        self.user_login = None
        self.user_mailbox = None
        self.by_uid = False
        self.idle_tag = None
        self.state = NONAUTH
        self.state_condition = asyncio.Condition()

    def connection_made(self, transport):
        self.transport = transport
        transport.write('* OK IMAP4rev1 MockIMAP Server ready\r\n'.encode())

    def data_received(self, data):
        for cmd_line in data.splitlines():
            if command_re.match(cmd_line) is None:
                self.send_untagged_line('BAD Error in IMAP command : Unknown command (%r).' % cmd_line)
                return
            command_array = cmd_line.decode().rstrip().split()
            if self.state is not IDLE:
                tag = command_array[0]
                self.by_uid = False
                self.exec_command(tag, command_array[1:])
            else:
                self.exec_command(None, command_array)

    def connection_lost(self, error):
        if error:
            log.error(error)
        else:
            log.debug('closing')
            self.transport.close()
        super().connection_lost(error)

    def exec_command(self, tag, command_array):
        command = command_array[0].lower()
        if not hasattr(self, command):
            return self.error(tag, 'Command "%s" not implemented' % command)
        getattr(self, command)(tag, *command_array[1:])

    def send_untagged_line(self, response, encoding='utf-8', continuation=False):
        log.debug("Sending %s", response)
        prefix = '+' if continuation else '*'
        self.transport.write('{prefix} {response}\r\n'.format(response=response, prefix=prefix).encode(encoding))

    def send_tagged_line(self, tag, response):
        log.debug("Sending %s", response)
        self.transport.write('{tag} {response}\r\n'.format(tag=tag, response=response).encode())

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
        self.send_untagged_line('idling', continuation=True)

    @critical_section(next_state=SELECTED)
    def done(self, _, *args):
        self.send_tagged_line(self.idle_tag, 'OK IDLE terminated')
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

    def search(self, tag, *args):
        keyword = None
        if 'keyword' in args[0].lower():
            keyword = args[1]
        unkeyword = args[0].lower() == 'unkeyword'
        self.send_untagged_line('SEARCH {msg_uids}'.format(msg_uids=' '.join(self.memory_search(keyword, unkeyword))))
        self.send_tagged_line(tag, 'OK %sSEARCH completed' % ('UID ' if self.by_uid else ''))

    def memory_search(self, keyword, unkeyword=False):
        return [str(msg.uid if self.by_uid else msg.id)
                for msg in self.server_state.get_mailbox_messages(self.user_login, self.user_mailbox)
                if keyword is None or ((keyword in msg.flags) != unkeyword)]

    def store(self, tag, *args):
        uid = int(args[0])  # args = ['12', '+FLAGS', 'FOO']
        flag = args[2]  # only support one flag and do not handle replacement (without + sign)
        for message in self.server_state.get_mailbox_messages(self.user_login, self.user_mailbox):
            if message.uid == uid:
                message.flags.append(flag)
                self.send_untagged_line('{uid} FETCH (UID {uid} FLAGS ({flags}))'.format(
                    uid=uid, flags=' '.join(message.flags)))
        self.send_tagged_line(tag, 'OK Store completed.')

    def fetch(self, tag, *args):
        uid = int(args[0])
        for message in self.server_state.get_mailbox_messages(self.user_login, self.user_mailbox):
            message_body = str(message)
            if message.uid == uid:
                self.send_untagged_line('{msg_uid} FETCH (UID {msg_uid} RFC822 {{{size}}}\r\n'
                                        '{message_body})'.format(msg_uid=message.uid,
                                                                 size=len(message_body.encode(message.encoding)),
                                                                 message_body=message_body),
                                        encoding=message.encoding)
        self.send_tagged_line(tag, 'OK FETCH completed.')

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


    def uid(self, tag, *args):
        self.by_uid = True
        try:
            self.exec_command(tag, args)
        finally:
            self.by_uid = False

    def error(self, tag, msg):
        self.send_tagged_line(tag, 'BAD %s' % msg)

    def notify_new_mail(self, uid):
        if self.idle_tag:
            self.send_untagged_line('{uid} EXISTS'.format(uid=uid))
            self.send_untagged_line('{uid} RECENT'.format(uid=uid))


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
        _SERVER_STATE.imap_receive(imap_user, mail, mailbox)
    else:
        for to in mail.to:
            _SERVER_STATE.imap_receive(to, mail, mailbox)


def get_imapconnection(user):
    return _SERVER_STATE.get_connection(user)


def create_imap_protocol():
    protocol = ImapProtocol(_SERVER_STATE)
    return protocol


def reset():
    global _SERVER_STATE
    _SERVER_STATE.reset()


class Mail(object):
    def __init__(self, to, mail_from='', subject='', content='', encoding='utf-8',
                 content_transfer_encoding='7bit',
                 date=None,
                 in_reply_to=None):
        """
        :type to: list
        :type mail_from: str
        :type subject: unicode
        :type content: unicode
        :type date: datetime
        :type encoding: str
        :type content_transfer_encoding: str
        """
        self.in_reply_to = in_reply_to
        self.content_transfer_encoding = content_transfer_encoding
        self.encoding = encoding
        self.date = datetime.now() if date is None else date
        self.content = content
        self.message_id = str(uuid.uuid1())
        self.uid = 0
        self.id = 0
        self.flags = []
        self.to = to
        self.subject = subject
        self.mail_from = mail_from

    def __str__(self):
        if self.content_transfer_encoding == 'quoted-printable':
            content = quopri.encodestring(self.content.encode(encoding=self.encoding)).decode('ascii')
        else:
            content = self.content
        return ('Return-Path: <{mail_from}>\r\n'
                'Delivered-To: <{to}>\r\n'
                'Received: from Mock IMAP Server\r\n'
                'Message-ID: <{message_id}@mockimap>\r\n'
                'Date: {date}\r\n'
                'From: {mail_from}\r\n'
                'User-Agent: python3\r\n'
                'MIME-Version: 1.0\r\n'
                'To: {to}\r\n'
                'Subject: {subject}\r\n'
                '{reply_to_header}'
                'Content-Type: text/plain; charset={charset}\r\n'
                'Content-Transfer-Encoding: {content_transfer_encoding}\r\n'
                '\r\n'
                '{content}\r\n').format(mail_from=self.mail_from, to=', '.join(self.to), message_id=self.message_id,
                                        date=self.date.strftime('%a, %d %b %Y %H:%M:%S %z'), subject=self.get_subject(),
                                        content=content, charset=self.encoding,
                                        content_transfer_encoding=self.content_transfer_encoding,
                                        reply_to_header='' if self.in_reply_to is None else 'In-Reply-To: <%s>\r\n' %
                                                                                            self.in_reply_to)

    def get_subject(self):
        try:
            self.subject.encode('ascii')
        except UnicodeEncodeError:
            return encode(self.subject, encoding='b')
        else:
            return self.subject


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    factory = loop.create_server(create_imap_protocol, 'localhost', 1143)
    server = loop.run_until_complete(factory)
    loop.run_forever()
