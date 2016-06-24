import asyncio
import logging
import quopri
import uuid
from datetime import datetime
from email._encoded_words import encode

import tzlocal

from copy import deepcopy

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
sh = logging.StreamHandler()
sh.setLevel(logging.INFO)
sh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s " +
                                  "[%(module)s:%(lineno)d] %(message)s"))
log.addHandler(sh)


class ImapProtocol(asyncio.Protocol):
    def __init__(self, mailbox_map):
        self.transport = None
        self.mailbox_map = mailbox_map
        self.user_login = None
        self.user_mailbox = None
        self.by_uid = False

    def connection_made(self, transport):
        self.transport = transport
        transport.write('* OK IMAP4rev1 MockIMAP Server ready\r\n'.encode())

    def data_received(self, data):
        command_array = data.decode().rstrip().split()
        tag = command_array[0]
        self.by_uid = False
        self.exec_command(tag, command_array[1:])

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

    def send_untagged_line(self, response, encoding='utf-8'):
        log.debug("Sending %s", response)
        self.transport.write('* {response}\r\n'.format(response=response).encode(encoding))

    def send_tagged_line(self, tag, response):
        log.debug("Sending %s", response)
        self.transport.write('{tag} {response}\r\n'.format(tag=tag, response=response).encode())

    def capability(self, tag, *args):
        self.send_untagged_line('CAPABILITY IMAP4rev1')
        self.send_tagged_line(tag, 'OK Pre-login capabilities listed, post-login capabilities have more')

    def login(self, tag, *args):
        self.user_login = args[0]
        if self.user_login not in self.mailbox_map:
            self.mailbox_map[self.user_login] = dict()
        self.send_untagged_line('CAPABILITY IMAP4rev1')
        self.send_tagged_line(tag, 'OK LOGIN completed')

    def select(self, tag, *args):
        self.user_mailbox = args[0]
        if self.user_mailbox not in self.mailbox_map[self.user_login]:
            self.mailbox_map[self.user_login][self.user_mailbox] = list()

        mailbox = self.get_mailbox_messages()
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
        self.send_tagged_line(tag, 'OK SEARCH completed')

    def memory_search(self, keyword, unkeyword=False):
        return [str(msg.uid) for msg in self.get_mailbox_messages()
                if keyword is None or ((keyword in msg.flags) != unkeyword)]

    def store(self, tag, *args):
        uid = int(args[0])  # args = ['12', '+FLAGS', 'FOO']
        flag = args[2]  # only support one flag and do not handle replacement (without + sign)
        for message in self.get_mailbox_messages():
            if message.uid == uid:
                message.flags.append(flag)
                self.send_untagged_line('{uid} FETCH (UID {uid} FLAGS ({flags}))'.format(
                    uid=uid, flags=' '.join(message.flags)))
        self.send_tagged_line(tag, 'OK Store completed.')

    def get_mailbox_messages(self):
        return self.mailbox_map[self.user_login][self.user_mailbox]

    def fetch(self, tag, *args):
        uid = int(args[0])
        for message in self.get_mailbox_messages():
            message_body = str(message)
            if message.uid == uid:
                self.send_untagged_line('{msg_uid} FETCH (UID {msg_uid} RFC822 {{{size}}}\r\n'
                                        '{message_body})'.format(msg_uid=message.uid,
                                                                 size=len(message_body.encode(message.encoding)),
                                                                 message_body=message_body),
                                        encoding=message.encoding)
        self.send_tagged_line(tag, 'OK FETCH completed.')

    def uid(self, tag, *args):
        self.by_uid = True
        self.exec_command(tag, args)

    def error(self, tag, msg):
        self.send_tagged_line(tag, 'BAD %s' % msg)


def imap_receive(mail, imap_user=None, mailbox='INBOX', to_list=None):
    """
    :param imap_user: str
    :type mail: Mail
    :type mailbox: str
    :type to_list: list
    """
    if imap_user is not None:
        _add_mail_to_mailboxes(mail, mailbox, imap_user)
    else:
        to_list = to_list if to_list is not None else mail.to
        for to in to_list:
            _add_mail_to_mailboxes(mail, mailbox, to)


def nb_mails_in_mailbox_map(mailbox_map):
    nb_mails = 0
    for user in mailbox_map.keys():
        for mailbox in mailbox_map[user].keys():
            nb_mails += len(mailbox_map[user][mailbox])
    return nb_mails


_MAILBOX_MAP = dict()


def _add_mail_to_mailboxes(mail, mailbox, to):
    if to not in _MAILBOX_MAP:
        _MAILBOX_MAP[to] = dict()
        _MAILBOX_MAP[to][mailbox] = list()
    m = deepcopy(mail)
    m.uid = nb_mails_in_mailbox_map(_MAILBOX_MAP) + 1
    _MAILBOX_MAP[to][mailbox].append(m)


def create_imap_protocol():
    return ImapProtocol(_MAILBOX_MAP)


def reset_mailboxes():
    global _MAILBOX_MAP
    _MAILBOX_MAP = dict()


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
                                        reply_to_header='' if self.in_reply_to is None else 'In-Reply-To: <%s>\r\n' % self.in_reply_to)

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
