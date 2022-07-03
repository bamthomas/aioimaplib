import re
from asyncio import run, wait_for
from collections import namedtuple
from email.message import Message
from email.parser import BytesHeaderParser, BytesParser
from typing import Collection

import aioimaplib

ID_HEADER_SET = {'Content-Type', 'From', 'To', 'Cc', 'Bcc', 'Date', 'Subject',
                                   'Message-ID', 'In-Reply-To', 'References'}
FETCH_MESSAGE_DATA_UID = re.compile(rb'.*UID (?P<uid>\d+).*')
FETCH_MESSAGE_DATA_SEQNUM = re.compile(rb'(?P<seqnum>\d+) FETCH.*')
FETCH_MESSAGE_DATA_FLAGS  = re.compile(rb'.*FLAGS \((?P<flags>.*?)\).*')
MessageAttributes = namedtuple('MessageAttributes', 'uid flags sequence_number')


async def fetch_messages_headers(imap_client: aioimaplib.IMAP4_SSL, max_uid: int) -> int:
    response = await imap_client.uid('fetch', '%d:*' % (max_uid + 1),
                                     '(UID FLAGS BODY.PEEK[HEADER.FIELDS (%s)])' % ' '.join(ID_HEADER_SET))
    new_max_uid = max_uid
    if response.result == 'OK':
        for i in range(0, len(response.lines) - 1, 3):
            fetch_command_without_literal = b'%s %s' % (response.lines[i], response.lines[i + 2])

            uid = int(FETCH_MESSAGE_DATA_UID.match(fetch_command_without_literal).group('uid'))
            flags = FETCH_MESSAGE_DATA_FLAGS.match(fetch_command_without_literal).group('flags')
            seqnum = FETCH_MESSAGE_DATA_SEQNUM.match(fetch_command_without_literal).group('seqnum')
            # these attributes could be used for local state management
            message_attrs = MessageAttributes(uid, flags, seqnum)
            print(message_attrs)

            # uid fetch always includes the UID of the last message in the mailbox
            # cf https://tools.ietf.org/html/rfc3501#page-61
            if uid > max_uid:
                message_headers = BytesHeaderParser().parsebytes(response.lines[i + 1])
                print(message_headers)
                new_max_uid = uid
    else:
        print('error %s' % response)
    return new_max_uid


async def fetch_message_body(imap_client: aioimaplib.IMAP4_SSL, uid: int) -> Message:
    dwnld_resp = await imap_client.uid('fetch', str(uid), 'BODY.PEEK[]')
    return BytesParser().parsebytes(dwnld_resp.lines[1])


def handle_server_push(push_messages: Collection[str]) -> None:
    for msg in push_messages:
        if msg.endswith('EXISTS'):
            print('new message: %s' % msg) # could fetch only the message instead of max_uuid:* in the loop
        elif msg.endswith('EXPUNGE'):
            print('message removed: %s' % msg)
        elif 'FETCH' in msg and '\Seen' in msg:
            print('message seen %s' % msg)
        else:
            print('unprocessed push message : %s' % msg)


async def imap_loop(host, user, password) -> None:
    imap_client = aioimaplib.IMAP4_SSL(host=host, timeout=30)
    await imap_client.wait_hello_from_server()

    await imap_client.login(user, password)
    await imap_client.select('INBOX')

    persistent_max_uid = 1
    while True:
        persistent_max_uid = await fetch_messages_headers(imap_client, persistent_max_uid)
        print('%s starting idle' % user)
        idle_task = await imap_client.idle_start(timeout=60)
        handle_server_push((await imap_client.wait_server_push()))
        imap_client.idle_done()
        await wait_for(idle_task, timeout=5)
        print('%s ending idle' % user)


if __name__ == '__main__':
    run(imap_loop('imap.server', 'account_id', 'password'))
