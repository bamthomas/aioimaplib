# -*- coding: utf-8 -*-
import asyncio

from aioimaplib import aioimaplib


@asyncio.coroutine
def wait_for_new_message(host, user, password):
    imap_client = aioimaplib.IMAP4_SSL(host=host)
    yield from imap_client.wait_hello_from_server()

    yield from imap_client.login(user, password)
    yield from imap_client.select()

    asyncio.async(imap_client.idle())
    while True:
        msg = yield from imap_client.wait_server_push()
        print('--> received from server: %s' % msg)
        if 'EXISTS' in msg:
            imap_client.idle_done()
            break

    yield from imap_client.logout()


@asyncio.coroutine
def fetch_mail(host, user, password):
    imap_client = aioimaplib.IMAP4_SSL(host=host)
    yield from imap_client.wait_hello_from_server()

    yield from imap_client.login(user, password)

    res, data = yield from imap_client.select()
    print('there is %s messages INBOX' % data[0])

    yield from imap_client.logout()


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(fetch_mail('my.imap.server', 'user', 'pass'))