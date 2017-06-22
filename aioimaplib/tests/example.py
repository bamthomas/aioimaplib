# -*- coding: utf-8 -*-
import asyncio

import logging

from aioimaplib import aioimaplib

aioimaplib.log.setLevel(logging.DEBUG)
sh = logging.StreamHandler()
sh.setLevel(logging.DEBUG)
sh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(module)s:%(lineno)d] %(message)s"))
aioimaplib.log.addHandler(sh)

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
    imap_client = aioimaplib.IMAP4_SSL(host=host, timeout=30)
    yield from imap_client.wait_hello_from_server()

    yield from imap_client.login(user, password)

    # response = yield from imap_client.select('Draft')

    yield from imap_client.list('""', '%')

    yield from imap_client.logout()


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    # loop.run_until_complete(fetch_mail('imap-mail.outlook.com', 'tobias.nuxung@outlook.fr', 'TBy2kiagy'))
    # loop.run_until_complete(fetch_mail('imap.mail.yahoo.com', 'paulmercier75@yahoo.com', 'demonstration'))
    loop.run_until_complete(fetch_mail('imap.gmail.com', 'thomasbam@gmail.com', 'y2k5iagy'))
