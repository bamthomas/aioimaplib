# -*- coding: utf-8 -*-
import asyncio

from aioimaplib import aioimaplib


async def wait_for_new_message(host, user, password):
    imap_client = aioimaplib.IMAP4_SSL(host=host)
    await imap_client.wait_hello_from_server()

    await imap_client.login(user, password)
    await imap_client.select()

    await imap_client.idle()
    while True:
        msg = await imap_client.wait_server_push()
        print('--> received from server: %s' % msg)
        if 'EXISTS' in msg:
            imap_client.idle_done()
            break

    await imap_client.logout()


async def fetch_mail(host, user, password):
    imap_client = aioimaplib.IMAP4_SSL(host=host)
    await imap_client.wait_hello_from_server()

    await imap_client.login(user, password)

    response = await imap_client.select()
    print('there is %s messages INBOX' % aioimaplib.extract_exists(response))

    await imap_client.logout()


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(fetch_mail('my.imap.server', 'user', 'pass'))