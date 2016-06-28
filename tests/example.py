# -*- coding: utf-8 -*-
import asyncio

from aioimaplib import aioimaplib


@asyncio.coroutine
def fetch_mail(host, user, password):
    imap_client = aioimaplib.IMAP4_SSL(host=host)
    yield from imap_client.wait_hello_from_server()

    yield from imap_client.login(user, password)
    yield from imap_client.logout()


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(fetch_mail('my.imap.server', 'user', 'pass'))