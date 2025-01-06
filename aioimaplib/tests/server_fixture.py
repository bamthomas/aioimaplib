import asyncio
import functools
import imaplib
import ssl
from email.charset import add_charset, SHORTEST
from ssl import SSLContext

import pytest

from aioimaplib import aioimaplib
from aioimaplib.tests.imapserver import MockImapServer
from aioimaplib.tests.ssl_cert import create_temp_self_signed_cert


async def main_test(server: MockImapServer, ssl_context: SSLContext | None):
    srv = await server.run_server(host='127.0.0.1', port=12345, fetch_chunk_size=64, ssl_context=ssl_context)
    async with srv:
        await srv.serve_forever()


@pytest.fixture()
def with_ssl():
    _cert_file, _cert_key = create_temp_self_signed_cert()
    ssl_context_server = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context_server.load_cert_chain(_cert_file, _cert_key)
    return ssl_context_server, _cert_file


@pytest.fixture()
def with_server(event_loop, capabilities=None):
    add_charset('utf-8', SHORTEST, None, 'utf-8')
    add_charset('cp1252', SHORTEST, None, 'cp1252')
    if capabilities is not None:
        imapserver = MockImapServer(loop=event_loop, capabilities=capabilities)
    else:
        imapserver = MockImapServer(loop=event_loop)
    cancel_handle = asyncio.ensure_future(main_test(server=imapserver, ssl_context=None))
    event_loop.run_until_complete(asyncio.sleep(0.01))

    try:
        yield imapserver
    finally:
        cancel_handle.cancel()

    imapserver.reset()


@pytest.fixture()
def with_ssl_server(event_loop, with_ssl):
    add_charset('utf-8', SHORTEST, None, 'utf-8')
    add_charset('cp1252', SHORTEST, None, 'cp1252')
    imapserver = MockImapServer(loop=event_loop)
    cancel_handle = asyncio.ensure_future(main_test(server=imapserver, ssl_context=with_ssl[0]))
    event_loop.run_until_complete(asyncio.sleep(0.01))

    try:
        yield imapserver
    finally:
        cancel_handle.cancel()

    imapserver.reset()


async def login_user(login, password, select=False, lib=imaplib.IMAP4, loop=None):
    args = {'host': '127.0.0.1', 'port': 12345} if loop is None else {'host': '127.0.0.1', 'port': 12345, 'loop': loop}
    imap_client = await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(lib, **args)), 1)

    await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.login, login, password)), 1)

    if select:
        await asyncio.wait_for(
            asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.select)), 1)

    return imap_client


async def login_user_async(login, password, select=False):
    imap_client = aioimaplib.IMAP4(host='127.0.0.1', port=12345, loop=asyncio.get_running_loop())
    await imap_client.wait_hello_from_server()
    await imap_client.login(login, password)
    if select:
        await imap_client.select()
    return imap_client
