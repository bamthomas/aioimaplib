import asyncio
import functools
import imaplib
import ssl
from email.charset import add_charset, SHORTEST
from ssl import SSLContext
from typing import Optional

import pytest

from aioimaplib import aioimaplib
from aioimaplib.tests.imapserver import MockImapServer
from aioimaplib.tests.ssl_cert import create_temp_self_signed_cert


async def main_test(server: MockImapServer, ssl_context: Optional[SSLContext]):
    srv = await server.run_server(host='127.0.0.1', port=12345, fetch_chunk_size=64, ssl_context=ssl_context)
    async with srv:
        try:
            await srv.serve_forever()
        except Exception:
            srv.shutdown()


@pytest.fixture()
def with_ssl():
    _cert_file, _cert_key = create_temp_self_signed_cert()
    ssl_context_server = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context_server.load_cert_chain(_cert_file, _cert_key)
    return ssl_context_server, _cert_file


@pytest.fixture
def advance_time(event_loop, request):
    return EventLoopClockAdvancer(event_loop)


@pytest.fixture()
def with_server(event_loop, request):
    capabilities = request.param if hasattr(request, 'param') else None  #
    imapserver = create_server(capabilities, event_loop)
    main_server_future = asyncio.ensure_future(main_test(server=imapserver, ssl_context=None))
    event_loop.run_until_complete(asyncio.sleep(0.01))
    try:
        yield imapserver
    finally:
        imapserver.reset()
        main_server_future.cancel()


def create_server(capabilities, event_loop):
    add_charset('utf-8', SHORTEST, None, 'utf-8')
    add_charset('cp1252', SHORTEST, None, 'cp1252')
    if capabilities is not None:
        imapserver = MockImapServer(loop=event_loop, capabilities=capabilities)
    else:
        imapserver = MockImapServer(loop=event_loop)
    return imapserver


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
        imapserver.reset()
        cancel_handle.cancel()


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


async def login_user_async(login, password, select=False, loop=None, timeout=1):
    test_loop = loop if loop is not None else asyncio.get_running_loop()
    imap_client = aioimaplib.IMAP4(host='127.0.0.1', port=12345, loop=test_loop, timeout=timeout)
    await imap_client.wait_hello_from_server()
    await imap_client.login(login, password)
    if select:
        await imap_client.select()
    return imap_client


class EventLoopClockAdvancer:
    """
    from https://github.com/pytest-dev/pytest-asyncio/pull/113
    A helper object that when called will advance the event loop's time. If the
    call is awaited, the caller task will wait an iteration for the update to
    wake up any awaiting handlers.
    """

    __slots__ = ("offset", "loop", "sleep_duration", "_base_time")

    def __init__(self, loop, sleep_duration=1e-6):
        self.offset = 0.0
        self._base_time = loop.time
        self.loop = loop
        self.sleep_duration = sleep_duration

        # incorporate offset timing into the event loop
        self.loop.time = self.time

    def time(self):
        """
        Return the time according to the event loop's clock. The time is
        adjusted by an offset.
        """
        return self._base_time() + self.offset

    async def __call__(self, seconds):
        """
        Advance time by a given offset in seconds. Returns an awaitable
        that will complete after all tasks scheduled for after advancement
        of time are proceeding.
        """
        # sleep so that the loop does everything currently waiting
        await asyncio.sleep(self.sleep_duration)

        if seconds > 0:
            # advance the clock by the given offset
            self.offset += seconds

            # Once the clock is adjusted, new tasks may have just been
            # scheduled for running in the next pass through the event loop
            await asyncio.sleep(self.sleep_duration)