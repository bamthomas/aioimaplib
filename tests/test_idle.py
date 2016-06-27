import asyncio

import functools

import asynctest
from imaplib2.imaplib2 import IMAP4
from mock import Mock
from tests.imapserver import create_imap_protocol, reset_mailboxes, imap_receive, Mail, _SERVER_STATE, \
    get_imapconnection


class TestImapServerIdle(asynctest.TestCase):
    def setUp(self):
        self.loop = asyncio.get_event_loop()
        factory = self.loop.create_server(create_imap_protocol, 'localhost', 12345)
        self.server = self.loop.run_until_complete(factory)
        self.loop.set_debug(enabled=True)

    @asyncio.coroutine
    def tearDown(self):
        reset_mailboxes()
        self.server.close()
        asyncio.wait_for(self.server.wait_closed(), 1)

    @asyncio.coroutine
    def test_idle(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)
        idle_callback = Mock()
        self.loop.run_in_executor(None, functools.partial(imap_client.idle, callback=idle_callback))
        yield from asyncio.wait_for(get_imapconnection('user').wait(idle=True), 1)

        self.loop.run_in_executor(None, functools.partial(imap_receive, Mail(to=['user'], mail_from='me', subject='hello')))

        yield from asyncio.wait_for(get_imapconnection('user').wait(idle=False), 1)
        idle_callback.assert_called_once()

    @asyncio.coroutine
    def login_user(self, login, password, select=False):
        imap_client = yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(IMAP4, host='localhost', port=12345)), 1)

        yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.login, login, password)), 1)

        if select:
            yield from asyncio.wait_for(
                self.loop.run_in_executor(None, functools.partial(imap_client.select)), 1)

        return imap_client