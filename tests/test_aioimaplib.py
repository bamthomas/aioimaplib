# -*- coding: utf-8 -*-
import asyncio

from aioimaplib import aioimaplib
from tests.imapserver import imap_receive, Mail
from tests.test_imapserver import WithImapServer


class TestAioimaplib(WithImapServer):
    @asyncio.coroutine
    def test_capabilities(self):
        imap_client = aioimaplib.IMAP4(port=12345, loop=self.loop)
        yield from asyncio.wait_for(imap_client.wait_hello_from_server(), 2)

        self.assertEquals('IMAP4REV1', imap_client.protocol.imap_version)

    @asyncio.coroutine
    def test_login(self):
        imap_client = aioimaplib.IMAP4(port=12345, loop=self.loop, timeout=3)
        yield from asyncio.wait_for(imap_client.wait_hello_from_server(), 2)

        result, data = yield from imap_client.login('user', 'password')

        self.assertEquals(aioimaplib.AUTH, imap_client.protocol.state)
        self.assertEqual('OK', result)
        self.assertEqual('LOGIN completed', data[-1])

    @asyncio.coroutine
    def test_login_twice(self):
        with self.assertRaises(aioimaplib.Error) as expected:
            imap_client = yield from self.login_user('user', 'pass')

            yield from imap_client.login('user', 'password')

        self.assertEqual(expected.exception.args, ('command LOGIN illegal in state AUTH',))

    @asyncio.coroutine
    def test_logout(self):
        imap_client = yield from self.login_user('user', 'pass')

        result, data = yield from imap_client.logout()

        self.assertEqual('OK', result)
        self.assertEqual(['BYE Logging out', 'LOGOUT completed'], data)
        self.assertEquals(aioimaplib.LOGOUT, imap_client.protocol.state)

    @asyncio.coroutine
    def test_select_no_messages(self):
        imap_client = yield from self.login_user('user', 'pass')

        result, data = yield from imap_client.select()

        self.assertEqual('OK', result)
        self.assertEqual(['0'], data)
        self.assertEquals(aioimaplib.SELECTED, imap_client.protocol.state)

    @asyncio.coroutine
    def test_search_two_messages(self):
        imap_receive(Mail(['user']))
        imap_receive(Mail(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        result, data = yield from imap_client.search('utf-8', 'ALL')

        self.assertEqual('OK', result)
        self.assertEqual(['1 2'], data)

    @asyncio.coroutine
    def login_user(self, login, password, select=False, lib=aioimaplib.IMAP4):
        imap_client = aioimaplib.IMAP4(port=12345, loop=self.loop, timeout=3)
        yield from asyncio.wait_for(imap_client.wait_hello_from_server(), 2)

        yield from imap_client.login('user', 'password')

        if select:
            yield from imap_client.select()
        return imap_client
