# -*- coding: utf-8 -*-
import asyncio

from aioimaplib import aioimaplib
from tests.test_imapserver import WithImapServer


class TestAioimaplib(WithImapServer):
    @asyncio.coroutine
    def test_capabilities(self):
        imap_client = aioimaplib.IMAP4(port=12345, loop=self.loop)
        yield from asyncio.wait_for(imap_client.protocol.wait(aioimaplib.NONAUTH), 2)

        yield from imap_client.protocol.wait_pending_commands()
        self.assertEquals('IMAP4REV1', imap_client.protocol.imap_version)

    @asyncio.coroutine
    def test_login(self):
        imap_client = aioimaplib.IMAP4(port=12345, loop=self.loop)
        yield from asyncio.wait_for(imap_client.protocol.wait(aioimaplib.NONAUTH), 2)

        result, data = yield from imap_client.login('user', 'password')

        self.assertEquals(aioimaplib.AUTH, imap_client.protocol.state)
        self.assertEqual('OK', result)
        self.assertEqual(['LOGIN completed'], data)