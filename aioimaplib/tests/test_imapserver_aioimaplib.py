# -*- coding: utf-8 -*-
#    aioimaplib : an IMAPrev4 lib using python asyncio
#    Copyright (C) 2016  Bruno Thomas
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
import asyncio

import asynctest

from aioimaplib import extract_exists
from aioimaplib.aioimaplib import Command
from aioimaplib.tests.test_aioimaplib import AioWithImapServer


class TestAioimaplib(AioWithImapServer, asynctest.TestCase):
    def setUp(self):
        self._init_server(self.loop)

    async def tearDown(self):
        await self._shutdown_server()

    async def test_append_too_long(self):
        imap_client = await self.login_user('user@mail', 'pass')
        self.assertEquals(0, extract_exists((await imap_client.examine('INBOX'))))

        message_bytes = b'do you see me ?'
        imap_client.protocol.literal_data = message_bytes * 2

        args = ['INBOX', '{%s}' % len(message_bytes)]
        response = await imap_client.protocol.execute(
            Command('APPEND', imap_client.protocol.new_tag(), *args, loop=self.loop)
        )
        self.assertEquals('BAD', response.result)
        self.assertTrue(b'expected CRLF but got' in response.lines[0])

    async def test_append_too_short(self):
        imap_client = await self.login_user('user@mail', 'pass')
        self.assertEquals(0, extract_exists((await imap_client.examine('INBOX'))))

        message_bytes = b'do you see me ?' * 2
        imap_client.protocol.literal_data = message_bytes[:5]

        args = ['INBOX', '{%s}' % len(message_bytes)]
        response = await imap_client.protocol.execute(
            Command('APPEND', imap_client.protocol.new_tag(), *args, loop=self.loop)
        )
        self.assertEquals('BAD', response.result)
        self.assertTrue(b'expected 30 but was' in response.lines[0])
