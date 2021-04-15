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

import functools

import time

from asynctest import TestCase
from imaplib2 import imaplib2
from mock import Mock
from aioimaplib.tests import imapserver
from aioimaplib.tests.imapserver import Mail
from aioimaplib.tests.test_imapserver import WithImapServer


class TestImapServerIdle(WithImapServer, TestCase):
    def setUp(self):
        self._init_server(self.loop)

    async def tearDown(self):
        await self._shutdown_server()

    async def test_idle(self):
        imap_client = await self.login_user('user', 'pass', select=True, lib=imaplib2.IMAP4)
        idle_callback = Mock()
        self.loop.run_in_executor(None, functools.partial(imap_client.idle, callback=idle_callback))
        await asyncio.wait_for(self.imapserver.get_connection('user').wait(imapserver.IDLE), 1)

        self.loop.run_in_executor(None, functools.partial(self.imapserver.receive,
                                                          Mail.create(to=['user'], mail_from='me', subject='hello')))

        await asyncio.wait_for(self.imapserver.get_connection('user').wait(imapserver.SELECTED), 5)
        time.sleep(0.1) # eurk hate sleeps but I don't know how to wait for the lib to receive end of IDLE
        idle_callback.assert_called_once()

    async def test_login_twice(self):
        with self.assertRaises(imaplib2.IMAP4.error) as expected:
            imap_client = await self.login_user('user', 'pass', lib=imaplib2.IMAP4)

            await asyncio.wait_for(
                self.loop.run_in_executor(None, functools.partial(imap_client.login, 'user', 'pass')), 1)

        self.assertEqual(expected.exception.args, ('command LOGIN illegal in state AUTH',))
