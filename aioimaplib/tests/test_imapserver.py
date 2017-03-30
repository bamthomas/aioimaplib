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
# -*- coding: utf-8 -*-
import email
import imaplib
import unittest
from datetime import datetime

import asyncio

import functools
from functools import partial

import asynctest
import pytz
from aioimaplib.tests import imapserver
from aioimaplib.tests.imapserver import ServerState, Mail


class TestMailToString(unittest.TestCase):
    def test_message_date_string(self):
        now = pytz.timezone('Europe/Paris').localize(datetime(2016, 2, 2, 12, 13, 14, 151))

        mail = imapserver.Mail.create(['user'], date=now)

        self.assertEqual(mail.email.get('Date'), 'Tue, 02 Feb 2016 12:13:14 +0100')

    def test_message_default_date_string_is_utc(self):
        mail = imapserver.Mail.create(['user'])

        self.assertTrue(mail.email.get('Date').endswith('+0000'))

    def test_message_title_string_without_accents_isnot_encoded(self):
        now = pytz.timezone('Europe/Paris').localize(datetime(2016, 2, 2, 12, 13, 14, 151))

        mail = imapserver.Mail.create(['user'], subject='subject', date=now)

        self.assertEqual(mail.email.get('Subject'), 'subject')

    def test_message_title_string_with_accents_is_base64encoded(self):
        mail = imapserver.Mail.create(['user'], subject='Classé ?')

        self.assertTrue('=?utf-8?b?Q2xhc3PDqSA/?=' in mail.as_string())

    def test_message_quoted_printable(self):
        mail = imapserver.Mail.create(['user'], content='Bonjour à vous', quoted_printable=True)

        self.assertTrue('Bonjour =C3=A0 vous' in mail.as_string(), msg='"=C3=A0" not found in %s' % mail.as_string())

    def test_message_not_quoted_printable(self):
        mail = imapserver.Mail.create(['user'], subject='élo ?', content='Bonjour à vous').as_bytes()

        m = email.message_from_bytes(mail)
        self.assertEquals('Bonjour à vous', m.get_payload(decode=True).decode())

    def test_header_encode_to(self):
        mail = imapserver.Mail.create(['Zébulon Durand <zeb@zebulon.io>'], mail_from='from@mail.fr', subject='subject')

        self.assertTrue('=?utf-8?q?Z=C3=A9bulon_Durand_=3Czeb=40zebulon=2Eio=3E?=' in mail.as_string(), msg='expected string not found in :%s\n' % mail.as_string())

    def test_mail_from(self):
        mail = imapserver.Mail.create(['user'], subject='subject')
        self.assertEquals(mail.email.get('From'), '')

        mail = imapserver.Mail.create(['user'], mail_from='<test@test>', subject='subject')
        self.assertEquals(mail.email.get('From'), '<test@test>')

        mail = imapserver.Mail.create(['user'], mail_from='test@test', subject='subject')
        self.assertEquals(mail.email.get('From'), '<test@test>')

        mail = imapserver.Mail.create(['user'], mail_from='Test <test@test>', subject='subject')
        self.assertEquals(mail.email.get('From'), 'Test <test@test>')


class TestServerState(unittest.TestCase):
    def test_max_ids_with_no_user(self):
        self.assertEquals(0, ServerState().max_uid('user'))
        self.assertEquals(0, ServerState().max_id('user', 'INBOX'))

    def test_max_ids_one_user_one_mail(self):
        server_state = ServerState()
        server_state.add_mail('user', Mail.create(['user']))

        self.assertEquals(1, server_state.max_id('user', 'INBOX'))
        self.assertEquals(1, server_state.max_uid('user'))
        self.assertEquals(0, server_state.max_id('user', 'OTHER_MAILBOX'))

    def test_max_ids_one_user_two_mails_one_per_mailbox(self):
        server_state = ServerState()
        server_state.add_mail('user', Mail.create(['user']), mailbox='INBOX')
        server_state.add_mail('user', Mail.create(['user']), mailbox='OUTBOX')

        self.assertEquals(1, server_state.max_id('user', 'INBOX'))
        self.assertEquals(1, server_state.max_id('user', 'OUTBOX'))
        self.assertEquals(2, server_state.max_uid('user'))


class WithImapServer(asynctest.ClockedTestCase):
    def setUp(self):
        factory = self.loop.create_server(partial(imapserver.create_imap_protocol, fetch_chunk_size=64, loop=self.loop),
                                          'localhost', 12345)
        self.server = self.loop.run_until_complete(factory)

    @asyncio.coroutine
    def tearDown(self):
        imapserver.reset()
        self.server.close()
        yield from asyncio.wait_for(self.server.wait_closed(), 1)

    @asyncio.coroutine
    def login_user(self, login, password, select=False, lib=imaplib.IMAP4):
        imap_client = yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(lib, host='localhost', port=12345)), 1)

        yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.login, login, password)), 1)

        if select:
            yield from asyncio.wait_for(
                self.loop.run_in_executor(None, functools.partial(imap_client.select)), 1)

        return imap_client
