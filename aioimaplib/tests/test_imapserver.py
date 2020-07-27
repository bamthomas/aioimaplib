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

import asynctest
import pytz
import sys

from aioimaplib.tests import imapserver
from aioimaplib.tests.imapserver import ServerState, Mail, MockImapServer, ImapProtocol, InvalidUidSet


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

    def test_build_sequence_range(self):
        self.assertEqual(range(1, 3), ImapProtocol(None)._build_sequence_range('1:2'))
        self.assertEqual(range(1, 12), ImapProtocol(None)._build_sequence_range('1:11'))
        self.assertEqual(range(1234, 12346), ImapProtocol(None)._build_sequence_range('1234:12345'))
        self.assertEqual(range(1, sys.maxsize), ImapProtocol(None)._build_sequence_range('1:*'))
        self.assertEqual([42], ImapProtocol(None)._build_sequence_range('42'))

    def test_build_sequence_badrange(self):
        with self.assertRaises(InvalidUidSet):
            ImapProtocol(None)._build_sequence_range('0:2')

        with self.assertRaises(InvalidUidSet):
            ImapProtocol(None)._build_sequence_range('2:0')

        with self.assertRaises(InvalidUidSet):
            ImapProtocol(None)._build_sequence_range('2:1')


class TestServerState(unittest.TestCase):
    def test_max_ids_with_no_user(self):
        self.assertEquals(0, ServerState().max_uid('user', 'INBOX'))
        self.assertEquals(0, ServerState().max_id('user', 'INBOX'))

    def test_max_ids_one_user_one_mail(self):
        server_state = ServerState()
        server_state.add_mail('user', Mail.create(['user']))

        self.assertEquals(1, server_state.max_id('user', 'INBOX'))
        self.assertEquals(1, server_state.max_uid('user', 'INBOX'))
        self.assertEquals(0, server_state.max_id('user', 'OTHER_MAILBOX'))

    def test_max_ids_one_user_three_mails_in_two_mailboxes(self):
        server_state = ServerState()
        server_state.add_mail('user', Mail.create(['user']), mailbox='INBOX')
        server_state.add_mail('user', Mail.create(['user']), mailbox='INBOX')
        server_state.add_mail('user', Mail.create(['user']), mailbox='OUTBOX')

        self.assertEquals(1, server_state.max_id('user', 'OUTBOX'))
        self.assertEquals(2, server_state.max_id('user', 'INBOX'))
        self.assertEquals(2, server_state.max_uid('user', 'INBOX'))

    def test_reprocess_ids_if_a_message_is_removed(self):
        server_state = ServerState()
        server_state.add_mail('user', Mail.create(['user'], 'from1'), mailbox='INBOX')
        server_state.add_mail('user', Mail.create(['user'], 'from2'), mailbox='INBOX')
        server_state.add_mail('user', Mail.create(['user'], 'from3'), mailbox='INBOX')

        server_state.remove_byid('user', 'INBOX', 1)
        self.assertEqual(1, server_state.get_mailbox_messages('user', 'INBOX')[0].id)
        self.assertEqual(2, server_state.get_mailbox_messages('user', 'INBOX')[1].id)
        self.assertEquals(2, server_state.max_id('user', 'INBOX'))
        self.assertEquals(3, server_state.max_uid('user', 'INBOX'))

        server_state.remove_byid('user', 'INBOX', 1)
        self.assertEqual(1, server_state.get_mailbox_messages('user', 'INBOX')[0].id)
        self.assertEquals(1, server_state.max_id('user', 'INBOX'))
        self.assertEquals(3, server_state.max_uid('user', 'INBOX'))


class WithImapServer(object):
    def _init_server(self, loop, capabilities=None, ssl_context=None):
        self.loop = loop
        if capabilities is not None:
            self.imapserver = MockImapServer(loop=loop, capabilities=capabilities)
        else:
            self.imapserver = MockImapServer(loop=loop)
        self.server = self.imapserver.run_server(
            host='127.0.0.1', port=12345, fetch_chunk_size=64, ssl_context=ssl_context
        )

    async def _shutdown_server(self):
        self.imapserver.reset()
        self.server.close()
        await asyncio.wait_for(self.server.wait_closed(), 1)

    async def login_user(self, login, password, select=False, lib=imaplib.IMAP4):
        imap_client = await asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(lib, host='127.0.0.1', port=12345)), 1)

        await asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.login, login, password)), 1)

        if select:
            await asyncio.wait_for(
                self.loop.run_in_executor(None, functools.partial(imap_client.select)), 1)

        return imap_client
