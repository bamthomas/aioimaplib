# -*- coding: utf-8 -*-
import email
import imaplib
import unittest
from datetime import datetime

import asyncio

import functools

import asynctest
import pytz
from tests import imapserver


class TestMailToString(unittest.TestCase):
    def test_message_date_string(self):
        now = pytz.timezone('Europe/Paris').localize(datetime(2016, 2, 2, 12, 13, 14, 151))

        mail = imapserver.Mail(['user'], date=now)

        self.assertEqual(email.message_from_string(str(mail)).get('Date'), 'Tue, 02 Feb 2016 12:13:14 +0100')

    def test_message_title_string_without_accents_isnot_encoded(self):
        now = pytz.timezone('Europe/Paris').localize(datetime(2016, 2, 2, 12, 13, 14, 151))

        mail = imapserver.Mail(['user'], subject='subject', date=now)

        self.assertEqual(email.message_from_string(str(mail)).get('Subject'), 'subject')

    def test_message_title_string_with_accents_is_base64encoded(self):
        mail = imapserver.Mail(['user'], subject='Classé ?')

        self.assertEqual(email.message_from_string(str(mail)).get('Subject'), '=?utf-8?b?Q2xhc3PDqSA/?=')

    def test_message_quoted_printable(self):
        mail = imapserver.Mail(['user'], content='Bonjour à vous', content_transfer_encoding='quoted-printable')

        self.assertTrue('Bonjour =C3=A0 vous' in str(mail), msg='"=C3=A0" not found in %s' % str(mail))


class WithImapServer(asynctest.TestCase):
    def setUp(self):
        self.loop = asyncio.get_event_loop()
        factory = self.loop.create_server(imapserver.create_imap_protocol, 'localhost', 12345)
        self.server = self.loop.run_until_complete(factory)

    @asyncio.coroutine
    def tearDown(self):
        imapserver.reset()
        self.server.close()
        asyncio.wait_for(self.server.wait_closed(), 1)

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
