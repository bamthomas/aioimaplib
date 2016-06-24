# -*- coding: utf-8 -*-
import asyncio
import email
import imaplib
import unittest
from datetime import datetime

import pytz

import asynctest
import functools
from tests.imapserver import Mail, create_imap_protocol, imap_receive, reset_mailboxes


class TestMailToString(unittest.TestCase):
    def test_message_date_string(self):
        now = pytz.timezone('Europe/Paris').localize(datetime(2016, 2, 2, 12, 13, 14, 151))

        mail = Mail(['user'], date=now)

        self.assertEqual(email.message_from_string(str(mail)).get('Date'), 'Tue, 02 Feb 2016 12:13:14 +0100')

    def test_message_title_string_without_accents_isnot_encoded(self):
        now = pytz.timezone('Europe/Paris').localize(datetime(2016, 2, 2, 12, 13, 14, 151))

        mail = Mail(['user'], subject='subject', date=now)

        self.assertEqual(email.message_from_string(str(mail)).get('Subject'), 'subject')

    def test_message_title_string_with_accents_is_base64encoded(self):
        mail = Mail(['user'], subject='Classé ?')

        self.assertEqual(email.message_from_string(str(mail)).get('Subject'), '=?utf-8?b?Q2xhc3PDqSA/?=')

    def test_message_quoted_printable(self):
        mail = Mail(['user'], content='Bonjour à vous', content_transfer_encoding='quoted-printable')

        self.assertTrue('Bonjour =C3=A0 vous' in str(mail), msg='"=C3=A0" not found in %s' % str(mail))


class TestImapServer(asynctest.TestCase):
    def setUp(self):
        self.loop = asyncio.get_event_loop()
        factory = self.loop.create_server(create_imap_protocol, 'localhost', 12345)
        self.server = self.loop.run_until_complete(factory)

    @asyncio.coroutine
    def tearDown(self):
        reset_mailboxes()
        self.server.close()
        asyncio.wait_for(self.server.wait_closed(), 1)

    @asyncio.coroutine
    def test_server_greetings_and_capabilities(self):
        pending_imap = self.loop.run_in_executor(None, functools.partial(imaplib.IMAP4, host='localhost', port=12345))
        imap_client = yield from asyncio.wait_for(pending_imap, 1)

        self.assertEqual('NONAUTH', imap_client.state)

    @asyncio.coroutine
    def test_server_login(self):
        pending_imap = self.loop.run_in_executor(None, functools.partial(imaplib.IMAP4, host='localhost', port=12345))
        imap_client = yield from asyncio.wait_for(pending_imap, 1)

        pending_login = self.loop.run_in_executor(None, functools.partial(imap_client.login, 'user', 'pass'))
        result, data = yield from asyncio.wait_for(pending_login, 1)

        self.assertEqual('OK', result)
        self.assertEqual([b'LOGIN completed'], data)

    @asyncio.coroutine
    def test_select_no_messages_in_mailbox(self):
        imap_client = yield from self.login_user('user', 'pass')

        result, data = yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.select)), 1)

        self.assertEqual('OK', result)
        self.assertEqual([b'0'], data)

    @asyncio.coroutine
    def test_select_one_message_in_mailbox(self):
        imap_receive(Mail(to=['user'], mail_from='me', subject='hello'))
        imap_client = yield from self.login_user('user', 'pass')

        result, data = yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.select)), 1)

        self.assertEqual('OK', result)
        self.assertEqual([b'1'], data)

    @asyncio.coroutine
    def test_select_one_message_in_INBOX_zero_in_OTHER(self):
        imap_receive(Mail(to=['user'], mail_from='me', subject='hello'))
        imap_client = yield from self.login_user('user', 'pass')

        _, data = yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.select)), 1)
        self.assertEqual([b'1'], data)

        _, data = yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.select, 'OTHER')), 1)
        self.assertEqual([b'0'], data)

    @asyncio.coroutine
    def test_search_by_uid_two_messages(self):
        imap_receive(Mail(['user']))
        imap_receive(Mail(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        result, data = yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.uid, 'search', None, 'ALL')), 1)

        self.assertEqual('OK', result)
        self.assertEqual([b'1 2'], data)

    @asyncio.coroutine
    def test_search_by_uid_one_message_two_recipients(self):
        imap_receive(Mail(['user1', 'user2']))
        imap_client = yield from self.login_user('user1', 'pass', select=True)

        result, data = yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.uid, 'search', None, 'ALL')), 1)

        self.assertEqual('OK', result)
        self.assertEqual([b'1'], data)

        imap_client = yield from self.login_user('user2', 'pass', select=True)

        result, data = yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.uid, 'search', None, 'ALL')), 1)

        self.assertEqual('OK', result)
        self.assertEqual([b'2'], data)

    @asyncio.coroutine
    def test_fetch_one_messages_by_uid(self):
        mail = Mail(['user'], mail_from='me', subject='hello', content='pleased to meet you, wont you guess my name ?')
        imap_receive(mail)
        imap_client = yield from self.login_user('user', 'pass', select=True)

        result, data = yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.uid, 'fetch', '1', '(RFC822)')), 1)

        self.assertEqual('OK', result)
        self.assertEqual([(b'1 (UID 1 RFC822 {368}', str(mail).encode()), b')'], data)

    @asyncio.coroutine
    def test_fetch_one_messages_by_uid_encoding_cp1252(self):
        imap_receive(Mail(['user'], mail_from='me', subject='hello', content='maître', encoding='cp1252'))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        _, data = yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.uid, 'fetch', '1', '(RFC822)')), 1)

        mail_content = data[0][1]
        self.assertTrue(b'charset=cp1252' in mail_content)
        self.assertTrue(b'ma\xeetre' in mail_content)
        self.assertEqual('maître', email.message_from_bytes(mail_content).get_payload().strip())

    @asyncio.coroutine
    def test_fetch_one_message_with_UID(self):
        imap_receive(Mail(['user'], mail_from='me', subject='hello', content='maître'))
        imap_receive(Mail(['user'], mail_from='you', subject='yo', content='bro'))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        _, data = yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.uid, 'fetch', '1', '(RFC822)')), 1)

        self.assertEqual(2, len(data))

    @asyncio.coroutine
    def test_store_and_search_by_keyword(self):
        imap_receive(Mail(['user']))
        imap_receive(Mail(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        result, data = yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.uid, 'search', None, 'KEYWORD FOO')), 1)

        self.assertEqual('OK', result)
        self.assertEqual([b''], data)

        result, data = yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.uid, 'store', '1', '+FLAGS FOO')), 1)
        self.assertEqual('OK', result)

        result, data = yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.uid, 'search', None, 'KEYWORD FOO')), 1)
        self.assertEqual('OK', result)
        self.assertEqual([b'1'], data)

        result, data = yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.uid, 'search', None, 'UNKEYWORD FOO')), 1)
        self.assertEqual('OK', result)
        self.assertEqual([b'2'], data)

    @asyncio.coroutine
    def login_user(self, login, password, select=False):
        imap_client = yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imaplib.IMAP4, host='localhost', port=12345)), 1)

        yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.login, login, password)), 1)

        if select:
            yield from asyncio.wait_for(
                self.loop.run_in_executor(None, functools.partial(imap_client.select)), 1)

        return imap_client
