# -*- coding: utf-8 -*-
import asyncio
import email
import imaplib

import functools
from tests import imapserver
from tests.imapserver import Mail, imap_receive, get_imapconnection
from tests.test_imapserver import WithImapServer


class TestImapServerWithImaplib(WithImapServer):
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
        self.assertEquals(imapserver.AUTH, get_imapconnection('user').state)

    @asyncio.coroutine
    def test_select_no_messages_in_mailbox(self):
        imap_client = yield from self.login_user('user', 'pass')

        result, data = yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.select)), 1)

        self.assertEqual('OK', result)
        self.assertEqual([b'0'], data)
        self.assertEquals(imapserver.SELECTED, get_imapconnection('user').state)

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
    def test_examine_no_messages_in_mailbox(self):
        imap_client = yield from self.login_user('user', 'pass')

        self.assertEquals(('OK', [b'0']), (yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.select, readonly=True)), 1)))

        self.assertEquals(imapserver.AUTH, get_imapconnection('user').state)

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
        self.assertEqual([b'1'], data)

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
    def test_expunge_messages(self):
        imap_receive(Mail(['user']))
        imap_receive(Mail(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        yield from asyncio.wait_for(self.loop.run_in_executor(None, imap_client.expunge), 1)

        self.assertEquals(('OK', [b'0']), (yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.select)), 1)))

    @asyncio.coroutine
    def test_noop(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)

        self.assertEquals(('OK', [b'NOOP completed.']),
                          (yield from asyncio.wait_for(self.loop.run_in_executor(None, imap_client.noop), 1)))

    @asyncio.coroutine
    def test_check(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)

        self.assertEquals(('OK', [b'CHECK completed.']),
                          (yield from asyncio.wait_for(self.loop.run_in_executor(None, imap_client.check), 1)))

    @asyncio.coroutine
    def test_status(self):
        imap_client = yield from self.login_user('user', 'pass')

        self.assertEquals(('OK', [b'INBOX (MESSAGES 0 UIDNEXT 1)']),
                          (yield from asyncio.wait_for(
                              self.loop.run_in_executor(None, functools.partial(imap_client.status, 'INBOX',
                                                                                '(MESSAGES UIDNEXT)')), 1)))

    @asyncio.coroutine
    def test_close(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)
        self.assertEquals(imapserver.SELECTED, get_imapconnection('user').state)

        self.assertEquals(('OK', [b'CLOSE completed.']),
                          (yield from asyncio.wait_for(self.loop.run_in_executor(None, imap_client.close), 1)))

        self.assertEquals(imapserver.AUTH, get_imapconnection('user').state)

    @asyncio.coroutine
    def test_copy_messages(self):
        imap_receive(Mail(['user']))
        imap_receive(Mail(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        result, _ = yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.copy, '1 2', 'MAILBOX')), 20)
        self.assertEqual('OK', result)

        self.assertEquals(('OK', [b'2']), (yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.select, 'MAILBOX')), 20)))

    @asyncio.coroutine
    def test_logout(self):
        imap_client = yield from self.login_user('user', 'pass')

        result, data = yield from asyncio.wait_for(self.loop.run_in_executor(None, imap_client.logout), 1)

        self.assertEqual('BYE', result)  # uhh ?
        self.assertEqual([b'Logging out'], data)
        self.assertEquals(imapserver.LOGOUT, get_imapconnection('user').state)
