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
import email
import imaplib
from datetime import datetime, timedelta

import functools
from email.charset import add_charset, SHORTEST

from aioimaplib.tests import imapserver
from aioimaplib.tests.imapserver import Mail, imap_receive, get_imapconnection
from aioimaplib.tests.test_imapserver import WithImapServer
from pytz import utc


class TestImapServerWithImaplib(WithImapServer):

    def __init__(self, methodName='runTest'):
        super().__init__(methodName)
        add_charset('utf-8', SHORTEST, None, 'utf-8')
        add_charset('cp1252', SHORTEST, None, 'cp1252')

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
        imap_client = yield from self.login_user('user@mail', 'pass')

        result, data = yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.select)), 1)

        self.assertEqual('OK', result)
        self.assertEqual([b'0'], data)
        self.assertEquals(imapserver.SELECTED, get_imapconnection('user@mail').state)

    @asyncio.coroutine
    def test_select_one_message_in_mailbox(self):
        imap_receive(Mail.create(to=['user'], mail_from='me', subject='hello'))
        imap_client = yield from self.login_user('user', 'pass')

        result, data = yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.select)), 1)

        self.assertEqual('OK', result)
        self.assertEqual([b'1'], data)

    @asyncio.coroutine
    def test_select_one_message_in_INBOX_zero_in_OTHER(self):
        imap_receive(Mail.create(to=['user'], mail_from='me', subject='hello'))
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
        imap_receive(Mail.create(['user']))
        imap_receive(Mail.create(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        result, data = yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.uid, 'search', 'utf-8', 'ALL')), 1)

        self.assertEqual('OK', result)
        self.assertEqual([b'1 2'], data)

    @asyncio.coroutine
    def test_search_by_uid_one_message_two_recipients(self):
        imap_receive(Mail.create(['user1', 'user2']))
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
    def test_fetch_one_message_by_uid(self):
        mail = Mail.create(['user'], mail_from='me', subject='hello', content='pleased to meet you, wont you guess my name ?')
        imap_receive(mail)
        imap_client = yield from self.login_user('user', 'pass', select=True)

        result, data = yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.uid, 'fetch', '1', '(RFC822)')), 1)

        self.assertEqual('OK', result)
        self.assertEqual([(b'1 (RFC822 {360}', mail.as_bytes()), b')'], data)

    @asyncio.coroutine
    def test_fetch_one_message_by_uid_with_bodypeek(self):
        mail = Mail.create(['user'], mail_from='me', subject='hello', content='this mail is still unread')
        imap_receive(mail)
        imap_client = yield from self.login_user('user', 'pass', select=True)

        result, data = yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.uid, 'fetch', '1', '(UID BODY.PEEK[])')), 1)

        self.assertEqual('OK', result)
        self.assertEqual([(b'1 (UID 1 BODY.PEEK[] {340}', mail.as_bytes()), b')'], data)

    @asyncio.coroutine
    def test_fetch_one_messages_by_uid_without_body(self):
        mail = Mail.create(['user'], mail_from='me', subject='hello', content='whatever')
        imap_receive(mail)
        imap_client = yield from self.login_user('user', 'pass', select=True)

        result, data = yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.uid, 'fetch', '1', '(UID FLAGS)')), 1)

        self.assertEqual('OK', result)
        self.assertEqual([(b'1 (UID 1 FLAGS ())')], data)

    @asyncio.coroutine
    def test_fetch_one_messages_by_uid_encoding_cp1252(self):
        imap_receive(Mail.create(['user'], mail_from='me', subject='hello', content='maître', encoding='cp1252'))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        _, data = yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.uid, 'fetch', '1', '(RFC822)')), 1)

        mail_content = data[0][1]
        self.assertTrue(b'charset="cp1252"' in mail_content)
        self.assertTrue(b'ma\xeetre' in mail_content)
        self.assertEqual('maître', email.message_from_bytes(mail_content).get_payload().strip())

    @asyncio.coroutine
    def test_fetch_one_message_with_UID(self):
        imap_receive(Mail.create(['user'], mail_from='me', subject='hello', content='maître'))
        imap_receive(Mail.create(['user'], mail_from='you', subject='yo', content='bro'))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        _, data = yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.uid, 'fetch', '1', '(RFC822)')), 1)

        self.assertEqual(2, len(data))

    @asyncio.coroutine
    def test_store_and_search_by_keyword(self):
        imap_receive(Mail.create(['user']))
        imap_receive(Mail.create(['user']))
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
    def test_search_by_uid_range(self):
        imap_receive(Mail.create(['user']))
        imap_receive(Mail.create(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        _, data = yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.uid, 'search', None, '1:2')), 1)
        self.assertEqual([b'1 2'], data)

        _, data = yield from asyncio.wait_for(
                    self.loop.run_in_executor(None, functools.partial(imap_client.uid, 'search', None, '1:*')), 1)
        self.assertEqual([b'1 2'], data)

        _, data = yield from asyncio.wait_for(
                    self.loop.run_in_executor(None, functools.partial(imap_client.uid, 'search', None, '1:1')), 1)
        self.assertEqual([b'1'], data)

    @asyncio.coroutine
    def test_expunge_messages(self):
        imap_receive(Mail.create(['user']))
        imap_receive(Mail.create(['user']))
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
    def test_subscribe_unsubscribe_lsub(self):
        imap_client = yield from self.login_user('user', 'pass')

        self.assertEquals(('OK', [b'SUBSCRIBE completed.']),
                          (yield from asyncio.wait_for(
                              self.loop.run_in_executor(None, functools.partial(
                                  imap_client.subscribe, '#fr.soc.feminisme')), 1)))

        self.assertEquals(('OK', [b'() "." #fr.soc.feminisme']),
                          (yield from asyncio.wait_for(
                              self.loop.run_in_executor(None, functools.partial(
                                  imap_client.lsub, '#fr', 'soc.*')), 1)))

        self.assertEquals(('OK', [b'UNSUBSCRIBE completed.']),
                          (yield from asyncio.wait_for(
                              self.loop.run_in_executor(None, functools.partial(
                                  imap_client.unsubscribe, '#fr.soc.feminisme')), 1)))

        self.assertEquals(('OK', [None]),
                          (yield from asyncio.wait_for(
                              self.loop.run_in_executor(None, functools.partial(
                                  imap_client.lsub, '#fr', '.*')), 1)))

    @asyncio.coroutine
    def test_close(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)
        self.assertEquals(imapserver.SELECTED, get_imapconnection('user').state)

        self.assertEquals(('OK', [b'CLOSE completed.']),
                          (yield from asyncio.wait_for(self.loop.run_in_executor(None, imap_client.close), 1)))

        self.assertEquals(imapserver.AUTH, get_imapconnection('user').state)

    @asyncio.coroutine
    def test_copy_messages(self):
        imap_receive(Mail.create(['user']))
        imap_receive(Mail.create(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        result, _ = yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.copy, '1 2', 'MAILBOX')), 20)
        self.assertEqual('OK', result)

        self.assertEquals(('OK', [b'2']), (yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.select, 'MAILBOX')), 20)))

    @asyncio.coroutine
    def test_create_delete_mailbox(self):
        imap_client = yield from self.login_user('user', 'pass')

        self.assertEquals(('NO', [b'STATUS completed.']),
                          (yield from asyncio.wait_for(
                              self.loop.run_in_executor(None, functools.partial(imap_client.status, 'MBOX', '(MESSAGES)')), 1)))

        self.assertEquals(('OK', [b'CREATE completed.']),
                          (yield from asyncio.wait_for(
                              self.loop.run_in_executor(None, functools.partial(imap_client.create, 'MBOX')), 1)))

        self.assertEquals(('OK', [b'MBOX (MESSAGES 0)']),
                          (yield from asyncio.wait_for(
                              self.loop.run_in_executor(None, functools.partial(imap_client.status, 'MBOX', '(MESSAGES)')), 1)))

        self.assertEquals(('OK', [b'DELETE completed.']),
                          (yield from asyncio.wait_for(
                              self.loop.run_in_executor(None, functools.partial(imap_client.delete, 'MBOX')), 1)))

        self.assertEquals(('NO', [b'STATUS completed.']),
                          (yield from asyncio.wait_for(
                              self.loop.run_in_executor(None, functools.partial(imap_client.status, 'MBOX', '(MESSAGES)')), 1)))

    @asyncio.coroutine
    def test_rename_mailbox(self):
        imap_receive(Mail.create(['user']))
        imap_client = yield from self.login_user('user', 'pass')

        self.assertEquals(('NO', [b'STATUS completed.']),
                          (yield from asyncio.wait_for(
                              self.loop.run_in_executor(None, functools.partial(imap_client.status, 'MBOX', '(MESSAGES)')), 1)))

        self.assertEquals(('OK', [b'RENAME completed.']),
                          (yield from asyncio.wait_for(
                              self.loop.run_in_executor(None, functools.partial(imap_client.rename, 'INBOX', 'MBOX')), 1)))

        self.assertEquals(('OK', [b'MBOX (MESSAGES 1)']),
                          (yield from asyncio.wait_for(
                              self.loop.run_in_executor(None, functools.partial(imap_client.status, 'MBOX', '(MESSAGES)')), 1)))

    @asyncio.coroutine
    def test_list(self):
        imap_client = yield from self.login_user('user', 'pass')
        self.assertEquals(('OK', [b'() "/" INBOX']),
                          (yield from asyncio.wait_for(
                              self.loop.run_in_executor(None, functools.partial(imap_client.list, '', '.*')), 1)))

        yield from asyncio.wait_for(
                              self.loop.run_in_executor(None, functools.partial(imap_client.create, 'MYBOX')), 1)

        self.assertEquals(('OK', [b'() "/" INBOX', b'() "/" MYBOX']),
                          (yield from asyncio.wait_for(
                              self.loop.run_in_executor(None, functools.partial(imap_client.list, '', '.*')), 1)))

    @asyncio.coroutine
    def test_append(self):
        imap_client = yield from self.login_user('user@mail', 'pass')

        self.assertEquals(('OK', [b'0']), (yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.select, 'INBOX', readonly=True)), 2)))

        msg = Mail.create(['user@mail'], subject='append msg', content='do you see me ?')
        self.assertEquals(('OK', [b'APPEND completed.']),
                          (yield from asyncio.wait_for(
                              self.loop.run_in_executor(None, functools.partial(
                                  imap_client.append, 'INBOX', 'FOO BAR', datetime.now(tz=utc), msg.as_bytes())), 2)))

        self.assertEquals(('OK', [b'1']), (yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.select, 'INBOX', readonly=True)), 2)))

    @asyncio.coroutine
    def test_logout(self):
        imap_client = yield from self.login_user('user', 'pass')

        result, data = yield from asyncio.wait_for(self.loop.run_in_executor(None, imap_client.logout), 1)

        self.assertEqual('BYE', result)  # uhh ?
        self.assertEqual([b'Logging out'], data)
        self.assertEquals(imapserver.LOGOUT, get_imapconnection('user').state)

    @asyncio.coroutine
    def test_rfc5032_within(self):
        imap_receive(Mail.create(['user'], date=datetime.now(tz=utc) - timedelta(seconds=84600*3))) # 1
        imap_receive(Mail.create(['user'], date=datetime.now(tz=utc) - timedelta(seconds=84600))) # 2
        imap_receive(Mail.create(['user'])) # 3
        imap_client = yield from self.login_user('user', 'pass', select=True)

        self.assertEquals([b'2 3'], (yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.search, 'utf-8', 'YOUNGER', '84700')), 1))[1])

        self.assertEquals([b'1'], (yield from asyncio.wait_for(
            self.loop.run_in_executor(None, functools.partial(imap_client.search, 'utf-8', 'OLDER', '84700')), 1))[1])
