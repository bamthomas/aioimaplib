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
import logging
import unittest
from datetime import datetime, timedelta
from functools import partial

from aioimaplib import aioimaplib
from aioimaplib.aioimaplib import Commands, fetch_message_with_literal_data_re, IMAP4ClientProtocol
from aioimaplib.tests import imapserver
from aioimaplib.tests.imapserver import imap_receive, Mail, get_imapconnection
from aioimaplib.tests.test_imapserver import WithImapServer
from mock import Mock, call
from pytz import utc

aioimaplib.log.setLevel(logging.INFO)
sh = logging.StreamHandler()
sh.setLevel(logging.INFO)
sh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(module)s:%(lineno)d] %(message)s"))
aioimaplib.log.addHandler(sh)


class TestAioimaplibUtils(unittest.TestCase):
    def setUp(self):
        self.imap_protocol = IMAP4ClientProtocol(None)
        self.line_handler = Mock()
        self.fetch_handler = Mock()

    def test_split_responses_no_data(self):
        self.imap_protocol._handle_responses(b'', self.line_handler, self.fetch_handler)
        self.line_handler.assert_not_called()
        self.fetch_handler.assert_not_called()

    def test_split_responses_regular_lines(self):
        self.imap_protocol._handle_responses(b'* BYE Logging out\r\nCAPB2 OK LOGOUT completed\r\n', self.line_handler,
                                             self.fetch_handler)
        self.line_handler.assert_has_calls([call('* BYE Logging out'), call('CAPB2 OK LOGOUT completed')])
        self.fetch_handler.assert_not_called()

    def test_split_responses_with_message_data(self):
        self.imap_protocol._handle_responses(b'* 1 FETCH (UID 1 RFC822 {26}\r\n...\r\n(mail content)\r\n...\r\n)\r\n'
                                             b'TAG OK FETCH completed.', self.line_handler, self.fetch_handler)
        self.fetch_handler.assert_called_once_with(b'* 1 FETCH (UID 1 RFC822 {26}\r\n'
                                                   b'...\r\n(mail content)\r\n...\r\n)', 27)
        self.line_handler.assert_called_once_with('TAG OK FETCH completed.')

    def test_split_responses_with_two_messages_data(self):
        self.imap_protocol._handle_responses(b'* 3 FETCH (UID 3 RFC822 {8}\r\nmail 1\r\n)\r\n'
                                             b'* 1 FETCH (UID 10 FLAGS (FOO))\r\n'  # could be from a previous store
                                             # cmd cf https://tools.ietf.org/html/rfc3501#section-5.5
                                             b'* 4 FETCH (UID 4 RFC822 {8}\r\nmail 2\r\n)\r\n'
                                             b'TAG OK FETCH completed.', self.line_handler, self.fetch_handler)

        self.line_handler.assert_has_calls([call('* 1 FETCH (UID 10 FLAGS (FOO))'),
                                            call('TAG OK FETCH completed.')])
        self.fetch_handler.assert_has_calls([call(b'* 3 FETCH (UID 3 RFC822 {8}\r\nmail 1\r\n)', 9),
                                             call(b'* 4 FETCH (UID 4 RFC822 {8}\r\nmail 2\r\n)', 9)])

    def test_split_responses_with_flag_fetch_message_data(self):
        self.imap_protocol._handle_responses(b'* 1 FETCH (UID 10 FLAGS (FOO))\r\n'
                                             b'* 1 FETCH (UID 15 FLAGS (BAR))\r\n'
                                             b'TAG OK STORE completed.', self.line_handler, self.fetch_handler)
        self.line_handler.assert_has_calls([call('* 1 FETCH (UID 10 FLAGS (FOO))'),
                                            call('* 1 FETCH (UID 15 FLAGS (BAR))'),
                                            call('TAG OK STORE completed.')])

    def test_split_responses_with_message_data_expunge(self):
        self.imap_protocol._handle_responses(b'* 123 EXPUNGE\r\nTAG OK SELECT completed.\r\n',
                                             self.line_handler, self.fetch_handler)
        self.line_handler.assert_has_calls([call('* 123 EXPUNGE'),
                                            call('TAG OK SELECT completed.')])

    def test_fetch_message_with_literal_data_re(self):
        self.assertIsNotNone(
            fetch_message_with_literal_data_re.match(b'* 95 FETCH (FLAGS (\\Seen \\Recent) RFC822 {424635}\r\n...'))
        self.assertIsNotNone(
            fetch_message_with_literal_data_re.match(b'* 12 FETCH (BODY[HEADER] {342}\r\n...'))


class AioWithImapServer(WithImapServer):
    @asyncio.coroutine
    def login_user(self, login, password, select=False, lib=aioimaplib.IMAP4):
        imap_client = aioimaplib.IMAP4(port=12345, loop=self.loop, timeout=3)
        yield from asyncio.wait_for(imap_client.wait_hello_from_server(), 2)

        yield from imap_client.login(login, password)

        if select:
            yield from imap_client.select()
        return imap_client


class TestAioimaplib(AioWithImapServer):
    def setUp(self):
        factory = self.loop.create_server(partial(imapserver.create_imap_protocol, fetch_chunk_size=64), 'localhost',
                                          12345)
        self.server = self.loop.run_until_complete(factory)

    @asyncio.coroutine
    def test_capabilities(self):
        imap_client = aioimaplib.IMAP4(port=12345, loop=self.loop)
        yield from asyncio.wait_for(imap_client.wait_hello_from_server(), 2)

        self.assertEquals('IMAP4REV1', imap_client.protocol.imap_version)
        self.assertEquals(['IMAP4rev1', 'LITERAL+', 'IDLE'], imap_client.protocol.capabilities)

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
    def test_examine_no_messages(self):
        imap_client = yield from self.login_user('user', 'pass')

        self.assertEquals(('OK', ['0']), (yield from imap_client.examine()))

        self.assertEquals(aioimaplib.AUTH, imap_client.protocol.state)

    @asyncio.coroutine
    def test_search_two_messages(self):
        imap_receive(Mail.create(['user']))
        imap_receive(Mail.create(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        result, data = yield from imap_client.search('ALL')

        self.assertEqual('OK', result)
        self.assertEqual('1 2', data[0])

    @asyncio.coroutine
    def test_uid_with_illegal_command(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)

        for command in {'COPY', 'FETCH', 'STORE'}.symmetric_difference(Commands.keys()):
            with self.assertRaises(aioimaplib.Abort) as expected:
                yield from imap_client.uid(command)

            self.assertEqual(expected.exception.args,
                             ('command UID only possible with COPY, FETCH or STORE (was %s)' % command,))

    @asyncio.coroutine
    def test_search_three_messages_by_uid(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)
        imap_receive(Mail.create(['user']))  # id=1 uid=1
        imap_receive(Mail.create(['user']), mailbox='OTHER_MAILBOX')  # id=1 uid=2
        imap_receive(Mail.create(['user']))  # id=2 uid=3

        self.assertEqual('1 3', (yield from imap_client.uid_search('ALL')).lines[0])
        self.assertEqual('1 2', (yield from imap_client.search('ALL')).lines[0])

    @asyncio.coroutine
    def test_fetch(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)
        mail = Mail.create(['user'], mail_from='me', subject='hello',
                           content='pleased to meet you, wont you guess my name ?')
        imap_receive(mail)

        result, data = yield from imap_client.fetch('1', '(RFC822)')

        self.assertEqual('OK', result)
        self.assertEqual([mail.as_bytes(), 'FETCH completed.'], data)

    @asyncio.coroutine
    def test_fetch_by_uid(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)
        mail = Mail.create(['user'], mail_from='me', subject='hello',
                           content='pleased to meet you, wont you guess my name ?')
        imap_receive(mail)

        response = (yield from imap_client.uid('fetch', '1', '(RFC822)'))

        self.assertEqual('OK', response.result)
        self.assertEquals(mail.as_bytes(), response.lines[0])

    @asyncio.coroutine
    def test_idle(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)

        idle = asyncio.async(imap_client.idle())
        self.assertEquals('idling', (yield from imap_client.wait_server_push()))

        imap_receive(Mail.create(to=['user'], mail_from='me', subject='hello'))

        self.assertEquals('1 EXISTS', (yield from imap_client.wait_server_push()))
        self.assertEquals('1 RECENT', (yield from imap_client.wait_server_push()))

        imap_client.idle_done()
        self.assertEquals(('OK', ['IDLE terminated']), (yield from asyncio.wait_for(idle, 1)))

    @asyncio.coroutine
    def test_idle_stop(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)
        idle = asyncio.async(imap_client.idle())
        self.assertEquals('idling', (yield from imap_client.wait_server_push()))
        self.assertTrue((yield from imap_client.stop_wait_server_push()))

        self.assertEquals('stop_wait_server_push', (yield from imap_client.wait_server_push()))

        imap_client.idle_done()
        yield from asyncio.wait_for(idle, 1)

    @asyncio.coroutine
    def test_idle_stop_does_nothing_if_no_pending_idle(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)

        self.assertFalse((yield from imap_client.stop_wait_server_push()))
        with self.assertRaises(asyncio.TimeoutError):
            yield from asyncio.wait_for(imap_client.wait_server_push(), 0.5)

    @asyncio.coroutine
    def test_store_and_search_by_keyword(self):
        imap_receive(Mail.create(['user']))
        imap_receive(Mail.create(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)
        self.assertEqual('', (yield from imap_client.uid_search('KEYWORD FOO', charset=None)).lines[0])

        self.assertEquals('OK', (yield from imap_client.uid('store', '1', '+FLAGS FOO')).result)

        self.assertEqual('1', (yield from imap_client.uid_search('KEYWORD FOO', charset=None)).lines[0])
        self.assertEqual('2', (yield from imap_client.uid_search('UNKEYWORD FOO', charset=None)).lines[0])

    @asyncio.coroutine
    def test_expunge_messages(self):
        imap_receive(Mail.create(['user']))
        imap_receive(Mail.create(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        self.assertEquals(('OK', ['1', '2', 'EXPUNGE completed.']), (yield from imap_client.expunge()))

        self.assertEquals(('OK', ['0']), (yield from imap_client.select()))

    @asyncio.coroutine
    def test_copy_messages(self):
        imap_receive(Mail.create(['user']))
        imap_receive(Mail.create(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        result, _ = yield from imap_client.copy('1', '2', 'MAILBOX')
        self.assertEqual('OK', result)

        self.assertEquals(('OK', ['2']), (yield from imap_client.select('MAILBOX')))

    @asyncio.coroutine
    def test_copy_messages_by_uid(self):
        imap_receive(Mail.create(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        result, _ = yield from imap_client.uid('copy', '1', 'MAILBOX')
        self.assertEqual('OK', result)

        self.assertEquals(('OK', ['1']), (yield from imap_client.select('MAILBOX')))

    @asyncio.coroutine
    def test_concurrency_1_executing_sync_commands_sequentially(self):
        imap_client = yield from self.login_user('user', 'pass')

        f1 = asyncio.async(imap_client.examine('INBOX'))
        f2 = asyncio.async(imap_client.examine('MAILBOX'))

        yield from asyncio.wait([f1, f2])
        self.assertIsNone(f1.exception())
        self.assertIsNone(f2.exception())

    @asyncio.coroutine
    def test_concurrency_2_executing_same_async_commands_sequentially(self):
        imap_receive(Mail.create(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        f1 = asyncio.async(imap_client.fetch('1', '(RFC822)'))
        f2 = asyncio.async(imap_client.fetch('1', '(RFC822)'))

        yield from asyncio.wait([f1, f2])
        self.assertIsNone(f1.exception())
        self.assertIsNone(f2.exception())

    @asyncio.coroutine
    def test_concurrency_3_executing_async_commands_in_parallel(self):
        # cf valid example in https://tools.ietf.org/html/rfc3501#section-5.5
        imap_receive(Mail.create(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        store = asyncio.async(imap_client.store('1', '+FLAGS FOO'))
        copy = asyncio.async(imap_client.copy('1', 'MBOX'))
        expunge = asyncio.async(imap_client.expunge())

        yield from asyncio.wait([store, copy, expunge])
        self.assertEquals(('OK', ['0']), (yield from imap_client.select()))
        self.assertEquals(('OK', ['1']), (yield from imap_client.select('MBOX')))
        self.assertEqual('1', (yield from imap_client.search('KEYWORD FOO', charset=None)).lines[0])

    @asyncio.coroutine
    def test_concurrency_4_sync_command_waits_for_async_commands_to_finish(self):
        imap_receive(Mail.create(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        asyncio.async(imap_client.copy('1', 'MBOX'))
        asyncio.async(imap_client.expunge())
        examine = asyncio.async(imap_client.examine('MBOX'))

        self.assertEquals(('OK', ['1']), (yield from asyncio.wait_for(examine, 1)))

    @asyncio.coroutine
    def test_noop(self):
        imap_client = yield from self.login_user('user', 'pass')
        self.assertEquals(('OK', ['NOOP completed.']), (yield from imap_client.noop()))

    @asyncio.coroutine
    def test_check(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)
        self.assertEquals(('OK', ['CHECK completed.']), (yield from imap_client.check()))

    @asyncio.coroutine
    def test_close(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)
        self.assertEquals(imapserver.SELECTED, get_imapconnection('user').state)

        self.assertEquals(('OK', ['CLOSE completed.']), (yield from imap_client.close()))

        self.assertEquals(imapserver.AUTH, get_imapconnection('user').state)

    @asyncio.coroutine
    def test_status(self):
        imap_client = yield from self.login_user('user', 'pass')

        self.assertEquals('INBOX (MESSAGES 0 UIDNEXT 1)',
                          (yield from imap_client.status('INBOX', '(MESSAGES UIDNEXT)')).lines[0])

    @asyncio.coroutine
    def test_subscribe_unsubscribe_lsub(self):
        imap_client = yield from self.login_user('user', 'pass')

        self.assertEquals(('OK', ['SUBSCRIBE completed.']), (yield from imap_client.subscribe('#fr.soc.feminisme')))
        self.assertEquals(('OK', ['() "." #fr.soc.feminisme', 'LSUB completed.']),
                          (yield from imap_client.lsub('#fr.', 'soc.*')))
        self.assertEquals(('OK', ['UNSUBSCRIBE completed.']), (yield from imap_client.unsubscribe('#fr.soc.feminisme')))
        self.assertEquals(('OK', ['LSUB completed.']), (yield from imap_client.lsub('#fr', '.*')))

    @asyncio.coroutine
    def test_create_delete_mailbox(self):
        imap_client = yield from self.login_user('user', 'pass')
        self.assertEquals('NO', (yield from imap_client.status('MBOX', '(MESSAGES)')).result)

        self.assertEquals(('OK', ['CREATE completed.']), (yield from imap_client.create('MBOX')))
        self.assertEquals('OK', (yield from imap_client.status('MBOX', '(MESSAGES)')).result)

        self.assertEquals(('OK', ['DELETE completed.']), (yield from imap_client.delete('MBOX')))
        self.assertEquals('NO', (yield from imap_client.status('MBOX', '(MESSAGES)')).result)

    @asyncio.coroutine
    def test_rename_mailbox(self):
        imap_client = yield from self.login_user('user', 'pass')
        self.assertEquals('NO', (yield from imap_client.status('MBOX', '(MESSAGES)')).result)

        self.assertEquals(('OK', ['RENAME completed.']), (yield from imap_client.rename('INBOX', 'MBOX')))

        self.assertEquals('OK', (yield from imap_client.status('MBOX', '(MESSAGES)')).result)

    @asyncio.coroutine
    def test_list(self):
        imap_client = yield from self.login_user('user', 'pass')
        self.assertEquals(('OK', ['() "/" INBOX', 'LIST completed.']), (yield from imap_client.list('', '.*')))

        yield from imap_client.create('MYBOX')
        self.assertEquals(('OK', ['() "/" INBOX', '() "/" MYBOX', 'LIST completed.']),
                          (yield from imap_client.list('', '.*')))

    @asyncio.coroutine
    def test_append(self):
        imap_client = yield from self.login_user('user@mail', 'pass')
        self.assertEquals(('OK', ['0']), (yield from imap_client.examine('INBOX')))

        msg = Mail.create(['user@mail'], subject='append msg', content='do you see me ?')
        self.assertEquals(('OK', ['APPEND completed.']),
                          (yield from imap_client.append(msg.as_bytes(), mailbox='INBOX',
                                                         flags='FOO BAR', date=datetime.now(tz=utc), )))

        self.assertEquals(('OK', ['1']), (yield from imap_client.examine('INBOX')))

    @asyncio.coroutine
    def test_rfc5032_within(self):
        imap_receive(Mail.create(['user'], date=datetime.now(tz=utc) - timedelta(seconds=84600 * 3)))  # 1
        imap_receive(Mail.create(['user'], date=datetime.now(tz=utc) - timedelta(seconds=84600)))  # 2
        imap_receive(Mail.create(['user']))  # 3
        imap_client = yield from self.login_user('user', 'pass', select=True)

        self.assertEquals('1', (yield from imap_client.search('OLDER', '84700')).lines[0])
        self.assertEquals('2 3', (yield from imap_client.search('YOUNGER', '84700')).lines[0])
