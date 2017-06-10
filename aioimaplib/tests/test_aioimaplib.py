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

import asynctest

from aioimaplib import aioimaplib, CommandTimeout, extract_exists, IncompleteLiteral
from aioimaplib.aioimaplib import Commands, IMAP4ClientProtocol, Command, Response
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

    def test_split_responses_no_data(self):
        self.imap_protocol._handle_responses(b'', self.line_handler)
        self.line_handler.assert_not_called()

    def test_split_responses_regular_lines(self):
        self.imap_protocol._handle_responses(b'* BYE Logging out\r\nCAPB2 OK LOGOUT completed\r\n', self.line_handler)
        self.line_handler.assert_has_calls([call('* BYE Logging out', None), call('CAPB2 OK LOGOUT completed', None)])

    def test_split_responses_with_message_data(self):
        cmd = Command('FETCH', 'TAG')
        self.line_handler.side_effect = [cmd, cmd, cmd]
        self.imap_protocol._handle_responses(b'* 1 FETCH (UID 1 RFC822 {26}\r\n...\r\n(mail content)\r\n...\r\n)\r\n'
                                             b'TAG OK FETCH completed.\r\n', self.line_handler)

        self.line_handler.assert_has_calls([call('* 1 FETCH (UID 1 RFC822 {26}', None)])
        self.line_handler.assert_has_calls([call(')', cmd)])
        self.line_handler.assert_has_calls([call('TAG OK FETCH completed.', None)])
        self.assertEqual([b'...\r\n(mail content)\r\n...\r\n'], cmd.response.lines)

    def test_split_responses_with_two_messages_data(self):
        cmd = Command('FETCH', 'TAG')
        self.line_handler.side_effect = [cmd, cmd, cmd, cmd, cmd]
        self.imap_protocol._handle_responses(b'* 3 FETCH (UID 3 RFC822 {6}\r\nmail 1)\r\n'
                                             b'* 4 FETCH (UID 4 RFC822 {6}\r\nmail 2)\r\n'
                                             b'TAG OK FETCH completed.\r\n', self.line_handler)

        self.line_handler.assert_has_calls([call('* 3 FETCH (UID 3 RFC822 {6}', None),
                                            call(')', cmd),
                                            call('* 4 FETCH (UID 4 RFC822 {6}', None),
                                            call(')', cmd),
                                            call('TAG OK FETCH completed.', None)])
        self.assertEqual([b'mail 1', b'mail 2'], cmd.response.lines)

    def test_split_responses_with_flag_fetch_message_data(self):
        self.imap_protocol._handle_responses(b'* 1 FETCH (UID 10 FLAGS (FOO))\r\n'
                                             b'* 1 FETCH (UID 15 FLAGS (BAR))\r\n'
                                             b'TAG OK STORE completed.\r\n', self.line_handler)
        self.line_handler.assert_has_calls([call('* 1 FETCH (UID 10 FLAGS (FOO))', None),
                                            call('* 1 FETCH (UID 15 FLAGS (BAR))', None),
                                            call('TAG OK STORE completed.', None)])

    def test_split_responses_with_message_data_expunge(self):
        self.imap_protocol._handle_responses(b'* 123 EXPUNGE\r\nTAG OK SELECT completed.\r\n', self.line_handler)
        self.line_handler.assert_has_calls([call('* 123 EXPUNGE', None),
                                            call('TAG OK SELECT completed.', None)])

    def test_unconplete_line_with_litteral_fetch(self):
        cmd = Command('FETCH', 'TAG')
        self.line_handler.side_effect = [cmd, cmd, cmd, cmd, cmd]
        with self.assertRaises(asyncio.IncompleteReadError) as expected:
            self.imap_protocol._handle_responses(b'* 12 FETCH (BODY[HEADER] {4}\r\nyo\r\n)\r\n* 13 FETCH (BODY[', self.line_handler)
            self.line_handler.assert_has_calls([call('* 12 FETCH (BODY[HEADER] {4}', None), call(')', cmd)])
            self.line_handler.reset_mock()

        self.imap_protocol._handle_responses(b'HEADER] {5}\r\nyo2\r\n)\r\nTAG OK STORE completed.\r\n',
                                             self.line_handler, expected.exception.partial)
        self.line_handler.assert_has_calls([call('* 13 FETCH (BODY[HEADER] {5}', None),
                                            call(')', cmd),
                                           call('TAG OK STORE completed.', None)])
        self.assertEqual([b'yo\r\n', b'yo2\r\n'], cmd.response.lines)

    def test_unconplete_line_during_litteral(self):
        cmd = Command('LIST', 'TAG')
        self.line_handler.side_effect = [cmd, cmd, cmd, cmd]

        with self.assertRaises(IncompleteLiteral) as expected:
            self.imap_protocol._handle_responses(b'* LIST () "/" {7}\r\nfoo/', self.line_handler)
            self.line_handler.assert_has_calls([call('* LIST () "/" {7}', None)])

        self.imap_protocol._handle_responses(b'bar\r\n* LIST () "/" baz\r\nTAG OK LIST completed\r\n', self.line_handler,
                                             expected.exception.partial, expected.exception.cmd)
        self.line_handler.assert_has_calls([call('* LIST () "/" baz', None),
                                            call('TAG OK LIST completed', None)])
        self.assertEqual([b'foo/bar'], cmd.response.lines)

    def test_unconplete_line_during_litteral_no_cmd_found(self):
        self.line_handler.side_effect = [None, None, None, None]

        with self.assertRaises(IncompleteLiteral) as expected:
            self.imap_protocol._handle_responses(b'* LIST () "/" {7}\r\nfoo/', self.line_handler)
            self.line_handler.assert_has_calls([call('* LIST () "/" {7}', None)])

        self.imap_protocol._handle_responses(b'bar\r\nTAG OK LIST completed\r\n', self.line_handler,
                                             expected.exception.partial, expected.exception.cmd)
        self.line_handler.assert_has_calls([call('* LIST () "/" {7}', None),
                                            call('', Command('NIL', 'unused')),
                                            call('TAG OK LIST completed', None)])

    def test_line_with_litteral_no_cmd_found_no_AttributeError_thrown(self):
        self.line_handler.side_effect = [None, None, None]
        self.imap_protocol._handle_responses(b'* 3 FETCH (UID 12 RFC822 {4}\r\nmail)\r\n'
                                             b'TAG OK FETCH completed.\r\n', self.line_handler)
        self.line_handler.assert_has_calls([call('* 3 FETCH (UID 12 RFC822 {4}', None),
                                            call(')', Command('NIL', 'unused')),
                                            call('TAG OK FETCH completed.', None)])

    def test_line_with_attachment_litterals(self):
        cmd = Command('FETCH', 'TAG')
        self.line_handler.side_effect = [cmd, cmd, cmd, cmd, cmd]
        self.imap_protocol._handle_responses(b'* 46 FETCH (UID 46 FLAGS () BODYSTRUCTURE ('
                                             b'("text" "calendar" ("charset" "UTF-8" "name" {16}\r\nG\xe9n\xe9ration 3.ics) '
                                             b'"<mqwssinzuqvhkzlnhlcq>" NIL "quoted-printable" 365 14 NIL '
                                             b'("attachment" ("filename" {16}\r\nG\xe9n\xe9ration 3.ics)))\r\n',
                                             self.line_handler)
        self.line_handler.assert_has_calls([call('* 46 FETCH (UID 46 FLAGS () BODYSTRUCTURE ('
                                                  '("text" "calendar" ("charset" "UTF-8" "name" {16}', None),
                                             call(') "<mqwssinzuqvhkzlnhlcq>" NIL "quoted-printable" 365 14 NIL '
                                                  '("attachment" ("filename" {16}', cmd),
                                             call(')))', cmd)])

        self.assertEqual([b'G\xe9n\xe9ration 3.ics', b'G\xe9n\xe9ration 3.ics'], cmd.response.lines)

    def test_command_repr(self):
        self.assertEqual('tag NAME', str(Command('NAME', 'tag')))
        self.assertEqual('tag NAME arg1 arg2', str(Command('NAME', 'tag', 'arg1', 'arg2')))
        self.assertEqual('tag UID NAME arg', str(Command('NAME', 'tag', 'arg', prefix='UID')))
        self.assertEqual('tag UID NAME', str(Command('NAME', 'tag', prefix='UID')))


class TestAioimaplibCommand(asynctest.ClockedTestCase):
    @asyncio.coroutine
    def test_command_timeout(self):
        cmd = Command('CMD', 'tag', loop=self.loop, timeout=1)
        yield from self.advance(2)
        with self.assertRaises(asyncio.TimeoutError):
            yield from cmd.wait()

    @asyncio.coroutine
    def test_command_close_cancels_timer(self):
        cmd = Command('CMD', 'tag', loop=self.loop, timeout=1)
        cmd.close('line', 'OK')
        yield from self.advance(3)

        yield from cmd.wait()
        self.assertEqual(Response('OK', ['line']), cmd.response)

    @asyncio.coroutine
    def test_command_begin_literal_data_resets_timer(self):
        cmd = Command('CMD', 'tag', loop=self.loop, timeout=2)

        yield from self.advance(1)
        cmd.begin_literal_data(7, b'literal')

        yield from self.advance(1.9)
        cmd.close('line', 'OK')

        yield from cmd.wait()
        self.assertEqual(Response('OK', [b'literal', 'line']), cmd.response)

    @asyncio.coroutine
    def test_command_append_data_resets_timer(self):
        cmd = Command('CMD', 'tag', loop=self.loop, timeout=2)
        cmd.begin_literal_data(4, b'da')

        yield from self.advance(1.9)
        cmd.append_literal_data(b'ta')

        yield from self.advance(1.9)
        cmd.close('line', 'OK')

        yield from cmd.wait()
        self.assertEqual(Response('OK', [b'data', 'line']), cmd.response)

    @asyncio.coroutine
    def test_command_append_literal_data_resets_timer(self):
        cmd = Command('CMD', 'tag', loop=self.loop, timeout=2)
        cmd.begin_literal_data(12, b'literal')

        yield from self.advance(1.9)
        cmd.append_literal_data(b' data')

        yield from self.advance(1.9)
        cmd.close('line', 'OK')

        yield from cmd.wait()
        self.assertEqual(Response('OK', [b'literal data', 'line']), cmd.response)

    @asyncio.coroutine
    def test_command_append_to_resp_resets_timer(self):
        cmd = Command('CMD', 'tag', loop=self.loop, timeout=2)

        yield from self.advance(1.9)
        cmd.append_to_resp('line 1')

        yield from self.advance(1.9)
        cmd.close('line 2', 'OK')

        yield from cmd.wait()
        self.assertEqual(Response('OK', ['line 1', 'line 2']), cmd.response)

    @asyncio.coroutine
    def test_command_timeout_while_receiving_data(self):
        cmd = Command('CMD', 'tag', loop=self.loop, timeout=2)

        yield from self.advance(1)
        cmd.begin_literal_data(12, b'literal')

        yield from self.advance(3)
        with self.assertRaises(asyncio.TimeoutError):
            yield from cmd.wait()


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
        factory = self.loop.create_server(partial(imapserver.create_imap_protocol, fetch_chunk_size=64, loop=self.loop),
                                          'localhost', 12345)
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

        resp = yield from imap_client.select()

        self.assertEqual('OK', resp[0])
        self.assertEqual(0, extract_exists(resp))
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

        self.assertEqual('1 2', (yield from imap_client.search('ALL')).lines[0])
        self.assertEqual('1 3', (yield from imap_client.uid_search('ALL')).lines[0])

    @asyncio.coroutine
    def test_fetch(self):
        print('test loop %r' % self.loop)
        imap_client = yield from self.login_user('user', 'pass', select=True)
        mail = Mail.create(['user'], mail_from='me', subject='hello',
                           content='pleased to meet you, wont you guess my name ?')
        imap_receive(mail)

        result, data = yield from imap_client.fetch('1', '(RFC822)')

        self.assertEqual('OK', result)
        self.assertEqual(['1 FETCH (UID 1 RFC822 {360}', mail.as_bytes(), ')', 'FETCH completed.'], data)

    @asyncio.coroutine
    def test_fetch_by_uid_without_body(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)
        mail = Mail.create(['user'], mail_from='me', subject='hello',
                           content='pleased to meet you, wont you guess my name ?')
        imap_receive(mail)

        response = (yield from imap_client.uid('fetch', '1', '(UID FLAGS)'))

        self.assertEqual('OK', response.result)
        self.assertEquals('1 FETCH (UID 1 FLAGS ())', response.lines[0])

    @asyncio.coroutine
    def test_fetch_by_uid(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)
        mail = Mail.create(['user'], mail_from='me', subject='hello',
                           content='pleased to meet you, wont you guess my name ?')
        imap_receive(mail)

        response = (yield from imap_client.uid('fetch', '1', '(RFC822)'))
        print(mail.as_bytes())
        print(response.lines)
        self.assertEqual('OK', response.result)
        self.assertEquals(mail.as_bytes(), response.lines[1])

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

        self.assertEquals(('OK', ['1 EXPUNGE', '2 EXPUNGE', 'EXPUNGE completed.']), (yield from imap_client.expunge()))

        self.assertEquals(0, extract_exists((yield from imap_client.select())))

    @asyncio.coroutine
    def test_copy_messages(self):
        imap_receive(Mail.create(['user']))
        imap_receive(Mail.create(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        result, _ = yield from imap_client.copy('1', '2', 'MAILBOX')
        self.assertEqual('OK', result)

        self.assertEquals(2, extract_exists((yield from imap_client.select('MAILBOX'))))

    @asyncio.coroutine
    def test_copy_messages_by_uid(self):
        imap_receive(Mail.create(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        result, _ = yield from imap_client.uid('copy', '1', 'MAILBOX')
        self.assertEqual('OK', result)

        self.assertEquals(1, extract_exists((yield from imap_client.select('MAILBOX'))))

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
        self.assertEquals(0, extract_exists((yield from imap_client.select())))
        self.assertEquals(1, extract_exists((yield from imap_client.select('MBOX'))))
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
    def test_when_async_commands_timeout__they_should_be_removed_from_protocol_state(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)
        yield from (imap_client.protocol.execute(Command(
            'DELAY', imap_client.protocol.new_tag(), '3', loop=self.loop)))

        noop_task = asyncio.async(imap_client.protocol.execute(
            Command('NOOP', imap_client.protocol.new_tag(), '', loop=self.loop, timeout=2)))
        yield from self.advance(1)
        self.assertEqual(1, len(imap_client.protocol.pending_async_commands))
        yield from self.advance(1.1)

        finished, pending = yield from asyncio.wait([noop_task], loop=self.loop)
        self.assertTrue(noop_task in finished)
        self.assertTrue(isinstance(noop_task.exception(), CommandTimeout))
        self.assertEqual(0, len(imap_client.protocol.pending_async_commands))

    @asyncio.coroutine
    def test_when_sync_commands_timeout__they_should_be_removed_from_protocol_state(self):
        imap_client = yield from self.login_user('user', 'pass')
        yield from (imap_client.protocol.execute(Command(
            'DELAY', imap_client.protocol.new_tag(), '3', loop=self.loop)))

        delay_task = asyncio.async(imap_client.protocol.execute(
            Command('DELAY', imap_client.protocol.new_tag(), '0', loop=self.loop, timeout=2)))
        yield from self.advance(1)
        self.assertIsNotNone(imap_client.protocol.pending_sync_command)
        yield from self.advance(1.1)

        finished, pending = yield from asyncio.wait([delay_task], loop=self.loop)
        self.assertTrue(delay_task in finished)
        self.assertTrue(isinstance(delay_task.exception(), CommandTimeout))
        self.assertIsNone(imap_client.protocol.pending_sync_command)

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
