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
import os
import ssl
import unittest
from datetime import datetime, timedelta

import asynctest
from mock import call, MagicMock
from pytz import utc

from aioimaplib import aioimaplib, CommandTimeout, extract_exists, \
    TWENTY_NINE_MINUTES, STOP_WAIT_SERVER_PUSH, FetchCommand, IdleCommand
from aioimaplib.aioimaplib import Commands, IMAP4ClientProtocol, Command, Response, Abort, AioImapException
from aioimaplib.tests import imapserver
from aioimaplib.tests.imapserver import Mail
from aioimaplib.tests.ssl_cert import create_temp_self_signed_cert
from aioimaplib.tests.test_imapserver import WithImapServer

aioimaplib.log.setLevel(logging.WARNING)
sh = logging.StreamHandler()
sh.setLevel(logging.INFO)
sh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(module)s:%(lineno)d] %(message)s"))
aioimaplib.log.addHandler(sh)


class TestAioimaplibUtils(unittest.TestCase):
    def setUp(self):
        self.imap_protocol = IMAP4ClientProtocol(None)
        self.imap_protocol._handle_line = MagicMock(return_value=None)

    def test_split_responses_no_data(self):
        self.imap_protocol.data_received(b'')
        self.imap_protocol._handle_line.assert_not_called()

    def test_split_responses_regular_lines(self):
        self.imap_protocol.data_received(b'* BYE Logging out\r\nCAPB2 OK LOGOUT completed\r\n')
        self.imap_protocol._handle_line.assert_has_calls([call('* BYE Logging out', None), call('CAPB2 OK LOGOUT completed', None)])

    def test_split_responses_with_message_data(self):
        cmd = Command('FETCH', 'TAG')
        self.imap_protocol._handle_line = MagicMock(return_value=cmd)
        self.imap_protocol.data_received(b'* 1 FETCH (UID 1 RFC822 {26}\r\n...\r\n(mail content)\r\n...\r\n)\r\n'
                                         b'TAG OK FETCH completed.\r\n')

        self.imap_protocol._handle_line.assert_has_calls([call('* 1 FETCH (UID 1 RFC822 {26}', None)])
        self.imap_protocol._handle_line.assert_has_calls([call(')', cmd)])
        self.imap_protocol._handle_line.assert_has_calls([call('TAG OK FETCH completed.', None)])
        self.assertEqual([b'...\r\n(mail content)\r\n...\r\n'], cmd.response.lines)

    def test_split_responses_with_two_messages_data(self):
        cmd = Command('FETCH', 'TAG')
        self.imap_protocol._handle_line = MagicMock(return_value=cmd)
        self.imap_protocol.data_received(b'* 3 FETCH (UID 3 RFC822 {6}\r\nmail 1)\r\n'
                                         b'* 4 FETCH (UID 4 RFC822 {6}\r\nmail 2)\r\n'
                                         b'TAG OK FETCH completed.\r\n')

        self.imap_protocol._handle_line.assert_has_calls([call('* 3 FETCH (UID 3 RFC822 {6}', None),
                                            call(')', cmd),
                                            call('* 4 FETCH (UID 4 RFC822 {6}', None),
                                            call(')', cmd),
                                            call('TAG OK FETCH completed.', None)])
        self.assertEqual([b'mail 1', b'mail 2'], cmd.response.lines)

    def test_split_responses_with_flag_fetch_message_data(self):
        self.imap_protocol.data_received(b'* 1 FETCH (UID 10 FLAGS (FOO))\r\n'
                                         b'* 1 FETCH (UID 15 FLAGS (BAR))\r\n'
                                         b'TAG OK STORE completed.\r\n')
        self.imap_protocol._handle_line.assert_has_calls([call('* 1 FETCH (UID 10 FLAGS (FOO))', None),
                                            call('* 1 FETCH (UID 15 FLAGS (BAR))', None),
                                            call('TAG OK STORE completed.', None)])

    def test_split_responses_with_message_data_expunge(self):
        self.imap_protocol.data_received(b'* 123 EXPUNGE\r\nTAG OK SELECT completed.\r\n')
        self.imap_protocol._handle_line.assert_has_calls([call('* 123 EXPUNGE', None),
                                            call('TAG OK SELECT completed.', None)])

    def test_unconplete_line_with_litteral_fetch(self):
        cmd = Command('FETCH', 'TAG')
        self.imap_protocol._handle_line = MagicMock(return_value=cmd)
        self.imap_protocol.data_received(b'* 12 FETCH (BODY[HEADER] {4}\r\nyo\r\n)\r\n* 13 FETCH (BODY[')
        self.imap_protocol.data_received(b'HEADER] {5}\r\nyo2\r\n)\r\nTAG OK STORE completed.\r\n')

        self.imap_protocol._handle_line.assert_has_calls([call('* 12 FETCH (BODY[HEADER] {4}', None), call(')', cmd)])
        self.imap_protocol._handle_line.assert_has_calls([call('* 13 FETCH (BODY[HEADER] {5}', None),
                                                         call(')', cmd),
                                                         call('TAG OK STORE completed.', None)])
        self.assertEqual([b'yo\r\n', b'yo2\r\n'], cmd.response.lines)

    def test_unconplete_lines_during_litteral(self):
        cmd = Command('LIST', 'TAG')
        self.imap_protocol._handle_line = MagicMock(return_value=cmd)

        self.imap_protocol.data_received(b'* LIST () "/" {11}\r\nfoo/')
        self.imap_protocol.data_received(b'bar/')
        self.imap_protocol.data_received(b'baz\r\n* LIST () "/" qux\r\nTAG OK LIST completed\r\n')

        self.imap_protocol._handle_line.assert_has_calls([call('* LIST () "/" {11}', None)])
        self.imap_protocol._handle_line.assert_has_calls([call('* LIST () "/" qux', None),
                                                          call('TAG OK LIST completed', None)])
        self.assertEqual([b'foo/bar/baz'], cmd.response.lines)

    def test_unconplete_line_during_litteral_no_cmd_found(self):
        self.imap_protocol.data_received(b'* LIST () "/" {7}\r\nfoo/')
        self.imap_protocol.data_received(b'bar\r\nTAG OK LIST completed\r\n')

        self.imap_protocol._handle_line.assert_has_calls([call('* LIST () "/" {7}', None)])
        self.imap_protocol._handle_line.assert_has_calls([call('* LIST () "/" {7}', None),
                                                          call('', Command('NIL', 'unused')),
                                                          call('TAG OK LIST completed', None)])

    def test_line_with_litteral_no_cmd_found_no_AttributeError_thrown(self):
        self.imap_protocol.data_received(b'* 3 FETCH (UID 12 RFC822 {4}\r\nmail)\r\n'
                                         b'TAG OK FETCH completed.\r\n')
        self.imap_protocol._handle_line.assert_has_calls([call('* 3 FETCH (UID 12 RFC822 {4}', None),
                                            call(')', Command('NIL', 'unused')),
                                            call('TAG OK FETCH completed.', None)])

    def test_line_with_attachment_litterals(self):
        cmd = Command('FETCH', 'TAG')
        self.imap_protocol._handle_line = MagicMock(return_value=cmd)

        self.imap_protocol.data_received(b'* 46 FETCH (UID 46 FLAGS () BODYSTRUCTURE ('
                                         b'("text" "calendar" ("charset" "UTF-8" "name" {16}\r\nG\xe9n\xe9ration 3.ics)'
                                         b' "<mqwssinzuqvhkzlnhlcq>" NIL "quoted-printable" 365 14 NIL '
                                         b'("attachment" ("filename" {16}\r\nG\xe9n\xe9ration 3.ics)))\r\n')

        self.imap_protocol._handle_line.assert_has_calls([call('* 46 FETCH (UID 46 FLAGS () BODYSTRUCTURE ('
                                            '("text" "calendar" ("charset" "UTF-8" "name" {16}', None),
                                             call(') "<mqwssinzuqvhkzlnhlcq>" NIL "quoted-printable" 365 14 NIL '
                                                  '("attachment" ("filename" {16}', cmd),
                                             call(')))', cmd)])
        self.assertEqual([b'G\xe9n\xe9ration 3.ics', b'G\xe9n\xe9ration 3.ics'], cmd.response.lines)

    def test_uncomplete_line_followed_by_uncomplete_literal(self):
        cmd = Command('FETCH', 'TAG')
        self.imap_protocol._handle_line = MagicMock(return_value=cmd)

        self.imap_protocol.data_received(b'* 2 FETCH (')
        self.imap_protocol.data_received(b'FLAGS () UID 160016 BODY[] {10}\r\non the ')
        self.imap_protocol.data_received(b'dot)\r\nTAG OK FETCH completed\r\n')

        self.imap_protocol._handle_line.assert_has_calls([call('* 2 FETCH (FLAGS () UID 160016 BODY[] {10}', None),
                                            call(')', cmd), call('TAG OK FETCH completed', None)])
        self.assertEqual([b'on the dot'], cmd.response.lines)

    # cf 1st FETCH in https://tools.ietf.org/html/rfc3501#section-8 example
    def test_uncomplete_fetch_message_attributes_without_literal(self):
        cmd = FetchCommand('TAG')
        self.imap_protocol._handle_line = MagicMock(return_value=cmd)

        line = b'* 12 FETCH (FLAGS (\Seen) BODY ("TEXT" "PLAIN" ("CHARSET" "US-ASCII") NIL NIL "7BIT" 3028 \r\n'
        cmd.append_to_resp(line.decode())
        self.imap_protocol.data_received(line)
        line = b'92))\r\nTAG OK FETCH completed\r\n'
        cmd.append_to_resp(line.decode())
        self.imap_protocol.data_received(line)

        self.imap_protocol._handle_line.assert_has_calls(
            [call('* 12 FETCH (FLAGS (\Seen) BODY ("TEXT" "PLAIN" ("CHARSET" "US-ASCII") NIL NIL "7BIT" 3028 ', None),
             call('92))', cmd), call('TAG OK FETCH completed', None)])

    def test_uncomplete_fetch_with_uncomplete_line(self):
        cmd = FetchCommand('TAG')
        self.imap_protocol._handle_line = MagicMock(return_value=cmd)

        self.imap_protocol.data_received(b'* 21 FETCH (FLAGS (\Seen) BODY[] {16}\r\nuncomplete fetch')
        self.imap_protocol.data_received(b')\r\nTAG OK FETCH completed\r\n')

        self.imap_protocol._handle_line.assert_has_calls(
            [call('* 21 FETCH (FLAGS (\Seen) BODY[] {16}', None),
             call(')', cmd), call('TAG OK FETCH completed', None)])

    def test_command_repr(self):
        self.assertEqual('tag NAME', str(Command('NAME', 'tag')))
        self.assertEqual('tag NAME arg1 arg2', str(Command('NAME', 'tag', 'arg1', 'arg2')))
        self.assertEqual('tag UID NAME arg', str(Command('NAME', 'tag', 'arg', prefix='UID')))
        self.assertEqual('tag UID NAME', str(Command('NAME', 'tag', prefix='UID')))


class TestDataReceived(unittest.TestCase):
    def setUp(self):
        self.imap_protocol = IMAP4ClientProtocol(None)

    def test_when_idle_continuation_line_in_same_dataframe_as_status_update(self):
        queue = asyncio.Queue()
        cmd = IdleCommand('TAG', queue)
        self.imap_protocol.pending_sync_command = cmd
        self.imap_protocol.data_received(b'+ idling\r\n* 1 EXISTS\r\n* 1 RECENT\r\n')

        self.assertEqual(['+ idling'], queue.get_nowait())
        self.assertEqual(['1 EXISTS', '1 RECENT'], queue.get_nowait())


class TestFetchWaitsForAllMessageAttributes(unittest.TestCase):
    def test_empty_fetch(self):
        self.assertFalse(FetchCommand('TAG').wait_data())

    def test_simple_fetch(self):
        fetch = FetchCommand('TAG')
        fetch.append_to_resp('12 FETCH (FLAGS (\Seen))')

        self.assertFalse(fetch.wait_data())

    def test_simple_fetch_with_two_lines(self):
        fetch = FetchCommand('TAG')
        fetch.append_to_resp('12 FETCH (FLAGS (\Seen) BODY ("TEXT" "PLAIN" ("CHARSET" "US-ASCII") NIL NIL "7BIT" 3028')
        self.assertTrue(fetch.wait_data())

        fetch.append_to_resp('92))')
        self.assertFalse(fetch.wait_data())

    def test_fetch_with_litteral(self):
        fetch = FetchCommand('TAG')
        fetch.append_to_resp('12 FETCH (FLAGS () BODY[] {13}')
        fetch.begin_literal_data(13, b'literal (data')
        fetch.append_to_resp(')')

        self.assertFalse(fetch.wait_data())

    def test_fetch_only_the_last_message_data(self):
        fetch = FetchCommand('TAG')
        fetch.append_to_resp('12 FETCH (FLAGS (\Seen)') # not closed on purpose
        self.assertTrue(fetch.wait_data())

        fetch.append_to_resp('13 FETCH (FLAGS (\Seen)')
        self.assertTrue(fetch.wait_data())

        fetch.append_to_resp(')')
        self.assertFalse(fetch.wait_data())


class TestAioimaplibCommand(asynctest.ClockedTestCase):
    @asyncio.coroutine
    def test_command_timeout(self):
        cmd = Command('CMD', 'tag', loop=self.loop, timeout=1)
        yield from self.advance(2)
        with self.assertRaises(AioImapException):
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
        with self.assertRaises(AioImapException):
            yield from cmd.wait()


class AioWithImapServer(WithImapServer):
    @asyncio.coroutine
    def login_user(self, login, password, select=False, lib=aioimaplib.IMAP4):
        imap_client = lib(port=12345, loop=self.loop, timeout=3)
        yield from asyncio.wait_for(imap_client.wait_hello_from_server(), 2)

        yield from imap_client.login(login, password)

        if select:
            yield from imap_client.select()
        return imap_client


class TestAioimaplib(AioWithImapServer, asynctest.TestCase):
    def setUp(self):
        self._init_server(self.loop)

    @asyncio.coroutine
    def tearDown(self):
        yield from self._shutdown_server()

    @asyncio.coroutine
    def test_capabilities(self):
        imap_client = aioimaplib.IMAP4(port=12345, loop=self.loop)
        yield from asyncio.wait_for(imap_client.wait_hello_from_server(), 2)

        self.assertEquals('IMAP4REV1', imap_client.protocol.imap_version)
        self.assertEquals({'IMAP4rev1', 'YESAUTH'}, imap_client.protocol.capabilities)
        self.assertTrue(imap_client.has_capability('YESAUTH'))

    @asyncio.coroutine
    def test_login(self):
        imap_client = aioimaplib.IMAP4(port=12345, loop=self.loop, timeout=3)
        yield from asyncio.wait_for(imap_client.wait_hello_from_server(), 2)

        result, data = yield from imap_client.login('user', 'password')

        self.assertEquals(aioimaplib.AUTH, imap_client.protocol.state)
        self.assertEqual('OK', result)
        self.assertEqual('LOGIN completed', data[-1])
        self.assertTrue(imap_client.has_capability('IDLE'))
        self.assertTrue(imap_client.has_capability('UIDPLUS'))

    @asyncio.coroutine
    def test_login_with_special_characters(self):
        imap_client = aioimaplib.IMAP4(port=12345, loop=self.loop, timeout=3)
        yield from asyncio.wait_for(imap_client.wait_hello_from_server(), 2)

        result, data = yield from imap_client.login('user', 'pass"word')

        self.assertEquals(aioimaplib.AUTH, imap_client.protocol.state)
        self.assertEqual('OK', result)
        self.assertEqual('LOGIN completed', data[-1])
        self.assertTrue(imap_client.has_capability('IDLE'))
        self.assertTrue(imap_client.has_capability('UIDPLUS'))

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

        self.assertEquals(0, extract_exists((yield from imap_client.examine())))

        self.assertEquals(aioimaplib.AUTH, imap_client.protocol.state)

    @asyncio.coroutine
    def test_search_two_messages(self):
        self.imapserver.receive(Mail.create(['user']))
        self.imapserver.receive(Mail.create(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        result, data = yield from imap_client.search('ALL')

        self.assertEqual('OK', result)
        self.assertEqual('1 2', data[0])

    @asyncio.coroutine
    def test_uid_with_illegal_command(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)

        for command in {'COPY', 'FETCH', 'STORE', 'EXPUNGE', 'MOVE'}.symmetric_difference(Commands.keys()):
            with self.assertRaises(aioimaplib.Abort) as expected:
                yield from imap_client.uid(command)

            self.assertEqual(expected.exception.args,
                             ('command UID only possible with COPY, FETCH, EXPUNGE (w/UIDPLUS) or STORE (was %s)' % command,))

    @asyncio.coroutine
    def test_search_three_messages_by_uid(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)
        self.imapserver.receive(Mail.create(['user']))  # id=1 uid=1
        self.imapserver.receive(Mail.create(['user']), mailbox='OTHER_MAILBOX')  # id=1 uid=1
        self.imapserver.receive(Mail.create(['user']))  # id=2 uid=2

        self.assertEqual('1 2', (yield from imap_client.search('ALL')).lines[0])
        self.assertEqual('1 2', (yield from imap_client.uid_search('ALL')).lines[0])

        yield from imap_client.select('OTHER_MAILBOX')
        self.assertEqual('1', (yield from imap_client.uid_search('ALL')).lines[0])

    @asyncio.coroutine
    def test_fetch(self):
        print('test loop %r' % self.loop)
        imap_client = yield from self.login_user('user', 'pass', select=True)
        mail = Mail.create(['user'], mail_from='me', subject='hello',
                           content='pleased to meet you, wont you guess my name ?')
        self.imapserver.receive(mail)

        result, data = yield from imap_client.fetch('1', '(RFC822)')
        content = mail.as_bytes()

        self.assertEqual('OK', result)
        self.assertEqual([
            '1 FETCH (RFC822 {%s}' % len(content), content, ')',
            'FETCH completed.'
        ], data)

    @asyncio.coroutine
    def test_fetch_by_uid_without_body(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)
        mail = Mail.create(['user'], mail_from='me', subject='hello',
                           content='pleased to meet you, wont you guess my name ?')
        self.imapserver.receive(mail)

        response = (yield from imap_client.uid('fetch', '1', '(UID FLAGS)'))

        self.assertEqual('OK', response.result)
        self.assertEquals('1 FETCH (UID 1 FLAGS ())', response.lines[0])

    @asyncio.coroutine
    def test_fetch_by_uid(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)
        mail = Mail.create(['user'], mail_from='me', subject='hello',
                           content='pleased to meet you, wont you guess my name ?')
        self.imapserver.receive(mail)

        response = (yield from imap_client.uid('fetch', '1', '(RFC822)'))
        self.assertEqual('OK', response.result)
        self.assertEquals(mail.as_bytes(), response.lines[1])

    @asyncio.coroutine
    def test_idle(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)

        idle = yield from imap_client.idle_start(timeout=0.3)
        self.imapserver.receive(Mail.create(to=['user'], mail_from='me', subject='hello'))

        self.assertEquals(['1 EXISTS', '1 RECENT'], (yield from imap_client.wait_server_push()))

        imap_client.idle_done()
        self.assertEquals(('OK', ['IDLE terminated']), (yield from asyncio.wait_for(idle, 1)))

        self.assertTrue(imap_client._idle_waiter._cancelled)
        with self.assertRaises(asyncio.TimeoutError):
            yield from imap_client.wait_server_push(timeout=0.1)

    @asyncio.coroutine
    def test_idle_loop(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)

        idle = yield from imap_client.idle_start(timeout=0.3)
        self.imapserver.receive(Mail.create(to=['user'], mail_from='me', subject='hello'))

        data = list()
        while imap_client.has_pending_idle():
            data.append((yield from imap_client.wait_server_push()))
            if data[-1] == STOP_WAIT_SERVER_PUSH:
                imap_client.idle_done()
                yield from asyncio.wait_for(idle, 1)

        self.assertEqual([['1 EXISTS', '1 RECENT'], STOP_WAIT_SERVER_PUSH], data)

    @asyncio.coroutine
    def test_idle_stop(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)
        idle = yield from imap_client.idle_start()

        self.assertTrue((yield from imap_client.stop_wait_server_push()))

        self.assertEquals(STOP_WAIT_SERVER_PUSH, (yield from imap_client.wait_server_push()))

        imap_client.idle_done()
        yield from asyncio.wait_for(idle, 1)

    @asyncio.coroutine
    def test_idle_stop_does_nothing_if_no_pending_idle(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)

        self.assertFalse((yield from imap_client.stop_wait_server_push()))

    @asyncio.coroutine
    def test_store_and_search_by_keyword(self):
        self.imapserver.receive(Mail.create(['user']))
        self.imapserver.receive(Mail.create(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)
        self.assertEqual('', (yield from imap_client.uid_search('KEYWORD FOO', charset=None)).lines[0])

        self.assertEquals('OK', (yield from imap_client.uid('store', '1', '+FLAGS (FOO)')).result)

        self.assertEqual('1', (yield from imap_client.uid_search('KEYWORD FOO', charset=None)).lines[0])
        self.assertEqual('2', (yield from imap_client.uid_search('UNKEYWORD FOO', charset=None)).lines[0])

    @asyncio.coroutine
    def test_expunge_messages(self):
        self.imapserver.receive(Mail.create(['user']))
        self.imapserver.receive(Mail.create(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        self.assertEquals(('OK', ['1 EXPUNGE', '2 EXPUNGE', 'EXPUNGE completed.']), (yield from imap_client.expunge()))

        self.assertEquals(0, extract_exists((yield from imap_client.select())))

    @asyncio.coroutine
    def test_copy_messages(self):
        self.imapserver.receive(Mail.create(['user']))
        self.imapserver.receive(Mail.create(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        result, _ = yield from imap_client.copy('1', '2', 'MAILBOX')
        self.assertEqual('OK', result)

        self.assertEquals(2, extract_exists((yield from imap_client.select('MAILBOX'))))

    @asyncio.coroutine
    def test_copy_messages_by_uid(self):
        self.imapserver.receive(Mail.create(['user']))
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
        self.imapserver.receive(Mail.create(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        f1 = asyncio.async(imap_client.fetch('1', '(RFC822)'))
        f2 = asyncio.async(imap_client.fetch('1', '(RFC822)'))

        yield from asyncio.wait([f1, f2])
        self.assertIsNone(f1.exception())
        self.assertIsNone(f2.exception())

    @asyncio.coroutine
    def test_concurrency_3_executing_async_commands_in_parallel(self):
        # cf valid example in https://tools.ietf.org/html/rfc3501#section-5.5
        self.imapserver.receive(Mail.create(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        store = asyncio.async(imap_client.store('1', '+FLAGS (FOO)'))
        copy = asyncio.async(imap_client.copy('1', 'MBOX'))
        expunge = asyncio.async(imap_client.expunge())

        yield from asyncio.wait([store, copy, expunge])
        self.assertEquals(0, extract_exists((yield from imap_client.select())))
        self.assertEquals(1, extract_exists((yield from imap_client.select('MBOX'))))
        self.assertEqual('1', (yield from imap_client.search('KEYWORD FOO', charset=None)).lines[0])

    @asyncio.coroutine
    def test_concurrency_4_sync_command_waits_for_async_commands_to_finish(self):
        self.imapserver.receive(Mail.create(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        asyncio.async(imap_client.copy('1', 'MBOX'))
        asyncio.async(imap_client.expunge())
        examine = asyncio.async(imap_client.examine('MBOX'))

        self.assertEquals(1, extract_exists((yield from asyncio.wait_for(examine, 1))))

    @asyncio.coroutine
    def test_noop(self):
        imap_client = yield from self.login_user('user', 'pass')
        self.assertEquals(('OK', ['NOOP completed.']), (yield from imap_client.noop()))

    @asyncio.coroutine
    def test_noop_with_untagged_data(self):
        imap_client = yield from self.login_user('user', 'pass')
        self.imapserver.receive(Mail.create(['user']))

        self.assertEquals(('OK', ['1 EXISTS', '1 RECENT', 'NOOP completed.']), (yield from imap_client.noop()))

    @asyncio.coroutine
    def test_check(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)
        self.assertEquals(('OK', ['CHECK completed.']), (yield from imap_client.check()))

    @asyncio.coroutine
    def test_close(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)
        self.assertEquals(imapserver.SELECTED, self.imapserver.get_connection('user').state)

        self.assertEquals(('OK', ['CLOSE completed.']), (yield from imap_client.close()))

        self.assertEquals(imapserver.AUTH, self.imapserver.get_connection('user').state)

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
        self.assertEquals(('OK', ['() "/" Drafts', '() "/" INBOX', '() "/" Sent', '() "/" Trash',
                                  'LIST completed.']), (yield from imap_client.list('""', '.*')))

        yield from imap_client.create('MYBOX')
        self.assertEquals(('OK', ['() "/" Drafts', '() "/" INBOX', '() "/" MYBOX', '() "/" Sent', '() "/" Trash',
                                  'LIST completed.']),
                          (yield from imap_client.list('""', '.*')))

    @asyncio.coroutine
    def test_append(self):
        imap_client = yield from self.login_user('user@mail', 'pass')
        self.assertEquals(0, extract_exists((yield from imap_client.examine('INBOX'))))

        msg = Mail.create(['user@mail'], subject='append msg', content='do you see me ?')
        response = yield from imap_client.append(msg.as_bytes(), mailbox='INBOX', flags='FOO BAR',
                                                 date=datetime.now(tz=utc), )
        self.assertEquals('OK', response.result)
        self.assertTrue('1] APPEND completed' in response.lines[0])

        self.assertEquals(1, extract_exists((yield from imap_client.examine('INBOX'))))

    @asyncio.coroutine
    def test_rfc5032_within(self):
        self.imapserver.receive(Mail.create(['user'], date=datetime.now(tz=utc) - timedelta(seconds=84600 * 3)))  # 1
        self.imapserver.receive(Mail.create(['user'], date=datetime.now(tz=utc) - timedelta(seconds=84600)))  # 2
        self.imapserver.receive(Mail.create(['user']))  # 3
        imap_client = yield from self.login_user('user', 'pass', select=True)

        self.assertEquals('1', (yield from imap_client.search('OLDER', '84700')).lines[0])
        self.assertEquals('2 3', (yield from imap_client.search('YOUNGER', '84700')).lines[0])

    @asyncio.coroutine
    def test_rfc4315_uidplus_expunge(self):
        self.imapserver.receive(Mail.create(['user']))
        self.imapserver.receive(Mail.create(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        self.assertEquals(('OK', ['1 EXPUNGE', 'UID EXPUNGE completed.']), (yield from imap_client.uid('expunge', '1:1')))

        self.assertEquals(1, extract_exists((yield from imap_client.select())))

    @asyncio.coroutine
    def test_rfc6851_move(self):
        self.imapserver.receive(Mail.create(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)
        uidvalidity = self.imapserver.get_connection('user').uidvalidity

        self.assertEqual(('OK', ['OK [COPYUID %d 1:1 1:1]' % uidvalidity, '1 EXPUNGE', 'Done']),
                         (yield from imap_client.move('1:1', 'Trash')))

        self.assertEquals(0, extract_exists((yield from imap_client.select())))
        self.assertEquals(1, extract_exists((yield from imap_client.select('Trash'))))

    @asyncio.coroutine
    def test_rfc6851_uidmove(self):
        self.imapserver.receive(Mail.create(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)
        uidvalidity = self.imapserver.get_connection('user').uidvalidity

        self.assertEqual(('OK', ['OK [COPYUID %d 1:1 1:1]' % uidvalidity, '1 EXPUNGE', 'Done']),
                         (yield from imap_client.uid('move', '1:1', 'Trash')))

        self.assertEquals(0, extract_exists((yield from imap_client.select())))
        self.assertEquals(1, extract_exists((yield from imap_client.select('Trash'))))

    @asyncio.coroutine
    def test_rfc5161_enable(self):
        imap_client = yield from self.login_user('user', 'pass')

        self.assertEqual(('OK', ['X-GOOD-IDEA CONDSTORE enabled']),
                         (yield from imap_client.enable('X-GOOD-IDEA CONDSTORE')))


class TestImapServerCapabilities(AioWithImapServer, asynctest.TestCase):
    def setUp(self):
        self._init_server(self.loop, capabilities='')

    @asyncio.coroutine
    def tearDown(self):
        yield from self._shutdown_server()

    @asyncio.coroutine
    def test_idle_messages_without_idle_capability_abort_command(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)
        with self.assertRaises(Abort):
            yield from imap_client.idle()

    @asyncio.coroutine
    def test_expunge_messages_without_uidplus_capability_abort_command(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)
        with self.assertRaises(Abort):
            yield from imap_client.uid('expunge', '1:1')

    @asyncio.coroutine
    def test_move_without_move_capability_abort_command(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)
        with self.assertRaises(Abort):
            yield from imap_client.move('1:1', 'Trash')

    @asyncio.coroutine
    def test_uidmove_without_move_capability_abort_command(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)
        with self.assertRaises(Abort):
            yield from imap_client.uid('move', '1:1', 'Trash')

    @asyncio.coroutine
    def test_enable_without_enable_capability_abort_command(self):
        imap_client = yield from self.login_user('user', 'pass')
        with self.assertRaises(Abort):
            yield from imap_client.enable('CAPABILITY')


class TestAioimaplibClocked(AioWithImapServer, asynctest.ClockedTestCase):

    def setUp(self):
        self._init_server(self.loop)

    @asyncio.coroutine
    def tearDown(self):
        yield from self._shutdown_server()

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
    def test_idle_start__exits_queueget_without_timeout_error(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)
        yield from imap_client.idle_start()

        push_task = asyncio.async(imap_client.wait_server_push(TWENTY_NINE_MINUTES + 2))
        yield from self.advance(TWENTY_NINE_MINUTES + 1)

        r = yield from asyncio.wait_for(push_task, 0)
        self.assertEqual(STOP_WAIT_SERVER_PUSH, r)


class TestAioimaplibCallback(AioWithImapServer, asynctest.TestCase):
    def setUp(self):
        self._init_server(self.loop)

    @asyncio.coroutine
    def test_callback_is_called_when_connection_is_lost(self):
        queue = asyncio.Queue()
        imap_client = aioimaplib.IMAP4(port=12345, loop=self.loop, timeout=3, conn_lost_cb=(
            lambda m: queue.put_nowait('called with %s' % m)))
        yield from asyncio.wait_for(imap_client.wait_hello_from_server(), 2)
        yield from imap_client.login('login', 'password')

        yield from self._shutdown_server()

        self.assertEqual('called with None', (yield from asyncio.wait_for(queue.get(), timeout=2)))


class TestAioimaplibSSL(WithImapServer, asynctest.TestCase):
    """ Test the aioimaplib with SSL

        SSL is handled transparently by asyncio, so we don't
        need to repeat all the tests - just ensure the encrypted
        connection happens
    """
    def setUp(self):
        self._cert_file, self._cert_key = create_temp_self_signed_cert()

        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(self._cert_file, self._cert_key)

        self._init_server(self.loop, ssl_context=ssl_context)

    @asyncio.coroutine
    def tearDown(self):
        yield from self._shutdown_server()
        os.remove(self._cert_file)
        os.remove(self._cert_key)

    @asyncio.coroutine
    def test_client_can_connect_to_server_over_ssl(self):
        ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self._cert_file)
        imap_client = aioimaplib.IMAP4_SSL(port=12345, loop=self.loop, ssl_context=ssl_context)
        yield from asyncio.wait_for(imap_client.wait_hello_from_server(), 2)

        self.assertEquals('IMAP4REV1', imap_client.protocol.imap_version)
        self.assertEquals({'IMAP4rev1', 'YESAUTH'}, imap_client.protocol.capabilities)
        self.assertTrue(imap_client.has_capability('YESAUTH'))
