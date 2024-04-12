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
from aioimaplib.tests.imapserver import Mail, MockImapServer, ImapProtocol
from aioimaplib.tests.ssl_cert import create_temp_self_signed_cert
from aioimaplib.tests.test_imapserver import WithImapServer
import pytest

aioimaplib.log.setLevel(logging.WARNING)
sh = logging.StreamHandler()
sh.setLevel(logging.INFO)
sh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(module)s:%(lineno)d] %(message)s"))
aioimaplib.log.addHandler(sh)


class TestAioimaplibUtils(unittest.TestCase):
    def setUp(self):
        self.imap_protocol = IMAP4ClientProtocol(None)
        self.imap_protocol._handle_line = MagicMock(return_value=None)
        aioimaplib.get_running_loop = asyncio.new_event_loop # monkey patch to avoid Exception "No running loop"

    def test_split_responses_no_data(self):
        self.imap_protocol.data_received(b'')
        self.imap_protocol._handle_line.assert_not_called()

    def test_split_responses_extremely_long(self):
        self.imap_protocol.data_received(b'UID 1\r\n' * 1500)

    def test_split_responses_regular_lines(self):
        self.imap_protocol.data_received(b'* BYE Logging out\r\nCAPB2 OK LOGOUT completed\r\n')
        self.imap_protocol._handle_line.assert_has_calls([call(b'* BYE Logging out', None), call(b'CAPB2 OK LOGOUT completed', None)])

    def test_split_responses_with_message_data(self):
        cmd = Command('FETCH', 'TAG')
        self.imap_protocol._handle_line = MagicMock(return_value=cmd)
        self.imap_protocol.data_received(b'* 1 FETCH (UID 1 RFC822 {26}\r\n...\r\n(mail content)\r\n...\r\n)\r\n'
                                         b'TAG OK FETCH completed.\r\n')

        self.imap_protocol._handle_line.assert_has_calls([call(b'* 1 FETCH (UID 1 RFC822 {26}', None)])
        self.imap_protocol._handle_line.assert_has_calls([call(b')', cmd)])
        self.imap_protocol._handle_line.assert_has_calls([call(b'TAG OK FETCH completed.', None)])
        assert [b'...\r\n(mail content)\r\n...\r\n'] == cmd.response.lines

    def test_split_responses_with_two_messages_data(self):
        cmd = Command('FETCH', 'TAG')
        self.imap_protocol._handle_line = MagicMock(return_value=cmd)
        self.imap_protocol.data_received(b'* 3 FETCH (UID 3 RFC822 {6}\r\nmail 1)\r\n'
                                         b'* 4 FETCH (UID 4 RFC822 {6}\r\nmail 2)\r\n'
                                         b'TAG OK FETCH completed.\r\n')

        self.imap_protocol._handle_line.assert_has_calls([call(b'* 3 FETCH (UID 3 RFC822 {6}', None),
                                            call(b')', cmd),
                                            call(b'* 4 FETCH (UID 4 RFC822 {6}', None),
                                            call(b')', cmd),
                                            call(b'TAG OK FETCH completed.', None)])
        assert [b'mail 1', b'mail 2'] == cmd.response.lines

    def test_split_responses_with_flag_fetch_message_data(self):
        self.imap_protocol.data_received(b'* 1 FETCH (UID 10 FLAGS (FOO))\r\n'
                                         b'* 1 FETCH (UID 15 FLAGS (BAR))\r\n'
                                         b'TAG OK STORE completed.\r\n')
        self.imap_protocol._handle_line.assert_has_calls([call(b'* 1 FETCH (UID 10 FLAGS (FOO))', None),
                                            call(b'* 1 FETCH (UID 15 FLAGS (BAR))', None),
                                            call(b'TAG OK STORE completed.', None)])

    def test_split_responses_with_message_data_expunge(self):
        self.imap_protocol.data_received(b'* 123 EXPUNGE\r\nTAG OK SELECT completed.\r\n')
        self.imap_protocol._handle_line.assert_has_calls([call(b'* 123 EXPUNGE', None),
                                            call(b'TAG OK SELECT completed.', None)])

    def test_unconplete_line_with_litteral_fetch(self):
        cmd = Command('FETCH', 'TAG')
        self.imap_protocol._handle_line = MagicMock(return_value=cmd)
        self.imap_protocol.data_received(b'* 12 FETCH (BODY[HEADER] {4}\r\nyo\r\n)\r\n* 13 FETCH (BODY[')
        self.imap_protocol.data_received(b'HEADER] {5}\r\nyo2\r\n)\r\nTAG OK STORE completed.\r\n')

        self.imap_protocol._handle_line.assert_has_calls([call(b'* 12 FETCH (BODY[HEADER] {4}', None), call(b')', cmd)])
        self.imap_protocol._handle_line.assert_has_calls([call(b'* 13 FETCH (BODY[HEADER] {5}', None),
                                                         call(b')', cmd),
                                                         call(b'TAG OK STORE completed.', None)])
        assert [b'yo\r\n', b'yo2\r\n'] == cmd.response.lines

    def test_unconplete_lines_during_litteral(self):
        cmd = Command('LIST', 'TAG')
        self.imap_protocol._handle_line = MagicMock(return_value=cmd)

        self.imap_protocol.data_received(b'* LIST () "/" {11}\r\nfoo/')
        self.imap_protocol.data_received(b'bar/')
        self.imap_protocol.data_received(b'baz\r\n* LIST () "/" qux\r\nTAG OK LIST completed\r\n')

        self.imap_protocol._handle_line.assert_has_calls([call(b'* LIST () "/" {11}', None)])
        self.imap_protocol._handle_line.assert_has_calls([call(b'* LIST () "/" qux', None),
                                                          call(b'TAG OK LIST completed', None)])
        assert [b'foo/bar/baz'] == cmd.response.lines

    def test_unconplete_line_during_litteral_no_cmd_found(self):
        self.imap_protocol.data_received(b'* LIST () "/" {7}\r\nfoo/')
        self.imap_protocol.data_received(b'bar\r\nTAG OK LIST completed\r\n')

        self.imap_protocol._handle_line.assert_has_calls([call(b'* LIST () "/" {7}', None)])
        self.imap_protocol._handle_line.assert_has_calls([call(b'* LIST () "/" {7}', None),
                                                          call(b'', Command('NIL', 'unused')),
                                                          call(b'TAG OK LIST completed', None)])

    def test_line_with_litteral_no_cmd_found_no_AttributeError_thrown(self):
        self.imap_protocol.data_received(b'* 3 FETCH (UID 12 RFC822 {4}\r\nmail)\r\n'
                                         b'TAG OK FETCH completed.\r\n')
        self.imap_protocol._handle_line.assert_has_calls([call(b'* 3 FETCH (UID 12 RFC822 {4}', None),
                                            call(b')', Command('NIL', 'unused')),
                                            call(b'TAG OK FETCH completed.', None)])

    def test_line_with_attachment_litterals(self):
        cmd = Command('FETCH', 'TAG')
        self.imap_protocol._handle_line = MagicMock(return_value=cmd)

        self.imap_protocol.data_received(b'* 46 FETCH (UID 46 FLAGS () BODYSTRUCTURE ('
                                         b'("text" "calendar" ("charset" "UTF-8" "name" {16}\r\nG\xe9n\xe9ration 3.ics)'
                                         b' "<mqwssinzuqvhkzlnhlcq>" NIL "quoted-printable" 365 14 NIL '
                                         b'("attachment" ("filename" {16}\r\nG\xe9n\xe9ration 3.ics)))\r\n')

        self.imap_protocol._handle_line.assert_has_calls([call(b'* 46 FETCH (UID 46 FLAGS () BODYSTRUCTURE ('
                                            b'("text" "calendar" ("charset" "UTF-8" "name" {16}', None),
                                             call(b') "<mqwssinzuqvhkzlnhlcq>" NIL "quoted-printable" 365 14 NIL '
                                                  b'("attachment" ("filename" {16}', cmd),
                                             call(b')))', cmd)])
        assert [b'G\xe9n\xe9ration 3.ics', b'G\xe9n\xe9ration 3.ics'] == cmd.response.lines

    def test_uncomplete_line_followed_by_uncomplete_literal(self):
        cmd = Command('FETCH', 'TAG')
        self.imap_protocol._handle_line = MagicMock(return_value=cmd)

        self.imap_protocol.data_received(b'* 2 FETCH (')
        self.imap_protocol.data_received(b'FLAGS () UID 160016 BODY[] {10}\r\non the ')
        self.imap_protocol.data_received(b'dot)\r\nTAG OK FETCH completed\r\n')

        self.imap_protocol._handle_line.assert_has_calls([call(b'* 2 FETCH (FLAGS () UID 160016 BODY[] {10}', None),
                                            call(b')', cmd), call(b'TAG OK FETCH completed', None)])
        assert [b'on the dot'] == cmd.response.lines

    # cf 1st FETCH in https://tools.ietf.org/html/rfc3501#section-8 example
    def test_uncomplete_fetch_message_attributes_without_literal(self):
        cmd = FetchCommand('TAG')
        self.imap_protocol._handle_line = MagicMock(return_value=cmd)

        line = b'* 12 FETCH (FLAGS (\Seen) BODY ("TEXT" "PLAIN" ("CHARSET" "US-ASCII") NIL NIL "7BIT" 3028 \r\n'
        cmd.append_to_resp(line)
        self.imap_protocol.data_received(line)
        line = b'92))\r\nTAG OK FETCH completed\r\n'
        cmd.append_to_resp(line)
        self.imap_protocol.data_received(line)

        self.imap_protocol._handle_line.assert_has_calls(
            [call(b'* 12 FETCH (FLAGS (\Seen) BODY ("TEXT" "PLAIN" ("CHARSET" "US-ASCII") NIL NIL "7BIT" 3028 ', None),
             call(b'92))', cmd), call(b'TAG OK FETCH completed', None)])

    def test_uncomplete_fetch_with_uncomplete_line(self):
        cmd = FetchCommand('TAG')
        self.imap_protocol._handle_line = MagicMock(return_value=cmd)

        self.imap_protocol.data_received(b'* 21 FETCH (FLAGS (\Seen) BODY[] {16}\r\nuncomplete fetch')
        self.imap_protocol.data_received(b')\r\nTAG OK FETCH completed\r\n')

        self.imap_protocol._handle_line.assert_has_calls(
            [call(b'* 21 FETCH (FLAGS (\Seen) BODY[] {16}', None),
             call(b')', cmd), call(b'TAG OK FETCH completed', None)])

    def test_command_repr(self):
        assert 'tag NAME' == str(Command('NAME', 'tag'))
        assert 'tag NAME arg1 arg2' == str(Command('NAME', 'tag', 'arg1', 'arg2'))
        assert 'tag UID NAME arg' == str(Command('NAME', 'tag', 'arg', prefix='UID'))
        assert 'tag UID NAME' == str(Command('NAME', 'tag', prefix='UID'))


class TestDataReceived(unittest.TestCase):
    def setUp(self):
        self.imap_protocol = IMAP4ClientProtocol(None)

    def test_when_idle_continuation_line_in_same_dataframe_as_status_update(self):
        queue = asyncio.Queue()
        cmd = IdleCommand('TAG', queue)
        self.imap_protocol.pending_sync_command = cmd
        self.imap_protocol.data_received(b'+ idling\r\n* 1 EXISTS\r\n* 1 RECENT\r\n')

        assert self.imap_protocol._idle_event.is_set()
        assert [b'1 EXISTS', b'1 RECENT'] == queue.get_nowait()


class TestFetchWaitsForAllMessageAttributes(unittest.TestCase):
    def test_empty_fetch(self):
        assert not FetchCommand('TAG').wait_data()

    def test_simple_fetch(self):
        fetch = FetchCommand('TAG')
        fetch.append_to_resp(b'12 FETCH (FLAGS (\Seen))')

        assert not fetch.wait_data()

    def test_simple_fetch_with_two_lines(self):
        fetch = FetchCommand('TAG')
        fetch.append_to_resp(b'12 FETCH (FLAGS (\Seen) BODY ("TEXT" "PLAIN" ("CHARSET" "US-ASCII") NIL NIL "7BIT" 3028')
        assert fetch.wait_data()

        fetch.append_to_resp(b'92))')
        assert not fetch.wait_data()

    def test_fetch_with_litteral(self):
        fetch = FetchCommand('TAG')
        fetch.append_to_resp(b'12 FETCH (FLAGS () BODY[] {13}')
        fetch.begin_literal_data(13, b'literal (data')
        fetch.append_to_resp(b')')

        assert not fetch.wait_data()

    def test_fetch_only_the_last_message_data(self):
        fetch = FetchCommand('TAG')
        fetch.append_to_resp(b'12 FETCH (FLAGS (\Seen)') # not closed on purpose
        assert fetch.wait_data()

        fetch.append_to_resp(b'13 FETCH (FLAGS (\Seen)')
        assert fetch.wait_data()

        fetch.append_to_resp(b')')
        assert not fetch.wait_data()


class TestAioimaplibCommand(asynctest.ClockedTestCase):
    async def test_command_timeout(self):
        cmd = Command('CMD', 'tag', loop=self.loop, timeout=1)
        await self.advance(2)
        with pytest.raises(AioImapException):
            await cmd.wait()

    async def test_command_close_cancels_timer(self):
        cmd = Command('CMD', 'tag', loop=self.loop, timeout=1)
        cmd.close('line', 'OK')
        await self.advance(3)

        await cmd.wait()
        assert Response('OK', ['line']) == cmd.response

    async def test_command_begin_literal_data_resets_timer(self):
        cmd = Command('CMD', 'tag', loop=self.loop, timeout=2)

        await self.advance(1)
        cmd.begin_literal_data(7, b'literal')

        await self.advance(1.9)
        cmd.close('line', 'OK')

        await cmd.wait()
        assert Response('OK', [b'literal', 'line']) == cmd.response

    async def test_command_append_data_resets_timer(self):
        cmd = Command('CMD', 'tag', loop=self.loop, timeout=2)
        cmd.begin_literal_data(4, b'da')

        await self.advance(1.9)
        cmd.append_literal_data(b'ta')

        await self.advance(1.9)
        cmd.close('line', 'OK')

        await cmd.wait()
        assert Response('OK', [b'data', 'line']) == cmd.response

    async def test_command_append_literal_data_resets_timer(self):
        cmd = Command('CMD', 'tag', loop=self.loop, timeout=2)
        cmd.begin_literal_data(12, b'literal')

        await self.advance(1.9)
        cmd.append_literal_data(b' data')

        await self.advance(1.9)
        cmd.close('line', 'OK')

        await cmd.wait()
        assert Response('OK', [b'literal data', 'line']) == cmd.response

    async def test_command_append_to_resp_resets_timer(self):
        cmd = Command('CMD', 'tag', loop=self.loop, timeout=2)

        await self.advance(1.9)
        cmd.append_to_resp('line 1')

        await self.advance(1.9)
        cmd.close('line 2', 'OK')

        await cmd.wait()
        assert Response('OK', ['line 1', 'line 2']) == cmd.response

    async def test_command_timeout_while_receiving_data(self):
        cmd = Command('CMD', 'tag', loop=self.loop, timeout=2)

        await self.advance(1)
        cmd.begin_literal_data(12, b'literal')

        await self.advance(3)
        with pytest.raises(AioImapException):
            await cmd.wait()


class AioWithImapServer(WithImapServer):
    async def login_user(self, login, password, select=False, lib=aioimaplib.IMAP4, timeout=3):
        imap_client = lib(port=12345, loop=self.loop, timeout=timeout)
        await asyncio.wait_for(imap_client.wait_hello_from_server(), 2)

        await imap_client.login(login, password)

        if select:
            await imap_client.select()
        return imap_client


class AllowedVersionsImapProtocol(ImapProtocol):
    def capability(self, tag, *args):
        """No sent IMAP4rev1"""
        self.send_untagged_line('CAPABILITY YESAUTH')
        self.send_tagged_line(tag, 'OK Pre-login capabilities listed, post-login capabilities have more')


class AllowedVersionsMockImapServer(MockImapServer):
    def run_server(self, host='127.0.0.1', port=1143, fetch_chunk_size=0, ssl_context=None):
        def create_protocol():
            protocol = AllowedVersionsImapProtocol(self._server_state, fetch_chunk_size, self.capabilities, self.loop)
            self._connections.append(protocol)
            return protocol

        server = self.loop.create_server(create_protocol, host, port, ssl=ssl_context)
        return self.loop.run_until_complete(server)


class AllowedVersionsAioWithImapServer(AioWithImapServer):
    def _init_server(self, loop, capabilities=None, ssl_context=None):
        self.loop = loop
        if capabilities is not None:
            self.imapserver = AllowedVersionsMockImapServer(loop=loop, capabilities=capabilities)
        else:
            self.imapserver = AllowedVersionsMockImapServer(loop=loop)
        self.server = self.imapserver.run_server(
            host='127.0.0.1', port=12345, fetch_chunk_size=64, ssl_context=ssl_context
        )


class TestAioimaplibAllowedVersions(AllowedVersionsAioWithImapServer, asynctest.TestCase):
    def setUp(self):
        self._init_server(self.loop)

    async def tearDown(self):
        await self._shutdown_server()

    async def test_capabilities_allowed_versions(self):
        with pytest.raises(asyncio.TimeoutError):
            with pytest.raises(aioimaplib.Error) as expected:
                await self.login_user('user', 'pass', timeout=1)

            assert expected == 'server not IMAP4 compliant'


class TestAioimaplib(AioWithImapServer, asynctest.TestCase):
    def setUp(self):
        self._init_server(self.loop)

    async def tearDown(self):
        await self._shutdown_server()

    async def test_capabilities(self):
        imap_client = aioimaplib.IMAP4(port=12345, loop=self.loop)
        await asyncio.wait_for(imap_client.wait_hello_from_server(), 2)

        assert 'IMAP4REV1' == imap_client.protocol.imap_version
        assert {'IMAP4rev1', 'YESAUTH'} == imap_client.protocol.capabilities
        assert imap_client.has_capability('YESAUTH')

    async def test_login(self):
        imap_client = aioimaplib.IMAP4(port=12345, loop=self.loop, timeout=3)
        await asyncio.wait_for(imap_client.wait_hello_from_server(), 2)

        result, data = await imap_client.login('user', 'password')

        assert aioimaplib.AUTH == imap_client.protocol.state
        assert 'OK' == result
        assert b'LOGIN completed' == data[-1]
        assert imap_client.has_capability('IDLE')
        assert imap_client.has_capability('UIDPLUS')

    async def test_xoauth2(self):
        imap_client = aioimaplib.IMAP4(port=12345, loop=self.loop, timeout=3)
        await asyncio.wait_for(imap_client.wait_hello_from_server(), 2)

        result, data = await imap_client.xoauth2('user', 'myspecialtoken')

        self.assertEquals(aioimaplib.AUTH, imap_client.protocol.state)
        self.assertEqual('OK', result)
        self.assertEqual(b'AUTHENTICATE completed', data[-1])

    async def test_login_with_special_characters(self):
        imap_client = aioimaplib.IMAP4(port=12345, loop=self.loop, timeout=3)
        await asyncio.wait_for(imap_client.wait_hello_from_server(), 2)

        result, data = await imap_client.login('user', 'pass"word')

        assert aioimaplib.AUTH == imap_client.protocol.state
        assert 'OK' == result
        assert b'LOGIN completed' == data[-1]

    async def test_login_twice(self):
        with pytest.raises(aioimaplib.Error) as expected:
            imap_client = await self.login_user('user', 'pass')

            await imap_client.login('user', 'password')

            assert expected == 'command LOGIN illegal in state AUTH'

    async def test_logout(self):
        imap_client = await self.login_user('user', 'pass')

        result, data = await imap_client.logout()

        assert 'OK' == result
        assert [b'BYE Logging out', b'LOGOUT completed'] == data
        assert aioimaplib.LOGOUT == imap_client.protocol.state

    async def test_select_no_messages(self):
        imap_client = await self.login_user('user', 'pass')

        resp = await imap_client.select()

        assert 'OK' == resp[0]
        assert 0 == extract_exists(resp)
        assert aioimaplib.SELECTED == imap_client.protocol.state

    async def test_examine_no_messages(self):
        imap_client = await self.login_user('user', 'pass')

        assert 0 == extract_exists((await imap_client.examine()))

        assert aioimaplib.AUTH == imap_client.protocol.state

    async def test_search_two_messages(self):
        self.imapserver.receive(Mail.create(['user']))
        self.imapserver.receive(Mail.create(['user']))
        imap_client = await self.login_user('user', 'pass', select=True)

        result, data = await imap_client.search('ALL')

        assert 'OK' == result
        assert b'1 2' == data[0]

    async def test_search_messages(self):
        """Increase compatibility with https://docs.python.org/3/library/imaplib.html#imap4-example."""
        self.imapserver.receive(Mail.create(['user']))
        self.imapserver.receive(Mail.create(['user']))
        imap_client = await self.login_user('user', 'pass', select=True)

        # E.g. typ, data = M.search(None, 'ALL')
        result, data = await imap_client.search(None, 'ALL')

        assert 'OK' == result
        assert b'1 2' == data[0]

    async def test_uid_with_illegal_command(self):
        imap_client = await self.login_user('user', 'pass', select=True)

        for command in {'COPY', 'FETCH', 'STORE', 'EXPUNGE', 'MOVE'}.symmetric_difference(Commands.keys()):
            with pytest.raises(aioimaplib.Abort) as expected:
                await imap_client.uid(command)

            assert ('command UID only possible with COPY, FETCH, EXPUNGE (w/UIDPLUS) or STORE (was %s)' % command) in str(expected)

    async def test_search_three_messages_by_uid(self):
        imap_client = await self.login_user('user', 'pass', select=True)
        self.imapserver.receive(Mail.create(['user']))  # id=1 uid=1
        self.imapserver.receive(Mail.create(['user']), mailbox='OTHER_MAILBOX')  # id=1 uid=1
        self.imapserver.receive(Mail.create(['user']))  # id=2 uid=2

        assert b'1 2' == (await imap_client.search('ALL')).lines[0]
        assert b'1 2' == (await imap_client.uid_search('ALL')).lines[0]

        await imap_client.select('OTHER_MAILBOX')
        assert b'1' == (await imap_client.uid_search('ALL')).lines[0]

    async def test_fetch(self):
        print('test loop %r' % self.loop)
        imap_client = await self.login_user('user', 'pass', select=True)
        mail = Mail.create(['user'], mail_from='me', subject='hello',
                           content='pleased to meet you, wont you guess my name ?')
        self.imapserver.receive(mail)

        result, data = await imap_client.fetch('1', '(RFC822)')
        content = mail.as_bytes()

        assert 'OK' == result
        assert [
            b'1 FETCH (RFC822 {%d}' % len(content), content, b')',
            b'FETCH completed.'
        ] == data

    async def test_fetch_by_uid_without_body(self):
        imap_client = await self.login_user('user', 'pass', select=True)
        mail = Mail.create(['user'], mail_from='me', subject='hello',
                           content='pleased to meet you, wont you guess my name ?')
        self.imapserver.receive(mail)

        response = (await imap_client.uid('fetch', '1', '(UID FLAGS)'))

        assert 'OK' == response.result
        assert b'1 FETCH (UID 1 FLAGS ())' == response.lines[0]

    async def test_fetch_by_uid(self):
        imap_client = await self.login_user('user', 'pass', select=True)
        mail = Mail.create(['user'], mail_from='me', subject='hello',
                           content='pleased to meet you, wont you guess my name ?')
        self.imapserver.receive(mail)

        response = (await imap_client.uid('fetch', '1', '(RFC822)'))
        assert 'OK' == response.result
        assert mail.as_bytes() == response.lines[1]

    async def test_idle(self):
        imap_client = await self.login_user('user', 'pass', select=True)

        idle = await imap_client.idle_start(timeout=0.3)
        self.imapserver.receive(Mail.create(to=['user'], mail_from='me', subject='hello'))

        assert [b'1 EXISTS', b'1 RECENT'] == (await imap_client.wait_server_push())

        imap_client.idle_done()
        assert ('OK', [b'IDLE terminated']) == (await asyncio.wait_for(idle, 1))

        assert imap_client._idle_waiter._cancelled
        with pytest.raises(asyncio.TimeoutError):
            await imap_client.wait_server_push(timeout=0.1)

    async def test_idle_loop(self):
        imap_client = await self.login_user('user', 'pass', select=True)

        idle = await imap_client.idle_start(timeout=0.3)
        self.imapserver.receive(Mail.create(to=['user'], mail_from='me', subject='hello'))

        data = list()
        while imap_client.has_pending_idle():
            data.append((await imap_client.wait_server_push()))
            if data[-1] == STOP_WAIT_SERVER_PUSH:
                imap_client.idle_done()
                await asyncio.wait_for(idle, 1)

        assert [[b'1 EXISTS', b'1 RECENT'], STOP_WAIT_SERVER_PUSH] == data

    async def test_idle_stop(self):
        imap_client = await self.login_user('user', 'pass', select=True)
        idle = await imap_client.idle_start()

        assert (await imap_client.stop_wait_server_push())

        assert STOP_WAIT_SERVER_PUSH == (await imap_client.wait_server_push())

        imap_client.idle_done()
        await asyncio.wait_for(idle, 1)

    async def test_idle_stop_does_nothing_if_no_pending_idle(self):
        imap_client = await self.login_user('user', 'pass', select=True)

        assert not (await imap_client.stop_wait_server_push())

    async def test_idle_error_response(self):
        imap_client = await self.login_user('user', 'pass', select=True)

        conn = self.imapserver.get_connection('user')
        def idle_error(tag, *args):
            conn.error(tag, "Error initiating IDLE")
        conn.idle = idle_error

        with pytest.raises(Abort):
            await imap_client.idle_start()

    async def test_store_and_search_by_keyword(self):
        self.imapserver.receive(Mail.create(['user']))
        self.imapserver.receive(Mail.create(['user']))
        imap_client = await self.login_user('user', 'pass', select=True)
        assert b'' == (await imap_client.uid_search('KEYWORD FOO', charset=None)).lines[0]

        assert 'OK' == (await imap_client.uid('store', '1', '+FLAGS (FOO)')).result

        assert b'1' == (await imap_client.uid_search('KEYWORD FOO', charset=None)).lines[0]
        assert b'2' == (await imap_client.uid_search('UNKEYWORD FOO', charset=None)).lines[0]

    async def test_expunge_messages(self):
        self.imapserver.receive(Mail.create(['user']))
        self.imapserver.receive(Mail.create(['user']))
        imap_client = await self.login_user('user', 'pass', select=True)

        assert ('OK', [b'1 EXPUNGE', b'2 EXPUNGE', b'EXPUNGE completed.']) == (await imap_client.expunge())

        assert 0 == extract_exists((await imap_client.select()))

    async def test_copy_messages(self):
        self.imapserver.receive(Mail.create(['user']))
        self.imapserver.receive(Mail.create(['user']))
        imap_client = await self.login_user('user', 'pass', select=True)

        result, _ = await imap_client.copy('1', '2', 'MAILBOX')
        assert 'OK' == result

        assert 2 == extract_exists((await imap_client.select('MAILBOX')))

    async def test_copy_messages_by_uid(self):
        self.imapserver.receive(Mail.create(['user']))
        imap_client = await self.login_user('user', 'pass', select=True)

        result, _ = await imap_client.uid('copy', '1', 'MAILBOX')
        assert 'OK' == result

        assert 1 == extract_exists((await imap_client.select('MAILBOX')))

    async def test_concurrency_1_executing_sync_commands_sequentially(self):
        imap_client = await self.login_user('user', 'pass')

        f1 = asyncio.ensure_future(imap_client.examine('INBOX'))
        f2 = asyncio.ensure_future(imap_client.examine('MAILBOX'))

        await asyncio.wait([f1, f2])
        assert f1.exception() is None
        assert f2.exception() is None

    async def test_concurrency_2_executing_same_async_commands_sequentially(self):
        self.imapserver.receive(Mail.create(['user']))
        imap_client = await self.login_user('user', 'pass', select=True)

        f1 = asyncio.ensure_future(imap_client.fetch('1', '(RFC822)'))
        f2 = asyncio.ensure_future(imap_client.fetch('1', '(RFC822)'))

        await asyncio.wait([f1, f2])
        assert f1.exception() is None
        assert f2.exception() is None

    async def test_concurrency_3_executing_async_commands_in_parallel(self):
        # cf valid example in https://tools.ietf.org/html/rfc3501#section-5.5
        self.imapserver.receive(Mail.create(['user']))
        imap_client = await self.login_user('user', 'pass', select=True)

        store = asyncio.ensure_future(imap_client.store('1', '+FLAGS (FOO)'))
        copy = asyncio.ensure_future(imap_client.copy('1', 'MBOX'))
        expunge = asyncio.ensure_future(imap_client.expunge())

        await asyncio.wait([store, copy, expunge])
        assert 0 == extract_exists((await imap_client.select()))
        assert 1 == extract_exists((await imap_client.select('MBOX')))
        assert b'1' == (await imap_client.search('KEYWORD FOO', charset=None)).lines[0]

    async def test_concurrency_4_sync_command_waits_for_async_commands_to_finish(self):
        self.imapserver.receive(Mail.create(['user']))
        imap_client = await self.login_user('user', 'pass', select=True)

        asyncio.ensure_future(imap_client.copy('1', 'MBOX'))
        asyncio.ensure_future(imap_client.expunge())
        examine = asyncio.ensure_future(imap_client.examine('MBOX'))

        assert 1 == extract_exists((await asyncio.wait_for(examine, 1)))

    async def test_noop(self):
        imap_client = await self.login_user('user', 'pass')
        assert ('OK', [b'NOOP completed.']) == (await imap_client.noop())

    async def test_noop_with_untagged_data(self):
        imap_client = await self.login_user('user', 'pass')
        self.imapserver.receive(Mail.create(['user']))

        assert ('OK', [b'1 EXISTS', b'1 RECENT', b'NOOP completed.']) == (await imap_client.noop())

    async def test_check(self):
        imap_client = await self.login_user('user', 'pass', select=True)
        assert ('OK', [b'CHECK completed.']) == (await imap_client.check())

    async def test_close(self):
        imap_client = await self.login_user('user', 'pass', select=True)
        assert imapserver.SELECTED == self.imapserver.get_connection('user').state

        assert ('OK', [b'CLOSE completed.']) == (await imap_client.close())

        assert imapserver.AUTH == self.imapserver.get_connection('user').state

    async def test_status(self):
        imap_client = await self.login_user('user', 'pass')

        assert b'INBOX (MESSAGES 0 UIDNEXT 1)' == \
                          (await imap_client.status('INBOX', '(MESSAGES UIDNEXT)')).lines[0]

    async def test_subscribe_unsubscribe_lsub(self):
        imap_client = await self.login_user('user', 'pass')

        assert ('OK', [b'SUBSCRIBE completed.']) == (await imap_client.subscribe('#fr.soc.feminisme'))
        assert ('OK', [b'() "." #fr.soc.feminisme', b'LSUB completed.']) == \
                          (await imap_client.lsub('#fr.', 'soc.*'))
        assert ('OK', [b'UNSUBSCRIBE completed.']) == (await imap_client.unsubscribe('#fr.soc.feminisme'))
        assert ('OK', [b'LSUB completed.']) == (await imap_client.lsub('#fr', '.*'))

    async def test_create_delete_mailbox(self):
        imap_client = await self.login_user('user', 'pass')
        assert 'NO' == (await imap_client.status('MBOX', '(MESSAGES)')).result

        assert ('OK', [b'CREATE completed.']) == (await imap_client.create('MBOX'))
        assert 'OK' == (await imap_client.status('MBOX', '(MESSAGES)')).result

        assert ('OK', [b'DELETE completed.']) == (await imap_client.delete('MBOX'))
        assert 'NO' == (await imap_client.status('MBOX', '(MESSAGES)')).result

    async def test_rename_mailbox(self):
        imap_client = await self.login_user('user', 'pass')
        assert 'NO' == (await imap_client.status('MBOX', '(MESSAGES)')).result

        assert ('OK', [b'RENAME completed.']) == (await imap_client.rename('INBOX', 'MBOX'))

        assert 'OK' == (await imap_client.status('MBOX', '(MESSAGES)')).result

    async def test_list(self):
        imap_client = await self.login_user('user', 'pass')
        assert ('OK', [b'() "/" Drafts', b'() "/" INBOX', b'() "/" Sent', b'() "/" Trash',
                                  b'LIST completed.']) == (await imap_client.list('""', '.*'))

        await imap_client.create('MYBOX')
        assert ('OK', [b'() "/" Drafts', b'() "/" INBOX', b'() "/" MYBOX', b'() "/" Sent', b'() "/" Trash',
                                  b'LIST completed.']) == \
                          (await imap_client.list('""', '.*'))

    async def test_get_quotaroot(self):
        imap_client = await self.login_user('user', 'pass')
        self.imapserver.receive(Mail.create(['user']))

        response = await imap_client.getquotaroot('INBOX')

        assert response.lines == [b'INBOX (STORAGE 294 5000)', b'GETQUOTAROOT completed.']

    async def test_append(self):
        imap_client = await self.login_user('user@mail', 'pass')
        assert 0 == extract_exists((await imap_client.examine('INBOX')))

        msg = Mail.create(['user@mail'], subject='append msg', content='do you see me ?')
        response = await imap_client.append(msg.as_bytes(), mailbox='INBOX', flags='FOO BAR',
                                                 date=datetime.now(tz=utc), )
        assert 'OK' == response.result
        assert b'1] APPEND completed' in response.lines[0]

        assert 1 == extract_exists((await imap_client.examine('INBOX')))

    async def test_rfc5032_within(self):
        self.imapserver.receive(Mail.create(['user'], date=datetime.now(tz=utc) - timedelta(seconds=84600 * 3)))  # 1
        self.imapserver.receive(Mail.create(['user'], date=datetime.now(tz=utc) - timedelta(seconds=84600)))  # 2
        self.imapserver.receive(Mail.create(['user']))  # 3
        imap_client = await self.login_user('user', 'pass', select=True)

        assert b'1' == (await imap_client.search('OLDER', '84700')).lines[0]
        assert b'2 3' == (await imap_client.search('YOUNGER', '84700')).lines[0]

    async def test_rfc4315_uidplus_expunge(self):
        self.imapserver.receive(Mail.create(['user']))
        self.imapserver.receive(Mail.create(['user']))
        imap_client = await self.login_user('user', 'pass', select=True)

        assert ('OK', [b'1 EXPUNGE', b'UID EXPUNGE completed.']) == (await imap_client.uid('expunge', '1:1'))

        assert 1 == extract_exists((await imap_client.select()))

    async def test_rfc6851_move(self):
        self.imapserver.receive(Mail.create(['user']))
        imap_client = await self.login_user('user', 'pass', select=True)
        uidvalidity = self.imapserver.get_connection('user').uidvalidity

        assert ('OK', [b'OK [COPYUID %d 1:1 1:1]' % uidvalidity, b'1 EXPUNGE', b'Done']) == \
                         (await imap_client.move('1:1', 'Trash'))

        assert 0 == extract_exists((await imap_client.select()))
        assert 1 == extract_exists((await imap_client.select('Trash')))

    async def test_rfc6851_uidmove(self):
        self.imapserver.receive(Mail.create(['user']))
        imap_client = await self.login_user('user', 'pass', select=True)
        uidvalidity = self.imapserver.get_connection('user').uidvalidity

        assert ('OK', [b'OK [COPYUID %d 1:1 1:1]' % uidvalidity, b'1 EXPUNGE', b'Done']) == \
                         (await imap_client.uid('move', '1:1', 'Trash'))

        assert 0 == extract_exists((await imap_client.select()))
        assert 1 == extract_exists((await imap_client.select('Trash')))

    async def test_rfc5161_enable(self):
        imap_client = await self.login_user('user', 'pass')

        assert ('OK', [b'X-GOOD-IDEA CONDSTORE enabled']) == \
                         (await imap_client.enable('X-GOOD-IDEA CONDSTORE'))

    async def test_rfc2342_namespace(self):
        imap_client = await self.login_user('user', 'pass')
        response = await imap_client.namespace()

        assert ('OK', [b'(("" "/")) NIL NIL', b'NAMESPACE command completed']) == response

    async def test_rfc2971_id(self):
        imap_client = await self.login_user('user', 'pass')
        response = await imap_client.id()
        assert ('OK', [b'ID command completed']) == response

    async def test_race_idle_done_and_server_push(self):
        imap_client = await self.login_user('user', 'pass', select=True)

        idle = await imap_client.idle_start(2)
        imap_client.idle_done()
        self.imapserver.receive(Mail.create(['user']))
        await asyncio.wait_for(idle, 1)

        idle = await imap_client.idle_start(2)
        imap_client.idle_done()
        await asyncio.wait_for(idle, 1)

        r = await imap_client.wait_server_push()
        assert [b'1 EXISTS', b'1 RECENT'] == r
        assert imap_client.protocol.idle_queue.empty()


class TestImapServerCapabilities(AioWithImapServer, asynctest.TestCase):
    def setUp(self):
        self._init_server(self.loop, capabilities='')

    async def tearDown(self):
        await self._shutdown_server()

    async def test_idle_messages_without_idle_capability_abort_command(self):
        imap_client = await self.login_user('user', 'pass', select=True)
        with pytest.raises(Abort):
            await imap_client.idle()

    async def test_expunge_messages_without_uidplus_capability_abort_command(self):
        imap_client = await self.login_user('user', 'pass', select=True)
        with pytest.raises(Abort):
            await imap_client.uid('expunge', '1:1')

    async def test_move_without_move_capability_abort_command(self):
        imap_client = await self.login_user('user', 'pass', select=True)
        with pytest.raises(Abort):
            await imap_client.move('1:1', 'Trash')

    async def test_uidmove_without_move_capability_abort_command(self):
        imap_client = await self.login_user('user', 'pass', select=True)
        with pytest.raises(Abort):
            await imap_client.uid('move', '1:1', 'Trash')

    async def test_enable_without_enable_capability_abort_command(self):
        imap_client = await self.login_user('user', 'pass')
        with pytest.raises(Abort):
            await imap_client.enable('CAPABILITY')

    async def test_namespace_without_namespace_capability_abort_command(self):
        imap_client = await self.login_user('user', 'pass')
        with pytest.raises(Abort):
            await imap_client.namespace()


class TestAioimaplibClocked(AioWithImapServer, asynctest.ClockedTestCase):

    def setUp(self):
        self._init_server(self.loop)

    async def tearDown(self):
        await self._shutdown_server()

    async def test_when_async_commands_timeout__they_should_be_removed_from_protocol_state(self):
        imap_client = await self.login_user('user', 'pass', select=True)
        await (imap_client.protocol.execute(Command(
            'DELAY', imap_client.protocol.new_tag(), '3', loop=self.loop)))

        noop_task = asyncio.ensure_future(imap_client.protocol.execute(
            Command('NOOP', imap_client.protocol.new_tag(), '', loop=self.loop, timeout=2)))
        await self.advance(1)
        assert 1 == len(imap_client.protocol.pending_async_commands)
        await self.advance(1.1)

        finished, pending = await asyncio.wait([noop_task])
        assert noop_task in finished
        assert isinstance(noop_task.exception(), CommandTimeout)
        assert 0 == len(imap_client.protocol.pending_async_commands)

    async def test_when_sync_commands_timeout__they_should_be_removed_from_protocol_state(self):
        imap_client = await self.login_user('user', 'pass')
        await (imap_client.protocol.execute(Command(
            'DELAY', imap_client.protocol.new_tag(), '3', loop=self.loop)))

        delay_task = asyncio.ensure_future(imap_client.protocol.execute(
            Command('DELAY', imap_client.protocol.new_tag(), '0', loop=self.loop, timeout=2)))
        await self.advance(1)
        assert imap_client.protocol.pending_sync_command is not None
        await self.advance(1.1)

        finished, pending = await asyncio.wait([delay_task])
        assert delay_task in finished
        assert isinstance(delay_task.exception(), CommandTimeout)
        assert imap_client.protocol.pending_sync_command is None

    async def test_idle_start__exits_queueget_without_timeout_error(self):
        imap_client = await self.login_user('user', 'pass', select=True)

        idle_timeout = 5
        await imap_client.idle_start(idle_timeout)

        push_task = asyncio.ensure_future(imap_client.wait_server_push(idle_timeout + 2))
        await self.advance(idle_timeout + 1)

        r = await asyncio.wait_for(push_task, 0)
        assert STOP_WAIT_SERVER_PUSH == r

    async def test_idle_start__exits_queueget_with_keepalive_without_timeout_error(self):
        imap_client = await self.login_user('user', 'pass', select=True)

        # Idle long enough for the server to issue a keep-alive
        server_idle_timeout = imapserver.ImapProtocol.IDLE_STILL_HERE_PERIOD_SECONDS
        idle_timeout = server_idle_timeout + 1
        idle = await imap_client.idle_start(idle_timeout)

        push_task = asyncio.ensure_future(imap_client.wait_server_push(server_idle_timeout - 1))

        # Advance time until we've received a keep-alive from server
        await self.advance(server_idle_timeout)

        # The original push task timed out
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(push_task, 0.1)

        # Read the keepalive from the server
        r = await imap_client.wait_server_push(0.1)
        assert [b'OK Still here'] == r

        # Advance the clock to the client timeout (idle waiter triggers)
        await self.advance(1)
        imap_client.idle_done()

        r = await asyncio.wait_for(idle, 1)
        assert "OK" == r.result

        assert not imap_client.protocol._idle_event.is_set()

        # Start another idle period
        idle = await imap_client.idle_start(idle_timeout)
        await self.advance(1)

        # Read 'stop_wait_server_push'
        push_task = asyncio.ensure_future(imap_client.wait_server_push(0.1))
        await self.advance(1)
        r = await asyncio.wait_for(push_task, None)
        assert STOP_WAIT_SERVER_PUSH == r

        # There shouldn't be anything left in the queue (no '+ idling')
        with pytest.raises(asyncio.TimeoutError):
            push_task = asyncio.ensure_future(imap_client.wait_server_push(0.1))
            await self.advance(1)
            await asyncio.wait_for(push_task, 0.1)

        imap_client.idle_done()
        await asyncio.wait_for(idle, 1)


class TestAioimaplibCallback(AioWithImapServer, asynctest.TestCase):
    def setUp(self):
        self._init_server(self.loop)

    async def test_callback_is_called_when_connection_is_lost(self):
        queue = asyncio.Queue()
        imap_client = aioimaplib.IMAP4(port=12345, loop=self.loop, timeout=3, conn_lost_cb=(
            lambda m: queue.put_nowait('called with %s' % m)))
        await asyncio.wait_for(imap_client.wait_hello_from_server(), 2)
        await imap_client.login('login', 'password')

        await self._shutdown_server()

        assert 'called with None' == (await asyncio.wait_for(queue.get(), timeout=2))


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

    async def tearDown(self):
        await self._shutdown_server()
        os.remove(self._cert_file)
        os.remove(self._cert_key)

    async def test_client_can_connect_to_server_over_ssl(self):
        ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self._cert_file)
        imap_client = aioimaplib.IMAP4_SSL(port=12345, loop=self.loop, ssl_context=ssl_context)
        await asyncio.wait_for(imap_client.wait_hello_from_server(), 2)

        assert 'IMAP4REV1' == imap_client.protocol.imap_version
        assert {'IMAP4rev1', 'YESAUTH'} == imap_client.protocol.capabilities
        assert imap_client.has_capability('YESAUTH')
