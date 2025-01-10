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
import ssl
import unittest
from datetime import datetime, timedelta

import pytest
from mock import call, MagicMock
from pytz import utc

from aioimaplib import aioimaplib, extract_exists, STOP_WAIT_SERVER_PUSH, FetchCommand, IdleCommand
from aioimaplib.aioimaplib import Commands, IMAP4ClientProtocol, Command, Abort
from aioimaplib.tests import imapserver
from aioimaplib.tests.imapserver import Mail
from aioimaplib.tests.server_fixture import with_ssl_server, with_ssl, with_server, login_user_async, create_server

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

    def test_incomplete_line_with_literal_fetch(self):
        cmd = Command('FETCH', 'TAG')
        self.imap_protocol._handle_line = MagicMock(return_value=cmd)
        self.imap_protocol.data_received(b'* 12 FETCH (BODY[HEADER] {4}\r\nyo\r\n)\r\n* 13 FETCH (BODY[')
        self.imap_protocol.data_received(b'HEADER] {5}\r\nyo2\r\n)\r\nTAG OK STORE completed.\r\n')

        self.imap_protocol._handle_line.assert_has_calls([call(b'* 12 FETCH (BODY[HEADER] {4}', None), call(b')', cmd)])
        self.imap_protocol._handle_line.assert_has_calls([call(b'* 13 FETCH (BODY[HEADER] {5}', None),
                                                         call(b')', cmd),
                                                         call(b'TAG OK STORE completed.', None)])
        assert [b'yo\r\n', b'yo2\r\n'] == cmd.response.lines

    def test_incomplete_lines_during_literal(self):
        cmd = Command('LIST', 'TAG')
        self.imap_protocol._handle_line = MagicMock(return_value=cmd)

        self.imap_protocol.data_received(b'* LIST () "/" {11}\r\nfoo/')
        self.imap_protocol.data_received(b'bar/')
        self.imap_protocol.data_received(b'baz\r\n* LIST () "/" qux\r\nTAG OK LIST completed\r\n')

        self.imap_protocol._handle_line.assert_has_calls([call(b'* LIST () "/" {11}', None)])
        self.imap_protocol._handle_line.assert_has_calls([call(b'* LIST () "/" qux', None),
                                                          call(b'TAG OK LIST completed', None)])
        assert [b'foo/bar/baz'] == cmd.response.lines

    def test_incomplete_line_during_literal_no_cmd_found(self):
        self.imap_protocol.data_received(b'* LIST () "/" {7}\r\nfoo/')
        self.imap_protocol.data_received(b'bar\r\nTAG OK LIST completed\r\n')

        self.imap_protocol._handle_line.assert_has_calls([call(b'* LIST () "/" {7}', None)])
        self.imap_protocol._handle_line.assert_has_calls([call(b'* LIST () "/" {7}', None),
                                                          call(b'', Command('NIL', 'unused')),
                                                          call(b'TAG OK LIST completed', None)])

    def test_line_with_literal_no_cmd_found_no_AttributeError_thrown(self):
        self.imap_protocol.data_received(b'* 3 FETCH (UID 12 RFC822 {4}\r\nmail)\r\n'
                                         b'TAG OK FETCH completed.\r\n')
        self.imap_protocol._handle_line.assert_has_calls([call(b'* 3 FETCH (UID 12 RFC822 {4}', None),
                                            call(b')', Command('NIL', 'unused')),
                                            call(b'TAG OK FETCH completed.', None)])

    def test_line_with_attachment_literals(self):
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

    def test_incomplete_line_followed_by_incomplete_literal(self):
        cmd = Command('FETCH', 'TAG')
        self.imap_protocol._handle_line = MagicMock(return_value=cmd)

        self.imap_protocol.data_received(b'* 2 FETCH (')
        self.imap_protocol.data_received(b'FLAGS () UID 160016 BODY[] {10}\r\non the ')
        self.imap_protocol.data_received(b'dot)\r\nTAG OK FETCH completed\r\n')

        self.imap_protocol._handle_line.assert_has_calls([call(b'* 2 FETCH (FLAGS () UID 160016 BODY[] {10}', None),
                                            call(b')', cmd), call(b'TAG OK FETCH completed', None)])
        assert [b'on the dot'] == cmd.response.lines

    # cf 1st FETCH in https://tools.ietf.org/html/rfc3501#section-8 example
    def test_incomplete_fetch_message_attributes_without_literal(self):
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

    def test_incomplete_fetch_with_incomplete_line(self):
        cmd = FetchCommand('TAG')
        self.imap_protocol._handle_line = MagicMock(return_value=cmd)

        self.imap_protocol.data_received(b'* 21 FETCH (FLAGS (\Seen) BODY[] {16}\r\nincomplete fetch')
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
        aioimaplib.get_running_loop = asyncio.new_event_loop  # monkey patch to avoid Exception "No running loop"

    def test_when_idle_continuation_line_in_same_dataframe_as_status_update(self):
        queue = asyncio.Queue()
        cmd = IdleCommand('TAG', queue)
        self.imap_protocol.pending_sync_command = cmd
        self.imap_protocol.data_received(b'+ idling\r\n* 1 EXISTS\r\n* 1 RECENT\r\n')

        assert self.imap_protocol._idle_event.is_set()
        assert [b'1 EXISTS', b'1 RECENT'] == queue.get_nowait()


class TestFetchWaitsForAllMessageAttributes(unittest.TestCase):
    def setUp(self):
        aioimaplib.get_running_loop = asyncio.new_event_loop  # monkey patch to avoid Exception "No running loop"

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

    def test_fetch_with_literal(self):
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


@pytest.mark.asyncio()
async def test_login(with_server):
    imap_client = aioimaplib.IMAP4(port=12345, loop=asyncio.get_running_loop(), timeout=3)
    await asyncio.wait_for(imap_client.wait_hello_from_server(), 2)

    result, data = await imap_client.login('user', 'password')

    assert aioimaplib.AUTH == imap_client.protocol.state
    assert 'OK' == result
    assert b'LOGIN completed' == data[-1]
    assert imap_client.has_capability('IDLE')
    assert imap_client.has_capability('UIDPLUS')


@pytest.mark.asyncio()
async def test_xoauth2(with_server):
    imap_client = aioimaplib.IMAP4(port=12345, loop=asyncio.get_running_loop(), timeout=3)
    await asyncio.wait_for(imap_client.wait_hello_from_server(), 2)

    result, data = await imap_client.xoauth2('user', 'myspecialtoken')

    assert aioimaplib.AUTH == imap_client.protocol.state
    assert 'OK' == result
    assert b'AUTHENTICATE completed' == data[-1]


@pytest.mark.asyncio()
async def test_login_with_special_characters(with_server):
    imap_client = aioimaplib.IMAP4(port=12345, loop=asyncio.get_running_loop(), timeout=3)
    await asyncio.wait_for(imap_client.wait_hello_from_server(), 2)

    result, data = await imap_client.login('user', 'pass"word')

    assert aioimaplib.AUTH == imap_client.protocol.state
    assert 'OK' == result
    assert b'LOGIN completed' == data[-1]


@pytest.mark.asyncio()
async def test_login_twice(with_server):
    with pytest.raises(aioimaplib.Error) as expected:
        imap_client = await login_user_async('user', 'pass')

        await imap_client.login('user', 'password')

        assert expected == 'command LOGIN illegal in state AUTH'


@pytest.mark.asyncio()
async def test_logout(with_server):
    imap_client = await login_user_async('user', 'pass')

    result, data = await imap_client.logout()

    assert 'OK' == result
    assert [b'BYE Logging out', b'LOGOUT completed'] == data
    assert aioimaplib.LOGOUT == imap_client.protocol.state


@pytest.mark.asyncio()
async def test_select_no_messages(with_server):
    imap_client = await login_user_async('user', 'pass')

    resp = await imap_client.select()

    assert 'OK' == resp[0]
    assert 0 == extract_exists(resp)
    assert aioimaplib.SELECTED == imap_client.protocol.state


@pytest.mark.asyncio()
async def test_examine_no_messages(with_server):
    imap_client = await login_user_async('user', 'pass')

    assert 0 == extract_exists((await imap_client.examine()))

    assert aioimaplib.AUTH == imap_client.protocol.state


@pytest.mark.asyncio()
async def test_search_two_messages(with_server):
    with_server.receive(Mail.create(['user']))
    with_server.receive(Mail.create(['user']))
    imap_client = await login_user_async('user', 'pass', select=True)

    result, data = await imap_client.search('ALL')

    assert 'OK' == result
    assert b'1 2' == data[0]


@pytest.mark.asyncio()
async def test_search_messages(with_server):
    """Increase compatibility with https://docs.python.org/3/library/imaplib.html#imap4-example."""
    with_server.receive(Mail.create(['user']))
    with_server.receive(Mail.create(['user']))
    imap_client = await login_user_async('user', 'pass', select=True)

    # E.g. typ, data = M.search(None, 'ALL')
    result, data = await imap_client.search(None, 'ALL')

    assert 'OK' == result
    assert b'1 2' == data[0]


@pytest.mark.asyncio()
async def test_uid_with_illegal_command(with_server):
    imap_client = await login_user_async('user', 'pass', select=True)

    for command in {'COPY', 'FETCH', 'STORE', 'EXPUNGE', 'MOVE'}.symmetric_difference(Commands.keys()):
        with pytest.raises(aioimaplib.Abort) as expected:
            await imap_client.uid(command)

        assert ('command UID only possible with COPY, FETCH, EXPUNGE (w/UIDPLUS) or STORE (was %s)' % command) in str(expected)


@pytest.mark.asyncio()
async def test_search_three_messages_by_uid(with_server):
    imap_client = await login_user_async('user', 'pass', select=True)
    with_server.receive(Mail.create(['user']))  # id=1 uid=1
    with_server.receive(Mail.create(['user']), mailbox='OTHER_MAILBOX')  # id=1 uid=1
    with_server.receive(Mail.create(['user']))  # id=2 uid=2

    assert b'1 2' == (await imap_client.search('ALL')).lines[0]
    assert b'1 2' == (await imap_client.uid_search('ALL')).lines[0]

    await imap_client.select('OTHER_MAILBOX')
    assert b'1' == (await imap_client.uid_search('ALL')).lines[0]


@pytest.mark.asyncio()
async def test_fetch(with_server):
    imap_client = await login_user_async('user', 'pass', select=True)
    mail = Mail.create(['user'], mail_from='me', subject='hello',
                       content='pleased to meet you, wont you guess my name ?')
    with_server.receive(mail)

    result, data = await imap_client.fetch('1', '(RFC822)')
    content = mail.as_bytes()

    assert 'OK' == result
    assert [
        b'1 FETCH (RFC822 {%d}' % len(content), content, b')',
        b'FETCH completed.'
    ] == data


@pytest.mark.asyncio()
async def test_fetch_by_uid_without_body(with_server):
    imap_client = await login_user_async('user', 'pass', select=True)
    mail = Mail.create(['user'], mail_from='me', subject='hello',
                       content='pleased to meet you, wont you guess my name ?')
    with_server.receive(mail)

    response = (await imap_client.uid('fetch', '1', '(UID FLAGS)'))

    assert 'OK' == response.result
    assert b'1 FETCH (UID 1 FLAGS ())' == response.lines[0]


@pytest.mark.asyncio()
async def test_fetch_by_uid(with_server):
    imap_client = await login_user_async('user', 'pass', select=True)
    mail = Mail.create(['user'], mail_from='me', subject='hello',
                       content='pleased to meet you, wont you guess my name ?')
    with_server.receive(mail)

    response = (await imap_client.uid('fetch', '1', '(RFC822)'))
    assert 'OK' == response.result
    assert mail.as_bytes() == response.lines[1]


@pytest.mark.asyncio()
async def test_idle(with_server):
    imap_client = await login_user_async('user', 'pass', select=True)

    idle = await imap_client.idle_start(timeout=0.3)
    with_server.receive(Mail.create(to=['user'], mail_from='me', subject='hello'))

    assert [b'1 EXISTS', b'1 RECENT'] == (await imap_client.wait_server_push())

    imap_client.idle_done()
    assert ('OK', [b'IDLE terminated']) == (await asyncio.wait_for(idle, 1))

    assert imap_client._idle_waiter._cancelled
    with pytest.raises(asyncio.TimeoutError):
        await imap_client.wait_server_push(timeout=0.1)


@pytest.mark.asyncio()
async def test_idle_loop(with_server):
    imap_client = await login_user_async('user', 'pass', select=True)

    idle = await imap_client.idle_start(timeout=0.3)
    with_server.receive(Mail.create(to=['user'], mail_from='me', subject='hello'))

    data = list()
    while imap_client.has_pending_idle():
        data.append((await imap_client.wait_server_push()))
        if data[-1] == STOP_WAIT_SERVER_PUSH:
            imap_client.idle_done()
            await asyncio.wait_for(idle, 1)

    assert [[b'1 EXISTS', b'1 RECENT'], STOP_WAIT_SERVER_PUSH] == data


@pytest.mark.asyncio()
async def test_idle_stop(with_server):
    imap_client = await login_user_async('user', 'pass', select=True)
    idle = await imap_client.idle_start()

    assert (await imap_client.stop_wait_server_push())

    assert STOP_WAIT_SERVER_PUSH == (await imap_client.wait_server_push())

    imap_client.idle_done()
    await asyncio.wait_for(idle, 1)


@pytest.mark.asyncio()
async def test_idle_stop_does_nothing_if_no_pending_idle(with_server):
    imap_client = await login_user_async('user', 'pass', select=True)

    assert not (await imap_client.stop_wait_server_push())


@pytest.mark.asyncio()
async def test_idle_error_response(with_server):
    imap_client = await login_user_async('user', 'pass', select=True)

    conn = with_server.get_connection('user')
    def idle_error(tag, *args):
        conn.error(tag, "Error initiating IDLE")
    conn.idle = idle_error

    with pytest.raises(Abort):
        await imap_client.idle_start()


@pytest.mark.asyncio()
async def test_store_and_search_by_keyword(with_server):
    with_server.receive(Mail.create(['user']))
    with_server.receive(Mail.create(['user']))
    imap_client = await login_user_async('user', 'pass', select=True)
    assert b'' == (await imap_client.uid_search('KEYWORD FOO', charset=None)).lines[0]

    assert 'OK' == (await imap_client.uid('store', '1', '+FLAGS (FOO)')).result

    assert b'1' == (await imap_client.uid_search('KEYWORD FOO', charset=None)).lines[0]
    assert b'2' == (await imap_client.uid_search('UNKEYWORD FOO', charset=None)).lines[0]


@pytest.mark.asyncio()
async def test_expunge_messages(with_server):
    with_server.receive(Mail.create(['user']))
    with_server.receive(Mail.create(['user']))
    imap_client = await login_user_async('user', 'pass', select=True)

    assert ('OK', [b'1 EXPUNGE', b'2 EXPUNGE', b'EXPUNGE completed.']) == (await imap_client.expunge())

    assert 0 == extract_exists((await imap_client.select()))


@pytest.mark.asyncio()
async def test_copy_messages(with_server):
    with_server.receive(Mail.create(['user']))
    with_server.receive(Mail.create(['user']))
    imap_client = await login_user_async('user', 'pass', select=True)

    result, _ = await imap_client.copy('1', '2', 'MAILBOX')
    assert 'OK' == result

    assert 2 == extract_exists((await imap_client.select('MAILBOX')))


@pytest.mark.asyncio()
async def test_copy_messages_by_uid(with_server):
    with_server.receive(Mail.create(['user']))
    imap_client = await login_user_async('user', 'pass', select=True)

    result, _ = await imap_client.uid('copy', '1', 'MAILBOX')
    assert 'OK' == result

    assert 1 == extract_exists((await imap_client.select('MAILBOX')))


@pytest.mark.asyncio()
async def test_concurrency_1_executing_sync_commands_sequentially(with_server):
    imap_client = await login_user_async('user', 'pass')

    f1 = asyncio.ensure_future(imap_client.examine('INBOX'))
    f2 = asyncio.ensure_future(imap_client.examine('MAILBOX'))

    await asyncio.wait([f1, f2])
    assert f1.exception() is None
    assert f2.exception() is None


@pytest.mark.asyncio()
async def test_concurrency_2_executing_same_async_commands_sequentially(with_server):
    with_server.receive(Mail.create(['user']))
    imap_client = await login_user_async('user', 'pass', select=True)

    f1 = asyncio.ensure_future(imap_client.fetch('1', '(RFC822)'))
    f2 = asyncio.ensure_future(imap_client.fetch('1', '(RFC822)'))

    await asyncio.wait([f1, f2])
    assert f1.exception() is None
    assert f2.exception() is None


@pytest.mark.asyncio()
async def test_concurrency_3_executing_async_commands_in_parallel(with_server):
    # cf valid example in https://tools.ietf.org/html/rfc3501#section-5.5
    with_server.receive(Mail.create(['user']))
    imap_client = await login_user_async('user', 'pass', select=True)

    store = asyncio.ensure_future(imap_client.store('1', '+FLAGS (FOO)'))
    copy = asyncio.ensure_future(imap_client.copy('1', 'MBOX'))
    expunge = asyncio.ensure_future(imap_client.expunge())

    await asyncio.wait([store, copy, expunge])
    assert 0 == extract_exists((await imap_client.select()))
    assert 1 == extract_exists((await imap_client.select('MBOX')))
    assert b'1' == (await imap_client.search('KEYWORD FOO', charset=None)).lines[0]


@pytest.mark.asyncio()
async def test_concurrency_4_sync_command_waits_for_async_commands_to_finish(with_server):
    with_server.receive(Mail.create(['user']))
    imap_client = await login_user_async('user', 'pass', select=True)

    asyncio.ensure_future(imap_client.copy('1', 'MBOX'))
    asyncio.ensure_future(imap_client.expunge())
    examine = asyncio.ensure_future(imap_client.examine('MBOX'))

    assert 1 == extract_exists((await asyncio.wait_for(examine, 1)))


@pytest.mark.asyncio()
async def test_noop(with_server):
    imap_client = await login_user_async('user', 'pass')
    assert ('OK', [b'NOOP completed.']) == (await imap_client.noop())


@pytest.mark.asyncio()
async def test_noop_with_untagged_data(with_server):
    imap_client = await login_user_async('user', 'pass')
    with_server.receive(Mail.create(['user']))

    assert ('OK', [b'1 EXISTS', b'1 RECENT', b'NOOP completed.']) == (await imap_client.noop())


@pytest.mark.asyncio()
async def test_check(with_server):
    imap_client = await login_user_async('user', 'pass', select=True)
    assert ('OK', [b'CHECK completed.']) == (await imap_client.check())


@pytest.mark.asyncio()
async def test_close(with_server):
    imap_client = await login_user_async('user', 'pass', select=True)
    assert imapserver.SELECTED == with_server.get_connection('user').state

    assert ('OK', [b'CLOSE completed.']) == (await imap_client.close())

    assert imapserver.AUTH == with_server.get_connection('user').state


@pytest.mark.asyncio()
async def test_status(with_server):
    imap_client = await login_user_async('user', 'pass')

    assert b'INBOX (MESSAGES 0 UIDNEXT 1)' == \
                      (await imap_client.status('INBOX', '(MESSAGES UIDNEXT)')).lines[0]


@pytest.mark.asyncio()
async def test_subscribe_unsubscribe_lsub(with_server):
    imap_client = await login_user_async('user', 'pass')

    assert ('OK', [b'SUBSCRIBE completed.']) == (await imap_client.subscribe('#fr.soc.feminisme'))
    assert ('OK', [b'() "." #fr.soc.feminisme', b'LSUB completed.']) == \
                      (await imap_client.lsub('#fr.', 'soc.*'))
    assert ('OK', [b'UNSUBSCRIBE completed.']) == (await imap_client.unsubscribe('#fr.soc.feminisme'))
    assert ('OK', [b'LSUB completed.']) == (await imap_client.lsub('#fr', '.*'))


@pytest.mark.asyncio()
async def test_create_delete_mailbox(with_server):
    imap_client = await login_user_async('user', 'pass')
    assert 'NO' == (await imap_client.status('MBOX', '(MESSAGES)')).result

    assert ('OK', [b'CREATE completed.']) == (await imap_client.create('MBOX'))
    assert 'OK' == (await imap_client.status('MBOX', '(MESSAGES)')).result

    assert ('OK', [b'DELETE completed.']) == (await imap_client.delete('MBOX'))
    assert 'NO' == (await imap_client.status('MBOX', '(MESSAGES)')).result


@pytest.mark.asyncio()
async def test_rename_mailbox(with_server):
    imap_client = await login_user_async('user', 'pass')
    assert 'NO' == (await imap_client.status('MBOX', '(MESSAGES)')).result

    assert ('OK', [b'RENAME completed.']) == (await imap_client.rename('INBOX', 'MBOX'))

    assert 'OK' == (await imap_client.status('MBOX', '(MESSAGES)')).result


@pytest.mark.asyncio()
async def test_list(with_server):
    imap_client = await login_user_async('user', 'pass')
    assert ('OK', [b'() "/" Drafts', b'() "/" INBOX', b'() "/" Sent', b'() "/" Trash',
                              b'LIST completed.']) == (await imap_client.list('""', '.*'))

    await imap_client.create('MYBOX')
    assert ('OK', [b'() "/" Drafts', b'() "/" INBOX', b'() "/" MYBOX', b'() "/" Sent', b'() "/" Trash',
                              b'LIST completed.']) == \
                      (await imap_client.list('""', '.*'))


@pytest.mark.asyncio()
async def test_get_quotaroot(with_server):
    imap_client = await login_user_async('user', 'pass')
    with_server.receive(Mail.create(['user']))

    response = await imap_client.getquotaroot('INBOX')

    assert response.lines == [b'INBOX (STORAGE 292 5000)', b'GETQUOTAROOT completed.']


@pytest.mark.asyncio()
async def test_append(with_server):
    imap_client = await login_user_async('user@mail', 'pass')
    assert 0 == extract_exists((await imap_client.examine('INBOX')))

    msg = Mail.create(['user@mail'], subject='append msg', content='do you see me ?')
    response = await imap_client.append(msg.as_bytes(), mailbox='INBOX', flags='FOO BAR',
                                             date=datetime.now(tz=utc), )
    assert 'OK' == response.result
    assert b'1] APPEND completed' in response.lines[0]

    assert 1 == extract_exists((await imap_client.examine('INBOX')))


@pytest.mark.asyncio()
async def test_rfc5032_within(with_server):
    with_server.receive(Mail.create(['user'], date=datetime.now(tz=utc) - timedelta(seconds=84600 * 3)))  # 1
    with_server.receive(Mail.create(['user'], date=datetime.now(tz=utc) - timedelta(seconds=84600)))  # 2
    with_server.receive(Mail.create(['user']))  # 3
    imap_client = await login_user_async('user', 'pass', select=True)

    assert b'1' == (await imap_client.search('OLDER', '84700')).lines[0]
    assert b'2 3' == (await imap_client.search('YOUNGER', '84700')).lines[0]


@pytest.mark.asyncio()
async def test_rfc4315_uidplus_expunge(with_server):
    with_server.receive(Mail.create(['user']))
    with_server.receive(Mail.create(['user']))
    imap_client = await login_user_async('user', 'pass', select=True)

    assert ('OK', [b'1 EXPUNGE', b'UID EXPUNGE completed.']) == (await imap_client.uid('expunge', '1:1'))

    assert 1 == extract_exists((await imap_client.select()))


@pytest.mark.asyncio()
async def test_rfc6851_move(with_server):
    with_server.receive(Mail.create(['user']))
    imap_client = await login_user_async('user', 'pass', select=True)
    uidvalidity = with_server.get_connection('user').uidvalidity

    assert ('OK', [b'OK [COPYUID %d 1:1 1:1]' % uidvalidity, b'1 EXPUNGE', b'Done']) == \
                     (await imap_client.move('1:1', 'Trash'))

    assert 0 == extract_exists((await imap_client.select()))
    assert 1 == extract_exists((await imap_client.select('Trash')))


@pytest.mark.asyncio()
async def test_rfc6851_uidmove(with_server):
    with_server.receive(Mail.create(['user']))
    imap_client = await login_user_async('user', 'pass', select=True)
    uidvalidity = with_server.get_connection('user').uidvalidity

    assert ('OK', [b'OK [COPYUID %d 1:1 1:1]' % uidvalidity, b'1 EXPUNGE', b'Done']) == \
                     (await imap_client.uid('move', '1:1', 'Trash'))

    assert 0 == extract_exists((await imap_client.select()))
    assert 1 == extract_exists((await imap_client.select('Trash')))


@pytest.mark.asyncio()
async def test_rfc5161_enable(with_server):
    imap_client = await login_user_async('user', 'pass')

    assert ('OK', [b'X-GOOD-IDEA CONDSTORE enabled']) == \
                     (await imap_client.enable('X-GOOD-IDEA CONDSTORE'))


@pytest.mark.asyncio()
async def test_rfc2342_namespace(with_server):
    imap_client = await login_user_async('user', 'pass')
    response = await imap_client.namespace()

    assert ('OK', [b'(("" "/")) NIL NIL', b'NAMESPACE command completed']) == response


@pytest.mark.asyncio()
async def test_rfc2971_id(with_server):
    imap_client = await login_user_async('user', 'pass')
    response = await imap_client.id()
    assert ('OK', [b'ID command completed']) == response


@pytest.mark.asyncio()
async def test_callback_is_called_when_connection_is_lost(event_loop):
    imapserver = create_server(None, event_loop)
    srv = await imapserver.run_server(host='127.0.0.1', port=12345, fetch_chunk_size=64, ssl_context=None)
    async with srv:
        await srv.start_serving()
        queue = asyncio.Queue()
        imap_client = aioimaplib.IMAP4(port=12345, loop=event_loop, timeout=3,
                                       conn_lost_cb=lambda m: queue.put_nowait('called with %s' % m))
        await asyncio.wait_for(imap_client.wait_hello_from_server(), 2)
        await imap_client.login('login', 'password')

        imapserver.reset()
        srv.close()
        await asyncio.wait_for(srv.wait_closed(), 1)

        assert 'called with None' == (await asyncio.wait_for(queue.get(), timeout=2))


@pytest.mark.asyncio()
async def test_client_can_connect_to_server_over_ssl(with_ssl, with_ssl_server):
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=with_ssl[1])
    imap_client = aioimaplib.IMAP4_SSL(port=12345, loop=asyncio.get_running_loop(), ssl_context=ssl_context)
    await asyncio.wait_for(imap_client.wait_hello_from_server(), 2)

    assert 'IMAP4REV1' == imap_client.protocol.imap_version
    assert {'IMAP4rev1', 'YESAUTH'} == imap_client.protocol.capabilities
    assert imap_client.has_capability('YESAUTH')
