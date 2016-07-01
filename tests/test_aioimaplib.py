# -*- coding: utf-8 -*-
import asyncio
import email
import unittest

from aioimaplib import aioimaplib
from aioimaplib.aioimaplib import Commands, _split_responses
from tests import imapserver
from tests.imapserver import imap_receive, Mail, get_imapconnection
from tests.test_imapserver import WithImapServer


class TestAioimaplibUtils(unittest.TestCase):
    def test_split_responses_no_data(self):
        self.assertEquals([], _split_responses(b''))

    def test_split_responses_regular_lines(self):
        self.assertEquals([b'* BYE Logging out', b'CAPB2 OK LOGOUT completed'],
                          _split_responses(b'* BYE Logging out\r\nCAPB2 OK LOGOUT completed\r\n'))

    def test_split_responses_with_message_data(self):
        self.assertEquals([b'* FETCH ...\r\n(mail content)\r\n...\r\n)',
                           b'TAG OK FETCH completed.'],
                          _split_responses(
                              b'* 1 FETCH (UID 1 RFC822 {26}\r\n...\r\n(mail content)\r\n...\r\n)\r\n'
                              b'TAG OK FETCH completed.'))

    def test_split_responses_with_two_messages_data(self):
        self.assertEquals([b'* FETCH mail 1\r\n)',
                           b'* FETCH mail 2\r\n)',
                           b'TAG OK FETCH completed.'],
                          _split_responses(
                              b'* 3 FETCH (UID 3 RFC822 {8}\r\nmail 1\r\n)\r\n'
                              b'* 4 FETCH (UID 4 RFC822 {8}\r\nmail 2\r\n)\r\n'
                              b'TAG OK FETCH completed.'))

    def test_split_responses_with_flag_fetch_message_data(self):
        self.assertEquals([b'* 1 FETCH (UID 10 FLAGS (FOO))',
                           b'* 1 FETCH (UID 15 FLAGS (BAR))',
                           b'TAG OK STORE completed.'],
                          _split_responses(b'* 1 FETCH (UID 10 FLAGS (FOO))\r\n'
                                           b'* 1 FETCH (UID 15 FLAGS (BAR))\r\n'
                                           b'TAG OK STORE completed.'))

    def test_split_responses_with_message_data_expunge(self):
        self.assertEquals([b'* 123 EXPUNGE', b'TAG OK SELECT completed.'],
                          _split_responses(b'* 123 EXPUNGE\r\nTAG OK SELECT completed.\r\n'))


class TestAioimaplib(WithImapServer):
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
        imap_receive(Mail(['user']))
        imap_receive(Mail(['user']))
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
        imap_receive(Mail(['user']))  # id=1 uid=1
        imap_receive(Mail(['user']), mailbox='OTHER_MAILBOX')  # id=1 uid=2
        imap_receive(Mail(['user']))  # id=2 uid=3

        self.assertEqual('1 3', (yield from imap_client.uid_search('ALL')).lines[0])
        self.assertEqual('1 2', (yield from imap_client.search('ALL')).lines[0])

    @asyncio.coroutine
    def test_fetch(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)
        mail = Mail(['user'], mail_from='me', subject='hello', content='pleased to meet you, wont you guess my name ?')
        imap_receive(mail)

        result, data = yield from imap_client.fetch('1', '(RFC822)')

        self.assertEqual('OK', result)
        self.assertEqual([str(mail).encode(), 'FETCH completed.'], data)
        emaillib_decoded_msg = email.message_from_bytes(data[0])
        self.assertEqual('hello', emaillib_decoded_msg['Subject'])

    @asyncio.coroutine
    def test_fetch_by_uid(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)
        mail = Mail(['user'], mail_from='me', subject='hello', content='pleased to meet you, wont you guess my name ?')
        imap_receive(mail)

        response = (yield from imap_client.uid('fetch', '1', '(RFC822)'))

        self.assertEqual('OK', response.result)
        self.assertEquals(str(mail).encode(), response.lines[0])

    @asyncio.coroutine
    def test_idle(self):
        imap_client = yield from self.login_user('user', 'pass', select=True)

        idle = asyncio.async(imap_client.idle())
        yield from asyncio.wait_for(get_imapconnection('user').wait(imapserver.IDLE), 1)

        idle_push = asyncio.async(imap_client.wait_server_push())
        imap_receive(Mail(to=['user'], mail_from='me', subject='hello'))

        self.assertEquals('1 EXISTS', (yield from idle_push))
        self.assertEquals('1 RECENT', (yield from imap_client.wait_server_push()))

        imap_client.idle_done()
        self.assertEquals(('OK', ['IDLE terminated']), (yield from asyncio.wait_for(idle, 1)))

    @asyncio.coroutine
    def test_store_and_search_by_keyword(self):
        imap_receive(Mail(['user']))
        imap_receive(Mail(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)
        self.assertEqual('', (yield from imap_client.uid_search('KEYWORD FOO', charset=None)).lines[0])

        self.assertEquals('OK', (yield from imap_client.uid('store', '1', '+FLAGS FOO')).result)

        self.assertEqual('1', (yield from imap_client.uid_search('KEYWORD FOO', charset=None)).lines[0])
        self.assertEqual('2', (yield from imap_client.uid_search('UNKEYWORD FOO', charset=None)).lines[0])

    @asyncio.coroutine
    def test_expunge_messages(self):
        imap_receive(Mail(['user']))
        imap_receive(Mail(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        self.assertEquals(('OK', ['1', '2', 'EXPUNGE completed.']), (yield from imap_client.expunge()))

        self.assertEquals(('OK', ['0']), (yield from imap_client.select()))

    @asyncio.coroutine
    def test_copy_messages(self):
        imap_receive(Mail(['user']))
        imap_receive(Mail(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        result, _ = yield from imap_client.copy('1', '2', 'MAILBOX')
        self.assertEqual('OK', result)

        self.assertEquals(('OK', ['2']), (yield from imap_client.select('MAILBOX')))

    @asyncio.coroutine
    def test_copy_messages_by_uid(self):
        imap_receive(Mail(['user']))
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
        imap_receive(Mail(['user']))
        imap_client = yield from self.login_user('user', 'pass', select=True)

        f1 = asyncio.async(imap_client.fetch('1', '(RFC822)'))
        f2 = asyncio.async(imap_client.fetch('1', '(RFC822)'))

        yield from asyncio.wait([f1, f2])
        self.assertIsNone(f1.exception())
        self.assertIsNone(f2.exception())

    @asyncio.coroutine
    def test_concurrency_3_executing_async_commands_in_parallel(self):
         # cf valid example in https://tools.ietf.org/html/rfc3501#section-5.5
        imap_receive(Mail(['user']))
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
        imap_receive(Mail(['user']))
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
    def test_subscribe_unsubscribe(self):
        imap_client = yield from self.login_user('user', 'pass')

        self.assertEquals(('OK', ['SUBSCRIBE completed.']), (yield from imap_client.subscribe('#fr.soc.feminisme')))
        self.assertEquals(('OK', ['UNSUBSCRIBE completed.']), (yield from imap_client.unsubscribe('#fr.soc.feminisme')))

    @asyncio.coroutine
    def login_user(self, login, password, select=False, lib=aioimaplib.IMAP4):
        imap_client = aioimaplib.IMAP4(port=12345, loop=self.loop, timeout=3)
        yield from asyncio.wait_for(imap_client.wait_hello_from_server(), 2)

        yield from imap_client.login('user', 'password')

        if select:
            yield from imap_client.select()
        return imap_client
