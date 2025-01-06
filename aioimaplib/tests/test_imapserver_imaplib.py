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
import functools
import imaplib
import ssl
from datetime import datetime, timedelta

import pytest
from pytz import utc

from aioimaplib.tests import imapserver
from aioimaplib.tests.imapserver import Mail
from aioimaplib.tests.server_fixture import with_server, login_user, with_ssl, with_ssl_server


@pytest.mark.asyncio
async def test_server_greetings_and_capabilities(with_server):
    pending_imap = asyncio.get_running_loop().run_in_executor(None, functools.partial(imaplib.IMAP4, host='127.0.0.1', port=12345))
    imap_client = await asyncio.wait_for(pending_imap, 1)

    assert 'NONAUTH' == imap_client.state


@pytest.mark.asyncio
async def test_server_login(with_server):
    pending_imap = asyncio.get_running_loop().run_in_executor(None, functools.partial(imaplib.IMAP4, host='127.0.0.1', port=12345))
    imap_client = await asyncio.wait_for(pending_imap, 1)

    pending_login = asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.login, 'user', 'pass'))
    result, data = await asyncio.wait_for(pending_login, 1)

    assert 'OK' == result
    assert [b'LOGIN completed'] == data
    assert imapserver.AUTH == with_server.get_connection('user').state


@pytest.mark.asyncio
async def test_select_no_messages_in_mailbox(with_server):
    imap_client = await login_user('user@mail', 'pass')

    result, data = await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.select)), 1)

    assert 'OK' == result
    assert [b'0'] == data
    assert imapserver.SELECTED == with_server.get_connection('user@mail').state


@pytest.mark.asyncio
async def test_select_one_message_in_mailbox(with_server):
    with_server.receive(Mail.create(to=['user'], mail_from='me', subject='hello'))
    imap_client = await login_user('user', 'pass')

    result, data = await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.select)), 1)

    assert 'OK' == result
    assert [b'1'] == data


@pytest.mark.asyncio
async def test_select_one_message_in_INBOX_zero_in_OTHER(with_server):
    with_server.receive(Mail.create(to=['user'], mail_from='me', subject='hello'))
    imap_client = await login_user('user', 'pass')

    _, data = await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.select)), 1)
    assert [b'1'] == data

    _, data = await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.select, 'OTHER')), 1)
    assert [b'0'] == data


@pytest.mark.asyncio
async def test_examine_no_messages_in_mailbox(with_server):
    imap_client = await login_user('user', 'pass')

    assert ('OK', [b'0']) == (await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.select, readonly=True)), 1))

    assert imapserver.AUTH == with_server.get_connection('user').state


@pytest.mark.asyncio
async def test_search_by_uid_two_messages(with_server):
    with_server.receive(Mail.create(['user']))
    with_server.receive(Mail.create(['user']))
    imap_client = await login_user('user', 'pass', select=True)

    result, data = await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.uid, 'search', 'utf-8', 'ALL')), 1)

    assert 'OK' == result
    assert [b'1 2'] == data


@pytest.mark.asyncio
async def test_search_by_uid_one_message_two_recipients(with_server):
    with_server.receive(Mail.create(['user1', 'user2']))
    imap_client = await login_user('user1', 'pass', select=True)

    result, data = await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.uid, 'search', None, 'ALL')), 1)

    assert 'OK' == result
    assert [b'1'] == data

    imap_client = await login_user('user2', 'pass', select=True)

    result, data = await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.uid, 'search', None, 'ALL')), 1)

    assert 'OK' == result
    assert [b'1'] == data


@pytest.mark.asyncio
async def test_fetch_one_message_by_uid(with_server):
    mail = Mail.create(['user'], mail_from='me', subject='hello', content='pleased to meet you, wont you guess my name ?')
    with_server.receive(mail)
    imap_client = await login_user('user', 'pass', select=True)

    result, data = await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.uid, 'fetch', '1', '(RFC822)')), 1)

    assert 'OK' == result
    assert [(b'1 (UID 1 RFC822 {360}', mail.as_bytes()), b')'] == data


@pytest.mark.asyncio
async def test_fetch_bad_range(with_server):
    imap_client = await login_user('user', 'pass', select=True)

    with pytest.raises(Exception) as expected:
        await asyncio.wait_for(
            asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.uid, 'fetch', '0:*', '(RFC822)')), 1)

        assert 'UID command error: BAD [b\'Error in IMAP command: Invalid uidset\']' == str(expected)

    with pytest.raises(Exception) as expected:
        await asyncio.wait_for(
            asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.uid, 'fetch', '2:0', '(RFC822)')), 1)

        assert 'UID command error: BAD [b\'Error in IMAP command: Invalid uidset\']' == str(expected)


@pytest.mark.asyncio
async def test_fetch_one_message_by_uid_with_bodypeek(with_server):
    mail = Mail.create(['user'], mail_from='me', subject='hello', content='this mail is still unread')
    with_server.receive(mail)
    imap_client = await login_user('user', 'pass', select=True)

    result, data = await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.uid, 'fetch', '1', '(UID BODY.PEEK[])')), 1)

    assert 'OK' == result
    assert [(b'1 (UID 1 BODY.PEEK[] {340}', mail.as_bytes()), b')'] == data


@pytest.mark.asyncio
async def test_fetch_one_messages_by_uid_without_body(with_server):
    mail = Mail.create(['user'], mail_from='me', subject='hello', content='whatever')
    with_server.receive(mail)
    imap_client = await login_user('user', 'pass', select=True)

    result, data = await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.uid, 'fetch', '1', '(UID FLAGS)')), 1)

    assert 'OK' == result
    assert [(b'1 (UID 1 FLAGS ())')] == data


@pytest.mark.asyncio
async def test_fetch_one_messages_by_id_without_body(with_server):
    mail = Mail.create(['user'], mail_from='me', subject='hello', content='whatever')
    with_server.receive(mail)
    imap_client = await login_user('user', 'pass', select=True)

    result, data = await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.fetch, '1', '(UID FLAGS)')), 1)
    assert [(b'1 (UID 1 FLAGS ())')] == data

    result, data = await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.fetch, '1', '(FLAGS)')), 1)
    assert [(b'1 (FLAGS ())')] == data


@pytest.mark.asyncio
async def test_fetch_messages_by_uid_range(with_server):
    mail = Mail.create(['user'], mail_from='me', subject='hello', content='whatever')
    with_server.receive(mail)
    imap_client = await login_user('user', 'pass', select=True)

    result, data = await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.uid, 'fetch', '1:1', '(FLAGS)')), 1)
    assert [(b'1 (UID 1 FLAGS ())')] == data

    result, data = await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.fetch, '1:*', '(UID FLAGS)')), 1)
    assert [(b'1 (UID 1 FLAGS ())')] == data


@pytest.mark.asyncio
async def test_fetch_one_messages_by_uid_encoding_cp1252(with_server):
    with_server.receive(Mail.create(['user'], mail_from='me', subject='hello', content='maître', encoding='cp1252'))
    imap_client = await login_user('user', 'pass', select=True)

    _, data = await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.uid, 'fetch', '1', '(RFC822)')), 1)

    mail_content = data[0][1]
    assert b'charset="cp1252"' in mail_content
    assert b'ma\xeetre' in mail_content
    assert 'maître' == email.message_from_bytes(mail_content).get_payload().strip()


@pytest.mark.asyncio
async def test_fetch_one_messages_out_of_two(with_server):
    with_server.receive(Mail.create(['user'], mail_from='me', subject='hello', content='maître'))
    with_server.receive(Mail.create(['user'], mail_from='you', subject='yo', content='bro'))
    imap_client = await login_user('user', 'pass', select=True)

    _, data = await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.uid, 'fetch', '1', '(RFC822)')), 1)

    assert 2 == len(data)


@pytest.mark.asyncio
async def test_fetch_one_message_with_headers(with_server):
    with_server.receive(Mail.create(['user'], mail_from='me', subject='hello', content='maître'))
    imap_client = await login_user('user', 'pass', select=True)

    _, data = await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.uid, 'fetch', '1', '(BODY.PEEK[HEADER.FIELDS (Content-type From)])')), 1)

    assert b'1 (UID 1 BODY[HEADER.FIELDS (Content-type From)] {57}' == data[0][0]
    assert b'Content-type: text/plain; charset="utf-8"\r\nFrom: <me>\r\n\r\n' == data[0][1]


@pytest.mark.asyncio
async def test_store(with_server):
    with_server.receive(Mail.create(['user']))
    imap_client = await login_user('user', 'pass', select=True)

    result, data = await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.uid, 'store', '1', '+FLAGS.SILENT (\Seen \Answered)')), 1)
    assert 'OK' == result

    result, data = await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.uid, 'fetch', '1', 'UID (FLAGS)')), 1)

    assert 'OK' == result
    assert [b'1 (UID 1 FLAGS (\Seen \Answered))'] == data


@pytest.mark.asyncio
async def test_store_and_search_by_keyword(with_server):
    with_server.receive(Mail.create(['user']))
    with_server.receive(Mail.create(['user']))
    imap_client = await login_user('user', 'pass', select=True)

    result, data = await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.uid, 'search', None, 'KEYWORD FOO')), 1)

    assert 'OK' == result
    assert [b''] == data

    result, data = await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.uid, 'store', '1', '+FLAGS (FOO)')), 1)
    assert 'OK' == result

    result, data = await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.uid, 'search', None, 'KEYWORD FOO')), 1)
    assert 'OK' == result
    assert [b'1'] == data

    result, data = await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.uid, 'search', None, 'UNKEYWORD FOO')), 1)
    assert 'OK' == result
    assert [b'2'] == data


@pytest.mark.asyncio
async def test_search_by_uid_range(with_server):
    with_server.receive(Mail.create(['user']))
    with_server.receive(Mail.create(['user']))
    imap_client = await login_user('user', 'pass', select=True)

    _, data = await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.uid, 'search', None, '1:2')), 1)
    assert [b'1 2'] == data

    _, data = await asyncio.wait_for(
                asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.uid, 'search', None, '1:*')), 1)
    assert [b'1 2'] == data

    _, data = await asyncio.wait_for(
                asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.uid, 'search', None, '1:1')), 1)
    assert [b'1'] == data


@pytest.mark.asyncio
async def test_expunge_messages(with_server):
    with_server.receive(Mail.create(['user']))
    with_server.receive(Mail.create(['user']))
    imap_client = await login_user('user', 'pass', select=True)

    await asyncio.wait_for(asyncio.get_running_loop().run_in_executor(None, imap_client.expunge), 1)

    assert ('OK', [b'0']) == (await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.select)), 1))


@pytest.mark.asyncio
async def test_noop(with_server):
    imap_client = await login_user('user', 'pass', select=True)

    assert ('OK', [b'NOOP completed.']) == \
                      (await asyncio.wait_for(asyncio.get_running_loop().run_in_executor(None, imap_client.noop), 1))


@pytest.mark.asyncio
async def test_check(with_server):
    imap_client = await login_user('user', 'pass', select=True)

    assert ('OK', [b'CHECK completed.']) == \
                      (await asyncio.wait_for(asyncio.get_running_loop().run_in_executor(None, imap_client.check), 1))


@pytest.mark.asyncio
async def test_status(with_server):
    imap_client = await login_user('user', 'pass')

    assert ('OK', [b'INBOX (MESSAGES 0 UIDNEXT 1)']) == \
                      (await asyncio.wait_for(
                          asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.status, 'INBOX',
                                                                            '(MESSAGES UIDNEXT)')), 1))


@pytest.mark.asyncio
async def test_subscribe_unsubscribe_lsub(with_server):
    imap_client = await login_user('user', 'pass')

    assert ('OK', [b'SUBSCRIBE completed.']) == \
                      (await asyncio.wait_for(
                          asyncio.get_running_loop().run_in_executor(None, functools.partial(
                              imap_client.subscribe, '#fr.soc.feminisme')), 1))

    assert ('OK', [b'() "." #fr.soc.feminisme']) == \
                      (await asyncio.wait_for(
                          asyncio.get_running_loop().run_in_executor(None, functools.partial(
                              imap_client.lsub, '#fr', 'soc.*')), 1))

    assert ('OK', [b'UNSUBSCRIBE completed.']) == \
                      (await asyncio.wait_for(
                          asyncio.get_running_loop().run_in_executor(None, functools.partial(
                              imap_client.unsubscribe, '#fr.soc.feminisme')), 1))

    assert ('OK', [None]) == \
                      (await asyncio.wait_for(
                          asyncio.get_running_loop().run_in_executor(None, functools.partial(
                              imap_client.lsub, '#fr', '.*')), 1))


@pytest.mark.asyncio
async def test_close(with_server):
    imap_client = await login_user('user', 'pass', select=True)
    assert imapserver.SELECTED == with_server.get_connection('user').state

    assert ('OK', [b'CLOSE completed.']) == \
                      (await asyncio.wait_for(asyncio.get_running_loop().run_in_executor(None, imap_client.close), 1))

    assert imapserver.AUTH == with_server.get_connection('user').state


@pytest.mark.asyncio
async def test_copy_messages(with_server):
    with_server.receive(Mail.create(['user']))
    with_server.receive(Mail.create(['user']))
    imap_client = await login_user('user', 'pass', select=True)

    result, _ = await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.copy, '1 2', 'MAILBOX')), 20)
    assert 'OK' == result

    assert ('OK', [b'2']) == (await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.select, 'MAILBOX')), 20))


@pytest.mark.asyncio
async def test_create_delete_mailbox(with_server):
    imap_client = await login_user('user', 'pass')

    assert ('NO', [b'STATUS completed.']) == \
                      (await asyncio.wait_for(
                          asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.status, 'MBOX', '(MESSAGES)')), 1))

    assert ('OK', [b'CREATE completed.']) == \
                      (await asyncio.wait_for(
                          asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.create, 'MBOX')), 1))

    assert ('OK', [b'MBOX (MESSAGES 0)']) == \
                      (await asyncio.wait_for(
                          asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.status, 'MBOX', '(MESSAGES)')), 1))

    assert ('OK', [b'DELETE completed.']) == \
                      (await asyncio.wait_for(
                          asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.delete, 'MBOX')), 1))

    assert ('NO', [b'STATUS completed.']) == \
                      (await asyncio.wait_for(
                          asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.status, 'MBOX', '(MESSAGES)')), 1))


@pytest.mark.asyncio
async def test_rename_mailbox(with_server):
    with_server.receive(Mail.create(['user']))
    imap_client = await login_user('user', 'pass')

    assert ('NO', [b'STATUS completed.']) == \
                      (await asyncio.wait_for(
                          asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.status, 'MBOX', '(MESSAGES)')), 1))

    assert ('OK', [b'RENAME completed.']) == \
                      (await asyncio.wait_for(
                          asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.rename, 'INBOX', 'MBOX')), 1))

    assert ('OK', [b'MBOX (MESSAGES 1)']) == \
                      (await asyncio.wait_for(
                          asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.status, 'MBOX', '(MESSAGES)')), 1))


@pytest.mark.asyncio
async def test_list(with_server):
    imap_client = await login_user('user', 'pass')
    assert ('OK', [b'() "/" Drafts', b'() "/" INBOX', b'() "/" Sent', b'() "/" Trash']) == \
                      (await asyncio.wait_for(
                          asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.list, '""', '*')), 1))


@pytest.mark.asyncio
async def test_append(with_server):
    imap_client = await login_user('user@mail', 'pass')

    assert ('OK', [b'0']) == (await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.select, 'INBOX', readonly=True)), 2))

    msg = Mail.create(['user@mail'], subject='append msg', content='do you see me ?')
    assert 'OK' == (await asyncio.wait_for(
                          asyncio.get_running_loop().run_in_executor(None, functools.partial(
                              imap_client.append, 'INBOX', 'FOO BAR', datetime.now(tz=utc), msg.as_bytes())), 2))[0]

    assert ('OK', [b'1']) == (await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.select, 'INBOX', readonly=True)), 2))


@pytest.mark.asyncio
async def test_logout(with_server):
    imap_client = await login_user('user', 'pass')

    result, data = await asyncio.wait_for(asyncio.get_running_loop().run_in_executor(None, imap_client.logout), 1)

    assert 'BYE' == result  # uhh ?
    assert [b'Logging out'] == data
    assert imapserver.LOGOUT == with_server.get_connection('user').state


@pytest.mark.asyncio
async def test_rfc5032_within(with_server):
    with_server.receive(Mail.create(['user'], date=datetime.now(tz=utc) - timedelta(seconds=84600 * 3))) # 1
    with_server.receive(Mail.create(['user'], date=datetime.now(tz=utc) - timedelta(seconds=84600))) # 2
    with_server.receive(Mail.create(['user'])) # 3
    imap_client = await login_user('user', 'pass', select=True)

    assert [b'2 3'] == (await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.search, 'utf-8', 'YOUNGER', '84700')), 1))[1]

    assert [b'1'] == (await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.search, 'utf-8', 'OLDER', '84700')), 1))[1]


@pytest.mark.asyncio
async def test_getquotaroot(with_server):
    imap_client = await login_user('user', 'pass')
    with_server.receive(Mail.create(['user']))

    assert ('OK', [[b'INBOX INBOX'], [b'INBOX (STORAGE 292 5000)']]) == \
                      (await asyncio.wait_for(asyncio.get_running_loop().run_in_executor(None,
                                                    functools.partial(imap_client.getquotaroot, 'INBOX')), 1))


@pytest.mark.asyncio()
async def test_client_can_connect_to_server_over_ssl(with_ssl, with_ssl_server):
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=with_ssl[1])

    pending_imap = asyncio.get_running_loop().run_in_executor(None, functools.partial(
        imaplib.IMAP4_SSL,
        host='127.0.0.1',
        port=12345,
        ssl_context=ssl_context)
    )
    imap_client = await asyncio.wait_for(pending_imap, 1)

    assert 'NONAUTH' == imap_client.state
