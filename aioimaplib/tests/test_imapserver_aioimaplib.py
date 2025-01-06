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

import pytest

from aioimaplib import extract_exists
from aioimaplib.aioimaplib import Command
from aioimaplib.tests.server_fixture import with_server, login_user_async


@pytest.mark.asyncio()
async def test_append_too_long(with_server):
    imap_client = await login_user_async('user@mail', 'pass')
    assert 0 == extract_exists((await imap_client.examine('INBOX')))

    message_bytes = b'do you see me ?'
    imap_client.protocol.literal_data = message_bytes * 2

    args = ['INBOX', '{%s}' % len(message_bytes)]
    response = await imap_client.protocol.execute(
        Command('APPEND', imap_client.protocol.new_tag(), *args, loop=asyncio.get_running_loop())
    )
    assert 'BAD' == response.result
    assert b'expected CRLF but got' in response.lines[0]


@pytest.mark.asyncio()
async def test_append_too_short(with_server):
    imap_client = await login_user_async('user@mail', 'pass')
    assert 0 == extract_exists((await imap_client.examine('INBOX')))

    message_bytes = b'do you see me ?' * 2
    imap_client.protocol.literal_data = message_bytes[:5]

    args = ['INBOX', '{%s}' % len(message_bytes)]
    response = await imap_client.protocol.execute(
        Command('APPEND', imap_client.protocol.new_tag(), *args, loop=asyncio.get_running_loop())
    )
    assert 'BAD' == response.result
    assert b'expected 30 but was' in response.lines[0]
