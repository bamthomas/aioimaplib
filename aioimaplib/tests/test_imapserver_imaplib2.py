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

import functools

import time

from imaplib2 import imaplib2
from mock import Mock
from aioimaplib.tests import imapserver
from aioimaplib.tests.imapserver import Mail
from aioimaplib.tests.server_fixture import with_server, login_user
import pytest


@pytest.mark.flaky(reruns=5)
@pytest.mark.asyncio()
async def test_idle(with_server):
    imap_client = await login_user('user', 'pass', select=True, lib=imaplib2.IMAP4)
    idle_callback = Mock()
    asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.idle, callback=idle_callback))
    await asyncio.wait_for(with_server.get_connection('user').wait(imapserver.IDLE), 1)

    asyncio.get_running_loop().run_in_executor(None, functools.partial(with_server.receive,
                                                      Mail.create(to=['user'], mail_from='me', subject='hello')))

    await asyncio.wait_for(with_server.get_connection('user').wait(imapserver.SELECTED), 5)
    time.sleep(0.2) # eurk hate sleeps but I don't know how to wait for the lib to receive end of IDLE
    idle_callback.assert_called_once()


@pytest.mark.asyncio()
async def test_login_twice(with_server):
    with pytest.raises(imaplib2.IMAP4.error) as expected:
        imap_client = await login_user('user', 'pass', lib=imaplib2.IMAP4)

        await asyncio.wait_for(
            asyncio.get_running_loop().run_in_executor(None, functools.partial(imap_client.login, 'user', 'pass')), 1)

        assert expected == 'command LOGIN illegal in state AUTH'
