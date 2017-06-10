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

import os
from aioimaplib.tests.imapserver import imap_receive, Mail
from aioimaplib.tests.test_aioimaplib import AioWithImapServer


class TestAioimaplibAcceptance(AioWithImapServer):
    @asyncio.coroutine
    def test_file_with_attachement(self):
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/test_attachment.eml'), mode='br') as msg:
            imap_client = yield from self.login_user('user@mail', 'pass', select=True)
            mail = Mail(email.message_from_binary_file(msg))

            imap_receive(mail, imap_user='user@mail')

            result, data = yield from imap_client.fetch('1', '(RFC822)')

            self.assertEqual('OK', result)
            self.assertEqual(['1 FETCH (UID 1 RFC822 {418898}', mail.as_bytes(), ')', 'FETCH completed.'], data)
