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
import os

from OpenSSL import crypto
from unittest import TestCase

from aioimaplib.tests.ssl_cert import create_temp_self_signed_cert


class TestSslCert(TestCase):
    def setUp(self):
        self.cert, self.key = create_temp_self_signed_cert()

    def tearDown(self):
        os.remove(self.cert)
        os.remove(self.key)

    def test_create_temp_self_signed_cert_returns_two_file_names(self):
        assert os.path.isfile(self.cert)
        assert os.path.isfile(self.key)

    def test_create_temp_self_signed_cert_returns_cert_as_first_value(self):
        with open(self.cert, 'rb') as f:
            data = f.read()

            try:
                crypto.load_certificate(crypto.FILETYPE_PEM, data)
            except crypto.Error:
                self.fail('First file is not a certificate')

    def test_create_temp_self_signed_cert_returns_key_as_second_value(self):
        with open(self.key, 'rb') as f:
            data = f.read()

            try:
                crypto.load_privatekey(crypto.FILETYPE_PEM, data)
            except crypto.Error:
                self.fail('First file is not a key')

    def test_create_temp_self_signed_cert_can_generate_more_than_one_pair_of_keys(self):
        (second_cert, second_key) = create_temp_self_signed_cert()
        assert self.cert != second_cert
        assert os.path.isfile(second_cert)
        assert self.key != second_key
        assert os.path.isfile(second_key)
        os.remove(second_cert)
        os.remove(second_key)
