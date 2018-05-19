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
from unittest import TestCase
import collections
from aioimaplib import (
    quoted,
    arguments_rfs2971,
    ID_MAX_FIELD_LEN,
    ID_MAX_VALUE_LEN,
    parse_capability,
    base64_encode,
    base64_decode
)


class TestQuote(TestCase):
    def test_quote_encloses_string_in_dquote_character(self):
        self.assertEqual('"hello"', quoted('hello'))

    def test_quote_escapes_dquote_character(self):
        self.assertEqual('"hello\\"world"', quoted('hello"world'))

    def test_quote_escapes_backlash_character(self):
        self.assertEqual('"hello\\\\world"', quoted('hello\\world'))

    def test_quote_returns_str_when_input_is_str(self):
        self.assertTrue(isinstance(quoted('hello'), str))

    def test_quote_returns_bytes_when_input_is_bytes(self):
        self.assertTrue(isinstance(quoted(b'hello'), bytes))


class TestArgument(TestCase):
    def test_arguments_rfs2971_empty(self):
        self.assertEqual(['NIL'], arguments_rfs2971())

    def test_arguments_rfs2971_with_kwargs(self):
        self.assertEqual(['(', '"name"', '"test"', ')'], arguments_rfs2971(name='test'))

    def test_arguments_rfs2971_with_max_items(self):
        with self.assertRaises(ValueError):
            fields = range(31)
            arguments_rfs2971(**{str(field): field for field in fields})

    def test_arguments_rfs2971_with_max_field_length(self):
        with self.assertRaises(ValueError):
            field = 'test' * (ID_MAX_FIELD_LEN + 1)
            arguments_rfs2971(**{field: 'test'})

    def test_arguments_rfs2971_with_max_value_length(self):
        with self.assertRaises(ValueError):
            value = 'test' * (ID_MAX_VALUE_LEN + 1)
            arguments_rfs2971(field=value)


class TestParseCapability(TestCase):
    def test_parse_capability_empty(self):
        self.assertEqual((None, collections.defaultdict(set)), parse_capability(''))

    def test_parse_capability(self):
        result = collections.defaultdict(set)
        result['TEST'].add('')
        result['TEST1'].add('1')
        result['TEST1'].add('2')

        self.assertEqual(('TEST', result), parse_capability('TEST TEST1=1 TEST1=2'))


class TestBase64(TestCase):
    def test_base64_decode_empty(self):
        self.assertEqual('', base64_decode(None))
        self.assertEqual('', base64_decode(''))

    def test_base64_decode_str(self):
        self.assertEqual(b'1234', base64_decode('MTIzNA=='))

    def test_base64_encode_empty(self):
        self.assertEqual('', base64_decode(None))
        self.assertEqual('', base64_decode(''))

    def test_base64_encode_str(self):
        self.assertEqual(b'MTIzNA==', base64_encode('1234'))

    def test_base64_encode_bytes(self):
        self.assertEqual(b'MTIzNA==', base64_encode(b'1234'))

    def test_base64_encode_long_str(self):
        self.assertEqual(
            b'MTIzNDU2Nzg5MTAxMTEyMTMxNDE1MTYxMTIzNDU2Nzg5MTAxMTEyMTMxNDE1MTYxMg==',
            base64_encode('1234567891011121314151611234567891011121314151612')
        )
