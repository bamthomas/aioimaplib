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
import pytest
from unittest import TestCase
from aioimaplib import quoted, arguments_rfs2971, ID_MAX_FIELD_LEN, ID_MAX_VALUE_LEN


class TestQuote(TestCase):
    def test_quote_encloses_string_in_dquote_character(self):
       assert '"hello"' == quoted('hello')

    def test_quote_escapes_dquote_character(self):
       assert '"hello\\"world"' == quoted('hello"world')

    def test_quote_escapes_backlash_character(self):
       assert '"hello\\\\world"' == quoted('hello\\world')

    def test_quote_returns_str_when_input_is_str(self):
        assert isinstance(quoted('hello'), str)


class TestArgument(TestCase):
    def test_arguments_rfs2971_empty(self):
       assert ['NIL'] == arguments_rfs2971()

    def test_arguments_rfs2971_with_kwargs(self):
       assert ['(', '"name"', '"test"', ')'] == arguments_rfs2971(name='test')

    def test_arguments_rfs2971_with_max_items(self):
        with pytest.raises(ValueError):
            fields = range(31)
            arguments_rfs2971(**{str(field): field for field in fields})

    def test_arguments_rfs2971_with_max_field_length(self):
        with pytest.raises(ValueError):
            field = 'test' * (ID_MAX_FIELD_LEN + 1)
            arguments_rfs2971(**{field: 'test'})

    def test_arguments_rfs2971_with_max_value_length(self):
        with pytest.raises(ValueError):
            value = 'test' * (ID_MAX_VALUE_LEN + 1)
            arguments_rfs2971(field=value)
