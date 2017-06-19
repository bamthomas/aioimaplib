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
from datetime import datetime, timezone, timedelta
import time
from enum import Enum

import re

import functools

import random
from collections import namedtuple


log = logging.getLogger(__name__)

IMAP4_PORT = 143
IMAP4_SSL_PORT = 993
STARTED, CONNECTED, NONAUTH, AUTH, SELECTED, LOGOUT = 'STARTED', 'CONNECTED', 'NONAUTH', 'AUTH', 'SELECTED', 'LOGOUT'
CRLF = b'\r\n'

AllowedVersions = ('IMAP4REV1', 'IMAP4')
Exec = Enum('Exec', 'sync async')
Cmd = namedtuple('Cmd', 'name           valid_states                exec')
Commands = {
    'APPEND':       Cmd('APPEND',       (AUTH, SELECTED),           Exec.sync),
    'AUTHENTICATE': Cmd('AUTHENTICATE', (NONAUTH,),                 Exec.sync),
    'CAPABILITY':   Cmd('CAPABILITY',   (NONAUTH, AUTH, SELECTED),  Exec.async),
    'CHECK':        Cmd('CHECK',        (SELECTED,),                Exec.async),
    'CLOSE':        Cmd('CLOSE',        (SELECTED,),                Exec.sync),
    'COMPRESS':     Cmd('COMPRESS',     (AUTH,),                    Exec.sync),
    'COPY':         Cmd('COPY',         (SELECTED,),                Exec.async),
    'CREATE':       Cmd('CREATE',       (AUTH, SELECTED),           Exec.async),
    'DELETE':       Cmd('DELETE',       (AUTH, SELECTED),           Exec.async),
    'DELETEACL':    Cmd('DELETEACL',    (AUTH, SELECTED),           Exec.async),
    'EXAMINE':      Cmd('EXAMINE',      (AUTH, SELECTED),           Exec.sync),
    'EXPUNGE':      Cmd('EXPUNGE',      (SELECTED,),                Exec.async),
    'FETCH':        Cmd('FETCH',        (SELECTED,),                Exec.async),
    'GETACL':       Cmd('GETACL',       (AUTH, SELECTED),           Exec.async),
    'GETQUOTA':     Cmd('GETQUOTA',     (AUTH, SELECTED),           Exec.async),
    'GETQUOTAROOT': Cmd('GETQUOTAROOT', (AUTH, SELECTED),           Exec.async),
    'ID':           Cmd('ID',           (NONAUTH, AUTH, LOGOUT, SELECTED), Exec.async),
    'IDLE':         Cmd('IDLE',         (SELECTED,),                Exec.sync),
    'LIST':         Cmd('LIST',         (AUTH, SELECTED),           Exec.async),
    'LOGIN':        Cmd('LOGIN',        (NONAUTH,),                 Exec.sync),
    'LOGOUT':       Cmd('LOGOUT',       (NONAUTH, AUTH, LOGOUT, SELECTED), Exec.sync),
    'LSUB':         Cmd('LSUB',         (AUTH, SELECTED),           Exec.async),
    'MYRIGHTS':     Cmd('MYRIGHTS',     (AUTH, SELECTED),           Exec.async),
    'NAMESPACE':    Cmd('NAMESPACE',    (AUTH, SELECTED),           Exec.async),
    'NOOP':         Cmd('NOOP',         (NONAUTH, AUTH, SELECTED),  Exec.async),
    'RENAME':       Cmd('RENAME',       (AUTH, SELECTED),           Exec.async),
    'SEARCH':       Cmd('SEARCH',       (SELECTED,),                Exec.async),
    'SELECT':       Cmd('SELECT',       (AUTH, SELECTED),           Exec.sync),
    'SETACL':       Cmd('SETACL',       (AUTH, SELECTED),           Exec.sync),
    'SETQUOTA':     Cmd('SETQUOTA',     (AUTH, SELECTED),           Exec.sync),
    'SORT':         Cmd('SORT',         (SELECTED,),                Exec.async),
    'STARTTLS':     Cmd('STARTTLS',     (NONAUTH,),                 Exec.sync),
    'STATUS':       Cmd('STATUS',       (AUTH, SELECTED),           Exec.async),
    'STORE':        Cmd('STORE',        (SELECTED,),                Exec.async),
    'SUBSCRIBE':    Cmd('SUBSCRIBE',    (AUTH, SELECTED),           Exec.sync),
    'THREAD':       Cmd('THREAD',       (SELECTED,),                Exec.async),
    'UID':          Cmd('UID',          (SELECTED,),                Exec.async),
    'UNSUBSCRIBE':  Cmd('UNSUBSCRIBE',  (AUTH, SELECTED),           Exec.sync),
    # for testing
    'DELAY':        Cmd('DELAY',        (AUTH, SELECTED),           Exec.sync),
}

Response = namedtuple('Response', 'result lines')


class Command(object):
    def __init__(self, name, tag, *args, prefix=None, untagged_resp_name=None, loop=asyncio.get_event_loop(), timeout=None):
        self.name = name
        self.tag = tag
        self.args = args
        self.prefix = prefix + ' ' if prefix else None
        self.untagged_resp_name = untagged_resp_name or name

        self.response = None
        self._exception = None
        self._event = asyncio.Event(loop=loop)
        self._loop = loop
        self._timeout = timeout
        self._timer = asyncio.Handle(lambda: None, None, loop)  # fake timer
        self._set_timer()
        self._literal_data = None
        self._expected_size = 0

    def __repr__(self):
        return '{tag} {prefix}{name}{space}{args}'.format(
            tag=self.tag, prefix=self.prefix or '', name=self.name,
            space=' ' if self.args else '', args=' '.join(self.args))

    # for tests
    def __eq__(self, other):
        return other is not None and other.tag == self.tag and other.name == self.name and other.args == self.args

    def close(self, line, result):
        self.append_to_resp(line, result=result)
        self._timer.cancel()
        self._event.set()

    def begin_literal_data(self, expected_size, literal_data=b''):
        self._expected_size = expected_size
        self._literal_data = b''
        return self.append_literal_data(literal_data)

    def wait_literal_data(self):
        return self._expected_size != 0 and len(self._literal_data) != self._expected_size

    def append_literal_data(self, data):
        nb_bytes_to_add = self._expected_size - len(self._literal_data)
        self._literal_data += data[0:nb_bytes_to_add]
        if not self.wait_literal_data():
            self.append_to_resp(self._literal_data)
            self._end_literal_data()
        self._reset_timer()
        return data[nb_bytes_to_add:]

    def append_to_resp(self, line, result='Pending'):
        if self.response is None:
            self.response = Response(result, [line])
        else:
            old = self.response
            self.response = Response(result, old.lines + [line])
        self._reset_timer()

    @asyncio.coroutine
    def wait(self):
        yield from self._event.wait()
        if self._exception is not None:
            raise self._exception

    def _end_literal_data(self):
        self._expected_size = 0
        self._literal_data = None

    def _set_timer(self):
        if self._timeout is not None:
            self._timer = self._loop.call_later(self._timeout, self._timeout_callback)

    def _timeout_callback(self):
        self._exception = CommandTimeout(self)
        self.close(str(self._exception), 'KO')

    def _reset_timer(self):
        self._timer.cancel()
        self._set_timer()


class Error(Exception):
    def __init__(self, reason):
        super().__init__(reason)


class Abort(Error):
    def __init__(self, reason):
        super().__init__(reason)


class CommandTimeout(asyncio.TimeoutError):
    def __init__(self, command):
        self.command = command


class IncompleteLiteral(Exception):
    def __init__(self, cmd):
        self.cmd = cmd


def change_state(coro):
    @functools.wraps(coro)
    @asyncio.coroutine
    def wrapper(self, *args, **kargs):
        with (yield from self.state_condition):
            res = yield from coro(self, *args, **kargs)
            log.debug('state -> %s' % self.state)
            self.state_condition.notify_all()
            return res

    return wrapper


# cf https://tools.ietf.org/html/rfc3501#section-9
# untagged responses types
literal_data_re = re.compile(rb'.*\{(?P<size>\d+)\}$')
message_data_re = re.compile(r'[0-9]+ ((FETCH)|(EXPUNGE))')
tagged_status_response_re = re.compile(r'[A-Z0-9]+ ((OK)|(NO)|(BAD))')


class IMAP4ClientProtocol(asyncio.Protocol):
    def __init__(self, loop):
        self.loop = loop
        self.transport = None
        self.state = STARTED
        self.state_condition = asyncio.Condition()
        self.capabilities = ()
        self.pending_async_commands = dict()
        self.pending_sync_command = None
        self.idle_queue = asyncio.Queue()
        self.imap_version = None
        self.literal_data = None
        self.incomplete_line = b''
        self.current_command = None

        self.tagnum = 0
        self.tagpre = int2ap(random.randint(4096, 65535))

    def connection_made(self, transport):
        self.transport = transport
        self.state = CONNECTED

    def data_received(self, d):
        log.debug('Received : %s' % d)
        try:
            self._handle_responses(self.incomplete_line + d, self._handle_line, self.current_command)
            self.incomplete_line = b''
            self.current_command = None
        except IncompleteLiteral as incomplete_literal:
            self.current_command = incomplete_literal.cmd
        except asyncio.IncompleteReadError as incomplete_read:
            log.debug('Incomplete line, storing partial : %s' % incomplete_read.partial[:100])
            self.incomplete_line = incomplete_read.partial

    def _handle_responses(self, data, line_handler, current_cmd=None):
        if not data:
            return
        if current_cmd is not None and current_cmd.wait_literal_data():
            data = current_cmd.append_literal_data(data)
            if current_cmd.wait_literal_data():
                raise IncompleteLiteral(current_cmd)

        line, separator, tail = data.partition(CRLF)
        if not separator:
            raise asyncio.IncompleteReadError(data, b'line should end with CRLF')

        cmd = line_handler(line.decode(), current_cmd)

        begin_literal = literal_data_re.match(line)
        if begin_literal:
            size = int(begin_literal.group('size'))
            if cmd is None:
                cmd = Command('NIL', 'unused')
            cmd.begin_literal_data(size)
            self._handle_responses(tail, line_handler, current_cmd=cmd)
        else:
            self._handle_responses(tail, line_handler)

    def _handle_line(self, line, current_cmd):
        if not line:
            return

        if self.state == CONNECTED:
            asyncio.async(self.welcome(line))
        elif tagged_status_response_re.match(line):
            self._response_done(line)
        elif current_cmd is not None:
            current_cmd.append_to_resp(line)
            return current_cmd
        elif line.startswith('*'):
            return self._untagged_response(line.replace('* ', ''))
        elif line.startswith('+'):
            self._continuation(line.replace('+ ', ''))
        else:
            log.info('unknown data received %s' % line)

    def connection_lost(self, exc):
        self.transport.close()

    def send(self, line):
        data = ('%s\r\n' % line).encode()
        log.debug('Sending : %s' % data)
        self.transport.write(data)

    @asyncio.coroutine
    def execute(self, command):
        if self.state not in Commands.get(command.name).valid_states:
            raise Abort('command %s illegal in state %s' % (command.name, self.state))

        if self.pending_sync_command is not None:
            yield from self.pending_sync_command.wait()

        if Commands.get(command.name).exec == Exec.sync:
            if self.pending_async_commands:
                yield from self.wait_async_pending_commands()
            self.pending_sync_command = command
        else:
            if self.pending_async_commands.get(command.untagged_resp_name) is not None:
                yield from self.pending_async_commands[command.untagged_resp_name].wait()
            self.pending_async_commands[command.untagged_resp_name] = command

        self.send(str(command))
        try:
            yield from command.wait()
        except CommandTimeout:
            if Commands.get(command.name).exec == Exec.sync:
                self.pending_sync_command = None
            else:
                self.pending_async_commands.pop(command.untagged_resp_name, None)
            raise

        return command.response

    @change_state
    @asyncio.coroutine
    def welcome(self, command):
        if 'PREAUTH' in command:
            self.state = AUTH
        elif 'OK' in command:
            self.state = NONAUTH
        else:
            raise Error(command)
        yield from self.capability()

    @change_state
    @asyncio.coroutine
    def login(self, user, password):
        response = yield from self.execute(
            Command('LOGIN', self.new_tag(), user, '"%s"' % password, loop=self.loop))

        if 'OK' == response.result:
            self.state = AUTH
        return response

    @change_state
    @asyncio.coroutine
    def logout(self):
        response = (yield from self.execute(Command('LOGOUT', self.new_tag(), loop=self.loop)))
        if 'OK' == response.result:
            self.state = LOGOUT
        return response

    @change_state
    @asyncio.coroutine
    def select(self, mailbox='INBOX'):
        response = yield from self.execute(
            Command('SELECT', self.new_tag(), mailbox, loop=self.loop))

        if 'OK' == response.result:
            self.state = SELECTED
        return response

    @change_state
    @asyncio.coroutine
    def close(self):
        response = yield from self.execute(Command('CLOSE', self.new_tag(), loop=self.loop))
        if response.result == 'OK':
            self.state = AUTH
        return response

    @asyncio.coroutine
    def examine(self, mailbox='INBOX'):
        response = yield from self.execute(
            Command('EXAMINE', self.new_tag(), mailbox, loop=self.loop))

        for line in response.lines:
            if 'EXISTS' in line:
                return Response(response.result, [line.replace(' EXISTS', '')])
        return response

    @asyncio.coroutine
    def idle(self):
        if 'IDLE' not in self.capabilities:
            Abort('server has not IDLE capability')
        return (yield from self.execute(Command('IDLE', self.new_tag(), loop=self.loop)))

    def idle_done(self):
        self.send('DONE')

    @asyncio.coroutine
    def search(self, *criteria, charset='utf-8', by_uid=False):
        args = ('CHARSET', charset) + criteria if charset is not None else criteria
        prefix = 'UID' if by_uid else ''

        return (yield from self.execute(
            Command('SEARCH', self.new_tag(), *args, prefix=prefix, loop=self.loop)))

    @asyncio.coroutine
    def fetch(self, message_set, message_parts, by_uid=False, timeout=None):
        return (yield from self.execute(
            Command('FETCH', self.new_tag(), message_set, message_parts,
                    prefix='UID' if by_uid else '', loop=self.loop, timeout=timeout)))

    @asyncio.coroutine
    def store(self, *args, by_uid=False):
        return (yield from self.execute(
            Command('STORE', self.new_tag(), *args,
                    prefix='UID' if by_uid else '', untagged_resp_name='FETCH', loop=self.loop)))

    @asyncio.coroutine
    def expunge(self):
        return (yield from self.execute(Command('EXPUNGE', self.new_tag(), loop=self.loop)))

    @asyncio.coroutine
    def uid(self, command, *criteria):
        if self.state not in Commands.get('UID').valid_states:
            raise Abort('command UID illegal in state %s' % self.state)

        if command.upper() == 'FETCH':
            return (yield from self.fetch(criteria[0], criteria[1], by_uid=True))
        if command.upper() == 'STORE':
            return (yield from self.store(*criteria, by_uid=True))
        if command.upper() == 'COPY':
            return (yield from self.copy(*criteria, by_uid=True))
        else:
            raise Abort('command UID only possible with COPY, FETCH or STORE (was %s)' % command.upper())

    @asyncio.coroutine
    def copy(self, *args, by_uid=True):
        return (yield from self.execute(
            Command('COPY', self.new_tag(), *args, prefix='UID' if by_uid else '', loop=self.loop)))

    @asyncio.coroutine
    def capability(self):
        response = yield from self.execute(Command('CAPABILITY', self.new_tag(), loop=self.loop))

        self.capabilities = response.lines[0].split()
        version = self.capabilities[0].upper()
        if version not in AllowedVersions:
            raise Error('server not IMAP4 compliant')
        else:
            self.imap_version = version

    @asyncio.coroutine
    def append(self, message_bytes, mailbox='INBOX', flags=None, date=None):
        args = [mailbox]
        if flags is not None:
            if (flags[0], flags[-1]) != ('(', ')'):
                args.append('(%s)' % flags)
            else:
                args.append(flags)
        if date is not None:
            args.append(time2internaldate(date))
        args.append('{%s}' % len(message_bytes))
        self.literal_data = message_bytes
        return (yield from self.execute(Command('APPEND', self.new_tag(), *args, loop=self.loop)))

    simple_commands = {'NOOP', 'CHECK', 'STATUS', 'CREATE', 'DELETE', 'RENAME',
                       'SUBSCRIBE', 'UNSUBSCRIBE', 'LSUB', 'LIST'}

    @asyncio.coroutine
    def simple_command(self, name, *args):
        if name not in self.simple_commands:
            raise NotImplementedError('simple command only available for %s' % self.simple_commands)
        return (yield from self.execute(Command(name, self.new_tag(), *args, loop=self.loop)))

    @asyncio.coroutine
    def wait_async_pending_commands(self):
        yield from asyncio.wait([asyncio.async(cmd.wait()) for cmd in self.pending_async_commands.values()])

    @asyncio.coroutine
    def wait(self, state_regexp):
        state_re = re.compile(state_regexp)
        with (yield from self.state_condition):
            yield from self.state_condition.wait_for(lambda: state_re.match(self.state))

    def has_pending_idle_command(self):
        return self.pending_sync_command is not None and self.pending_sync_command.name == 'IDLE'

    def _untagged_response(self, line):
        if self.pending_sync_command is not None:
            if self.has_pending_idle_command():
                asyncio.async(self.idle_queue.put(line))
                return
            else:
                self.pending_sync_command.append_to_resp(line)
                command = self.pending_sync_command
        else:
            match = message_data_re.match(line)
            if match:
                cmd_name, text = match.group(1), match.string
            else:
                cmd_name, _, text = line.partition(' ')
            command = self.pending_async_commands.get(cmd_name.upper())
            if command is not None:
                command.append_to_resp(text)
            else:
                log.info('ignored untagged response : %s' % line)
        return command

    def _response_done(self, line):
        log.debug('tagged status %s' % line)
        tag, _, response = line.partition(' ')

        if self.pending_sync_command is not None:
            if self.pending_sync_command.tag != tag:
                raise Abort('unexpected tagged response with pending sync command (%s) response: %s' %
                            (self.pending_sync_command, response))
            command = self.pending_sync_command
            self.pending_sync_command = None
        else:
            cmds = self._find_pending_async_cmd_by_tag(tag)
            if len(cmds) == 0:
                raise Abort('unexpected tagged (%s) response: %s' % (tag, response))
            elif len(cmds) > 1:
                raise Error('inconsistent state : two commands have the same tag (%s)' % cmds)
            command = cmds.pop()
            self.pending_async_commands.pop(command.untagged_resp_name)

        response_result, _, response_text = response.partition(' ')
        command.close(response_text, result=response_result)

    def _continuation(self, line):
        if 'literal data' in line:
            # APPEND case
            if self.literal_data is None:
                Abort('asked for literal data but have no literal data to send')
            self.transport.write(self.literal_data)
            self.transport.write(CRLF)
            self.literal_data = None
        elif self.has_pending_idle_command():
            asyncio.async(self.idle_queue.put(line))
        else:
            log.info('server says %s (ignored)' % line)

    def new_tag(self):
        tag = self.tagpre + str(self.tagnum)
        self.tagnum += 1
        return tag

    def _find_pending_async_cmd_by_tag(self, tag):
        return [c for c in self.pending_async_commands.values() if c is not None and c.tag == tag]


class IMAP4(object):
    TIMEOUT_SECONDS = 10

    def __init__(self, host='localhost', port=IMAP4_PORT, loop=asyncio.get_event_loop(), timeout=TIMEOUT_SECONDS):
        self.timeout = timeout
        self.port = port
        self.host = host
        self.protocol = None
        self.create_client(host, port, loop)

    def create_client(self, host, port, loop):
        self.protocol = IMAP4ClientProtocol(loop)
        loop.create_task(loop.create_connection(lambda: self.protocol, host, port))

    @asyncio.coroutine
    def wait_hello_from_server(self):
        yield from asyncio.wait_for(self.protocol.wait('AUTH|NONAUTH'), self.timeout)

    @asyncio.coroutine
    def login(self, user, password):
        return (yield from asyncio.wait_for(self.protocol.login(user, password), self.timeout))

    @asyncio.coroutine
    def logout(self):
        return (yield from asyncio.wait_for(self.protocol.logout(), self.timeout))

    @asyncio.coroutine
    def select(self, mailbox='INBOX'):
        return (yield from asyncio.wait_for(self.protocol.select(mailbox), self.timeout))

    def examine(self, mailbox='INBOX'):
        return (yield from asyncio.wait_for(self.protocol.examine(mailbox), self.timeout))

    @asyncio.coroutine
    def search(self, *criteria, charset='utf-8'):
        return (yield from asyncio.wait_for(self.protocol.search(*criteria, charset=charset), self.timeout))

    @asyncio.coroutine
    def uid_search(self, *criteria, charset='utf-8'):
        return (
            yield from asyncio.wait_for(self.protocol.search(*criteria, by_uid=True, charset=charset), self.timeout))

    @asyncio.coroutine
    def uid(self, command, *criteria):
        return (yield from asyncio.wait_for(self.protocol.uid(command, *criteria), self.timeout))

    @asyncio.coroutine
    def store(self, *criteria):
        return (yield from asyncio.wait_for(self.protocol.store(*criteria), self.timeout))

    @asyncio.coroutine
    def copy(self, *criteria):
        return (yield from asyncio.wait_for(self.protocol.copy(*criteria), self.timeout))

    @asyncio.coroutine
    def expunge(self):
        return (yield from asyncio.wait_for(self.protocol.expunge(), self.timeout))

    @asyncio.coroutine
    def fetch(self, message_set, message_parts):
        return (yield from self.protocol.fetch(message_set, message_parts, timeout=self.timeout))

    @asyncio.coroutine
    def idle(self):
        return (yield from self.protocol.idle())

    def idle_done(self):
        self.protocol.idle_done()

    @asyncio.coroutine
    def stop_wait_server_push(self):
        if self.protocol.has_pending_idle_command():
            yield from self.protocol.idle_queue.put('stop_wait_server_push')
            return True
        return False

    @asyncio.coroutine
    def wait_server_push(self):
        return (yield from self.protocol.idle_queue.get())

    @asyncio.coroutine
    def noop(self):
        return (yield from asyncio.wait_for(self.protocol.simple_command('NOOP'), self.timeout))

    @asyncio.coroutine
    def check(self):
        return (yield from asyncio.wait_for(self.protocol.simple_command('CHECK'), self.timeout))

    @asyncio.coroutine
    def status(self, mailbox, names):
        return (yield from asyncio.wait_for(self.protocol.simple_command('STATUS', mailbox, names), self.timeout))

    @asyncio.coroutine
    def subscribe(self, mailbox):
        return (yield from asyncio.wait_for(self.protocol.simple_command('SUBSCRIBE', mailbox), self.timeout))

    @asyncio.coroutine
    def unsubscribe(self, mailbox):
        return (yield from asyncio.wait_for(self.protocol.simple_command('UNSUBSCRIBE', mailbox), self.timeout))

    @asyncio.coroutine
    def lsub(self, reference_name, mailbox_name):
        return (yield from asyncio.wait_for(self.protocol.simple_command('LSUB', reference_name, mailbox_name), self.timeout))

    @asyncio.coroutine
    def create(self, mailbox_name):
        return (yield from asyncio.wait_for(self.protocol.simple_command('CREATE', mailbox_name), self.timeout))

    @asyncio.coroutine
    def delete(self, mailbox_name):
        return (yield from asyncio.wait_for(self.protocol.simple_command('DELETE', mailbox_name), self.timeout))

    @asyncio.coroutine
    def rename(self, old_mailbox_name, new_mailbox_name):
        return (yield from asyncio.wait_for(self.protocol.simple_command('RENAME', old_mailbox_name, new_mailbox_name), self.timeout))

    @asyncio.coroutine
    def list(self, reference_name, mailbox_pattern):
        return (yield from asyncio.wait_for(self.protocol.simple_command('LIST', reference_name, mailbox_pattern), self.timeout))

    @asyncio.coroutine
    def append(self, message_bytes, mailbox='INBOX', flags=None, date=None):
        return (yield from asyncio.wait_for(self.protocol.append(message_bytes, mailbox, flags, date), self.timeout))

    @asyncio.coroutine
    def close(self):
        return (yield from asyncio.wait_for(self.protocol.close(), self.timeout))


def extract_exists(response):
    for line in response.lines:
        if 'EXISTS' in line:
            return int(line.replace(' EXISTS', ''))


class IMAP4_SSL(IMAP4):
    def __init__(self, host='localhost', port=IMAP4_SSL_PORT, loop=asyncio.get_event_loop(),
                 timeout=IMAP4.TIMEOUT_SECONDS):
        super().__init__(host, port, loop, timeout)

    def create_client(self, host, port, loop):
        self.protocol = IMAP4ClientProtocol(loop)
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        loop.create_task(loop.create_connection(lambda: self.protocol, host, port, ssl=ssl_context))


# functions from imaplib
def int2ap(num):
    """Convert integer to A-P string representation."""
    val = ''
    ap = 'ABCDEFGHIJKLMNOP'
    num = int(abs(num))
    while num:
        num, mod = divmod(num, 16)
        val += ap[mod:mod + 1]
    return val

Months = ' Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split(' ')
Mon2num = {s.encode():n+1 for n, s in enumerate(Months[1:])}

def time2internaldate(date_time):
    """Convert date_time to IMAP4 INTERNALDATE representation.

    Return string in form: '"DD-Mmm-YYYY HH:MM:SS +HHMM"'.  The
    date_time argument can be a number (int or float) representing
    seconds since epoch (as returned by time.time()), a 9-tuple
    representing local time, an instance of time.struct_time (as
    returned by time.localtime()), an aware datetime instance or a
    double-quoted string.  In the last case, it is assumed to already
    be in the correct format.
    """
    if isinstance(date_time, (int, float)):
        dt = datetime.fromtimestamp(date_time, timezone.utc).astimezone()
    elif isinstance(date_time, tuple):
        try:
            gmtoff = date_time.tm_gmtoff
        except AttributeError:
            if time.daylight:
                dst = date_time[8]
                if dst == -1:
                    dst = time.localtime(time.mktime(date_time))[8]
                gmtoff = -(time.timezone, time.altzone)[dst]
            else:
                gmtoff = -time.timezone
        delta = timedelta(seconds=gmtoff)
        dt = datetime(*date_time[:6], tzinfo=timezone(delta))
    elif isinstance(date_time, datetime):
        if date_time.tzinfo is None:
            raise ValueError("date_time must be aware")
        dt = date_time
    elif isinstance(date_time, str) and (date_time[0],date_time[-1]) == ('"','"'):
        return date_time        # Assume in correct format
    else:
        raise ValueError("date_time not of a known type")
    fmt = '"%d-{}-%Y %H:%M:%S %z"'.format(Months[dt.month])
    return dt.strftime(fmt)
