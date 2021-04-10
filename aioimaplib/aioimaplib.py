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
import functools
import logging
import random
import re
import ssl
import time
from asyncio import set_event_loop
from collections import namedtuple
from copy import copy
from datetime import datetime, timezone, timedelta
from enum import Enum

try:
    from asyncio import get_running_loop
except ImportError:
    def get_running_loop() -> asyncio.AbstractEventLoop:
        loop = asyncio.get_event_loop()
        if not loop.is_running():
            raise RuntimeError("no running event loop")
        return loop

# to avoid imap servers to kill the connection after 30mn idling
# cf https://www.imapwiki.org/ClientImplementation/Synchronization

TWENTY_NINE_MINUTES = 1740
STOP_WAIT_SERVER_PUSH = 'stop_wait_server_push'

log = logging.getLogger(__name__)

STARTED     = 'STARTED'
CONNECTED   = 'CONNECTED'
NONAUTH     = 'NONAUTH'
AUTH        = 'AUTH'
SELECTED    = 'SELECTED'
LOGOUT      = 'LOGOUT'

ID_MAX_PAIRS_COUNT = 30
ID_MAX_FIELD_LEN = 30
ID_MAX_VALUE_LEN = 1024

AllowedVersions = ('IMAP4REV1', 'IMAP4')
Exec = Enum('Exec', 'is_sync is_async')
Cmd = namedtuple('Cmd', 'name           valid_states                exec')
Commands = {
    'APPEND':       Cmd('APPEND',       (AUTH, SELECTED),           Exec.is_sync),
    'AUTHENTICATE': Cmd('AUTHENTICATE', (NONAUTH,),                 Exec.is_sync),
    'CAPABILITY':   Cmd('CAPABILITY',   (NONAUTH, AUTH, SELECTED),  Exec.is_async),
    'CHECK':        Cmd('CHECK',        (SELECTED,),                Exec.is_async),
    'CLOSE':        Cmd('CLOSE',        (SELECTED,),                Exec.is_sync),
    'COMPRESS':     Cmd('COMPRESS',     (AUTH,),                    Exec.is_sync),
    'COPY':         Cmd('COPY',         (SELECTED,),                Exec.is_async),
    'CREATE':       Cmd('CREATE',       (AUTH, SELECTED),           Exec.is_async),
    'DELETE':       Cmd('DELETE',       (AUTH, SELECTED),           Exec.is_async),
    'DELETEACL':    Cmd('DELETEACL',    (AUTH, SELECTED),           Exec.is_async),
    'ENABLE':       Cmd('ENABLE',       (AUTH,),                    Exec.is_sync),
    'EXAMINE':      Cmd('EXAMINE',      (AUTH, SELECTED),           Exec.is_sync),
    'EXPUNGE':      Cmd('EXPUNGE',      (SELECTED,),                Exec.is_async),
    'FETCH':        Cmd('FETCH',        (SELECTED,),                Exec.is_async),
    'GETACL':       Cmd('GETACL',       (AUTH, SELECTED),           Exec.is_async),
    'GETMETADATA':  Cmd('GETMETADATA',  (AUTH, SELECTED),           Exec.is_async),
    'GETQUOTA':     Cmd('GETQUOTA',     (AUTH, SELECTED),           Exec.is_async),
    'GETQUOTAROOT': Cmd('GETQUOTAROOT', (AUTH, SELECTED),           Exec.is_async),
    'ID':           Cmd('ID',           (NONAUTH, AUTH, LOGOUT, SELECTED), Exec.is_async),
    'IDLE':         Cmd('IDLE',         (SELECTED,),                Exec.is_sync),
    'LIST':         Cmd('LIST',         (AUTH, SELECTED),           Exec.is_async),
    'LOGIN':        Cmd('LOGIN',        (NONAUTH,),                 Exec.is_sync),
    'LOGOUT':       Cmd('LOGOUT',       (NONAUTH, AUTH, LOGOUT, SELECTED), Exec.is_sync),
    'LSUB':         Cmd('LSUB',         (AUTH, SELECTED),           Exec.is_async),
    'MYRIGHTS':     Cmd('MYRIGHTS',     (AUTH, SELECTED),           Exec.is_async),
    'MOVE':         Cmd('MOVE',         (SELECTED,),                Exec.is_sync),
    'NAMESPACE':    Cmd('NAMESPACE',    (AUTH, SELECTED),           Exec.is_async),
    'NOOP':         Cmd('NOOP',         (NONAUTH, AUTH, SELECTED),  Exec.is_async),
    'RENAME':       Cmd('RENAME',       (AUTH, SELECTED),           Exec.is_async),
    'SEARCH':       Cmd('SEARCH',       (SELECTED,),                Exec.is_async),
    'SELECT':       Cmd('SELECT',       (AUTH, SELECTED),           Exec.is_sync),
    'SETACL':       Cmd('SETACL',       (AUTH, SELECTED),           Exec.is_sync),
    'SETMETADATA':  Cmd('SETMETADATA',  (AUTH, SELECTED),           Exec.is_async),
    'SETQUOTA':     Cmd('SETQUOTA',     (AUTH, SELECTED),           Exec.is_sync),
    'SORT':         Cmd('SORT',         (SELECTED,),                Exec.is_async),
    'STARTTLS':     Cmd('STARTTLS',     (NONAUTH,),                 Exec.is_sync),
    'STATUS':       Cmd('STATUS',       (AUTH, SELECTED),           Exec.is_async),
    'STORE':        Cmd('STORE',        (SELECTED,),                Exec.is_async),
    'SUBSCRIBE':    Cmd('SUBSCRIBE',    (AUTH, SELECTED),           Exec.is_sync),
    'THREAD':       Cmd('THREAD',       (SELECTED,),                Exec.is_async),
    'UID':          Cmd('UID',          (SELECTED,),                Exec.is_async),
    'UNSUBSCRIBE':  Cmd('UNSUBSCRIBE',  (AUTH, SELECTED),           Exec.is_sync),
    # for testing
    'DELAY':        Cmd('DELAY',        (AUTH, SELECTED),           Exec.is_sync),
}

Response = namedtuple('Response', 'result lines')


def quoted(s):
    """ Given a string, return a quoted string as per RFC 3501, section 9."""
    if isinstance(s, str):
        return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'
    else:
        return b'"' + s.replace(b'\\', b'\\\\').replace(b'"', b'\\"') + b'"'

def unquoted(s):
    """ Given a string, return an unquoted string as per RFC 3501, section 9."""
    if isinstance(s, str):
        if (s[0], s[-1]) == ('"', '"'):
            return s[1:-1].replace('\\"', '"').replace('\\\\', '\\')
        return s
    else:
        if (s[0], s[-1]) == (b'"', b'"'):
            return s[1:-1].replace(b'\\"', '"').replace(b'\\\\', b'\\')
    return s


def arguments_rfc2971(**kwargs):
    if kwargs:
        if len(kwargs) > ID_MAX_PAIRS_COUNT:
            raise ValueError('Must not send more than 30 field-value pairs')
        args = ['(']
        for field, value in kwargs.items():
            field = quoted(str(field))
            value = quoted(str(value)) if value is not None else 'NIL'
            if len(field) > ID_MAX_FIELD_LEN:
                raise ValueError('Field: {} must not be longer than 30'.format(field))
            if len(value) > ID_MAX_VALUE_LEN:
                raise ValueError('Field: {} value: {} must not be longer than 1024'.format(field, value))
            args.extend((field, value))
        args.append(')')
    else:
        args = ['NIL']
    return args


class Command(object):
    def __init__(self, name, tag, *args, by_uid=False, untagged_name=None, loop=None, timeout=None):
        self.name = name
        self.tag = tag
        self.args = args
        self.by_uid = by_uid
        if untagged_name is None:
            self.untagged_names = (name,)
        elif isinstance(untagged_name, str):
            self.untagged_names = (untagged_name,)
        else:  # expecting iterable
            self.untagged_names = untagged_name

        self.response = None
        self._exception = None
        self._loop = loop if loop is not None else get_running_loop()
        self._event = asyncio.Event()
        self._timeout = timeout
        self._timer = asyncio.Handle(lambda: None, None, self._loop)  # fake timer
        self._set_timer()
        self._literal_data = None
        self._expected_size = 0

    def __repr__(self):
        return '{tag} {prefix}{name}{space}{args}'.format(
            tag=self.tag,
            prefix='UID ' if self.by_uid else '',
            name=self.name,
            space=' ' if self.args else '',
            args=' '.join(self.args),
        )

    # for tests
    def __eq__(self, other):
        return other is not None and other.tag == self.tag and other.name == self.name and other.args == self.args

    def close(self, line, result):
        self.append_to_resp(line, result=result)
        self._timer.cancel()
        self._event.set()

    def begin_literal_data(self, expected_size, literal_data=b''):
        self._expected_size = expected_size
        self._literal_data = bytearray()
        return self.append_literal_data(literal_data)

    def wait_literal_data(self):
        return self._expected_size != 0 and len(self._literal_data) != self._expected_size

    def wait_data(self):
        return self.wait_literal_data()

    def append_literal_data(self, data):
        nb_bytes_to_add = self._expected_size - len(self._literal_data)
        self._literal_data += data[0:nb_bytes_to_add]
        if not self.wait_literal_data():
            self.append_to_resp(self._literal_data)
            self._end_literal_data()
        self._reset_timer()
        return data[nb_bytes_to_add:]

    def append_to_resp(self, line, result='Pending'):
        try:
            self.response.lines.append(line)
            if result != self.response.result:
                self.response = Response(result, self.response.lines)
        except AttributeError:
            self.response = Response(result, [line])
        self._reset_timer()

    async def wait(self):
        await self._event.wait()
        if self._exception is not None:
            raise self._exception

    def flush(self):
        pass

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


class FetchCommand(Command):
    FETCH_MESSAGE_DATA_RE = re.compile(r'[0-9]+ FETCH \(')

    def __init__(self, tag, message_set, parts, modifiers=None, untagged_name=None, **kwargs):
        if modifiers:
            args = (message_set, parts, modifiers)
            if 'VANISHED' in modifiers.upper():
                untagged_name = ('FETCH', 'VANISHED')
        else:
            args = (message_set, parts)
        super().__init__('FETCH', tag, *args, untagged_name=untagged_name, **kwargs)

    def wait_data(self):
        if self.response is None:
            return False
        last_line = self.response.lines[-1]
        return not isinstance(last_line, str) or \
               not (last_line.endswith(')') or last_line.startswith('(EARLIER)'))


class IdleCommand(Command):
    def __init__(self, tag, queue, *args, **kwargs):
        super().__init__('IDLE', tag, *args, **kwargs)
        self.queue = queue
        self.buffer = list()

    def append_to_resp(self, line, result='Pending'):
        if result != 'Pending':
            super().append_to_resp(line, result)
        else:
            self.buffer.append(line)

    def flush(self):
        if self.buffer:
            self.queue.put_nowait(copy(self.buffer))
            self.buffer.clear()


class AioImapException(Exception):
    def __init__(self, reason):
        super().__init__(reason)


class Error(AioImapException):
    pass


class Abort(Error):
    pass


class CommandTimeout(AioImapException):
    pass


class IncompleteRead(AioImapException):
    def __init__(self, cmd, data=b''):
        self.cmd = cmd
        self.data = data


def change_state(coro):
    @functools.wraps(coro)
    async def wrapper(self, *args, **kargs):
        async with self.state_condition:
            res = await coro(self, *args, **kargs)
            log.debug('state -> %s' % self.state)
            self.state_condition.notify_all()
            return res

    return wrapper


# cf https://tools.ietf.org/html/rfc3501#section-9
# untagged responses types
literal_data_re = re.compile(rb'.*\{(?P<size>\d+)\}$')
message_data_re = re.compile(r'[0-9]+ (FETCH|EXPUNGE)')
tagged_status_response_re = re.compile(r'[A-Z0-9]+ (OK|NO|BAD)')
capability_re = re.compile(r'\[CAPABILITY ([^\]]+)\]')


class IMAP4ClientProtocol(asyncio.Protocol):
    def __init__(self, loop, conn_lost_cb=None):
        self.loop = loop if loop is not None else get_running_loop()
        set_event_loop(self.loop)
        self.transport = None
        self.state = STARTED
        self.state_condition = asyncio.Condition()
        self.capabilities = set()
        self.pending_async_commands = dict()
        self.pending_sync_command = None
        self.idle_queue = asyncio.Queue()
        self.imap_version = None
        self.literal_data = None
        self.incomplete_line = b''
        self.current_command = None
        self.conn_lost_cb = conn_lost_cb

        self.tagnum = 0
        self.tagpre = int2ap(random.randint(4096, 65535))

    def connection_made(self, transport):
        self.transport = transport
        self.state = CONNECTED

    def data_received(self, d):
        log.debug('Received : %s' % d)
        try:
            self._handle_responses(self.incomplete_line + d, self.current_command)
            self.incomplete_line = b''
            self.current_command = None
        except IncompleteRead as incomplete_read:
            self.current_command = incomplete_read.cmd
            self.incomplete_line = incomplete_read.data

    def connection_lost(self, exc):
        log.debug('connection lost: %s', exc)
        if self.conn_lost_cb is not None:
            self.conn_lost_cb(exc)

    def _handle_responses(self, data, current_cmd=None):
        if not data:
            if self.pending_sync_command is not None:
                self.pending_sync_command.flush()
            if current_cmd is not None and current_cmd.wait_data():
                raise IncompleteRead(current_cmd)
            return

        if current_cmd is not None and current_cmd.wait_literal_data():
            data = current_cmd.append_literal_data(data)
            if current_cmd.wait_literal_data():
                raise IncompleteRead(current_cmd)

        line, separator, tail = data.partition(b'\r\n')
        if not separator:
            raise IncompleteRead(current_cmd, data)

        cmd = self._handle_line(line.decode(), current_cmd)

        begin_literal = literal_data_re.match(line)
        if begin_literal:
            size = int(begin_literal.group('size'))
            if cmd is None:
                cmd = Command('NIL', 'unused')
            cmd.begin_literal_data(size)
            self._handle_responses(tail, current_cmd=cmd)
        elif cmd is not None and cmd.wait_data():
            self._handle_responses(tail, current_cmd=cmd)
        else:
            self._handle_responses(tail)

    def _handle_line(self, line, current_cmd):
        if not line:
            return
        if self.state == CONNECTED:
            asyncio.ensure_future(self.welcome(line))
        elif tagged_status_response_re.match(line):
            self._response_done(line)
        elif current_cmd is not None:
            current_cmd.append_to_resp(line)
            return current_cmd
        elif line.startswith('*'):
            return self._untagged_response(line)
        elif line.startswith('+'):
            self._continuation(line)
        else:
            log.info('unknown data received %s' % line)

    def send(self, line):
        data = ('%s\r\n' % line).encode()
        log.debug('Sending : %s' % data)
        self.transport.write(data)

    async def execute(self, command):
        if self.pending_sync_command is not None:
            await self.pending_sync_command.wait()

        if Commands[command.name].exec == Exec.is_sync:
            if self.pending_async_commands:
                await self.wait_async_pending_commands()
            self.pending_sync_command = command
        else:
            for untagged_name in command.untagged_names:
                pending_same_name = self.pending_async_commands.get(untagged_name)
                if pending_same_name is not None:
                    await pending_same_name.wait()
                self.pending_async_commands[untagged_name] = command

        self.send(str(command))
        try:
            await command.wait()
        except CommandTimeout:
            if Commands[command.name].exec == Exec.is_sync:
                self.pending_sync_command = None
            else:
                for untagged_name in command.untagged_names:
                    self.pending_async_commands.pop(untagged_name, None)
            raise

        return command.response

    @change_state
    async def welcome(self, command):
        if 'PREAUTH' in command:
            self.state = AUTH
        elif 'OK' in command:
            self.state = NONAUTH
            match = capability_re.search(command)
            if match:
                self.update_capabilities(match.group(1))
        else:
            raise Error(command)

        if not self.capabilities:
            await self.capability()

    @change_state
    async def login(self, user, password):
        if self.state not in Commands['LOGIN'].valid_states:
            raise Error('command LOGIN illegal in state %s' % (self.state,))

        response = await self.execute(
            Command('LOGIN', self.new_tag(), user, '%s' % quoted(password), loop=self.loop))

        if 'OK' == response.result:
            self.state = AUTH
            for line in response.lines:
                match = capability_re.search(line)
                if match:
                    self.update_capabilities(match.group(1))
        return response

    @change_state
    async def logout(self):
        response = await self.execute(Command('LOGOUT', self.new_tag(), loop=self.loop))
        if 'OK' == response.result:
            self.state = LOGOUT
        return response

    @change_state
    async def select(self, mailbox='INBOX'):
        response = await self.execute(
            Command('SELECT', self.new_tag(), mailbox, loop=self.loop))

        if 'OK' == response.result:
            self.state = SELECTED
        return response

    @change_state
    async def close(self):
        response = await self.execute(Command('CLOSE', self.new_tag(), loop=self.loop))
        if response.result == 'OK':
            self.state = AUTH
        return response

    async def idle(self):
        if 'IDLE' not in self.capabilities:
            raise Abort('server has not IDLE capability')
        return await self.execute(IdleCommand(self.new_tag(), self.idle_queue, loop=self.loop))

    def has_pending_idle_command(self):
        return self.pending_sync_command is not None and self.pending_sync_command.name == 'IDLE'

    def idle_done(self):
        self.send('DONE')

    async def search(self, *criteria, charset='UTF-8', by_uid=False, ret=None, timeout=None):
        # TODO: don't wait for concurrent esearch commands
        #       because esearch untagged response contains tag
        if charset:
            criteria = ('CHARSET', charset) + criteria
        if ret:
            if 'ESEARCH' not in self.capabilities:
                raise Abort('server has not ESEARCH capability')
            criteria = ('RETURN', '(%s)' % ret) + criteria
        return await self.execute(
            Command('SEARCH',
                    self.new_tag(),
                    *criteria,
                    untagged_name='ESEARCH' if ret else 'SEARCH',
                    by_uid=by_uid,
                    loop=self.loop,
                    timeout=timeout,
                    ))

    async def thread(self, algorithm, *criteria, charset='UTF-8', by_uid=False, timeout=None):
        if 'THREAD='+algorithm.upper() not in self.capabilities:
            raise Abort('server has not THREAD=%s capability' % algorithm.upper())
        return await self.execute(
            Command('THREAD',
                    self.new_tag(),
                    algorithm,
                    charset,
                    *criteria,
                    by_uid=by_uid,
                    loop=self.loop,
                    timeout=timeout,
                    ))

    async def sort(self, sort, search='ALL', charset='UTF-8', by_uid=False, ret=None, timeout=None):
        # TODO: don't wait for concurrent esort commands
        #       because esort untagged response contains tag

        args = ['(%s)' % sort, charset, search]
        if ret:
            if 'ESORT' not in self.capabilities:
                raise Abort('server has not ESORT capability')
            args.insert(0, 'RETURN (%s)' % ret)
        return await self.execute(
            Command('SORT',
                    self.new_tag(),
                    *args,
                    untagged_name='ESEARCH' if ret else 'SORT',
                    by_uid=by_uid,
                    loop=self.loop,
                    timeout=timeout,
                    ))

    async def fetch(self, message_set, parts, modifiers=None, by_uid=False, timeout=None):
        return await self.execute(
            FetchCommand(self.new_tag(), message_set, parts, modifiers,
                         by_uid=by_uid, loop=self.loop, timeout=timeout))

    async def store(self, *args, by_uid=False, timeout=None):
        return await self.execute(
            Command('STORE', self.new_tag(), *args, by_uid=by_uid,
                    untagged_name='FETCH', loop=self.loop, timeout=timeout))

    async def expunge(self, *args, by_uid=False, timeout=None):
        return await self.execute(
            Command('EXPUNGE', self.new_tag(), *args, by_uid=by_uid,
                    loop=self.loop, timeout=timeout))

    async def uid(self, command, *criteria, timeout=None):
        if self.state not in Commands['UID'].valid_states:
            raise Abort('command UID illegal in state %s' % self.state)

        command = command.lower()
        if command == 'expunge':
            if 'UIDPLUS' not in self.capabilities:
                raise Abort('EXPUNGE with uids is only valid with UIDPLUS capability. UIDPLUS not in (%s)' % self.capabilities)
        elif command not in {'fetch', 'store', 'copy', 'move', 'search', 'sort'}:
            raise Abort('command UID only possible with COPY, FETCH, MOVE,'
                        ' SEARCH, SORT, EXPUNGE (w/UIDPLUS) or STORE'
                        ' (was %s)' % (command.upper(),))
        return await getattr(self, command)(*criteria, by_uid=True, timeout=timeout)

    async def copy(self, *args, by_uid=False, timeout=None):
        return await self.execute(
            Command('COPY', self.new_tag(), *args, by_uid=by_uid,
                    loop=self.loop, timeout=timeout))

    async def move(self, uid_set, mailbox, by_uid=False, timeout=None):
        if 'MOVE' not in self.capabilities:
            raise Abort('server has not MOVE capability')

        return await self.execute(
            Command('MOVE', self.new_tag(), uid_set, mailbox, by_uid=by_uid,
                    loop=self.loop, timeout=timeout))

    async def capability(self):
        response = await self.execute(Command('CAPABILITY', self.new_tag(), loop=self.loop))
        self.update_capabilities(response.lines[0])

    def update_capabilities(self, string):
        self.capabilities = set(string.upper().strip().split())
        for version in AllowedVersions:
            if version in self.capabilities:
                self.imap_version = version
                break
        else:
            raise Error('server not IMAP4 compliant')

    async def append(self, message_bytes, mailbox='INBOX', flags=None, date=None, timeout=None):
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
        return await self.execute(Command('APPEND', self.new_tag(), *args, loop=self.loop, timeout=timeout))

    async def getmetadata(self, mailbox, metadata, options=None, timeout=None):
        args = () if options is None else (options)
        return await self.execute(Command('GETMETADATA', self.new_tag(), mailbox, metadata, *args,
                                          untagged_name='METADATA', loop=self.loop, timeout=timeout))

    async def setmetadata(self, mailbox, metadata, timeout=None):
        return await self.execute(Command('SETMETADATA', self.new_tag(), mailbox, metadata, loop=self.loop, timeout=None))

    async def id(self, **kwargs):
        args = arguments_rfc2971(**kwargs)
        return await self.execute(Command('ID', self.new_tag(), *args, loop=self.loop))

    simple_commands = {'NOOP', 'CHECK', 'STATUS', 'CREATE', 'DELETE', 'RENAME',
                       'SUBSCRIBE', 'UNSUBSCRIBE', 'LSUB', 'LIST', 'EXAMINE', 'ENABLE'}

    async def namespace(self):
        if 'NAMESPACE' not in self.capabilities:
            raise Abort('server has not NAMESPACE capability')
        return (await self.execute(Command('NAMESPACE', self.new_tag(), loop=self.loop)))

    async def list(self, reference_name='""', mailbox_pattern='*', ret=None, timeout=None):
        args = [reference_name, mailbox_pattern]
        untagged_name = None
        if ret:
            args.append('RETURN (%s)' % ret)
            if 'STATUS' in ret.upper():
                untagged_name = ('LIST', 'STATUS')
        return await self.execute(
            Command('LIST', self.new_tag(), *args,
                    untagged_name=untagged_name,
                    timeout=timeout))

    async def simple_command(self, name, *args):
        if name not in self.simple_commands:
            raise NotImplementedError('simple command only available for %s' % self.simple_commands)
        return await self.execute(Command(name, self.new_tag(), *args, loop=self.loop))

    async def wait_async_pending_commands(self):
        await asyncio.wait([asyncio.ensure_future(cmd.wait()) for cmd in self.pending_async_commands.values()])

    async def wait(self, states):
        async with self.state_condition:
            await self.state_condition.wait_for(lambda: self.state in states)

    def _untagged_response(self, line):
        line = line[2:]  # remove '* '
        if self.pending_sync_command is not None:
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
                # noop is async and servers can send untagged responses
                command = self.pending_async_commands.get('NOOP')
                if command is not None:
                    command.append_to_resp(line)
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
            elif len(cmds) > 1 and cmds[0] is not cmds[1]:
                # LIST-STATUS and FETCH VANISHED is 2 times in pending_async_commands
                raise Error('inconsistent state : two commands have the same tag (%s)' % cmds)
            command = cmds.pop()
            for untagged_name in command.untagged_names:
                self.pending_async_commands.pop(untagged_name)

        result, _, text = response.partition(' ')
        command.close(text, result)

    def _continuation(self, line):
        if self.pending_sync_command is not None and self.pending_sync_command.name == 'APPEND':
            if self.literal_data is None:
                Abort('asked for literal data but have no literal data to send')
            self.transport.write(self.literal_data)
            self.transport.write(b'\r\n')
            self.literal_data = None
        elif self.pending_sync_command is not None:
            log.debug('continuation line appended to pending sync command %s : %s' % (self.pending_sync_command, line))
            self.pending_sync_command.append_to_resp(line)
            self.pending_sync_command.flush()
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

    def __init__(self, host='127.0.0.1', port=143, loop=None, timeout=TIMEOUT_SECONDS, conn_lost_cb=None, ssl_context=None):
        self.host = host
        self.port = port
        self.loop = asyncio.get_running_loop() if loop is None else loop
        self.timeout = timeout
        self.conn_lost_cb = conn_lost_cb
        self.ssl_context = ssl_context
        self.protocol = None
        self._idle_waiter = None
        self.create_client(host, port, self.loop, conn_lost_cb, ssl_context)

    def create_client(self, host, port, loop, conn_lost_cb=None, ssl_context=None):
        local_loop = loop if loop is not None else get_running_loop()
        self.protocol = IMAP4ClientProtocol(local_loop, conn_lost_cb)
        local_loop.create_task(local_loop.create_connection(lambda: self.protocol, host, port, ssl=ssl_context))

    def get_state(self):
        return self.protocol and self.protocol.state

    async def wait_hello_from_server(self):
        await asyncio.wait_for(self.protocol.wait({AUTH, NONAUTH}), self.timeout)

    async def login(self, user, password):
        return await asyncio.wait_for(self.protocol.login(user, password), self.timeout)

    async def logout(self):
        if self.protocol is not None:
            return await asyncio.wait_for(self.protocol.logout(), self.timeout)

    async def select(self, mailbox='INBOX'):
        return await asyncio.wait_for(self.protocol.select(mailbox), self.timeout)

    async def search(self, *criteria, charset='UTF-8', ret=None):
        return await self.protocol.search(*criteria, charset=charset, ret=ret, timeout=self.timeout)

    async def uid_search(self, *criteria, charset='UTF-8', ret=None):
        return await self.protocol.search(*criteria, by_uid=True, charset=charset, ret=ret, timeout=self.timeout)

    async def thread(self, algorithm='REFERENCES', search='ALL', charset='UTF-8'):
        return await self.protocol.thread(algorithm, search, charset=charset, timeout=self.timeout)

    async def uid_thread(self, algorithm='REFERENCES', search='ALL', charset='UTF-8'):
        return await self.protocol.thread(algorithm, search, charset=charset, by_uid=True, timeout=self.timeout)

    async def sort(self, search, sort='ALL', charset='UTF-8', ret=None):
        return await self.protocol.sort(search, sort, charset=charset, ret=ret, timeout=self.timeout)

    async def uid_sort(self, search, sort='ALL', charset='UTF-8', ret=None):
        return await self.protocol.sort(search, sort, by_uid=True, charset=charset, ret=ret, timeout=self.timeout)

    async def uid(self, command, *criteria):
        return await self.protocol.uid(command, *criteria, timeout=self.timeout)

    async def store(self, *criteria):
        return await self.protocol.store(*criteria, timeout=self.timeout)

    async def uid_store(self, *criteria):
        return await self.protocol.store(*criteria, by_uid=True, timeout=self.timeout)

    async def copy(self, *criteria):
        return await self.protocol.copy(*criteria, timeout=self.timeout)

    async def uid_copy(self, *criteria):
        return await self.protocol.copy(*criteria, by_uid=True, timeout=self.timeout)

    async def expunge(self):
        return await self.protocol.expunge(timeout=self.timeout)

    async def uid_expunge(self, *args):
        return await self.protocol.expunge(*args, by_uid=True, timeout=self.timeout)

    async def fetch(self, message_set, message_parts, modifiers=None):
        return await self.protocol.fetch(message_set, message_parts, modifiers,
                                         timeout=self.timeout)

    async def uid_fetch(self, message_set, message_parts, modifiers=None):
        return await self.protocol.fetch(message_set, message_parts, modifiers,
                                         by_uid=True, timeout=self.timeout)

    async def idle(self):
        return await self.protocol.idle()

    def idle_done(self):
        if self._idle_waiter is not None:
            self._idle_waiter.cancel()
        self.protocol.idle_done()

    async def stop_wait_server_push(self):
        if self.protocol.has_pending_idle_command():
            await self.protocol.idle_queue.put(STOP_WAIT_SERVER_PUSH)
            return True
        return False

    async def wait_server_push(self, timeout=TWENTY_NINE_MINUTES):
        return await asyncio.wait_for(self.protocol.idle_queue.get(), timeout=timeout)

    async def idle_start(self, timeout=TWENTY_NINE_MINUTES):
        if self._idle_waiter is not None:
            self._idle_waiter.cancel()
        idle = asyncio.ensure_future(self.idle())
        self._idle_waiter = self.protocol.loop.call_later(timeout, lambda: asyncio.ensure_future(self.stop_wait_server_push()))
        await self.wait_server_push(self.timeout) # idling continuation
        return idle

    def has_pending_idle(self):
        return self.protocol.has_pending_idle_command()

    async def id(self, **kwargs):
        if self.protocol is None:
            await self.create_client()
            await self.wait_hello_from_server()
        return await asyncio.wait_for(self.protocol.id(**kwargs), self.timeout)

    async def namespace(self):
        return await asyncio.wait_for(self.protocol.namespace(), self.timeout)

    async def noop(self):
        return await asyncio.wait_for(self.protocol.simple_command('NOOP'), self.timeout)

    async def check(self):
        return await asyncio.wait_for(self.protocol.simple_command('CHECK'), self.timeout)

    async def examine(self, mailbox='INBOX'):
        return await asyncio.wait_for(self.protocol.simple_command('EXAMINE', mailbox), self.timeout)

    async def status(self, mailbox, names):
        return await asyncio.wait_for(self.protocol.simple_command('STATUS', mailbox, names), self.timeout)

    async def subscribe(self, mailbox):
        return await asyncio.wait_for(self.protocol.simple_command('SUBSCRIBE', mailbox), self.timeout)

    async def unsubscribe(self, mailbox):
        return await asyncio.wait_for(self.protocol.simple_command('UNSUBSCRIBE', mailbox), self.timeout)

    async def lsub(self, reference_name, mailbox_name):
        return await asyncio.wait_for(self.protocol.simple_command('LSUB', reference_name, mailbox_name), self.timeout)

    async def create(self, mailbox_name):
        return await asyncio.wait_for(self.protocol.simple_command('CREATE', mailbox_name), self.timeout)

    async def delete(self, mailbox_name):
        return await asyncio.wait_for(self.protocol.simple_command('DELETE', mailbox_name), self.timeout)

    async def rename(self, old_mailbox_name, new_mailbox_name):
        return await asyncio.wait_for(self.protocol.simple_command('RENAME', old_mailbox_name, new_mailbox_name), self.timeout)

    async def list(self, reference_name='""', mailbox_pattern='*', ret=None):
        return await self.protocol.list(reference_name, mailbox_pattern, ret, timeout=self.timeout)

    async def append(self, message_bytes, mailbox='INBOX', flags=None, date=None):
        return await self.protocol.append(message_bytes, mailbox, flags, date, timeout=self.timeout)

    async def close(self):
        return await asyncio.wait_for(self.protocol.close(), self.timeout)

    async def move(self, seq_set, mailbox):
        return await asyncio.wait_for(self.protocol.move(seq_set, mailbox), self.timeout)

    async def uid_move(self, uid_set, mailbox):
        return await asyncio.wait_for(self.protocol.move(uid_set, mailbox, by_uid=True), self.timeout)

    async def enable(self, capability):
        if 'ENABLE' not in self.protocol.capabilities:
            raise Abort('server has not ENABLE capability')
        return await asyncio.wait_for(self.protocol.simple_command('ENABLE', capability), self.timeout)

    async def getmetadata(self, mailbox, metadata, options=None):
        return await self.protocol.getmetadata(mailbox, metadata, options, timeout=self.timeout)

    async def setmetadata(self, mailbox, metadata, value):
        return await self.protocol.setmetadata(mailbox, metadata, timeout=self.timeout)

    def has_capability(self, capability):
        return capability in self.protocol.capabilities


def extract_exists(response):
    for line in response.lines:
        if 'EXISTS' in line:
            return int(line.replace(' EXISTS', ''))


class IMAP4_SSL(IMAP4):
    def __init__(self, host='127.0.0.1', port=993, loop=None ,
                 timeout=IMAP4.TIMEOUT_SECONDS, ssl_context=None):
        if ssl_context is None:
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        super().__init__(host, port, loop, timeout, None, ssl_context)


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


def iter_messageset(s):
    """Parses IMAP messageset
    yields integers in given order without sorting
    does not remove duplicates
    example: "1,3:5,1:2" -> 1,3,4,5,1,2
    raises ValueError if
    """
    for pair in s.split(','):
        start, _, end = pair.partition(':')
        for i in range(int(start or 1), int(end or start or 0)+1):
            yield i


thread_atom_re = re.compile(r'([()]|[0-9]+)')
def parse_thread(lines):
    """returns list of ints|lists from first thread line"""
    for line in lines:
        atoms = thread_atom_re.findall(line)
        return nest_atoms(atoms)[0]


def parse_fetch(lines):
    """Iterates over fetch lines
    yields (str, dict)
    Need only lines without last line 'Fetch completed...'
    """
    parser = ResponseParser()
    for line in lines:
        if parser.feed(line):
            try:
                seq, _, vv = parser.values()
            except ValueError:
                print(parser.values())
            yield seq, {vv[i]: vv[i+1] for i in range(0, len(vv), 2)}
            parser = ResponseParser()


def parse_metadata(lines):
    """Iterates over metadata lines
    yields (str, dict)
    Need only lines without last line 'Fetch completed...'
    """
    parser = ResponseParser()
    for line in lines:
        if parser.feed(line):
            try:
                name, vv = parser.values()
            except ValueError:
                print(parser.values())
            yield name, {vv[i]: vv[i+1] for i in range(0, len(vv), 2)}
            parser = ResponseParser()


class ResponseParser:
    __slots__ = 'atoms', 'literal_next'

    # doesn't work for BODY.PEEK[HEADER.FIELDS (SUBJECT)]
    # and similar with brackets inside field name
    atom_re = re.compile(r'''
        ( # brackets
        [()]
        | # quoted
        \"(?:|.*?[^\\](?:(?:\\\\)+)?)\"
        | # other value without space
        [^()\s]+
        )''', re.VERBOSE)

    def __init__(self):
        self.atoms = []
        self.literal_next = False

    def feed(self, line):
        if self.literal_next:
            self.atoms[-1] = line
            self.literal_next = False
            return False
        atoms = self.atom_re.findall(line)
        self.atoms.extend(atoms)
        if atoms[-1][-1] == '}':
            self.literal_next = True
            return False
        return True

    def values(self):
        values, i = nest_atoms(self.atoms)
        return values

def nest_atoms(atoms, i=0):
    values = []
    while i < len(atoms):
        value = atoms[i]
        if value == '(':
            value, i = nest_atoms(atoms, i+1)
        elif value == ')':
            return values, i
        values.append(value)
        i += 1
    return values, i


list_re = re.compile(r'\(([^)]*)\) ([^ ]+) (.+)')
def parse_list(lines):
    """
    Iterate over list lines
    yields tuples (flags:set, sep:str, name:str)
    """
    for line in lines:
        match = list_re.match(line)
        if match:
            flags, sep, name = match.group(1, 2, 3)
            yield set(flags.split()), unquoted(sep), name


status_re = re.compile(r'(\S+|\".*?[^\\](?:(?:\\\\)+)?\")\s+\((.*)\)')
def parse_status(lines):
    """
    Iterate over status lines
    yields dicts
    """
    for line in lines:
        match = status_re.match(line)
        if match:
            ss = match.group(2).split()
            return {ss[i]: ss[i + 1] for i in range(0, len(ss), 2)}
    return {}


def parse_list_status(lines):
    """
    Iterate over list lines
    yields tuples (flags:set, sep, name, status:dict)
    """
    mailboxes = {}
    for line in lines:
        match = list_re.match(line)
        if match:
            flags, sep, name = match.group(1, 2, 3)
            mailboxes[name] = (set(flags.split()), unquoted(sep), name, {})
        else:
            match = status_re.match(line)
            if match:
                name = match.group(1)
                try:
                    status = mailboxes[name][3]
                except KeyError:
                    continue
                ss = match.group(2).split()
                status.update((ss[i], ss[i+1]) for i in range(0, len(ss), 2))
    return mailboxes.values()


esearch_re = re.compile(r'\(TAG "([^"]+)"\)(?: UID)?\s*(.*)')
def parse_esearch(lines):
    """
    Parses first esearch line
    returns dict or empty dict
    """
    for line in lines:
        match = esearch_re.match(line)
        if match:
            dd = match.group(2).split()
            return {dd[i]: dd[i+1] for i in range(0, len(dd), 2)}
    return {}


def format_messageset(ints) -> str:
    "Sorts and compresses sequence of integers to str in IMAP message set format"
    return encode_messageset(ints).decode()


def encode_messageset(ints) -> bytearray:
    """Sorts and compresses sequence of integers
    returns bytearray in IMAP message set format"""
    out = bytearray()
    last = None
    skipped = False
    for i in sorted(ints):
        if i - 1 == last:
            skipped = True
        elif last is None:
            out += b'%d' % i
        elif i - 1 > last:
            if skipped:
                out += b':%d,%d' % (last, i)
                skipped = False
            else:
                out += b',%d' % (i)
        last = i
    if skipped:
        out += b':%d' % last
    return out
