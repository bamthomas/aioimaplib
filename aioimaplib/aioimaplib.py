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
import sys
import time
from asyncio import BaseTransport, Future
from collections import namedtuple
from copy import copy
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Union, Any, Coroutine, Callable, Optional, Pattern, List

# to avoid imap servers to kill the connection after 30mn idling
# cf https://www.imapwiki.org/ClientImplementation/Synchronization
TWENTY_NINE_MINUTES = 1740.0

STOP_WAIT_SERVER_PUSH = ['stop_wait_server_push']
PY37_OR_LATER = sys.version_info[:2] >= (3, 7)

log = logging.getLogger(__name__)

IMAP4_PORT = 143
IMAP4_SSL_PORT = 993
STARTED, CONNECTED, NONAUTH, AUTH, SELECTED, LOGOUT = 'STARTED', 'CONNECTED', 'NONAUTH', 'AUTH', 'SELECTED', 'LOGOUT'
CRLF = b'\r\n'

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


def get_running_loop() -> asyncio.AbstractEventLoop:
    if PY37_OR_LATER:
        return asyncio.get_running_loop()

    loop = asyncio.get_event_loop()
    if not loop.is_running():
        raise RuntimeError("no running event loop")

    return loop


def quoted(arg: str) -> str:
    """ Given a string, return a quoted string as per RFC 3501, section 9.

        Implementation copied from https://github.com/mjs/imapclient
        (imapclient/imapclient.py), 3-clause BSD license
    """
    arg = arg.replace('\\', '\\\\')
    arg = arg.replace('"', '\\"')
    return '"' + arg + '"'


def arguments_rfs2971(**kwargs: Union[dict, list, str]) -> Union[dict, list]:
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
    def __init__(self, name: str, tag: str, *args, prefix: str = None, untagged_resp_name: str = None,
                 loop: asyncio.AbstractEventLoop = None, timeout: float = None) -> None:
        self.name = name
        self.tag = tag
        self.args = args
        self.prefix = prefix + ' ' if prefix else None
        self.untagged_resp_name = untagged_resp_name or name

        self._exception = None
        self._loop = loop if loop is not None else get_running_loop()
        self._event = asyncio.Event(loop=self._loop)
        self._timeout = timeout
        self._timer = asyncio.Handle(lambda: None, None, self._loop)  # fake timer
        self._set_timer()
        self._expected_size = 0
        
        self._resp_literal_data = bytearray()
        self._resp_result = 'Init'
        self._resp_lines: List[bytes] = list()

    def __repr__(self) -> str:
        return '{tag} {prefix}{name}{space}{args}'.format(
            tag=self.tag, prefix=self.prefix or '', name=self.name,
            space=' ' if self.args else '', args=' '.join(self.args))

    # for tests
    def __eq__(self, other):
        return other is not None and other.tag == self.tag and other.name == self.name and other.args == self.args

    @property
    def response(self):
        return Response(self._resp_result, self._resp_lines)

    def close(self, line: bytes, result: str) -> None:
        self.append_to_resp(line, result=result)
        self._timer.cancel()
        self._event.set()

    def begin_literal_data(self, expected_size: int, literal_data: bytes = b'') -> bytes:
        self._expected_size = expected_size
        return self.append_literal_data(literal_data)

    def wait_literal_data(self) -> bool:
        return self._expected_size != 0 and len(self._resp_literal_data) != self._expected_size

    def wait_data(self) -> bool:
        return self.wait_literal_data()

    def append_literal_data(self, data: bytes) -> bytes:
        nb_bytes_to_add = self._expected_size - len(self._resp_literal_data)
        self._resp_literal_data.extend(data[0:nb_bytes_to_add])
        if not self.wait_literal_data():
            self.append_to_resp(self._resp_literal_data)
            self._end_literal_data()
        self._reset_timer()
        return data[nb_bytes_to_add:]

    def append_to_resp(self, line: bytes, result: str = 'Pending') -> None:
        self._resp_result = result
        self._resp_lines.append(line)
        self._reset_timer()

    async def wait(self) -> None:
        await self._event.wait()
        if self._exception is not None:
            raise self._exception

    def flush(self) -> None:
        pass

    def _end_literal_data(self) -> None:
        self._expected_size = 0
        self._resp_literal_data = bytearray()

    def _set_timer(self) -> None:
        if self._timeout is not None:
            self._timer = self._loop.call_later(self._timeout, self._timeout_callback)

    def _timeout_callback(self) -> None:
        self._exception = CommandTimeout(self)
        self.close(str(self._exception).encode(), 'KO')

    def _reset_timer(self) -> None:
        self._timer.cancel()
        self._set_timer()


class FetchCommand(Command):
    FETCH_MESSAGE_DATA_RE = re.compile(rb'[0-9]+ FETCH \(')

    def __init__(self, tag: str, *args, prefix: str = None, untagged_resp_name: str = None,
                 loop: asyncio.AbstractEventLoop = None, timeout: float = None) -> None:
        super().__init__('FETCH', tag, *args, prefix=prefix, untagged_resp_name=untagged_resp_name,
                         loop=loop, timeout=timeout)

    def wait_data(self) -> bool:
        last_fetch_index = 0
        for index, line in enumerate(self._resp_lines):
            if isinstance(line, bytes) and self.FETCH_MESSAGE_DATA_RE.match(line):
                last_fetch_index = index
        return not matched_parenthesis(b''.join(filter(lambda l: isinstance(l, bytes),
                                                      self.response.lines[last_fetch_index:])))


def matched_parenthesis(fetch_response: bytes) -> bool:
    return fetch_response.count(b'(') == fetch_response.count(b')')


class IdleCommand(Command):
    def __init__(self, tag: str, queue: asyncio.Queue, *args, prefix: str = None, untagged_resp_name: str = None,
                 loop: asyncio.AbstractEventLoop = None, timeout: float = None) -> None:
        super().__init__('IDLE', tag, *args, prefix=prefix, untagged_resp_name=untagged_resp_name,
                         loop=loop, timeout=timeout)
        self.queue = queue
        self.buffer: List[bytes] = list()

    def append_to_resp(self, line: bytes, result: str = 'Pending') -> None:
        if result != 'Pending':
            super().append_to_resp(line, result)
        else:
            self.buffer.append(line)

    def flush(self) -> None:
        if self.buffer:
            self.queue.put_nowait(copy(self.buffer))
            self.buffer.clear()


class AioImapException(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)


class Error(AioImapException):
    def __init__(self, reason: str):
        super().__init__(reason)


class Abort(Error):
    def __init__(self, reason: str):
        super().__init__(reason)


class CommandTimeout(AioImapException):
    def __init__(self, command: Command):
        self.command = command


class IncompleteRead(AioImapException):
    def __init__(self, cmd: Command, data: bytes = b''):
        self.cmd = cmd
        self.data = data


def change_state(coro: Callable[..., Coroutine[Any, Any, Optional[Response]]]):
    @functools.wraps(coro)
    async def wrapper(self, *args, **kargs) -> Optional[Response]:
        async with self.state_condition:
            res = await coro(self, *args, **kargs)
            log.debug('state -> %s' % self.state)
            self.state_condition.notify_all()
            return res

    return wrapper


# cf https://tools.ietf.org/html/rfc3501#section-9
# untagged responses types
literal_data_re = re.compile(rb'.*\{(?P<size>\d+)\}$')
message_data_re = re.compile(rb'[0-9]+ ((FETCH)|(EXPUNGE))')
tagged_status_response_re = re.compile(rb'[A-Z0-9]+ ((OK)|(NO)|(BAD))')


class IMAP4ClientProtocol(asyncio.Protocol):
    def __init__(self, loop: Optional[asyncio.AbstractEventLoop], conn_lost_cb: Callable[[Optional[Exception]], None] = None):
        self.loop = loop
        self.transport = None
        self.state = STARTED
        self.state_condition = asyncio.Condition()
        self.capabilities = set()
        self.pending_async_commands = dict()
        self.pending_sync_command = None
        self.idle_queue = asyncio.Queue()
        self._idle_event = asyncio.Event(loop=loop)
        self.imap_version = None
        self.literal_data = None
        self.incomplete_line = b''
        self.current_command = None
        self.conn_lost_cb = conn_lost_cb

        self.tagnum = 0
        self.tagpre = int2ap(random.randint(4096, 65535))

    def connection_made(self, transport: BaseTransport) -> None:
        self.transport = transport
        self.state = CONNECTED

    def data_received(self, d: bytes) -> None:
        log.debug('Received : %s' % d)
        try:
            self._handle_responses(self.incomplete_line + d, self._handle_line, self.current_command)
            self.incomplete_line = b''
            self.current_command = None
        except IncompleteRead as incomplete_read:
            self.current_command = incomplete_read.cmd
            self.incomplete_line = incomplete_read.data

    def connection_lost(self, exc: Optional[Exception]) -> None:
        log.debug('connection lost: %s', exc)
        if self.conn_lost_cb is not None:
            self.conn_lost_cb(exc)

    def _handle_responses(self, data: bytes, line_handler: Callable[[bytes, Command], Optional[Command]], current_cmd: Command = None) -> None:
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

        line, separator, tail = data.partition(CRLF)
        if not separator:
            raise IncompleteRead(current_cmd, data)

        cmd = line_handler(line, current_cmd)

        begin_literal = literal_data_re.match(line)
        if begin_literal:
            size = int(begin_literal.group('size'))
            if cmd is None:
                cmd = Command('NIL', 'unused')
            cmd.begin_literal_data(size)
            self._handle_responses(tail, line_handler, current_cmd=cmd)
        elif cmd is not None and cmd.wait_data():
            self._handle_responses(tail, line_handler, current_cmd=cmd)
        else:
            self._handle_responses(tail, line_handler)

    def _handle_line(self, line: bytes, current_cmd: Command) -> Optional[Command]:
        if not line:
            return

        if self.state == CONNECTED:
            asyncio.ensure_future(self.welcome(line))
        elif tagged_status_response_re.match(line):
            self._response_done(line)
        elif current_cmd is not None:
            current_cmd.append_to_resp(line)
            return current_cmd
        elif line.startswith(b'*'):
            return self._untagged_response(line)
        elif line.startswith(b'+'):
            self._continuation(line)
        else:
            log.info('unknown data received %s' % line)

    def send(self, line: str) -> None:
        data = ('%s\r\n' % line).encode()
        log.debug('Sending : %s' % data)
        self.transport.write(data)

    async def execute(self, command: Command) -> Response:
        if self.state not in Commands.get(command.name).valid_states:
            raise Abort('command %s illegal in state %s' % (command.name, self.state))

        if self.pending_sync_command is not None:
            await self.pending_sync_command.wait()

        if Commands.get(command.name).exec == Exec.is_sync:
            if self.pending_async_commands:
                await self.wait_async_pending_commands()
            self.pending_sync_command = command
        else:
            if self.pending_async_commands.get(command.untagged_resp_name) is not None:
                await self.pending_async_commands[command.untagged_resp_name].wait()
            self.pending_async_commands[command.untagged_resp_name] = command

        self.send(str(command))
        try:
            await command.wait()
        except CommandTimeout:
            if Commands.get(command.name).exec == Exec.is_sync:
                self.pending_sync_command = None
            else:
                self.pending_async_commands.pop(command.untagged_resp_name, None)
            raise
        finally:
            if command.name == 'IDLE':
                self._idle_event.clear()

        return command.response

    @change_state
    async def welcome(self, command: bytes) -> None:
        if b'PREAUTH' in command:
            self.state = AUTH
        elif b'OK' in command:
            self.state = NONAUTH
        else:
            raise Error(command.decode())
        await self.capability()

    @change_state
    async def login(self, user: str, password: str) -> Response:
        response = await self.execute(
            Command('LOGIN', self.new_tag(), user, '%s' % quoted(password), loop=self.loop))

        if 'OK' == response.result:
            self.state = AUTH
            for line in response.lines:
                if b'CAPABILITY' in line:
                    self.capabilities = self.capabilities.union(set(line.decode().replace('CAPABILITY', '').strip().split()))
        return response

    @change_state
    async def logout(self) -> Response:
        response = (await self.execute(Command('LOGOUT', self.new_tag(), loop=self.loop)))
        if 'OK' == response.result:
            self.state = LOGOUT
        return response

    @change_state
    async def select(self, mailbox='INBOX') -> Response:
        response = await self.execute(
            Command('SELECT', self.new_tag(), mailbox, loop=self.loop))

        if 'OK' == response.result:
            self.state = SELECTED
        return response

    @change_state
    async def close(self) -> Response:
        response = await self.execute(Command('CLOSE', self.new_tag(), loop=self.loop))
        if response.result == 'OK':
            self.state = AUTH
        return response

    async def idle(self) -> Response:
        if 'IDLE' not in self.capabilities:
            raise Abort('server has not IDLE capability')
        self._idle_event.clear()
        return await self.execute(IdleCommand(self.new_tag(), self.idle_queue, loop=self.loop))

    def has_pending_idle_command(self) -> bool:
        return self.pending_sync_command is not None and self.pending_sync_command.name == 'IDLE'

    def idle_done(self) -> None:
        self.send('DONE')

    async def search(self, *criteria, charset: Optional[str] = 'utf-8', by_uid: bool = False) -> Response:
        args = ('CHARSET', charset) + criteria if charset is not None else criteria
        prefix = 'UID' if by_uid else ''

        return await self.execute(
            Command('SEARCH', self.new_tag(), *args, prefix=prefix, loop=self.loop))

    async def fetch(self, message_set: str, message_parts: str, by_uid: bool = False, timeout: float = None) -> Response:
        return await self.execute(
            FetchCommand(self.new_tag(), message_set, message_parts,
                         prefix='UID' if by_uid else '', loop=self.loop, timeout=timeout))

    async def store(self, *args: str, by_uid: bool = False) -> Response:
        return await self.execute(
            Command('STORE', self.new_tag(), *args,
                    prefix='UID' if by_uid else '', untagged_resp_name='FETCH', loop=self.loop))

    async def expunge(self, *args: str, by_uid=False) -> Response:
        return await self.execute(
            Command('EXPUNGE', self.new_tag(), *args,
                    prefix='UID' if by_uid else '', loop=self.loop))

    async def uid(self, command: str, *criteria: str, timeout: float = None) -> Response:
        if self.state not in Commands.get('UID').valid_states:
            raise Abort('command UID illegal in state %s' % self.state)

        if command.upper() == 'FETCH':
            return await self.fetch(criteria[0], criteria[1], by_uid=True, timeout=timeout)
        if command.upper() == 'STORE':
            return await self.store(*criteria, by_uid=True)
        if command.upper() == 'COPY':
            return await self.copy(*criteria, by_uid=True)
        if command.upper() == 'MOVE':
            return await self.move(*criteria, by_uid=True)
        if command.upper() == 'EXPUNGE':
            if 'UIDPLUS' not in self.capabilities:
                raise Abort('EXPUNGE with uids is only valid with UIDPLUS capability. UIDPLUS not in (%s)' % self.capabilities)
            return await self.expunge(*criteria, by_uid=True)
        raise Abort('command UID only possible with COPY, FETCH, EXPUNGE (w/UIDPLUS) or STORE (was %s)' % command.upper())

    async def copy(self, *args: str, by_uid: bool = False) -> Response:
        return (await self.execute(
            Command('COPY', self.new_tag(), *args, prefix='UID' if by_uid else '', loop=self.loop)))

    async def move(self, uid_set: str, mailbox: str, by_uid: bool = False) -> Response:
        if 'MOVE' not in self.capabilities:
            raise Abort('server has not MOVE capability')

        return (await self.execute(
            Command('MOVE', self.new_tag(), uid_set, mailbox, prefix='UID' if by_uid else '', loop=self.loop)))

    async def capability(self) -> None: # that should be a Response (would avoid the Optional)
        response = await self.execute(Command('CAPABILITY', self.new_tag(), loop=self.loop))

        capability_list = response.lines[0].decode().split()
        self.capabilities = set(capability_list)
        try:
            self.imap_version = list(
                filter(lambda x: x.upper() in AllowedVersions, capability_list)).pop().upper()
        except IndexError:
            raise Error('server not IMAP4 compliant')

    async def append(self, message_bytes: bytes, mailbox: str = 'INBOX', flags: str = None, date: Any = None, timeout: float = None) -> Response:
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

    async def id(self, **kwargs: Union[dict, list, str]) -> Response:
        args = arguments_rfs2971(**kwargs)
        return await self.execute(Command('ID', self.new_tag(), *args, loop=self.loop))

    simple_commands = {'NOOP', 'CHECK', 'STATUS', 'CREATE', 'DELETE', 'RENAME',
                       'SUBSCRIBE', 'UNSUBSCRIBE', 'LSUB', 'LIST', 'EXAMINE', 'ENABLE'}

    async def namespace(self) -> Response:
        if 'NAMESPACE' not in self.capabilities:
            raise Abort('server has not NAMESPACE capability')
        return await self.execute(Command('NAMESPACE', self.new_tag(), loop=self.loop))

    async def simple_command(self, name, *args: str) -> Response:
        if name not in self.simple_commands:
            raise NotImplementedError('simple command only available for %s' % self.simple_commands)
        return await self.execute(Command(name, self.new_tag(), *args, loop=self.loop))

    async def wait_async_pending_commands(self) -> None:
        await asyncio.wait([asyncio.ensure_future(cmd.wait()) for cmd in self.pending_async_commands.values()])

    async def wait(self, state_regexp: Pattern) -> None:
        state_re = re.compile(state_regexp)
        async with self.state_condition:
            await self.state_condition.wait_for(lambda: state_re.match(self.state))

    async def wait_for_idle_response(self):
        await self._idle_event.wait()

    def _untagged_response(self, line: bytes) -> Command:
        line = line.replace(b'* ', b'')
        if self.pending_sync_command is not None:
            self.pending_sync_command.append_to_resp(line)
            command = self.pending_sync_command
        else:
            match = message_data_re.match(line)
            if match:
                cmd_name, text = match.group(1), match.string
            else:
                cmd_name, _, text = line.partition(b' ')
            command = self.pending_async_commands.get(cmd_name.decode().upper())
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

    def _response_done(self, line: bytes) -> None:
        log.debug('tagged status %s' % line)
        tag, _, response = line.partition(b' ')

        if self.pending_sync_command is not None:
            if self.pending_sync_command.tag != tag.decode():
                raise Abort('unexpected tagged response with pending sync command (%s) response: %s' %
                            (self.pending_sync_command, response))
            command = self.pending_sync_command
            self.pending_sync_command = None
        else:
            cmds = self._find_pending_async_cmd_by_tag(tag.decode())
            if len(cmds) == 0:
                raise Abort('unexpected tagged (%s) response: %s' % (tag, response))
            elif len(cmds) > 1:
                raise Error('inconsistent state : two commands have the same tag (%s)' % cmds)
            command = cmds.pop()
            self.pending_async_commands.pop(command.untagged_resp_name)

        response_result, _, response_text = response.partition(b' ')
        command.close(response_text, result=response_result.decode())

    def _continuation(self, line: bytes) -> None:
        if self.pending_sync_command is None:
            log.info('server says %s (ignored)' % line)
        elif self.pending_sync_command.name == 'APPEND':
            if self.literal_data is None:
                Abort('asked for literal data but have no literal data to send')
            self.transport.write(self.literal_data)
            self.transport.write(CRLF)
            self.literal_data = None
        elif self.pending_sync_command.name == 'IDLE':
            log.debug('continuation line -- assuming IDLE is active : %s', line)
            self._idle_event.set()
        else:
            log.debug('continuation line appended to pending sync command %s : %s' % (self.pending_sync_command, line))
            self.pending_sync_command.append_to_resp(line)
            self.pending_sync_command.flush()

    def new_tag(self) -> str:
        tag = self.tagpre + str(self.tagnum)
        self.tagnum += 1
        return tag

    def _find_pending_async_cmd_by_tag(self, tag: str) -> list:
        return [c for c in self.pending_async_commands.values() if c is not None and c.tag == tag]


class IMAP4(object):
    TIMEOUT_SECONDS = 10.0

    def __init__(self, host: str = '127.0.0.1', port: int = IMAP4_PORT, loop: asyncio.AbstractEventLoop = None,
                 timeout: float = TIMEOUT_SECONDS, conn_lost_cb: Callable[[Optional[Exception]], None] = None,
                 ssl_context: ssl.SSLContext = None):
        self.timeout = timeout
        self.port = port
        self.host = host
        self.protocol = None
        self._idle_waiter = None
        self.create_client(host, port, loop, conn_lost_cb, ssl_context)

    def create_client(self, host: str, port: int, loop: asyncio.AbstractEventLoop,
                      conn_lost_cb: Callable[[Optional[Exception]], None] = None, ssl_context: ssl.SSLContext = None) -> None:
        local_loop = loop if loop is not None else get_running_loop()
        self.protocol = IMAP4ClientProtocol(local_loop, conn_lost_cb)
        local_loop.create_task(local_loop.create_connection(lambda: self.protocol, host, port, ssl=ssl_context))

    def get_state(self) -> str:
        return self.protocol.state

    async def wait_hello_from_server(self) -> None:
        await asyncio.wait_for(self.protocol.wait('AUTH|NONAUTH'), self.timeout)

    async def login(self, user: str, password: str) -> Response:
        return await asyncio.wait_for(self.protocol.login(user, password), self.timeout)

    async def logout(self) -> Response:
        return await asyncio.wait_for(self.protocol.logout(), self.timeout)

    async def select(self, mailbox: str = 'INBOX') -> Response:
        return await asyncio.wait_for(self.protocol.select(mailbox), self.timeout)

    async def search(self, *criteria: str, charset: Optional[str] = 'utf-8') -> Response:
        return await asyncio.wait_for(self.protocol.search(*criteria, charset=charset), self.timeout)

    async def uid_search(self, *criteria: str, charset: Optional[str] = 'utf-8') -> Response:
        return await asyncio.wait_for(self.protocol.search(*criteria, by_uid=True, charset=charset), self.timeout)

    async def uid(self, command: str, *criteria: str) -> Response:
        return await self.protocol.uid(command, *criteria, timeout=self.timeout)

    async def store(self, *criteria: str) -> Response:
        return await asyncio.wait_for(self.protocol.store(*criteria), self.timeout)

    async def copy(self, *criteria: str) -> Response:
        return await asyncio.wait_for(self.protocol.copy(*criteria), self.timeout)

    async def expunge(self) -> Response:
        return await asyncio.wait_for(self.protocol.expunge(), self.timeout)

    async def fetch(self, message_set: str, message_parts: str) -> Response:
        return await self.protocol.fetch(message_set, message_parts, timeout=self.timeout)

    async def idle(self) -> Response:
        return await self.protocol.idle()

    def idle_done(self) -> None:
        if self._idle_waiter is not None:
            self._idle_waiter.cancel()
        self.protocol.idle_done()

    async def stop_wait_server_push(self) -> bool:
        if self.protocol.has_pending_idle_command():
            await self.protocol.idle_queue.put(STOP_WAIT_SERVER_PUSH)
            return True
        return False

    async def wait_server_push(self, timeout: float = TWENTY_NINE_MINUTES) -> Response:
        return await asyncio.wait_for(self.protocol.idle_queue.get(), timeout=timeout)

    async def idle_start(self, timeout: float = TWENTY_NINE_MINUTES) -> Future:
        if self._idle_waiter is not None:
            self._idle_waiter.cancel()
        idle = asyncio.ensure_future(self.idle())
        wait_for_ack = asyncio.ensure_future(self.protocol.wait_for_idle_response())
        await asyncio.wait({idle, wait_for_ack}, return_when=asyncio.FIRST_COMPLETED)
        if not self.has_pending_idle():
            wait_for_ack.cancel()
            raise Abort('server returned error to IDLE command')

        self._idle_waiter = self.protocol.loop.call_later(timeout, lambda: asyncio.ensure_future(self.stop_wait_server_push()))
        return idle

    def has_pending_idle(self) -> bool:
        return self.protocol.has_pending_idle_command()

    async def id(self, **kwargs) -> Response:
        return await asyncio.wait_for(self.protocol.id(**kwargs), self.timeout)

    async def namespace(self) -> Response:
        return await asyncio.wait_for(self.protocol.namespace(), self.timeout)

    async def noop(self) -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('NOOP'), self.timeout)

    async def check(self) -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('CHECK'), self.timeout)

    async def examine(self, mailbox: str = 'INBOX') -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('EXAMINE', mailbox), self.timeout)

    async def status(self, mailbox: str, names: str) -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('STATUS', mailbox, names), self.timeout)

    async def subscribe(self, mailbox: str) -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('SUBSCRIBE', mailbox), self.timeout)

    async def unsubscribe(self, mailbox: str) -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('UNSUBSCRIBE', mailbox), self.timeout)

    async def lsub(self, reference_name: str, mailbox_name: str) -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('LSUB', reference_name, mailbox_name), self.timeout)

    async def create(self, mailbox_name: str) -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('CREATE', mailbox_name), self.timeout)

    async def delete(self, mailbox_name: str) -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('DELETE', mailbox_name), self.timeout)

    async def rename(self, old_mailbox_name: str, new_mailbox_name: str) -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('RENAME', old_mailbox_name, new_mailbox_name), self.timeout)

    async def list(self, reference_name: str, mailbox_pattern: Pattern) -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('LIST', reference_name, mailbox_pattern), self.timeout)

    async def append(self, message_bytes, mailbox: str = 'INBOX', flags: str = None, date: Any = None) -> Response:
        return await self.protocol.append(message_bytes, mailbox, flags, date, timeout=self.timeout)

    async def close(self) -> Response:
        return await asyncio.wait_for(self.protocol.close(), self.timeout)

    async def move(self, uid_set: str, mailbox: str) -> Response:
        return await asyncio.wait_for(self.protocol.move(uid_set, mailbox), self.timeout)

    async def enable(self, capability: str) -> Response:
        if 'ENABLE' not in self.protocol.capabilities:
            raise Abort('server has not ENABLE capability')

        return await asyncio.wait_for(self.protocol.simple_command('ENABLE', capability), self.timeout)

    def has_capability(self, capability: str) -> bool:
        return capability in self.protocol.capabilities


def extract_exists(response: Response) -> Optional[int]:
    for line in response.lines:
        if b'EXISTS' in line:
            return int(line.replace(b' EXISTS', b'').decode())


class IMAP4_SSL(IMAP4):
    def __init__(self, host: str = '127.0.0.1', port: int = IMAP4_SSL_PORT, loop: asyncio.AbstractEventLoop = None,
                 timeout: float = IMAP4.TIMEOUT_SECONDS, ssl_context: ssl.SSLContext = None):
        super().__init__(host, port, loop, timeout, None, ssl_context)

    def create_client(self, host: str, port: int, loop: asyncio.AbstractEventLoop,
                      conn_lost_cb: Callable[[Optional[Exception]], None] = None, ssl_context: ssl.SSLContext = None) -> None:
        if ssl_context is None:
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        super().create_client(host, port, loop, conn_lost_cb, ssl_context)


# functions from imaplib
def int2ap(num) -> str:
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


def time2internaldate(date_time: Any) -> str:
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
