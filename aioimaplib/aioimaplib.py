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
from concurrent import futures


log = logging.getLogger(__name__)
TIMEOUT_SECONDS = 10
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
}

Response = namedtuple('Response', 'result lines')


class UpdatableTimeout:

    def __init__(self, timeout, loop=asyncio.get_event_loop()):
        self.loop = loop
        self.timeout = timeout
        self.timeout_handle = None
        self.waiter = asyncio.Future(loop=loop)

    def _raise_timeout(self):
        if not self.waiter.done():
            self.waiter.set_exception(asyncio.futures.TimeoutError())

    def update(self):
        if self.timeout_handle is None:
            return
        self.timeout_handle.cancel()
        self.timeout_handle = self.loop.call_later(self.timeout, self._raise_timeout)

    def done(self):
        if not self.waiter.done():
            self.timeout_handle.cancel()
            self.waiter.set_result(None)
    
    def exception(self):
        if not self.waiter.done():
            return None
        return self.waiter.exception()

    @asyncio.coroutine
    def wait(self):

        if self.timeout is None:
            return

        if self.timeout_handle is None:
            self.timeout_handle = self.loop.call_later(self.timeout, self._raise_timeout)

        try:
            yield from self.waiter
            if self.waiter.exception() is not None:
                raise self.waiter.exception()
        finally:
            self.timeout_handle.cancel()


class Command(object):

    def __init__(self, name, tag, *args, prefix=None, untagged_resp_name=None,
                 loop=asyncio.get_event_loop(), timeout=TIMEOUT_SECONDS):
        self.name = name
        self.args = args
        self.prefix = prefix + ' ' if prefix else None
        self.untagged_resp_name = untagged_resp_name or name
        self.response = None
        self.event = asyncio.Event(loop=loop)
        self.new_data_timeout = UpdatableTimeout(timeout, loop=loop)
        self.tag = tag
        self.literal_data = None
        self.expected_size = 0

    def __repr__(self):
        return '{tag} {prefix}{name}{space}{args}'.format(
            tag=self.tag, prefix=self.prefix or '', name=self.name,
            space=' ' if self.args else '', args=' '.join(self.args))

    def close(self, line, result):
        self.append_to_resp(line, result=result)
        self.new_data_timeout.done()
        self.event.set()

    def begin_literal_data(self, data, expected_size):
        self.literal_data = data
        self.expected_size = expected_size
        self.new_data_timeout.update()

    def end_literal_data(self):
        self.append_to_resp(self.literal_data.rstrip(b')'))
        self.expected_size = 0
        self.literal_data = None
        self.new_data_timeout.update()

    def has_literal_data(self):
        return self.expected_size != 0 and len(self.literal_data) != self.expected_size

    def append_literal_data(self, data):
        nb_bytes_to_add = self.expected_size - len(self.literal_data)
        self.literal_data += data[0:nb_bytes_to_add]
        self.new_data_timeout.update()
        return data[nb_bytes_to_add:]

    def append_to_resp(self, line, result='Pending'):
        if self.response is None:
            self.response = Response(result, [line])
        else:
            old = self.response
            self.response = Response(result, old.lines + [line])
        self.new_data_timeout.update()

    @asyncio.coroutine
    def wait(self):
        yield from asyncio.wait(
            [self.event.wait(), self.new_data_timeout.wait()],
            return_when=futures.FIRST_EXCEPTION)
        if self.new_data_timeout.exception() is not None:
            raise asyncio.futures.TimeoutError()


class Error(Exception):
    def __init__(self, reason):
        super().__init__(reason)


class Abort(Error):
    def __init__(self, reason):
        super().__init__(reason)


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
fetch_message_with_literal_data_re = re.compile(rb'\* [0-9]+ FETCH [\w \\\[\]\(\)\.\-\:\+\"]+ \{(?P<size>\d+)\}\r\n')
message_data_without_literal_re = re.compile(r'[0-9]+ ((FETCH)|(EXPUNGE))([\w \(\)]+)?')
tagged_status_response_re = re.compile(r'[A-Z0-9]+ ((OK)|(NO)|(BAD))')


class IMAP4ClientProtocol(asyncio.Protocol):

    def __init__(self, loop, timeout=TIMEOUT_SECONDS):
        self.loop = loop
        self.timeout = timeout
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

        self.tagnum = 0
        self.tagpre = int2ap(random.randint(4096, 65535))

    def connection_made(self, transport):
        self.transport = transport
        self.state = CONNECTED

    def data_received(self, d):
        log.debug('Received : %s' % d)
        if self._incomplete_fetch_literal():
            data = self._append_fetch_data(d)
        else:
            data = d
        try:
            self._handle_responses(data, self._handle_line, self._untagged_fetch_with_literal, self.incomplete_line)
            self.incomplete_line = b''
        except asyncio.IncompleteReadError as incomplete_error:
            log.debug('Incomplete line, storing partial : %s' % incomplete_error.partial)
            self.incomplete_line = incomplete_error.partial

    def _handle_responses(self, d, line_handler, fetch_handler, incomplete_line=b''):
        if not d:
            return
        data = incomplete_line + d
        match_fetch_message = fetch_message_with_literal_data_re.match(data)
        if match_fetch_message:
            head, crlf, tail = data.partition(CRLF)
            msg_size = match_fetch_message.group('size')
            # we want to cut -----------------------
            #                              ...here |
            #                               so 4+1 v
            # b'* 3 FETCH (UID 3 RFC822 {4}\r\nmail)\r\n...
            end_message_index_with_parenthesis = int(msg_size) + 1

            fetch_handler(head + crlf + tail[0:end_message_index_with_parenthesis], end_message_index_with_parenthesis)
            after_fetch = tail[end_message_index_with_parenthesis:]
            self._handle_responses(after_fetch, line_handler, fetch_handler)
        else:
            line, separator, tail = data.partition(CRLF)
            if not separator:
                raise asyncio.IncompleteReadError(data, b'line should end with CRLF')
            else:
                line_handler(line.decode())
                self._handle_responses(tail, line_handler, fetch_handler)

    def _handle_line(self, line):
        if not line:
            return
        elif self.state == CONNECTED:
            asyncio.async(self.welcome(line))
        elif line.startswith('*'):
            self._untagged_response(line.replace('* ', ''))
        elif line.startswith('+'):
            self._continuation(line.replace('+ ', ''))
        elif tagged_status_response_re.match(line):
            self._response_done(line)
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
        yield from command.wait()
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
            Command('LOGIN', self.new_tag(), user, '"%s"' % password, loop=self.loop, timeout=self.timeout))

        if 'OK' == response.result:
            self.state = AUTH
        return response

    @change_state
    @asyncio.coroutine
    def logout(self):
        response = (yield from self.execute(Command('LOGOUT', self.new_tag(), loop=self.loop, timeout=self.timeout)))
        if 'OK' == response.result:
            self.state = LOGOUT
        return response

    @change_state
    @asyncio.coroutine
    def select(self, mailbox='INBOX'):
        response = yield from self.execute(
            Command('SELECT', self.new_tag(), mailbox, loop=self.loop, timeout=self.timeout))

        if 'OK' == response.result:
            self.state = SELECTED
        for line in response.lines:
            if 'EXISTS' in line:
                return Response(response.result, [line.replace(' EXISTS', '')])
        return response

    @change_state
    @asyncio.coroutine
    def close(self):
        response = yield from self.execute(Command('CLOSE', self.new_tag(), loop=self.loop, timeout=self.timeout))
        if response.result == 'OK':
            self.state = AUTH
        return response

    @asyncio.coroutine
    def examine(self, mailbox='INBOX'):
        response = yield from self.execute(
            Command('EXAMINE', self.new_tag(), mailbox, loop=self.loop, timeout=self.timeout))

        for line in response.lines:
            if 'EXISTS' in line:
                return Response(response.result, [line.replace(' EXISTS', '')])
        return response

    @asyncio.coroutine
    def idle(self):
        if 'IDLE' not in self.capabilities:
            Abort('server has not IDLE capability')
        return (yield from self.execute(Command('IDLE', self.new_tag(), loop=self.loop, timeout=self.timeout)))

    def idle_done(self):
        self.send('DONE')

    @asyncio.coroutine
    def search(self, *criteria, charset='utf-8', by_uid=False):
        args = ('CHARSET', charset) + criteria if charset is not None else criteria
        prefix = 'UID' if by_uid else ''

        return (yield from self.execute(
            Command('SEARCH', self.new_tag(), *args, prefix=prefix, loop=self.loop, timeout=self.timeout)))

    @asyncio.coroutine
    def fetch(self, message_set, message_parts, by_uid=False):
        return (yield from self.execute(
            Command('FETCH', self.new_tag(), message_set, message_parts,
                    prefix='UID' if by_uid else '', loop=self.loop, timeout=self.timeout)))

    @asyncio.coroutine
    def store(self, *args, by_uid=False):
        return (yield from self.execute(
            Command('STORE', self.new_tag(), *args,
                    prefix='UID' if by_uid else '', untagged_resp_name='FETCH', loop=self.loop, timeout=self.timeout)))

    @asyncio.coroutine
    def expunge(self):
        return (yield from self.execute(Command('EXPUNGE', self.new_tag(), loop=self.loop, timeout=self.timeout)))

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
            Command('COPY', self.new_tag(), *args, prefix='UID' if by_uid else '',
                    loop=self.loop, timeout=self.timeout)))

    @asyncio.coroutine
    def capability(self):
        response = yield from self.execute(Command('CAPABILITY', self.new_tag(), loop=self.loop, timeout=self.timeout))

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
        return (yield from self.execute(Command('APPEND', self.new_tag(), *args, loop=self.loop, timeout=self.timeout)))

    simple_commands = {'NOOP', 'CHECK', 'STATUS', 'CREATE', 'DELETE', 'RENAME',
                       'SUBSCRIBE', 'UNSUBSCRIBE', 'LSUB', 'LIST'}

    @asyncio.coroutine
    def simple_command(self, name, *args):
        if name not in self.simple_commands:
            raise NotImplementedError('simple command only available for %s' % self.simple_commands)
        return (yield from self.execute(Command(name, self.new_tag(), *args, loop=self.loop, timeout=self.timeout)))

    @asyncio.coroutine
    def wait_async_pending_commands(self):
        yield from asyncio.wait([asyncio.async(cmd.wait()) for cmd in self.pending_async_commands.values()])

    @asyncio.coroutine
    def wait(self, state_regexp):
        state_re = re.compile(state_regexp)
        with (yield from self.state_condition):
            yield from self.state_condition.wait_for(lambda: state_re.match(self.state))

    def _untagged_fetch_with_literal(self, raw_line, msg_size):
        pending_fetch = self.pending_async_commands.get('FETCH')
        if pending_fetch is None:
            raise Abort('unexpected fetch message (%r) response:' % raw_line)
        msg_header, _, msg = raw_line.partition(CRLF)
        pending_fetch.append_to_resp(msg_header)
        if len(msg) < msg_size:
            # email message is not complete we should wait the future chunks
            pending_fetch.begin_literal_data(msg, msg_size)
        else:
            pending_fetch.append_to_resp(msg.rstrip(b')'))

    def _incomplete_fetch_literal(self):
        return 'FETCH' in self.pending_async_commands and \
               self.pending_async_commands.get('FETCH').has_literal_data()

    def _append_fetch_data(self, data):
        pending_fetch = self.pending_async_commands.get('FETCH')
        rest = pending_fetch.append_literal_data(data)
        if not pending_fetch.has_literal_data():
            pending_fetch.end_literal_data()
        return rest

    def has_pending_idle_command(self):
        return self.pending_sync_command is not None and self.pending_sync_command.name == 'IDLE'

    def _untagged_response(self, line):
        if self.pending_sync_command is not None:
            if self.has_pending_idle_command():
                asyncio.async(self.idle_queue.put(line))
            else:
                self.pending_sync_command.append_to_resp(line)
        else:
            match = message_data_without_literal_re.match(line)
            if match:
                command, text = match.group(1), match.string
            else:
                command, _, text = line.partition(' ')
            pending_async_command = self.pending_async_commands.get(command.upper())
            if pending_async_command is not None:
                pending_async_command.append_to_resp(text)
            else:
                log.info('ignored untagged response : %s' % line)

    def _response_done(self, line):
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

    def __init__(self, host='localhost', port=IMAP4_PORT, loop=asyncio.get_event_loop(), timeout=TIMEOUT_SECONDS):
        self.timeout = timeout
        self.port = port
        self.host = host
        self.protocol = None
        self.create_client(host, port, loop)

    def create_client(self, host, port, loop):
        self.protocol = IMAP4ClientProtocol(loop, timeout=self.timeout)
        loop.create_task(loop.create_connection(lambda: self.protocol, host, port))

    @asyncio.coroutine
    def wait_hello_from_server(self):
        yield from asyncio.wait_for(self.protocol.wait('AUTH|NONAUTH'), self.timeout)

    @asyncio.coroutine
    def login(self, user, password):
        return (yield from self.protocol.login(user, password))

    @asyncio.coroutine
    def logout(self):
        return (yield from self.protocol.logout())

    @asyncio.coroutine
    def select(self, mailbox='INBOX'):
        return (yield from self.protocol.select(mailbox))

    def examine(self, mailbox='INBOX'):
        return (yield from self.protocol.examine(mailbox))

    @asyncio.coroutine
    def search(self, *criteria, charset='utf-8'):
        return (yield from self.protocol.search(*criteria, charset=charset))

    @asyncio.coroutine
    def uid_search(self, *criteria, charset='utf-8'):
        return (yield from self.protocol.search(*criteria, by_uid=True, charset=charset))

    @asyncio.coroutine
    def uid(self, command, *criteria):
        return (yield from self.protocol.uid(command, *criteria))

    @asyncio.coroutine
    def store(self, *criteria):
        return (yield from self.protocol.store(*criteria))

    @asyncio.coroutine
    def copy(self, *criteria):
        return (yield from self.protocol.copy(*criteria))

    @asyncio.coroutine
    def expunge(self):
        return (yield from self.protocol.expunge())

    @asyncio.coroutine
    def fetch(self, message_set, message_parts):
        return (yield from self.protocol.fetch(message_set, message_parts))

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
        return (yield from self.protocol.simple_command('NOOP'))

    @asyncio.coroutine
    def check(self):
        return (yield from self.protocol.simple_command('CHECK'))

    @asyncio.coroutine
    def status(self, mailbox, names):
        return (yield from self.protocol.simple_command('STATUS', mailbox, names))

    @asyncio.coroutine
    def subscribe(self, mailbox):
        return (yield from self.protocol.simple_command('SUBSCRIBE', mailbox))

    @asyncio.coroutine
    def unsubscribe(self, mailbox):
        return (yield from self.protocol.simple_command('UNSUBSCRIBE', mailbox))

    @asyncio.coroutine
    def lsub(self, reference_name, mailbox_name):
        return (yield from self.protocol.simple_command('LSUB', reference_name, mailbox_name))

    @asyncio.coroutine
    def create(self, mailbox_name):
        return (yield from self.protocol.simple_command('CREATE', mailbox_name))

    @asyncio.coroutine
    def delete(self, mailbox_name):
        return (yield from self.protocol.simple_command('DELETE', mailbox_name))

    @asyncio.coroutine
    def rename(self, old_mailbox_name, new_mailbox_name):
        return (yield from self.protocol.simple_command('RENAME', old_mailbox_name, new_mailbox_name))

    @asyncio.coroutine
    def list(self, reference_name, mailbox_pattern):
        return (yield from self.protocol.simple_command('LIST', reference_name, mailbox_pattern))

    @asyncio.coroutine
    def append(self, message_bytes, mailbox='INBOX', flags=None, date=None):
        return (yield from self.protocol.append(message_bytes, mailbox, flags, date))

    @asyncio.coroutine
    def close(self):
        return (yield from self.protocol.close())


class IMAP4_SSL(IMAP4):
    def __init__(self, host='localhost', port=IMAP4_SSL_PORT, loop=asyncio.get_event_loop(),
                 timeout=TIMEOUT_SECONDS):
        super().__init__(host, port, loop, timeout)

    def create_client(self, host, port, loop):
        self.protocol = IMAP4ClientProtocol(loop, timeout=self.timeout)
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
Mon2num = {s.encode(): n + 1 for n, s in enumerate(Months[1:])}


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
    elif isinstance(date_time, str) and (date_time[0], date_time[-1]) == ('"', '"'):
        return date_time        # Assume in correct format
    else:
        raise ValueError("date_time not of a known type")
    fmt = '"%d-{}-%Y %H:%M:%S %z"'.format(Months[dt.month])
    return dt.strftime(fmt)
