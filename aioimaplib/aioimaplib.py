# -*- coding: utf-8 -*-
import asyncio
import logging
import ssl
from enum import Enum

import re

import functools

import random
from collections import namedtuple


log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
sh = logging.StreamHandler()
sh.setLevel(logging.DEBUG)
sh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(module)s:%(lineno)d] %(message)s"))
log.addHandler(sh)

IMAP4_PORT = 143
IMAP4_SSL_PORT = 993
STARTED, CONNECTED, NONAUTH, AUTH, SELECTED, LOGOUT = 'STARTED', 'CONNECTED', 'NONAUTH', 'AUTH', 'SELECTED', 'LOGOUT'
CRLF = b'\r\n'

AllowedVersions = ('IMAP4REV1', 'IMAP4')
Exec = Enum('Exec', 'sync async')
Cmd = namedtuple('Cmd', 'name valid_states exec')
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
    'GETANNOTATION':Cmd('GETANNOTATION',(AUTH, SELECTED),           Exec.async),
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
    'PARTIAL':      Cmd('PARTIAL',      (SELECTED,),                Exec.async),
    'PROXYAUTH':    Cmd('PROXYAUTH',    (AUTH,),                    Exec.sync),
    'RENAME':       Cmd('RENAME',       (AUTH, SELECTED),           Exec.async),
    'SEARCH':       Cmd('SEARCH',       (SELECTED,),                Exec.async),
    'SELECT':       Cmd('SELECT',       (AUTH, SELECTED),           Exec.sync),
    'SETACL':       Cmd('SETACL',       (AUTH, SELECTED),           Exec.sync),
    'SETANNOTATION':Cmd('SETANNOTATION',(AUTH, SELECTED),           Exec.async),
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


Response = namedtuple('Response', 'result text')


class Command(object):
    def __init__(self, name, tag, *args, prefix='', loop=asyncio.get_event_loop()):
        self.name = name
        self.args = args
        self.prefix = prefix
        self.response = None
        self.event = asyncio.Event(loop=loop)
        self.tag = tag

    def __repr__(self):
        return '%s %s%s %s' % (self.tag, self.prefix, self.name, ' '.join(self.args))

    def close(self, line, result):
        self.append_to_resp(line, result=result)
        self.event.set()

    def append_to_resp(self, line, result='Pending'):
        if self.response is None:
            self.response = Response(result, [line])
        else:
            old = self.response
            self.response = Response(result, old.text + [line])

    @asyncio.coroutine
    def wait(self):
        yield from self.event.wait()


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
fetch_message_data_re = re.compile(rb'\* [0-9]+ FETCH')
resp_state_re = re.compile(rb'OK|NO|BAD .*')
literal_re = re.compile(rb'.*{(?P<size>\d+)}$')


class IMAP4ClientProtocol(asyncio.Protocol):
    def __init__(self, loop):
        self.loop = loop
        self.transport = None
        self.state = STARTED
        self.state_condition = asyncio.Condition()
        self.capabilities = ()
        self.pending_async_commands = dict()
        self.pending_sync_command = None
        self.imap_version = None

        self.tagnum = 0
        self.tagpre = int2ap(random.randint(4096, 65535))

    def connection_made(self, transport):
        self.transport = transport
        self.state = CONNECTED

    def data_received(self, data):
        log.debug('Received : %s' % data)
        lines = _split_responses(data)
        for line in lines:
            response_line = line.decode()
            if self.state == CONNECTED:
                asyncio.async(self.welcome(response_line))
            else:
                if response_line.startswith('*'):
                    self._untagged_response(response_line.replace('* ', ''))
                elif response_line.startswith('+'):
                    self._continuation(response_line.replace('+ ', ''))
                else:
                    self._response_done(response_line)

    def connection_lost(self, exc):
        self.transport.close()

    def send(self, line):
        data = ('%s\r\n' % line).encode()
        log.debug('Sending : %s' % data)
        self.transport.write(data)

    @asyncio.coroutine
    def execute_command(self, command):
        if self.state not in Commands.get(command.name).valid_states:
            raise Abort('command %s illegal in state %s' % (command.name, self.state))

        self.send(str(command))

        if Commands.get(command.name).exec == Exec.sync:
            self.pending_sync_command = command
        else:
            self.pending_async_commands[command.name] = command

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
        response = yield from self.execute_command(
            Command('LOGIN', self.new_tag(), user, '"%s"' % password, loop=self.loop))

        if 'OK' == response.result:
            self.state = AUTH
        return response

    @change_state
    @asyncio.coroutine
    def logout(self):
        response = (yield from self.execute_command(Command('LOGOUT', self.new_tag(), loop=self.loop)))
        if 'OK' == response.result:
            self.state = LOGOUT
        return response

    @change_state
    @asyncio.coroutine
    def select(self, mailbox='INBOX'):
        response = yield from self.execute_command(
            Command('SELECT', self.new_tag(), mailbox, loop=self.loop))

        if 'OK' == response.result:
            self.state = SELECTED
        for line in response.text:
            if 'EXISTS' in line:
                return Response(response.result, [line.replace(' EXISTS', '')])
        return response

    @asyncio.coroutine
    def idle(self):
        return (yield from self.execute_command(Command('IDLE', self.new_tag(), loop=self.loop)))

    @asyncio.coroutine
    def search(self, *criteria, charset='utf-8', by_uid=False):
        args = ('CHARSET', charset) + criteria if charset is not None else criteria
        prefix = 'UID ' if by_uid else ''

        response = yield from self.execute_command(
            Command('SEARCH', self.new_tag(), *args, prefix=prefix, loop=self.loop))

        for line in response.text:
            if 'SEARCH' in line:
                return Response(response.result, [line.replace('SEARCH ', '')])
        return response

    @asyncio.coroutine
    def fetch(self, message_set, message_parts, by_uid=False):
        response = yield from self.execute_command(
            Command('FETCH', self.new_tag(), message_set, message_parts,
                    prefix='UID ' if by_uid else '', loop=self.loop))

        head, _, tail = response.text[0].partition(CRLF.decode())
        return Response(response.result, [head, tail.rstrip(')').encode()])

    @asyncio.coroutine
    def uid(self, command, *criteria):
        if self.state not in Commands.get('UID').valid_states:
            raise Error('command UID illegal in state %s' % self.state)

        if command.upper() not in {'COPY', 'FETCH', 'STORE'}:
            raise Abort('command UID only possible with COPY, FETCH or STORE (was %s)' % command)

        if command.upper() == 'FETCH':
            return self.fetch(criteria[0], criteria[1], by_uid=True)

    @asyncio.coroutine
    def capability(self):
        response = yield from self.execute_command(Command('CAPABILITY', self.new_tag(), loop=self.loop))

        version = None
        for line in response.text:
            if 'CAPABILITY' in line:
                version = line.split()[1].upper()
        if version not in AllowedVersions:
            raise Error('server not IMAP4 compliant')
        else:
            self.imap_version = version

    @asyncio.coroutine
    def wait_pending_commands(self):
        for command in self.pending_async_commands.values():
            yield from command.wait()

    @asyncio.coroutine
    def wait(self, state_regexp):
        state_re = re.compile(state_regexp)
        with (yield from self.state_condition):
            yield from self.state_condition.wait_for(lambda: state_re.match(self.state))

    def _untagged_response(self, line):
        if self.pending_sync_command is not None:
            self.pending_sync_command.append_to_resp(line)
            if self.pending_sync_command.name == 'IDLE':
                self.send('DONE')
        else:
            if 'FETCH' in line:
                _, _, line = line.partition(' ')
            command, _, text = line.partition(' ')
            pending_async_command = self.pending_async_commands.get(command.upper())
            if pending_async_command is None:
                raise Abort('unexpected untagged (%s) response:' % line)
            pending_async_command.append_to_resp('%s %s' % (command, text))

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
                raise Error('unconsistent state : two commands have the same tag (%s)' % cmds)
            command = cmds[0]
            self.pending_async_commands[command.name] = None

        response_result, _, response_text = response.partition(' ')
        command.close(response_text, result=response_result)

    def _continuation(self, *args):
        # TODO What ?
        pass

    def new_tag(self):
        tag = self.tagpre + str(self.tagnum)
        self.tagnum += 1
        return tag

    def _find_pending_async_cmd_by_tag(self, tag):
        return [c for c in self.pending_async_commands.values() if c is not None and c.tag == tag]


def _split_responses(data):
    if fetch_message_data_re.match(data):
        head, _, tail = data.partition(CRLF)
        msg_size = literal_re.match(head).group('size')
        # we want to cut -----------------------
        #                              ...here |
        #                               so 4+1 v
        # b'* 3 FETCH (UID 3 RFC822 {4}\r\nmail)\r\n...
        end_message_index_with_parenthesis = int(msg_size) + 1

        fetch_line = head + CRLF + tail[0:end_message_index_with_parenthesis]
        after_fetch = tail[end_message_index_with_parenthesis:].strip()

        return [fetch_line] + _split_responses(after_fetch)
    else:
        return data.strip().splitlines()


class IMAP4(object):
    TIMEOUT_SECONDS = 30

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

    @asyncio.coroutine
    def search(self, *criteria, charset='utf-8'):
        return (yield from asyncio.wait_for(self.protocol.search(*criteria, charset=charset), self.timeout))

    @asyncio.coroutine
    def uid_search(self, *criteria, charset='utf-8'):
        return (yield from asyncio.wait_for(self.protocol.search(*criteria, by_uid=True, charset=charset), self.timeout))

    @asyncio.coroutine
    def uid(self, command, *criteria):
        return (yield from asyncio.wait_for(self.protocol.uid(command, *criteria), self.timeout))

    @asyncio.coroutine
    def fetch(self, message_set, message_parts):
        return (yield from asyncio.wait_for(self.protocol.fetch(message_set, message_parts), self.timeout))

    def idle(self, callback=None):
        future = asyncio.async(self.protocol.idle(), loop=self.protocol.loop)
        future.add_done_callback(callback)
        return future


class IMAP4_SSL(IMAP4):
    def __init__(self, host='localhost', port=IMAP4_SSL_PORT, loop=asyncio.get_event_loop(),
                 timeout=IMAP4.TIMEOUT_SECONDS):
        super().__init__(host, port, loop, timeout)

    def create_client(self, host, port, loop):
        self.protocol = IMAP4ClientProtocol(loop)
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        loop.create_task(loop.create_connection(lambda: self.protocol, host, port, ssl=ssl_context))


def int2ap(num):
    """Convert integer to A-P string representation."""
    val = ''; ap = 'ABCDEFGHIJKLMNOP'
    num = int(abs(num))
    while num:
        num, mod = divmod(num, 16)
        val += ap[mod:mod + 1]
    return val
