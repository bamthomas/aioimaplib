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
    def __init__(self, name, *args, **kwargs):
        self.name = name
        self.args = args
        self.response = None
        self.event = asyncio.Event(loop=kwargs.pop('loop', asyncio.get_event_loop()))
        self.kwargs = kwargs

    def __repr__(self):
        return '%s %s' % (self.name, ' '.join(self.args))

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


class IMAP4ClientProtocol(asyncio.Protocol):
    def __init__(self, loop):
        self.loop = loop
        self.transport = None
        self.state = STARTED
        self.state_condition = asyncio.Condition()
        self.capabilities = ()
        self.tagged_commands = dict()
        self.pending_sync_command = None
        self.imap_version = None

        self.tagnum = 0
        self.tagpre = int2ap(random.randint(4096, 65535))

    def connection_made(self, transport):
        self.transport = transport
        self.state = CONNECTED

    def data_received(self, data):
        log.debug('Received : %s' % data)
        lines = data.rstrip().split(b'\r\n')
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
                    self._tagged_response(response_line)

    def connection_lost(self, exc):
        self.transport.close()
        self.state = LOGOUT

    def send_tagged_command(self, command):
        tag = self._new_tag()

        command_string = '{tag} {command}\r\n'.format(tag=tag, command=command).encode()
        log.debug('Sending : %s' % command_string)
        self.transport.write(command_string)

        self.tagged_commands[tag] = command
        if Commands.get(command.name).exec == Exec.sync:
            self.pending_sync_command = command

    def capability(self, *args):
        version = args[0].upper()
        if version not in AllowedVersions:
            raise Error('server not IMAP4 compliant')
        else:
            self.imap_version = version

    @asyncio.coroutine
    def wait_pending_commands(self):
        for command in self.tagged_commands.values():
            yield from command.wait()

    @asyncio.coroutine
    def wait(self, state_regexp):
        state_re = re.compile(state_regexp)
        with (yield from self.state_condition):
            yield from self.state_condition.wait_for(lambda: state_re.match(self.state))

    @change_state
    @asyncio.coroutine
    def welcome(self, command):
        if 'PREAUTH' in command:
            self.state = AUTH
        elif 'OK' in command:
            self.state = NONAUTH
        else:
            raise Error(command)
        self.send_tagged_command(Command('CAPABILITY', loop=self.loop))

    @change_state
    @asyncio.coroutine
    def login(self, user, password):
        if self.state not in Commands.get('LOGIN').valid_states:
            raise Error('command LOGIN illegal in state %s' % self.state)

        login_cmd = Command('LOGIN', user, '"%s"' % password, loop=self.loop)
        self.send_tagged_command(login_cmd)
        yield from login_cmd.wait()
        if 'OK' == login_cmd.response.result:
            self.state = AUTH
        return login_cmd.response

    @change_state
    @asyncio.coroutine
    def logout(self):
        if self.state not in Commands.get('LOGOUT').valid_states:
            raise Error('command LOGOUT illegal in state %s' % self.state)

        logout_cmd = Command('LOGOUT', loop=self.loop)
        self.send_tagged_command(logout_cmd)
        yield from logout_cmd.wait()
        if 'OK' == logout_cmd.response.result:
            self.connection_lost(None)
        return logout_cmd.response

    @change_state
    @asyncio.coroutine
    def select(self, mailbox='INBOX'):
        if self.state not in Commands.get('SELECT').valid_states:
            raise Error('command SELECT illegal in state %s' % self.state)
        select_cmd = Command('SELECT', mailbox, loop=self.loop)
        self.send_tagged_command(select_cmd)
        yield from select_cmd.wait()
        if 'OK' == select_cmd.response.result:
            self.state = SELECTED
        for line in select_cmd.response.text:
            if 'EXISTS' in line:
                return Response(select_cmd.response.result, [line.replace(' EXISTS', '')])
        return select_cmd.response

    def bye(self, *args): pass

    def _untagged_response(self, line):
        if self.pending_sync_command is not None:
            self.pending_sync_command.append_to_resp(line)
        else:
            command, _, text = line.partition(' ')
            if not hasattr(self, command.lower()):
                raise Error('Command "%s" not implemented' % command)
            getattr(self, command.lower())(*text.split())

    def _continuation(self, *args):
        # TODO
        pass

    def _tagged_response(self, line):
        tag, _, response = line.partition(' ')
        if tag not in self.tagged_commands:
            raise Abort('unexpected tagged (%s) response: %s' % (tag, response))

        response_result, _, response_text = response.partition(' ')
        self.tagged_commands.get(tag).close(response_text, result=response_result)
        self.tagged_commands[tag] = None  # where do we purge None values?
        if self.pending_sync_command is not None:
            self.pending_sync_command = None

        if response_result != 'OK':
            raise Abort('response status %s for : %s' % (response_result, response_text))

    def _new_tag(self):
        tag = self.tagpre + str(self.tagnum)
        self.tagnum += 1
        return tag


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
