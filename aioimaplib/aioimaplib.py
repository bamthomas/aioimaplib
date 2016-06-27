# -*- coding: utf-8 -*-
import asyncio
import logging

import functools

import random
from collections import namedtuple


log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
sh = logging.StreamHandler()
sh.setLevel(logging.INFO)
sh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(module)s:%(lineno)d] %(message)s"))
log.addHandler(sh)

IMAP4_PORT = 143
IMAP4_SSL_PORT = 993
STARTED, CONNECTED, NONAUTH, AUTH, SELECTED, LOGOUT = 'STARTED', 'CONNECTED', 'NONAUTH', 'AUTH', 'SELECTED', 'LOGOUT'

AllowedVersions = ('IMAP4REV1', 'IMAP4')


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

    def ok(self, response):
        self.response = response
        self.event.set()

    @asyncio.coroutine
    def wait(self):
        yield from self.event.wait()


class IMAP4ClientProtocol(asyncio.Protocol):
    class Error(Exception):
        def __init__(self, reason):
            super().__init__(reason)

    class Abort(Error):
        def __init__(self, reason):
            super().__init__(reason)

    def __init__(self, loop):
        self.loop = loop
        self.transport = None
        self.state = STARTED
        self.state_condition = asyncio.Condition()
        self.capabilities = ()
        self.tagged_commands = dict()
        self.imap_version = None

        self.tagnum = 0
        self.tagpre = int2ap(random.randint(4096, 65535))

    def connection_made(self, transport):
        self.transport = transport
        self.state = CONNECTED

    def data_received(self, data, encoding='utf-8'):
        log.debug('Received : %s' % data)
        lines = data.rstrip().split(b'\r\n')
        for line in lines:
            response_array = line.decode(encoding=encoding).split()
            if self.state == CONNECTED:
                asyncio.async(self.welcome(response_array))
            else:
                if response_array[0] == '*':
                    self._untagged_response(response_array[1:])
                elif response_array[0] == '+':
                    self._continuation(response_array[1:])
                else:
                    self._tagged_response(response_array[0], response_array[1:])

    def connection_lost(self, exc):
        self.transport.close()
        self.state = LOGOUT

    def send_tagged_command(self, command):
        tag = self._new_tag()
        command_string = '{tag} {command}\r\n'.format(tag=tag, command=command).encode()
        log.debug('Sending : %s' % command_string)
        self.transport.write(command_string)
        self.tagged_commands[tag] = command

    def capability(self, *args):
        version = args[0].upper()
        if version not in AllowedVersions:
            raise self.Error('server not IMAP4 compliant')
        else:
            self.imap_version = version

    @asyncio.coroutine
    def wait_pending_commands(self):
        for command in self.tagged_commands.values():
            yield from command.wait()

    @asyncio.coroutine
    def wait(self, state):
        with (yield from self.state_condition):
            yield from self.state_condition.wait_for(lambda: self.state == state)

    @change_state
    @asyncio.coroutine
    def welcome(self, command_array):
        if 'PREAUTH' in command_array:
            self.state = AUTH
        elif 'OK' in command_array:
            self.state = NONAUTH
        else:
            raise self.Error(command_array)
        self.send_tagged_command(Command('CAPABILITY', loop=self.loop))

    @change_state
    @asyncio.coroutine
    def login(self, user, password):
        login_cmd = Command('LOGIN', user, password, loop=self.loop)
        self.send_tagged_command(login_cmd)
        yield from login_cmd.wait()
        if 'OK' == login_cmd.response.result:
            self.state = AUTH
        return login_cmd.response

    def _untagged_response(self, response_array):
        command = response_array[0].lower()
        if not hasattr(self, command):
            raise self.Error('Command "%s" not implemented' % command)
        getattr(self, command)(*response_array[1:])

    def _continuation(self, *args):
        # TODO
        pass

    def _tagged_response(self, tag, args):
        if not tag in self.tagged_commands:
            raise self.Abort('unexpected tagged (%s) response: %s' % (tag, args))

        response_result = args[0]
        if 'OK' == response_result:
            self.tagged_commands.get(tag).ok(Response(response_result, [' '.join(args[1:])]))
            self.tagged_commands[tag] = None # where do we purge None values?
        else:
            raise self.Abort('response status %s for : %s' % (response_result, args))

    def _new_tag(self):
        tag = self.tagpre + str(self.tagnum)
        self.tagnum += 1
        return tag


class IMAP4(object):
    TIMEOUT_SECONDS = 30

    def __init__(self, host='localhost', port=IMAP4_PORT, loop=asyncio.get_event_loop()):
        self.port = port
        self.host = host
        self.protocol = IMAP4ClientProtocol(loop)
        loop.create_task(loop.create_connection(lambda: self.protocol, 'localhost', 12345))

    @asyncio.coroutine
    def login(self, user, password):
        return (yield from asyncio.wait_for(self.protocol.login(user, password), self.TIMEOUT_SECONDS))


def int2ap(num):
    """Convert integer to A-P string representation."""
    val = ''; AP = 'ABCDEFGHIJKLMNOP'
    num = int(abs(num))
    while num:
        num, mod = divmod(num, 16)
        val += AP[mod:mod + 1]
    return val
