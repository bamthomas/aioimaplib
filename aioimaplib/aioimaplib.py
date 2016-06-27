# -*- coding: utf-8 -*-
import asyncio
import logging

import re

import random

from functools import update_wrapper

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
sh = logging.StreamHandler()
sh.setLevel(logging.DEBUG)
sh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s " +
                                  "[%(module)s:%(lineno)d] %(message)s"))
log.addHandler(sh)

IMAP4_PORT = 143
IMAP4_SSL_PORT = 993
STARTED, CONNECTED, NONAUTH, AUTH, SELECTED, LOGOUT = 'STARTED', 'CONNECTED', 'NONAUTH', 'AUTH', 'SELECTED', 'LOGOUT'

AllowedVersions = ('IMAP4REV1', 'IMAP4')

#       Patterns to match server responses
Continuation = re.compile(br'\+( (?P<data>.*))?')
Flags = re.compile(br'.*FLAGS \((?P<flags>[^\)]*)\)')
InternalDate = re.compile(br'.*INTERNALDATE "'
                          br'(?P<day>[ 0123][0-9])-(?P<mon>[A-Z][a-z][a-z])-(?P<year>[0-9][0-9][0-9][0-9])'
                          br' (?P<hour>[0-9][0-9]):(?P<min>[0-9][0-9]):(?P<sec>[0-9][0-9])'
                          br' (?P<zonen>[-+])(?P<zoneh>[0-9][0-9])(?P<zonem>[0-9][0-9])'
                          br'"')
Literal = re.compile(br'.*{(?P<size>\d+)}$', re.ASCII)
MapCRLF = re.compile(br'\r\n|\r|\n')
Response_code = re.compile(br'\[(?P<type>[A-Z-]+)( (?P<data>[^\]]*))?\]')
Untagged_response = re.compile(br'\* (?P<type>[A-Z-]+)( (?P<data>.*))?')
Untagged_status = re.compile(br'\* (?P<data>\d+) (?P<type>[A-Z-]+)( (?P<data2>.*))?', re.ASCII)


def critical_section(func):
    @asyncio.coroutine
    def execute_section(self, critical_func, *args, **kwargs):
        with (yield from self.state_condition):
            critical_func(self, *args, **kwargs)
            log.debug('state -> %s' % self.state)
            self.state_condition.notify_all()

    def wrapper(self, *args, **kwargs):
        asyncio.wait(asyncio.async(execute_section(self, func, *args, **kwargs)))
    return update_wrapper(wrapper, func)


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

    @asyncio.coroutine
    def wait(self, state):
        with (yield from self.state_condition):
            yield from self.state_condition.wait_for(lambda: self.state == state)

    def data_received(self, data):
        response_array = data.decode().rstrip().split()
        if self.state == CONNECTED:
            self.welcome(response_array)
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

    @critical_section
    def welcome(self, command_array):
        if 'PREAUTH' in command_array:
            self.state = AUTH
        elif 'OK' in command_array:
            self.state = NONAUTH
        else:
            raise self.Error(command_array)
        self.send_tagged_command('CAPABILITY')

    def send_tagged_command(self, command):
        tag = self._new_tag()
        self.transport.write('{tag} {command}\r\n'.format(tag=tag, command=command).encode())
        self.tagged_commands[tag] = asyncio.Event(loop=self.loop)
        return tag

    def _new_tag(self):
        tag = self.tagpre + str(self.tagnum)
        self.tagnum += 1
        return tag

    def capability(self, *args):
        version = args[0].upper()
        if version not in AllowedVersions:
            raise self.Error('server not IMAP4 compliant')
        else:
            self.imap_version = version

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

        response_status = args[0]
        if 'OK' == response_status:
            self.tagged_commands.get(tag).set()
            self.tagged_commands[tag] = None # where do we purge None values?
        else:
            raise self.Abort('response status %s for : %s' % (response_status, args))

    @asyncio.coroutine
    def wait_pending_commands(self):
        for event in self.tagged_commands.values():
            yield from event.wait()


class IMAP4(object):
    def __init__(self, host='localhost', port=IMAP4_PORT, loop=asyncio.get_event_loop()):
        self.port = port
        self.host = host
        self.protocol = IMAP4ClientProtocol(loop)
        loop.create_task(loop.create_connection(lambda: self.protocol, 'localhost', 12345))

    def login(self, user, password):
        pass


def int2ap(num):
    """Convert integer to A-P string representation."""
    val = ''; AP = 'ABCDEFGHIJKLMNOP'
    num = int(abs(num))
    while num:
        num, mod = divmod(num, 16)
        val += AP[mod:mod + 1]
    return val
