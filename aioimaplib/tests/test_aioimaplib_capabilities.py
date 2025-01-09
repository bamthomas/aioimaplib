import asyncio
import logging

import pytest

from aioimaplib import aioimaplib
from aioimaplib.aioimaplib import Abort
from aioimaplib.tests.imapserver import ImapProtocol, ServerState
from aioimaplib.tests.server_fixture import with_server, login_user_async

aioimaplib.log.setLevel(logging.WARNING)
sh = logging.StreamHandler()
sh.setLevel(logging.INFO)
sh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(module)s:%(lineno)d] %(message)s"))
aioimaplib.log.addHandler(sh)


@pytest.mark.asyncio()
async def test_capabilities(with_server):
    imap_client = aioimaplib.IMAP4(port=12345, loop=asyncio.get_running_loop())
    await asyncio.wait_for(imap_client.wait_hello_from_server(), 2)

    assert 'IMAP4REV1' == imap_client.protocol.imap_version
    assert {'IMAP4rev1', 'YESAUTH'} == imap_client.protocol.capabilities
    assert imap_client.has_capability('YESAUTH')


@pytest.mark.asyncio()
async def test_capabilities_server_not_compliant(event_loop):
    def create_protocol():
        class NotCompliantProtocol(ImapProtocol):
            def capability(self, tag, *args):
                """No sent IMAP4rev1"""
                self.send_untagged_line('CAPABILITY YESAUTH')
                self.send_tagged_line(tag, 'OK Pre-login capabilities listed, post-login capabilities have more')
        protocol = NotCompliantProtocol(ServerState(), loop=event_loop)
        return protocol

    srv = await event_loop.create_server(create_protocol, host='127.0.0.1', port=12345, ssl=None)
    async with srv:
        await srv.start_serving()

        with pytest.raises(asyncio.TimeoutError):
            with pytest.raises(aioimaplib.Error) as expected:
                await login_user_async('user', 'pass', timeout=0.1)

            assert expected == 'server not IMAP4 compliant'


@pytest.mark.parametrize("with_server", [''], indirect=True) # '' = no capabilities
@pytest.mark.asyncio()
async def test_idle_messages_without_idle_capability_abort_command(with_server):
    imap_client = await login_user_async('user', 'pass', select=True)
    with pytest.raises(Abort):
        await asyncio.wait_for(imap_client.idle(), timeout=2)


@pytest.mark.parametrize("with_server", [''], indirect=True) # '' = no capabilities
@pytest.mark.asyncio()
async def test_expunge_messages_without_uidplus_capability_abort_command(with_server):
    imap_client = await login_user_async('user', 'pass', select=True)
    with pytest.raises(Abort):
        await imap_client.uid('expunge', '1:1')


@pytest.mark.parametrize("with_server", [''], indirect=True) # '' = no capabilities
@pytest.mark.asyncio()
async def test_move_without_move_capability_abort_command(with_server):
    imap_client = await login_user_async('user', 'pass', select=True)
    with pytest.raises(Abort):
        await imap_client.move('1:1', 'Trash')


@pytest.mark.parametrize("with_server", [''], indirect=True) # '' = no capabilities
@pytest.mark.asyncio()
async def test_uidmove_without_move_capability_abort_command(with_server):
    imap_client = await login_user_async('user', 'pass', select=True)
    with pytest.raises(Abort):
        await imap_client.uid('move', '1:1', 'Trash')


@pytest.mark.parametrize("with_server", [''], indirect=True) # '' = no capabilities
@pytest.mark.asyncio()
async def test_enable_without_enable_capability_abort_command(with_server):
    imap_client = await login_user_async('user', 'pass')
    with pytest.raises(Abort):
        await imap_client.enable('CAPABILITY')


@pytest.mark.parametrize("with_server", [''], indirect=True) # '' = no capabilities
@pytest.mark.asyncio()
async def test_namespace_without_namespace_capability_abort_command(with_server):
    imap_client = await login_user_async('user', 'pass')
    with pytest.raises(Abort):
        await imap_client.namespace()
