import asyncio
import logging

import pytest

from aioimaplib import aioimaplib
from aioimaplib.aioimaplib import Abort
from aioimaplib.tests.imapserver import ImapProtocol, ServerState, MockImapServer
from aioimaplib.tests.server_fixture import with_server, login_user_async, main_test

aioimaplib.log.setLevel(logging.WARNING)
sh = logging.StreamHandler()
sh.setLevel(logging.INFO)
sh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(module)s:%(lineno)d] %(message)s"))
aioimaplib.log.addHandler(sh)


@pytest.mark.skip(reason="it passes alone but blocks the other tests in this module")
@pytest.mark.asyncio()
async def test_capabilities_server_not_compliant(event_loop):
    class NotCompliantProtocol(ImapProtocol):
        def capability(self, tag, *args):
            """should send CAPABILITY IMAP4rev1 YESAUTH """
            self.send_untagged_line('CAPABILITY YESAUTH')
            self.send_tagged_line(tag, 'OK Pre-login capabilities listed, post-login capabilities have more')

    class NotCompliantServer(MockImapServer):
        def run_server(self, host='127.0.0.1', port=1143, fetch_chunk_size=0, ssl_context=None):
            return event_loop.create_server(lambda: NotCompliantProtocol(ServerState(), loop=self.loop), host=host, port=port, ssl=None)

    imap_srv = NotCompliantServer(loop=event_loop)
    srv = await imap_srv.run_server(port=12345)
    main_server_future = asyncio.ensure_future(main_test(server=srv, ssl_context=None))

    with pytest.raises(asyncio.TimeoutError):
        with pytest.raises(aioimaplib.Error) as expected:
            await login_user_async('user', 'pass', timeout=0.1)

        assert expected == 'server not IMAP4 compliant'


@pytest.mark.asyncio()
async def test_capabilities(with_server):
    imap_client = aioimaplib.IMAP4(port=12345, loop=asyncio.get_running_loop())
    await asyncio.wait_for(imap_client.wait_hello_from_server(), 2)

    assert 'IMAP4REV1' == imap_client.protocol.imap_version
    assert {'IMAP4rev1', 'YESAUTH'} == imap_client.protocol.capabilities
    assert imap_client.has_capability('YESAUTH')


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
