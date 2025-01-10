import asyncio

import pytest

from aioimaplib import Command, CommandTimeout, STOP_WAIT_SERVER_PUSH, AioImapException, Response
from aioimaplib.tests import imapserver
from aioimaplib.tests.server_fixture import with_server, login_user_async, advance_time


@pytest.mark.asyncio()
async def test_command_timeout(event_loop, with_server, advance_time):
    cmd = Command('CMD', 'tag', loop=event_loop, timeout=1)
    await advance_time(2)
    with pytest.raises(AioImapException):
        await cmd.wait()


@pytest.mark.asyncio()
async def test_command_close_cancels_timer(event_loop, with_server, advance_time):
    cmd = Command('CMD', 'tag', loop=event_loop, timeout=1)
    cmd.close(b'line', 'OK')
    await advance_time(3)

    await cmd.wait()
    assert Response('OK', [b'line']) == cmd.response


@pytest.mark.asyncio()
async def test_command_begin_literal_data_resets_timer(event_loop, with_server, advance_time):
    cmd = Command('CMD', 'tag', loop=event_loop, timeout=2)

    await advance_time(1)
    cmd.begin_literal_data(7, b'literal')

    await advance_time(1.9)
    cmd.close(b'line', 'OK')

    await cmd.wait()
    assert Response('OK', [b'literal', b'line']) == cmd.response


@pytest.mark.asyncio()
async def test_command_append_data_resets_timer(event_loop, with_server, advance_time):
    cmd = Command('CMD', 'tag', loop=event_loop, timeout=2)
    cmd.begin_literal_data(4, b'da')

    await advance_time(1.9)
    cmd.append_literal_data(b'ta')

    await advance_time(1.9)
    cmd.close(b'line', 'OK')

    await cmd.wait()
    assert Response('OK', [b'data', b'line']) == cmd.response


@pytest.mark.asyncio()
async def test_command_append_literal_data_resets_timer(event_loop, with_server, advance_time):
    cmd = Command('CMD', 'tag', loop=event_loop, timeout=2)
    cmd.begin_literal_data(12, b'literal')

    await advance_time(1.9)
    cmd.append_literal_data(b' data')

    await advance_time(1.9)
    cmd.close(b'line', 'OK')

    await cmd.wait()
    assert Response('OK', [b'literal data', b'line']) == cmd.response


@pytest.mark.asyncio()
async def test_command_append_to_resp_resets_timer(event_loop, with_server, advance_time):
    cmd = Command('CMD', 'tag', loop=event_loop, timeout=2)

    await advance_time(1.9)
    cmd.append_to_resp(b'line 1')

    await advance_time(1.9)
    cmd.close(b'line 2', 'OK')

    await cmd.wait()
    assert Response('OK', [b'line 1', b'line 2']) == cmd.response


@pytest.mark.asyncio()
async def test_command_timeout_while_receiving_data(event_loop, with_server, advance_time):
    cmd = Command('CMD', 'tag', loop=event_loop, timeout=2)

    await advance_time(1)
    cmd.begin_literal_data(12, b'literal')

    await advance_time(3)
    with pytest.raises(AioImapException):
        await cmd.wait()


@pytest.mark.asyncio()
async def test_when_async_commands_timeout__they_should_be_removed_from_protocol_state(event_loop, with_server, advance_time):
    imap_client = await login_user_async('user', 'pass', select=True, loop=event_loop)
    await (imap_client.protocol.execute(Command(
        'DELAY', imap_client.protocol.new_tag(), '3', loop=event_loop)))

    noop_task = asyncio.ensure_future(imap_client.protocol.execute(
        Command('NOOP', imap_client.protocol.new_tag(), '', loop=event_loop, timeout=2)))
    await advance_time(1)

    assert 1 == len(imap_client.protocol.pending_async_commands)
    await advance_time(1.1)

    finished, pending = await asyncio.wait([noop_task])
    assert noop_task in finished
    assert isinstance(noop_task.exception(), CommandTimeout)
    assert 0 == len(imap_client.protocol.pending_async_commands)


@pytest.mark.asyncio()
async def test_when_sync_commands_timeout__they_should_be_removed_from_protocol_state(event_loop, with_server, advance_time):
    imap_client = await login_user_async('user', 'pass', select=True, loop=event_loop)
    await (imap_client.protocol.execute(Command(
        'DELAY', imap_client.protocol.new_tag(), '3', loop=event_loop)))

    delay_task = asyncio.ensure_future(imap_client.protocol.execute(
        Command('DELAY', imap_client.protocol.new_tag(), '0', loop=event_loop, timeout=2)))
    await advance_time(1)
    assert imap_client.protocol.pending_sync_command is not None
    await advance_time(1.1)

    finished, pending = await asyncio.wait([delay_task])
    assert delay_task in finished
    assert isinstance(delay_task.exception(), CommandTimeout)
    assert imap_client.protocol.pending_sync_command is None


# test failing with python 12
@pytest.mark.asyncio()
async def test_idle_start__exits_queue_get_without_timeout_error(event_loop, with_server, advance_time):
    imap_client = await login_user_async('user', 'pass', select=True, loop=event_loop)

    idle_timeout = 5
    await imap_client.idle_start(idle_timeout)

    push_task = asyncio.ensure_future(imap_client.wait_server_push(idle_timeout + 2))
    await advance_time(idle_timeout + 1)

    r = await asyncio.wait_for(push_task, 0)
    assert STOP_WAIT_SERVER_PUSH == r


@pytest.mark.asyncio()
async def test_idle_start__exits_queueget_with_keepalive_without_timeout_error(event_loop, with_server, advance_time):
    imap_client = await login_user_async('user', 'pass', select=True, loop=event_loop)

    # Idle long enough for the server to issue a keep-alive
    server_idle_timeout = imapserver.ImapProtocol.IDLE_STILL_HERE_PERIOD_SECONDS
    idle_timeout = server_idle_timeout + 1
    idle = await imap_client.idle_start(idle_timeout)

    push_task = asyncio.ensure_future(imap_client.wait_server_push(server_idle_timeout - 1))

    # Advance time until we've received a keep-alive from server
    await advance_time(server_idle_timeout)

    # The original push task timed out
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(push_task, 0.1)

    # Read the keepalive from the server
    r = await imap_client.wait_server_push(0.1)
    assert [b'OK Still here'] == r

    # Advance the clock to the client timeout (idle waiter triggers)
    await advance_time(1)
    imap_client.idle_done()

    r = await asyncio.wait_for(idle, 1)
    assert "OK" == r.result

    assert not imap_client.protocol._idle_event.is_set()

    # Start another idle period
    idle = await imap_client.idle_start(idle_timeout)
    await advance_time(1)

    # Read 'stop_wait_server_push'
    push_task = asyncio.ensure_future(imap_client.wait_server_push(0.1))
    await advance_time(1)
    r = await asyncio.wait_for(push_task, None)
    assert STOP_WAIT_SERVER_PUSH == r

    # There shouldn't be anything left in the queue (no '+ idling')
    with pytest.raises(asyncio.TimeoutError):
        push_task = asyncio.ensure_future(imap_client.wait_server_push(0.1))
        await advance_time(1)
        await asyncio.wait_for(push_task, 0.1)

    imap_client.idle_done()
    await asyncio.wait_for(idle, 1)

