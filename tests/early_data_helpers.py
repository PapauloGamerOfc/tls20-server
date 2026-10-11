"""Assert a wire-level early-record rejection independently of TCP scheduling."""

import asyncio
from unittest.mock import patch

from tls20_server.errors import ProtocolError
from tls20_server.handshake import Wire


async def assert_early_record_overflow(case, attempt, *, finish_after_rejection=False):
    original_fatal, original_send = Wire.fatal, Wire.send_frame
    rejected = asyncio.Event()
    alerts, sealed_alerts, delayed_finishes = [], [], []
    completed = len(case.channels)

    async def fatal(wire, error, state=None):
        if wire.writer.get_extra_info("peername")[1] == case.port:
            return await original_fatal(wire, error, state)
        alerts.append(error.alert)
        if state is None:
            return await original_fatal(wire, error, state)
        seal = state.seal

        def capture(content, kind, *args, **kwargs):
            sealed = seal(content, kind, *args, **kwargs)
            sealed_alerts.append((content, kind))
            return sealed

        with patch.object(state, "seal", capture):
            await original_fatal(wire, error, state)
        rejected.set()

    async def send(wire, message, state=None):
        if (finish_after_rejection and message[0] == 20
                and wire.writer.get_extra_info("peername")[1] == case.port):
            # Deterministically exercise the peer-already-closed schedule that
            # exposed these tests' ProtocolError-only assumption on CI.
            await asyncio.wait_for(rejected.wait(), 2)
            delayed_finishes.append(True)
            await asyncio.sleep(0)
        return await original_send(wire, message, state)

    with patch.object(Wire, "fatal", fatal), patch.object(Wire, "send_frame", send):
        with case.assertRaises((ProtocolError, ConnectionError)) as failure:
            await attempt()
        await asyncio.wait_for(rejected.wait(), 2)
    # A transport exception alone is insufficient: the server must actually
    # seal fatal record_overflow, deliver no early data and establish no channel.
    case.assertEqual(alerts, [22])
    case.assertEqual(sealed_alerts, [(b"\x02\x16", 21)])
    case.assertEqual(delayed_finishes, [True] if finish_after_rejection else [])
    case.assertFalse(case.early)
    case.assertEqual(len(case.channels), completed)
    if isinstance(failure.exception, ProtocolError) and failure.exception.alert != 22:
        case.assertIsInstance(failure.exception.__cause__, asyncio.IncompleteReadError)
