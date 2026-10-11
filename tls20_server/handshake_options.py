"""Negotiation of optional control profiles; no secret derivation or I/O."""

from dataclasses import dataclass

from .errors import ProtocolError
from .optional_controls import SignalingBinding, TicketRequest, heartbeat_mode, ticket_hint


@dataclass(frozen=True)
class ControlSelection:
    extensions: tuple = ()
    heartbeat_local_mode: int | None = None
    heartbeat_peer_mode: int | None = None
    expected_tickets: int | None = None
    signaling_context: bytes = b""


def _local_heartbeat(mode):
    if mode is not None and (type(mode) is not int or mode not in (1, 2)):
        raise ValueError("local heartbeat mode must be 1, 2 or None")


def client_controls(*, heartbeat=None, tickets=None, signaling=None):
    _local_heartbeat(heartbeat)
    result = []
    if heartbeat is not None:
        result.append((15, bytes((heartbeat,))))
    if tickets is not None:
        if not isinstance(tickets, TicketRequest):
            raise ValueError("tickets must be a TicketRequest")
        result.append((58, tickets.encode()))
    if signaling is not None:
        if not isinstance(signaling, SignalingBinding):
            raise ValueError("signaling requires independently verified SignalingBinding")
        result.extend(signaling.extensions().items())
    return tuple(result)


def server_controls(offers, *, heartbeat=None, ticket_limit=1, tickets_enabled=True,
                    resumed=False, signaling=None):
    """Call for the final CH, before authenticating/sending the EE selection.

    `resumed` means a selected resumption ticket, NOT a direct/imported PSK.
    Ticket counts are hints, bounded by the explicitly configured local budget.
    Preserve these negotiated values on the resulting channel, not on HRR.
    """
    _local_heartbeat(heartbeat)
    responses = []
    peer_mode = heartbeat_mode(offers[15]) if 15 in offers else None
    local_mode = heartbeat if peer_mode is not None else None
    if local_mode is None:
        peer_mode = None
    else:
        responses.append((15, bytes((local_mode,))))
    expected = None
    if 58 in offers:
        request = TicketRequest.parse(offers[58])
        expected = request.select(resumed=resumed, local_limit=ticket_limit if tickets_enabled else 0)
        responses.append((58, bytes((expected,))))
    context = b""
    if signaling is not None:
        if not isinstance(signaling, SignalingBinding):
            raise ValueError("signaling requires independently verified SignalingBinding")
        signaling.validate(offers)
        responses.extend((kind, value) for kind, value in signaling.extensions().items() if kind in offers)
        context = signaling.context()
    return ControlSelection(tuple(responses), local_mode, peer_mode, expected, context)


def client_control_selection(responses, *, heartbeat=None, tickets=None, signaling=None):
    """Check received EE against this attempt's own CH and current policy."""
    _local_heartbeat(heartbeat)
    peer_mode = None
    if 15 in responses:
        if heartbeat is None:
            raise ProtocolError("unoffered heartbeat response", alert=110)
        peer_mode = heartbeat_mode(responses[15])
    expected = None
    if 58 in responses:
        if tickets is None:
            raise ProtocolError("unoffered ticket request hint", alert=110)
        expected = ticket_hint(responses[58])
    if signaling is None:
        if 55 in responses or 56 in responses:
            raise ProtocolError("unoffered external signaling response", alert=110)
        context = b""
    else:
        signaling.validate(responses)
        context = signaling.context()
    return ControlSelection((), heartbeat if peer_mode is not None else None,
                            peer_mode, expected, context)
