"""Errors safe to expose without dumping protocol secrets."""


class ProtocolError(ValueError):
    """Invalid peer input or an exhausted connection limit."""

    def __init__(self, message, *, alert=40):
        super().__init__(message)
        self.alert = alert


class ConfigurationError(ValueError):
    """Invalid local settings or credential files."""


class PeerClosed(ProtocolError):
    """A peer alert ended the exchange; do not send a responding fatal alert."""
