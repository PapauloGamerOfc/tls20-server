"""Errors safe to expose without dumping protocol secrets."""


class ProtocolError(ValueError):
    """Invalid peer input or an exhausted connection limit."""


class ConfigurationError(ValueError):
    """Invalid local settings or credential files."""
