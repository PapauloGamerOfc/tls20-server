"""Explicitly authorized, test-build-only TLS 2.0 key-log sink.

No environment variable enables this feature. It never appends to an existing
file, follows a leaf symlink, prints a secret, or changes a handshake outcome.
The sink remains sensitive after closure: the operator owns secure disposal.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat
import threading

from . import _build_features

EXPORTER_LABELS = frozenset(("TLS20_EARLY_EXPORTER_SECRET", "TLS20_EXPORTER_SECRET"))
TRAFFIC_LABELS = frozenset((
    "TLS20_CLIENT_EARLY_TRAFFIC_SECRET", "TLS20_CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "TLS20_SERVER_HANDSHAKE_TRAFFIC_SECRET", "TLS20_CLIENT_TRAFFIC_SECRET_0",
    "TLS20_SERVER_TRAFFIC_SECRET_0",
))


def format_entry(label, client_random, secret):
    if label not in EXPORTER_LABELS | TRAFFIC_LABELS:
        raise ValueError("unsupported TLS 2.0 diagnostic label")
    if not isinstance(client_random, bytes) or len(client_random) != 32:
        raise ValueError("diagnostic client random must have length 32")
    if not isinstance(secret, bytes) or not 1 <= len(secret) <= 255:
        raise ValueError("invalid diagnostic secret length")
    return (label + " " + client_random.hex() + " " + secret.hex() + "\n").encode("ascii")


def _windows_create(path):
    """Create with a protected DACL granting access only to the process user."""
    import ctypes
    from ctypes import wintypes
    import msvcrt

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    security.OpenProcessToken.argtypes = (wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE))
    security.GetTokenInformation.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD))
    security.ConvertSidToStringSidW.argtypes = (ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR))
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p)
    kernel.LocalFree.argtypes = (ctypes.c_void_p,)
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    token = wintypes.HANDLE()
    sid_text, descriptor = wintypes.LPWSTR(), ctypes.c_void_p()
    class SecurityAttributes(ctypes.Structure):
        _fields_ = (("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p), ("bInheritHandle", wintypes.BOOL))
    kernel.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  ctypes.POINTER(SecurityAttributes), wintypes.DWORD,
                                  wintypes.DWORD, wintypes.HANDLE)
    kernel.CreateFileW.restype = wintypes.HANDLE
    try:
        if not security.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
            raise OSError("cannot authorize diagnostic sink owner")
        size = wintypes.DWORD()
        security.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        data = ctypes.create_string_buffer(size.value)
        if not security.GetTokenInformation(token, 1, data, size, ctypes.byref(size)):
            raise OSError("cannot authorize diagnostic sink owner")
        sid = ctypes.cast(data, ctypes.POINTER(ctypes.c_void_p))[0]
        if not security.ConvertSidToStringSidW(sid, ctypes.byref(sid_text)):
            raise OSError("cannot authorize diagnostic sink owner")
        sddl = "O:" + sid_text.value + "D:P(A;;FA;;;" + sid_text.value + ")"
        if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
            raise OSError("cannot protect diagnostic sink")
        attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
        # CREATE_NEW + OPEN_REPARSE_POINT cannot reuse a link or overwrite a file.
        handle = kernel.CreateFileW(str(path), 0x40000000, 1, ctypes.byref(attributes), 1, 0x00200080, None)
        if handle == ctypes.c_void_p(-1).value:
            raise OSError("cannot create new protected diagnostic sink")
        try:
            return msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY)
        except BaseException:
            kernel.CloseHandle(handle)
            raise
    finally:
        if descriptor:
            kernel.LocalFree(descriptor)
        if sid_text:
            kernel.LocalFree(ctypes.cast(sid_text, ctypes.c_void_p))
        if token:
            kernel.CloseHandle(token)


def _create(path):
    path = Path(path)
    if not path.is_absolute() or not path.name or path.name in (".", ".."):
        raise ValueError("diagnostic sink must be an absolute file path")
    if os.name == "nt":
        # Normalize only the parent, never dereference a pre-existing leaf.
        return _windows_create(path.parent.resolve(strict=True) / path.name)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        owner = os.fstat(directory)
        if owner.st_uid != os.getuid() or owner.st_mode & 0o022:
            raise OSError("diagnostic directory must be owned by the operator and not writable by others")
        return os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                       0o600, dir_fd=directory)
    finally:
        os.close(directory)


class DiagnosticSink:
    def __init__(self, path, *, authorize_test_data=False, authorize_traffic=False, authorize_exporters=False):
        if not _build_features.TEST_DIAGNOSTICS:
            raise RuntimeError("key logging is unavailable in production builds")
        if authorize_test_data is not True or (authorize_traffic is not True and authorize_exporters is not True):
            raise ValueError("explicit local test-data and category authorization required")
        self._traffic, self._exporters = authorize_traffic is True, authorize_exporters is True
        self._lock = threading.Lock()
        self._fd = _create(path)
        self.error = None
        owner = os.fstat(self._fd)
        if not stat.S_ISREG(owner.st_mode) or (os.name != "nt" and (owner.st_uid != os.getuid() or owner.st_mode & 0o077)):
            self.close()
            raise OSError("diagnostic sink access policy failed")

    def emit(self, label, client_random, secret):
        """Sink failure disables logging without failing authentication."""
        if (not _build_features.TEST_DIAGNOSTICS or (label in EXPORTER_LABELS and not self._exporters)
                or (label in TRAFFIC_LABELS and not self._traffic)):
            return
        with self._lock:
            if self._fd is None:
                return
            try:
                entry = format_entry(label, client_random, secret)
                offset = 0
                while offset < len(entry):
                    written = os.write(self._fd, entry[offset:])
                    if written <= 0:
                        raise OSError("diagnostic sink write failed")
                    offset += written
            except (OSError, ValueError):
                self.error = "diagnostic sink disabled after a local failure"
                self._close_locked()

    def _close_locked(self):
        fd, self._fd = self._fd, None
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass

    def close(self):
        with self._lock:
            self._close_locked()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def emit(sink, label, client_random, secret):
    """Handshake hook: no callbacks or sink construction from peer input."""
    if _build_features.TEST_DIAGNOSTICS and isinstance(sink, DiagnosticSink):
        sink.emit(label, client_random, secret)
