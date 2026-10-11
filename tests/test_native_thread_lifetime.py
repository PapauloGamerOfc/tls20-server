"""Private OpenSSL contexts must detach every worker before context destruction."""

from concurrent.futures import ThreadPoolExecutor
import os
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tls20_server.errors import ConfigurationError, ProtocolError
from tls20_server.openssl_provider import OpenSSLProvider, _synchronized
from tls20_server.pake_native import PakeProvider


class NativeScopeTests(unittest.TestCase):
    def provider(self):
        events = []
        provider = object.__new__(OpenSSLProvider)
        provider._lock = threading.RLock()
        provider._context, provider._provider = 123, 456
        provider._live_keys, provider._ciphers = 0, {}
        provider.lib = SimpleNamespace(
            OPENSSL_thread_stop_ex=lambda ctx: events.append(("stop", ctx)),
            OSSL_PROVIDER_unload=lambda ptr: events.append(("unload", ptr)),
            OSSL_LIB_CTX_free=lambda ctx: events.append(("free", ctx)),
        )
        self.addCleanup(provider.close)
        return provider, events

    def test_nested_operations_detach_only_after_outermost_return(self):
        provider, events = self.provider()

        @_synchronized
        def operation(self):
            with self._native_scope():
                self.assertion = len(events)
            self.assertion += len(events)

        with provider._native_scope():
            operation(provider)
            self.assertEqual(provider.assertion, 0)
            self.assertEqual(events, [])
        self.assertEqual(events, [("stop", 123)])

    def test_exception_detaches_and_close_orders_cleanup_before_free(self):
        provider, events = self.provider()
        with self.assertRaisesRegex(ValueError, "fixture"):
            with provider._native_scope():
                with provider._native_scope():
                    raise ValueError("fixture")
        self.assertEqual(events, [("stop", 123)])
        provider.close()
        self.assertEqual(events[1:], [("stop", 123), ("unload", 456), ("free", 123)])
        provider.close()
        self.assertEqual(len(events), 4)

    def test_nested_distinct_contexts_do_not_clear_other_context(self):
        one, first = self.provider()
        two, second = self.provider()
        two._context = 789
        with one._native_scope():
            with two._native_scope():
                pass
            self.assertEqual(second, [("stop", 789)])
            self.assertEqual(first, [])
        self.assertEqual(first, [("stop", 123)])


@unittest.skipUnless(os.environ.get("TLS20_TEST_OPENSSL"), "explicit native provider fixture required")
class NativeThreadLifetimeTests(unittest.TestCase):
    def tracked_provider(self, stops):
        original_bind = OpenSSLProvider._bind

        def bind(provider):
            original_bind(provider)
            original_stop = provider.lib.OPENSSL_thread_stop_ex

            def stop(context):
                stops.append((threading.get_ident(), context))
                original_stop(context)

            provider.lib.OPENSSL_thread_stop_ex = stop

        with patch.object(OpenSSLProvider, "_bind", bind):
            return OpenSSLProvider(os.environ["TLS20_TEST_OPENSSL"])

    def test_failed_constructor_detaches_worker_before_freeing_context(self):
        events = []
        original_bind = OpenSSLProvider._bind

        def bind(provider):
            original_bind(provider)
            stop = provider.lib.OPENSSL_thread_stop_ex
            free = provider.lib.OSSL_LIB_CTX_free

            def record_stop(context):
                events.append(("stop", threading.get_ident(), context))
                stop(context)

            def record_free(context):
                events.append(("free", threading.get_ident(), context))
                free(context)

            provider.lib.OPENSSL_thread_stop_ex = record_stop
            provider.lib.OSSL_LIB_CTX_free = record_free
            provider.lib.EVP_CIPHER_fetch = lambda *args: None

        with ThreadPoolExecutor(max_workers=1) as pool:
            with patch.object(OpenSSLProvider, "_bind", bind):
                with self.assertRaisesRegex(ConfigurationError, "cipher is unavailable"):
                    pool.submit(OpenSSLProvider, os.environ["TLS20_TEST_OPENSSL"]).result(timeout=10)
            self.assertEqual([kind for kind, _, _ in events], ["stop", "stop", "free"])
            self.assertEqual(len({thread for _, thread, _ in events}), 1)
            self.assertNotEqual(events[0][1], threading.get_ident())

    def test_persistent_workers_detach_before_context_closed_on_another_thread(self):
        # In the crash, main-thread teardown freed a libctx while asyncio's
        # persistent executor threads still retained its DRBG/exit callbacks.
        # Keep the same pool alive across independently created/freed contexts.
        pool = ThreadPoolExecutor(max_workers=3)
        provider = None
        try:
            for _ in range(16):
                stops = []
                provider = pool.submit(self.tracked_provider, stops).result(timeout=10)
                self.assertTrue(stops, "constructor must detach its worker thread")
                stops.clear()
                barrier = threading.Barrier(3)

                def native_work():
                    barrier.wait(timeout=10)
                    key, public = provider.generate_sm2()
                    try:
                        self.assertEqual(len(public), 65)
                        provider.digest("sm3", b"fixture")
                    finally:
                        key.close()
                    return threading.get_ident()

                jobs = [pool.submit(native_work) for _ in range(3)]
                workers = {job.result(timeout=10) for job in jobs}
                self.assertEqual(len(workers), 3)
                self.assertEqual({thread for thread, _ in stops}, workers)
                self.assertEqual(provider._live_keys, 0)
                provider.close()
                self.assertIsNone(provider._context)
                provider = None
        finally:
            # Even when asserting against an unfixed implementation, drain
            # workers first so the failed regression does not crash the runner.
            pool.shutdown(wait=True)
            if provider is not None:
                provider.close()

    @unittest.skipUnless(os.environ.get("TLS20_TEST_PAKE"), "explicit native PAKE fixture required")
    def test_pake_worker_failure_and_live_state_detach_without_destroying_state(self):
        stops = []
        native = self.tracked_provider(stops)
        helper = PakeProvider(native, os.environ["TLS20_TEST_PAKE"])
        pool = ThreadPoolExecutor(max_workers=1)
        state = None
        try:
            stops.clear()
            state = pool.submit(helper.create, bytes(32), bytes(32)).result(timeout=10)
            self.assertEqual(len(stops), 1)
            worker_id = stops[0][0]
            self.assertNotEqual(worker_id, threading.get_ident())
            # Per-thread cleanup must not free the heap-owned PAKE state, and
            # the provider remains unclosable while that state owns a key.
            with self.assertRaisesRegex(ProtocolError, "keys are alive"):
                native.close()
            stops.clear()
            commitment = pool.submit(state.commit).result(timeout=10)
            self.assertEqual(len(commitment), 97)
            self.assertEqual([thread for thread, _ in stops], [worker_id])
            stops.clear()
            with self.assertRaises(ProtocolError):
                pool.submit(state.finish, bytes(len(commitment))).result(timeout=10)
            # finish -> close is nested: cleanup happens once, after both.
            self.assertEqual([thread for thread, _ in stops], [worker_id])
            self.assertEqual(native._live_keys, 0)
            native.close()
        finally:
            pool.shutdown(wait=True)
            if state is not None:
                state.close()
            native.close()
