"""Semantic refusal tests for the embedded helper; no third party packages."""
import importlib.util
import pathlib
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.dont_write_bytecode = True
SOURCE = pathlib.Path(__file__).resolve().parents[2] / "crates/lovelyhawk-core/src/nginx_process.py"
spec = importlib.util.spec_from_file_location("nginx_process", SOURCE)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class RuntimeBoundaryTests(unittest.TestCase):
    def test_unrelated_zombie_does_not_fail_worker_inventory(self):
        def proc_read(path, _limit):
            if path.endswith("/stat"):
                state = "Z" if "/99/" in path else "S"
                return ("99 (nginx) " + state + " 41 " + "0 " * 17 + "100\n").encode()
            return b"" if "/99/" in path else b"nginx: worker process\0"
        with patch.object(helper, "process_ids", return_value=[99, 42]), patch.object(helper, "read", side_effect=proc_read):
            self.assertEqual(helper.workers(41), {(42, 100)})

    def test_only_complete_conventional_titles_are_admitted(self):
        for name in ("nginx", "/usr/sbin/nginx"):
            self.assertEqual(helper.launch_arguments("nginx: master process " + name, "/usr/sbin/nginx"), [])
            self.assertEqual(helper.launch_arguments("nginx: master process " + name + " -g daemon off;", "/usr/sbin/nginx"), ["-g", "daemon off;"])
        for suffix in (" -c /etc/nginx/other.conf", " -g daemon off; include /tmp/a;", " -p /tmp/other", " -g 'daemon off;'", " -g daemon off;\n", "\x00"):
            with self.assertRaises(helper.Refusal):
                helper.launch_arguments("nginx: master process nginx" + suffix, "/usr/sbin/nginx")

    def test_scope_rederived_from_binary_rejects_tampered_durable_record(self):
        with patch.object(helper, "build_scope", return_value={"config": "/etc/nginx/nginx.conf"}):
            with self.assertRaisesRegex(helper.Refusal, "runtime-identity-changed"):
                helper.verify_scope({"config": "/etc/nginx/other.conf"})

    def test_new_master_sharing_config_invalidates_previous_runtime_scope(self):
        with patch.object(helper, "build_scope", return_value={"config": "/etc/nginx/nginx.conf"}), \
             patch.object(helper, "master_ids", return_value=[41, 43]), patch.object(helper, "capture", return_value={}):
            with self.assertRaisesRegex(helper.Refusal, "shared-master-configuration"):
                helper.verify_scope({"pid": 41, "config": "/etc/nginx/nginx.conf"})

    def test_exited_pinned_process_never_receives_reload(self):
        with patch.object(helper.os, "pidfd_open", return_value=987), patch.object(helper.os, "close") as close, \
             patch.object(helper, "workers", return_value={(42, 100)}), patch.object(helper, "verify"), \
             patch.object(helper, "live", side_effect=helper.Refusal("process-exited")), \
             patch.object(helper.signal, "pidfd_send_signal") as send:
            with self.assertRaisesRegex(helper.Refusal, "process-exited"):
                helper.reload_and_verify({"pid": 41})
            send.assert_not_called()
            close.assert_called_once_with(987)

    def test_signal_uses_pinned_descriptor_and_unchanged_workers_do_not_pass(self):
        with patch.object(helper.os, "pidfd_open", return_value=987), patch.object(helper.os, "close"), \
             patch.object(helper, "workers", return_value={(42, 100)}), patch.object(helper, "verify"), \
             patch.object(helper, "live"), patch.object(helper.time, "monotonic", side_effect=[0, 16]), \
             patch.object(helper.signal, "pidfd_send_signal") as send:
            with self.assertRaisesRegex(helper.Refusal, "reload-worker-transition-unverified"):
                helper.reload_and_verify({"pid": 41})
            send.assert_called_once_with(987, helper.signal.SIGHUP)


class ConnectivityBoundaryTests(unittest.TestCase):
    endpoint = {"address": "127.0.0.1", "port": 8443, "inode": 900, "network_namespace": 123}

    def test_proc_tcp_decodes_both_native_word_orders_and_ignores_connections(self):
        import ipaddress
        for byteorder in ("little", "big"):
            for address in ("127.0.0.1", "0.0.0.0", "::1", "2001:db8::1234", "::ffff:127.0.0.1"):
                ip = ipaddress.ip_address(address)
                encoded = "".join("%08X" % int.from_bytes(ip.packed[i:i+4], byteorder) for i in range(0, len(ip.packed), 4))
                row = ("0: %s:20FB 00000000:0000 0A 0:0 0:0 0 0 0 900\n" % encoded).encode()
                with patch.object(helper.sys, "byteorder", byteorder):
                    self.assertEqual(helper.tcp_listeners(b"header\n" + row, ip.version == 6),
                                     [{"address": str(ip), "port": 8443, "inode": 900}])
                    self.assertEqual(helper.tcp_listeners(b"header\n" + row.replace(b" 0A ", b" 01 "), ip.version == 6), [])

    def test_changed_or_shared_listener_cannot_authorize_a_probe(self):
        with patch.object(helper, "owned_listeners", return_value=([], [])):
            with self.assertRaisesRegex(helper.Refusal, "listener-changed"):
                helper.verify_listener({"pid": 41}, self.endpoint)
        for other in [dict(self.endpoint, inode=901), dict(self.endpoint, address="0.0.0.0", inode=901),
                      dict(self.endpoint, address="::", inode=901)]:
            with patch.object(helper, "owned_listeners", return_value=([self.endpoint], [self.endpoint, other])):
                with self.assertRaisesRegex(helper.Refusal, "ambiguous-listener"):
                    helper.verify_listener({"pid": 41}, self.endpoint)
        with patch.object(helper, "owned_listeners", return_value=([self.endpoint], [self.endpoint])):
            helper.verify_listener({"pid": 41}, self.endpoint)

    def test_client_context_never_enables_environment_key_logging(self):
        import ssl
        with patch.dict(helper.os.environ, {"SSLKEYLOGFILE": "/must-not-create-session-key-log"}):
            context = helper.tls_context(ssl, "TLSv1_2", False)
            self.assertIsNone(context.keylog_filename)
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
            self.assertEqual(context.maximum_version, ssl.TLSVersion.TLSv1_2)

    def test_legacy_deprecation_diagnostics_do_not_corrupt_the_json_transport(self):
        import ssl
        import warnings
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always")
            for version in ("TLSv1", "TLSv1_1"):
                helper.tls_context(ssl, version, True)
            self.assertEqual(captured, [])

    def test_probe_names_and_paths_cannot_inject_destinations_or_headers(self):
        for name in ("", "https://a.test", "a:443", "a\r\nHost:evil", "*.test", "256.1.1.1", "a..test", "a."):
            with self.assertRaises(helper.Refusal): helper.probe_name(name)
        for path in ("", "//evil", "/a?secret=1", "/a#x", "/a\\b", "/a b", "/a\nCookie:secret"):
            with self.assertRaises(helper.Refusal): helper.probe_path(path)

    def test_only_an_explicit_peer_protocol_alert_counts_as_protocol_rejection(self):
        import ssl
        import socket
        for reason, expected in [("TLSV1_ALERT_PROTOCOL_VERSION", "protocol-rejected"),
                                 ("SSLV3_ALERT_HANDSHAKE_FAILURE", "inconclusive"),
                                 ("UNEXPECTED_EOF_WHILE_READING", "inconclusive"),
                                 ("NO_PROTOCOLS_AVAILABLE", "local-unavailable")]:
            error = ssl.SSLError(1, "not exposed to callers")
            error.reason = reason
            context = MagicMock()
            context.wrap_socket.side_effect = error
            with patch.object(helper, "tls_context", return_value=context), patch.object(socket, "socket"):
                result = helper.probe_version(ssl, socket, self.endpoint, "a.test", "/", "TLSv1")
                self.assertEqual(result["outcome"], expected)
                self.assertIsNone(result["httpStatus"])
                self.assertIsNone(result["certificateSha256"])

    def test_legacy_acceptance_does_not_send_http_or_claim_certificate_verification(self):
        import ssl
        import socket
        context = MagicMock()
        connection = context.wrap_socket.return_value.__enter__.return_value
        connection.version.return_value = "TLSv1"
        with patch.object(helper, "tls_context", return_value=context), patch.object(socket, "socket"), patch.object(helper, "head_status") as head:
            result = helper.probe_version(ssl, socket, self.endpoint, "a.test", "/", "TLSv1")
            self.assertEqual(result["detail"], "legacy-accepted")
            self.assertIsNone(result["certificateSha256"])
            head.assert_not_called()

    def test_head_retains_status_without_returning_cookies_or_reason_phrase(self):
        connection = MagicMock()
        connection.recv.return_value = b"HTTP/1.1 404 secret-reason\r\nSet-Cookie: secret\r\n\r\nsecret-body"
        status = helper.head_status(connection, "a.test", 8443, "/missing", helper.time.monotonic() + 4)
        self.assertEqual(status, 404)
        connection.sendall.assert_called_once_with(b"HEAD /missing HTTP/1.1\r\nHost: a.test:8443\r\nConnection: close\r\n\r\n")
        connection.recv.return_value = b"not HTTP\r\n"
        with self.assertRaises(helper.Refusal):
            helper.head_status(connection, "a.test", 8443, "/", helper.time.monotonic() + 4)


if __name__ == "__main__":
    unittest.main()
