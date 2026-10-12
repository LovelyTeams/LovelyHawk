"""Golden procfs decoding/refusal tests; actual PID/socket checks use the lab."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("pg_process", Path(__file__).parents[2] / "crates/lovelyhawk-core/src/postgresql_process.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ProcessProbeTests(unittest.TestCase):
    request = {"backendPid": 42, "serverAddress": "127.0.0.1", "serverPort": 5432, "clientAddress": "127.0.0.1", "clientPort": 42000, "dataDirectory": None}
    row = b" 0: 0100007F:1538 0100007F:A410 01 00000000:00000000 00:00000000 00000000 999 0 12345\n"

    def socket(self, rows, link="socket:[12345]"):
        entries = MagicMock()
        entries.__enter__.return_value = [SimpleNamespace(path="/proc/42/fd/9")]
        with patch.object(probe, "read", side_effect=lambda path, limit: b"header\n" + (rows if path.endswith("/tcp") else b"")), patch.object(probe.os, "scandir", return_value=entries), patch.object(probe.os, "readlink", return_value=link), patch.object(probe.sys, "byteorder", "little"):
            return probe.socket_inode(42, self.request)

    def test_ipv4_ipv6_mapped_and_native_endianness(self):
        with patch.object(probe.sys, "byteorder", "little"):
            self.assertEqual(str(probe.address("0100007F")), "127.0.0.1")
            self.assertEqual(str(probe.address("00000000000000000000000001000000")), "::1")
            self.assertEqual(str(probe.address("0000000000000000FFFF00000100007F")), "127.0.0.1")
        with patch.object(probe.sys, "byteorder", "big"):
            self.assertEqual(str(probe.address("7F000001")), "127.0.0.1")

    def test_only_the_exact_owned_established_connection_matches(self):
        self.assertEqual(self.socket(self.row), "12345")
        for row in [self.row.replace(b":A410", b":A411"), self.row.replace(b" 01 ", b" 06 "), self.row + self.row]:
            with self.assertRaises(probe.Refusal):
                self.socket(row)
        with self.assertRaisesRegex(probe.Refusal, "socket-unmatched"):
            self.socket(self.row, "socket:[99999]")

    def test_malformed_and_unbounded_procfs_are_not_empty_results(self):
        with self.assertRaisesRegex(probe.Refusal, "invalid-procfs"):
            self.socket(b"unexpected\n")
        with tempfile.TemporaryFile() as stream:
            stream.write(b"12345"); stream.seek(0)
            with patch("builtins.open", return_value=stream), self.assertRaisesRegex(probe.Refusal, "limit-exceeded"):
                probe.read("ignored", 4)

    def test_process_comm_parentheses_do_not_shift_parent_or_start_time(self):
        fields = [b"S", b"17"] + [b"0"] * 17 + [b"654321"]
        with patch.object(probe, "read", return_value=b"42 (post ) gres) " + b" ".join(fields)):
            self.assertEqual(probe.process_stat(42), (17, 654321))
        fields[0] = b"Z"
        with patch.object(probe, "read", return_value=b"42 (postgres) " + b" ".join(fields)), self.assertRaisesRegex(probe.Refusal, "process-changed"):
            probe.process_stat(42)

    def test_missing_pidfd_fails_before_any_process_path_is_read(self):
        with patch.object(probe.sys, "platform", "unsupported"), patch.object(probe, "read") as read, self.assertRaisesRegex(probe.Refusal, "unsupported"):
            probe.capture(self.request)
        read.assert_not_called()

    def test_unsupported_platform_has_a_structured_result_without_reading_input(self):
        with patch.object(probe.sys, "platform", "unsupported"), patch.object(probe.sys, "stdin") as stdin, patch("builtins.print") as output:
            probe.main()
        stdin.buffer.read.assert_not_called()
        self.assertEqual(json.loads(output.call_args.args[0]), {"state": "unavailable", "reason": "unsupported", "process": None})


if __name__ == "__main__":
    unittest.main()
