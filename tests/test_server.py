import json
import os
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock

from orbis_sentinel.server import SentinelServer

ROUTE = "/sentinel/api/v1/status"


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.old_cwd = os.getcwd()
        os.chdir(self.directory.name)
        self.path = "s"
        self.server = None
        self.thread = None

    def tearDown(self):
        if self.server:
            self.server.server_close()
        if self.thread:
            self.thread.join(1)
            self.assertFalse(self.thread.is_alive())
        if getattr(self, "peer_patch", None):
            self.peer_patch.stop()
        os.chdir(self.old_cwd)
        self.directory.cleanup()

    def start(self, providers=None, **kwargs):
        self.peer_patch = mock.patch.object(SentinelServer, "_peer_uid", return_value=os.geteuid()) if not hasattr(socket, "SO_PEERCRED") and not hasattr(socket.socket, "getpeereid") else None
        if self.peer_patch:
            self.peer_patch.start()
        self.server = SentinelServer(self.path, providers or {ROUTE: lambda: {"ok": True}}, **kwargs)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()

    def connect(self):
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(1)
        client.connect(self.path)
        return client

    def request(self, data):
        with self.connect() as client:
            result = b""
            try:
                client.sendall(data)
                while True:
                    chunk = client.recv(65536)
                    if not chunk:
                        break
                    result += chunk
            except (ConnectionResetError, BrokenPipeError):
                pass
            return result

    def test_valid_and_response_headers(self):
        self.start()
        result = self.request(b"GET /sentinel/api/v1/status HTTP/1.1\r\nHost: local\r\n\r\n")
        head, body = result.split(b"\r\n\r\n")
        self.assertIn(b"200 OK", head)
        self.assertIn(b"Cache-Control: no-store", head)
        self.assertIn(b"X-Content-Type-Options: nosniff", head)
        self.assertNotIn(b"Access-Control", head)
        self.assertEqual(json.loads(body), {"ok": True})
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_rejections(self):
        calls = []
        self.start({ROUTE: lambda: calls.append(1)})
        cases = [
            (b"POST /sentinel/api/v1/status HTTP/1.1\r\n\r\n", b"405"),
            (b"GET /sentinel/api/v1/status?x=1 HTTP/1.1\r\n\r\n", b"404"),
            (b"GET /other HTTP/1.0\r\n\r\n", b"404"),
            (b"GET /sentinel/api/v1/status HTTP/1.1\r\nContent-Length: 1\r\n\r\nx", b"400"),
            (b"GET /sentinel/api/v1/status HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n", b"400"),
            (b"GET /sentinel/api/v1/status HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", b"400"),
            (b"GET /sentinel/api/v1/status HTTP/1.1\r\nBad Header: x\r\n\r\n", b"400"),
            (b"GET " + b"x" * 8200, b"431"),
        ]
        for request, expected in cases:
            with self.subTest(expected=expected):
                self.assertIn(expected, self.request(request).split(b"\r\n", 1)[0])
        self.assertEqual(calls, [])

    def test_provider_failure_nan_and_size(self):
        def fail():
            raise RuntimeError("private detail")
        self.start({ROUTE: fail})
        request = b"GET /sentinel/api/v1/status HTTP/1.0\r\n\r\n"
        for provider in (fail, lambda: float('nan'), lambda: 'x' * 1048577):
            self.server.providers[ROUTE] = provider
            response = self.request(request)
            self.assertIn(b"503 Service Unavailable", response)
            self.assertNotIn(b"private detail", response)

    def test_unauthorized_peer_is_closed_before_callback(self):
        calls = []
        self.start({ROUTE: lambda: calls.append(1)}, allowed_uids=[])
        self.assertEqual(self.request(b"GET /sentinel/api/v1/status HTTP/1.0\r\n\r\n"), b"")
        self.assertEqual(calls, [])

    def test_capacity_is_released_after_disconnect(self):
        self.start(max_connections=1, request_timeout=2)
        entered = threading.Event()
        original = self.server._request
        def observed(conn, deadline):
            entered.set()
            return original(conn, deadline)
        self.server._request = observed
        with self.connect() as held:
            held.sendall(b"G")
            self.assertTrue(entered.wait(1))
            self.assertEqual(self.request(b"GET /sentinel/api/v1/status HTTP/1.0\r\n\r\n"), b"")
        end = time.monotonic() + 2
        while time.monotonic() < end:
            result = self.request(b"GET /sentinel/api/v1/status HTTP/1.0\r\n\r\n")
            if b"200 OK" in result: break
            time.sleep(0.005)
        self.assertIn(b"200 OK", result)

    def test_absolute_deadline_is_not_extended_by_incoming_bytes(self):
        self.server = SentinelServer(self.path, {ROUTE: lambda: {"ok": True}})
        now, timeouts = [0.0], []
        class DrippingConnection:
            def settimeout(self, value): timeouts.append(value)
            def recv(self, size):
                now[0] += 0.1
                return b"G"
        with mock.patch("orbis_sentinel.server.time.monotonic", side_effect=lambda: now[0]):
            with self.assertRaises(TimeoutError):
                self.server._request(DrippingConnection(), 0.25)
        self.assertEqual(len(timeouts), 3)
        self.assertAlmostEqual(timeouts[0], 0.25)
        self.assertAlmostEqual(timeouts[-1], 0.05)

    def test_inherited_listener_and_replacement_preserved(self):
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(self.path)
        listener.listen(2)
        try:
            try:
                listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
                checked_listener = listener
            except OSError:
                class CheckedListener:
                    family = listener.family
                    def getsockopt(self, level, option):
                        if option == socket.SO_ACCEPTCONN:
                            return 1
                        return listener.getsockopt(level, option)
                    def dup(self):
                        return listener.dup()
                checked_listener = CheckedListener()
            self.start(listener=checked_listener)
            self.assertIn(b"200 OK", self.request(b"GET /sentinel/api/v1/status HTTP/1.0\r\n\r\n"))
            self.server.server_close()
            self.assertTrue(os.path.exists(self.path))
            self.assertGreaterEqual(listener.fileno(), 0)
        finally:
            listener.close()

    def test_created_socket_replacement_not_removed(self):
        self.start()
        os.unlink(self.path)
        with open(self.path, "w") as replacement:
            replacement.write("keep")
        self.server.server_close()
        with open(self.path) as replacement:
            self.assertEqual(replacement.read(), "keep")

    def test_path_and_listener_validation(self):
        with open(self.path, "w"):
            pass
        with self.assertRaises(FileExistsError):
            SentinelServer(self.path, {})
        os.unlink(self.path)
        os.chmod(self.directory.name, 0o755)
        with self.assertRaises(ValueError):
            SentinelServer(self.path, {})
        os.chmod(self.directory.name, 0o700)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            with self.assertRaises(ValueError):
                SentinelServer(self.path, {}, listener=listener)
        with self.assertRaises(ValueError):
            SentinelServer(self.path, {"/other": lambda: None})
        with self.assertRaises(ValueError):
            SentinelServer(self.path, {}, allowed_uids=[True])
        for values in ({"max_connections": 65}, {"request_timeout": 31}):
            with self.assertRaises(ValueError): SentinelServer(self.path, {}, **values)

    def test_missing_peer_credentials_fail_closed(self):
        self.start()
        with mock.patch.object(SentinelServer, "_peer_uid", side_effect=OSError):
            self.assertEqual(self.request(b"GET /sentinel/api/v1/status HTTP/1.0\r\n\r\n"), b"")


if __name__ == "__main__":
    unittest.main()
