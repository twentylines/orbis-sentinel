import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import threading
from unittest.mock import patch

from orbis_sentinel.runtime import activation_listener, main
from orbis_sentinel.collector import TelemetryCollector
from orbis_sentinel.server import SentinelServer
from test_collector import _blocked_worker


class ActivationTests(unittest.TestCase):
    def test_activation_requires_exact_process_and_one_named_socket(self):
        for values in ({}, {"LISTEN_PID": "0", "LISTEN_FDS": "1"},
                       {"LISTEN_PID": str(os.getpid()), "LISTEN_FDS": "2"},
                       {"LISTEN_PID": str(os.getpid()), "LISTEN_FDS": "1", "LISTEN_FDNAMES": "other"}):
            with patch.dict(os.environ, values, clear=True):
                with self.assertRaises(ValueError): activation_listener()

    def test_invalid_activation_exits_without_starting_a_worker(self):
        with patch.dict(os.environ, {}, clear=True), patch("orbis_sentinel.runtime.TelemetryCollector") as collector:
            self.assertEqual(main(["--systemd-socket"]), 1)
            collector.return_value.start.assert_not_called()
            collector.return_value.close.assert_called_once()


@unittest.skipUnless(sys.platform.startswith("linux"), "requires real Linux Unix peer credentials")
class RuntimeLinuxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name) / "api.sock")
        self.launcher = Path(__file__).resolve().parents[1] / "bin/orbis-sentinel"
        self.processes = []
        self.addCleanup(self.cleanup)

    def cleanup(self):
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

    def launch(self, listener=None, observer_path=None):
        if listener is None:
            args = [sys.executable, "-I", str(self.launcher), "--socket", self.path]
            if observer_path is not None:
                args.extend(["--observer-socket", observer_path])
            process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        else:
            code = ("import os,sys; fd=int(sys.argv[1]); os.dup2(fd,3); os.set_inheritable(3,True); "
                    "os.environ.update(LISTEN_PID=str(os.getpid()),LISTEN_FDS='1',LISTEN_FDNAMES='api'); "
                    "os.execv(sys.executable,[sys.executable,'-I',sys.argv[2],'--systemd-socket'])")
            process = subprocess.Popen([sys.executable, "-c", code, str(listener.fileno()), str(self.launcher)],
                                       pass_fds=(listener.fileno(),), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.processes.append(process)
        return process

    def request(self, path="health"):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(2)
            conn.connect(self.path)
            conn.sendall(("GET /sentinel/api/v1/" + path + " HTTP/1.1\r\nHost: sentinel\r\n\r\n").encode())
            response = b""
            while chunk := conn.recv(65536): response += chunk
        head, body = response.split(b"\r\n\r\n", 1)
        self.assertTrue(head.startswith(b"HTTP/1.1 200"), head)
        return json.loads(body)

    def ready(self, process):
        end = time.monotonic() + 5
        while time.monotonic() < end:
            if process.poll() is not None:
                self.fail("service exited: " + process.stderr.read().decode())
            try:
                return self.request()
            except (OSError, ValueError):
                time.sleep(0.02)
        self.fail("service did not become ready")

    def stop(self, process):
        process.send_signal(signal.SIGTERM)
        self.assertEqual(process.wait(timeout=5), 0)
        stderr = process.stderr.read().decode()
        process.stderr.close()
        self.assertEqual(stderr, "")

    def test_standalone_service_without_orbis_and_real_telemetry(self):
        process = self.launch()
        self.assertEqual(self.ready(process)["state"], "ready")
        status = self.request("status")
        self.assertEqual(status["components"]["orbis"]["state"], "unknown")
        self.assertIsNone(status["components"]["orbis"]["installedVersion"])
        self.assertEqual(status["components"]["sentinel"]["state"], "healthy")
        end = time.monotonic() + 5
        while time.monotonic() < end:
            telemetry = self.request("telemetry")
            if telemetry["state"] == "ready": break
            time.sleep(0.02)
        self.assertEqual(telemetry["state"], "ready")
        self.assertGreater(telemetry["sample"]["memory"]["totalBytes"], 0)
        self.assertGreater(telemetry["sample"]["filesystems"]["/"]["totalBytes"], 0)
        self.stop(process)
        self.assertFalse(os.path.lexists(self.path))

    def test_inherited_listener_survives_process_restart(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(self.path)
            listener.listen(8)
            identity = os.lstat(self.path).st_ino
            first = self.launch(listener)
            self.ready(first)
            self.stop(first)
            self.assertEqual(os.lstat(self.path).st_ino, identity)
            second = self.launch(listener)
            self.assertEqual(self.ready(second)["state"], "ready")
            self.stop(second)
            self.assertEqual(os.lstat(self.path).st_ino, identity)

    def test_capture_api_remains_responsive_without_orbis_or_host_observer(self):
        process = self.launch(observer_path="/run/orbis-observer/progress.sock")
        self.ready(process)
        point = "12345678-1234-4123-8123-123456789abc"
        for _ in range(4):
            result = self.request("captures/" + point + "/progress")
            self.assertEqual(result["schema"], "orbis-sentinel.capture-progress.v1")
            self.assertEqual(result["id"], point)
            self.assertFalse(result["available"])
            self.assertIsNone(result["progress"])
            self.assertEqual(self.request()["state"], "ready")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(2)
            connection.connect(self.path)
            connection.sendall(("GET /sentinel/captures/" + point + " HTTP/1.1\r\nHost: sentinel\r\n\r\n").encode())
            response = b""
            while chunk := connection.recv(65536):
                response += chunk
        head, body = response.split(b"\r\n\r\n", 1)
        self.assertIn(b"200 OK", head)
        self.assertIn(b"text/html", head)
        self.assertIn(b"Capturing Orbis", body)
        self.assertIn(b"/sentinel/capture-assets/capture.js", body)
        self.stop(process)

    def test_health_api_remains_ready_when_worker_stalls(self):
        collector = TelemetryCollector(interval=0.1, max_age=0.3, worker=_blocked_worker)
        self.addCleanup(collector.close)
        collector.start()
        with SentinelServer(self.path, {
                "/sentinel/api/v1/health": lambda: {"state": "ready"},
                "/sentinel/api/v1/telemetry": collector.snapshot}) as server:
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                end = time.monotonic() + 5
                while self.request("telemetry")["state"] != "ready" and time.monotonic() < end:
                    time.sleep(0.02)
                self.assertEqual(self.request("telemetry")["state"], "ready")
                time.sleep(0.35)
                self.assertEqual(self.request("telemetry")["state"], "stale")
                for _ in range(10): self.assertEqual(self.request()["state"], "ready")
                collector.maintain()
                self.assertEqual(self.request("telemetry")["state"], "unavailable")
                self.assertEqual(self.request()["state"], "ready")
            finally:
                server.shutdown()
                thread.join(timeout=3)
                self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    unittest.main()
