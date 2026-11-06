import json
import os
import signal
import socket
import time
import unittest
from unittest.mock import patch

from orbis_sentinel.collector import TelemetryCollector


def _blocked_worker(output, paths, interval):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    output.send(json.dumps({"observed": time.monotonic(), "sample": {
        "schema": "orbis-sentinel.telemetry.v1", "sampledAt": 1}}).encode())
    while True:
        time.sleep(1)


class _Process:
    def __init__(self, alive=True):
        self.alive = alive
        self.calls = []

    def is_alive(self): return self.alive
    def terminate(self): self.calls.append("terminate")
    def kill(self): self.calls.append("kill")
    def join(self, timeout): self.calls.append(("join", timeout))
    def close(self): self.calls.append("close")


class CollectorTests(unittest.TestCase):
    def fixture(self):
        self.now = 10.0
        collector = TelemetryCollector(interval=0.1, max_age=0.3, monotonic=lambda: self.now)
        receiver, self.output = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        receiver.setblocking(False)
        collector.receiver, collector.process, collector.started = receiver, _Process(), 10
        self.addCleanup(self.output.close)
        self.addCleanup(collector.close)
        return collector

    def send(self, observed, **sample):
        self.output.send(json.dumps({"observed": observed, "sample": {
            "schema": "orbis-sentinel.telemetry.v1", **sample}}).encode())

    def test_starting_fresh_cached_isolated_and_stale(self):
        collector = self.fixture()
        self.assertEqual(collector.snapshot()["state"], "starting")
        self.send(10, cpuPercent=12)
        first = collector.snapshot()
        self.assertEqual(first["state"], "ready")
        first["sample"]["cpuPercent"] = 99
        self.assertEqual(collector.snapshot()["sample"]["cpuPercent"], 12)
        self.now = 11
        stale = collector.snapshot()
        self.assertEqual(stale["state"], "stale")
        self.assertEqual(stale["ageMs"], 1000)

    def test_future_reordered_malformed_nonfinite_and_oversize_packets_ignored(self):
        collector = self.fixture()
        self.send(9.9, cpuPercent=1)
        collector.snapshot()
        for value in (b'{', b'[]', b'{"observed":NaN,"sample":{}}'):
            self.output.send(value)
        self.send(11, cpuPercent=2)
        self.send(9, cpuPercent=3)
        self.send(10, cpuPercent=float("nan"))
        self.assertEqual(collector.snapshot()["sample"]["cpuPercent"], 1)
        # Darwin's datagram ceiling is lower than Linux's API message bound.
        with patch("orbis_sentinel.collector._MAX_MESSAGE", 512):
            self.output.send(b'x' * 513)
            self.assertEqual(collector.snapshot()["sample"]["cpuPercent"], 1)

    def test_stalled_worker_is_killed_before_any_replacement(self):
        collector = self.fixture()
        process = collector.process
        self.now = 11
        collector.maintain()
        self.assertEqual(process.calls, ["terminate"])
        self.now = 14
        self.send(14, cpuPercent=1)
        collector.maintain()
        self.assertEqual(process.calls, ["terminate", "kill"])
        self.assertIs(collector.process, process)
        self.assertEqual(collector.snapshot()["state"], "unavailable")

    def test_repeated_exits_hold_instead_of_spawning_crash_loop(self):
        collector = self.fixture()
        process = collector.process
        process.alive = False
        collector.attempts = [6, 7, 8, 9, 10]
        collector.maintain()
        self.assertEqual(process.calls, [("join", 0), "close"])
        self.assertIsNone(collector.process)
        self.assertEqual(collector.snapshot()["state"], "unavailable")
        self.assertTrue(collector.failed)

    def test_real_spawn_and_owned_exit(self):
        collector = TelemetryCollector(interval=0.1, max_age=1.0)
        self.addCleanup(collector.close)
        collector.start()
        process = collector.process
        end = time.monotonic() + 5
        while time.monotonic() < end:
            result = collector.snapshot()
            if result["state"] == "ready": break
            time.sleep(0.02)
        self.assertEqual(result["state"], "ready")
        self.assertEqual(result["sample"]["schema"], "orbis-sentinel.telemetry.v1")
        self.assertIs(collector.process, process)
        collector.close()
        self.assertIsNone(collector.process)
        self.assertEqual(collector.snapshot()["state"], "unavailable")
        with self.assertRaises(RuntimeError): collector.start()

    def test_blocked_read_does_not_block_snapshot_or_cleanup(self):
        collector = TelemetryCollector(interval=0.1, max_age=0.3, worker=_blocked_worker)
        self.addCleanup(collector.close)
        collector.start()
        end = time.monotonic() + 5
        while collector.snapshot()["state"] != "ready" and time.monotonic() < end:
            time.sleep(0.02)
        self.assertEqual(collector.snapshot()["state"], "ready")
        started = time.monotonic()
        for _ in range(100): collector.snapshot()
        self.assertLess(time.monotonic() - started, 0.5)
        collector.close()
        self.assertIsNone(collector.process)

    def test_invalid_configuration(self):
        for age in (True, -1, float("inf"), 0.1, 3601):
            with self.assertRaises(ValueError): TelemetryCollector(max_age=age)
        with self.assertRaises(ValueError): TelemetryCollector(paths=["relative"])


if __name__ == "__main__":
    unittest.main()
