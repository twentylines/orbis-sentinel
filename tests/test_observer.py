import copy
import json
import os
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from orbis_sentinel.observer import ObserverClient, ObserverCollector, validate_progress, validate_capture, _observer_worker


POINT = "12345678-1234-4123-8123-123456789abc"


def capture():
    return {"version": 1, "id": POINT, "state": "running", "phase": "starting-orbis",
            "completedBytes": 0, "totalBytes": None, "restartVerified": False}


def progress(phase="restarting"):
    return {"version": 1, "job": {"id": "12345678-1234-4123-8123-123456789abc", "state": "running",
                                  "targetTag": "v0.8.0-beta.1", "phase": phase}}


class ValidationTests(unittest.TestCase):
    def test_capture_exact_identity_completion_and_unknown_counts(self):
        self.assertEqual(validate_capture(capture(), POINT), capture())
        for key, bad in (("id", "0" * 36), ("version", True), ("completedBytes", True),
                         ("completedBytes", 2 ** 53), ("totalBytes", -1), ("phase", "complete"),
                         ("restartVerified", True), ("extra", "private")):
            with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                validate_capture({**capture(), key: bad}, POINT)
        complete = {**capture(), "state": "complete", "phase": "complete", "restartVerified": True}
        self.assertEqual(validate_capture(complete, POINT), complete)
        with self.assertRaises(ValueError):
            validate_capture({**capture(), "completedBytes": 2, "totalBytes": 1}, POINT)

    def test_all_phases_and_no_job_are_observations_only(self):
        self.assertEqual(validate_progress({"version": 1, "job": None}), {"version": 1, "job": None})
        for phase in (None, "downloading", "installing", "restarting", "verifying", "recovering"):
            self.assertEqual(validate_progress(progress(phase)), progress(phase))

    def test_exact_public_schema_and_numeric_bounds(self):
        bad = [{"version": True, "job": None}, {"version": 1, "job": None, "secret": "hidden"}]
        for key, value in (("targetTag", "v1.2.3\n"), ("id", "12345678-1234-4123-8123-123456789abc\n"),
                           ("state", "idle"), ("phase", "idle"), ("path", "hidden")):
            item = progress()
            item["job"][key] = value
            bad.append(item)
        good = progress("downloading")
        good["job"]["download"] = {"schema": "orbis.download-progress.v1", "phase": "downloading", "currentBytes": 5,
                                   "totalBytes": 10, "totalKnown": True, "alreadyCached": False,
                                   "layersComplete": 0, "layersTotal": 1, "updatedAt": 123.5}
        self.assertEqual(validate_progress(good), good)
        for key, value in (("currentBytes", True), ("totalBytes", 4), ("totalKnown", False), ("alreadyCached", True),
                           ("layersTotal", 4097), ("updatedAt", float("nan")), ("updatedAt", 10 ** 400), ("path", "hidden")):
            item = copy.deepcopy(good)
            item["job"]["download"][key] = value
            bad.append(item)
        for item in bad:
            with self.subTest(item=item), self.assertRaises(ValueError): validate_progress(item)

    def test_configuration_is_local_bounded_and_explicit(self):
        for value in ("relative", "/" + "a" * 108, "/a\0b"):
            with self.assertRaises(ValueError): ObserverClient(value)
        with self.assertRaises(ValueError): ObserverClient("/run/observer.sock", group_id=True)


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.old = os.getcwd()
        self.temp = tempfile.TemporaryDirectory()
        os.chdir(self.temp.name)
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind("s")
        self.listener.listen(4)
        self.listener.settimeout(0.1)
        self.stop = threading.Event()
        self.calls = []
        self.respond = self.default_response
        self.client = ObserverClient("/run/orbis-observer/progress.sock")
        self.client.path = "s"
        self.identity = patch.object(self.client, "_identity", return_value=("pinned",))
        self.peer = patch.object(self.client, "_peer_uid", return_value=0)
        self.identity.start()
        self.peer.start()
        self.thread = threading.Thread(target=self.serve)
        self.thread.start()

    def tearDown(self):
        self.stop.set()
        self.thread.join(3)
        self.assertFalse(self.thread.is_alive())
        self.listener.close()
        self.identity.stop()
        self.peer.stop()
        os.chdir(self.old)
        self.temp.cleanup()

    def default_response(self, route):
        if route == "/v1/capability":
            return {"schema": "orbis.sentinel-observer.v1", "protocolVersion": 1, "kind": "core-update-progress"}
        return progress()

    def serve(self):
        while not self.stop.is_set():
            try: conn, _ = self.listener.accept()
            except socket.timeout: continue
            with conn:
                conn.settimeout(2)
                data = b""
                try:
                    while b"\r\n\r\n" not in data:
                        chunk = conn.recv(4096)
                        if not chunk: break
                        data += chunk
                    if not data: continue
                    route = data.split(b" ")[1].decode()
                    self.calls.append(route)
                    value = self.respond(route)
                    body = value if type(value) is bytes else json.dumps(value).encode()
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
                except (OSError, ValueError): pass

    def test_capability_then_progress_only(self):
        self.assertEqual(self.client.read(), progress())
        self.assertEqual(self.calls, ["/v1/capability", "/v1/core-operation/progress"])

    def test_capture_negotiates_separately_and_cannot_cross_points(self):
        capability = {"schema": "orbis.sentinel-observer.capture.v1", "protocolVersion": 1, "kind": "core-capture-progress"}
        self.respond = lambda route: capability if route == "/v2/capture-capability" else capture()
        self.assertEqual(self.client.read_capture(POINT), capture())
        self.assertEqual(self.calls, ["/v2/capture-capability", "/v2/core-captures/" + POINT + "/progress"])
        self.calls.clear()
        for value in (POINT + "?x=1", "../" + POINT, POINT.upper(), None):
            with self.assertRaises(ValueError):
                self.client.read_capture(value)
        self.assertEqual(self.calls, [])
        self.respond = lambda route: capability if route == "/v2/capture-capability" else {**capture(), "id": "00000000-0000-4000-8000-000000000000"}
        with self.assertRaises(ValueError):
            self.client.read_capture(POINT)

    def test_old_observer_does_not_get_forced_into_capture_support(self):
        with self.assertRaises(ValueError):
            self.client.read_capture(POINT)
        self.assertEqual(self.calls, ["/v2/capture-capability"])
        self.assertEqual(self.client.read(), progress())

    def test_wrong_server_peer_is_refused_before_any_http(self):
        self.peer.stop()
        self.peer = patch.object(self.client, "_peer_uid", return_value=12345)
        self.peer.start()
        with self.assertRaises(ValueError): self.client.read()
        self.assertEqual(self.calls, [])

    def test_wrong_capability_rejected_before_progress(self):
        self.respond = lambda route: {"schema": "orbis.sentinel-observer.v1", "protocolVersion": True, "kind": "core-update-progress"}
        with self.assertRaises(ValueError): self.client.read()
        self.assertEqual(self.calls, ["/v1/capability"])

    def test_replacement_and_oversize_duplicate_or_invalid_json_are_refused(self):
        self.identity.stop()
        self.identity = patch.object(self.client, "_identity", side_effect=[("before",), ("after",)])
        self.identity.start()
        with self.assertRaises(ValueError): self.client.read()
        self.identity.stop()
        self.identity = patch.object(self.client, "_identity", return_value=("pinned",))
        self.identity.start()
        for value in (b"x" * 16385, b'{"version":1,"version":1,"job":null}', b"\xff"):
            self.respond = lambda route, value=value: self.default_response(route) if route == "/v1/capability" else value
            with self.subTest(value=value[:30]), self.assertRaises(ValueError): self.client.read()

    def test_one_absolute_deadline_covers_both_requests(self):
        with patch("orbis_sentinel.observer.time.monotonic", side_effect=[1, 4]):
            with self.assertRaises(TimeoutError): self.client.read()


class CollectorTests(unittest.TestCase):
    def test_shared_worker_collects_on_demand_with_one_deadline_and_expires_interest(self):
        class Finished(BaseException):
            pass
        calls = []
        class Client:
            def __init__(self, path):
                self.reads = 0
            def read_capture(self, point, *, deadline):
                calls.append(('capture', point, deadline))
                return capture()
            def read(self, *, deadline):
                self.reads += 1
                if self.reads > 2:
                    raise Finished
                calls.append(('update', deadline))
                return progress()
        output, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.addCleanup(receiver.close)
        receiver.settimeout(1)
        receiver.send(json.dumps({'capture': POINT}).encode())
        with patch('orbis_sentinel.observer.ObserverClient', Client), \
                patch('orbis_sentinel.observer.time.monotonic', side_effect=[100, 100, 120, 120, 121]), \
                patch('orbis_sentinel.observer.time.sleep'), self.assertRaises(Finished):
            _observer_worker(output, ('/run/orbis-observer/progress.sock',), 1)
        first = json.loads(receiver.recv(65536))
        second = json.loads(receiver.recv(65536))
        self.assertEqual(first['sample']['capture'], capture())
        self.assertIsNone(second['sample']['capture'])
        self.assertEqual(calls, [('capture', POINT, 102), ('update', 102), ('update', 122)])
        self.assertEqual(output.fileno(), -1)

    def test_capture_cache_never_leaks_a_stale_or_different_point(self):
        collector = ObserverCollector("/run/orbis-observer/progress.sock")
        self.addCleanup(collector.close)
        for state, sample in (("ready", capture()), ("stale", capture()), ("unavailable", capture()),
                              ("ready", {**capture(), "id": "00000000-0000-4000-8000-000000000000"}),
                              ("ready", {**capture(), "private": "hidden"}), ("ready", None)):
            with self.subTest(state=state, sample=sample):
                value = {"state": state, "ageMs": 123, "sample": {"capture": sample}}
                with patch("orbis_sentinel.observer.TelemetryCollector.snapshot", return_value=value):
                    result = collector.capture_snapshot(POINT)
                expected = state == "ready" and sample == capture()
                self.assertEqual(result["available"], expected)
                self.assertEqual(result["progress"], capture() if expected else None)

    def test_failed_stale_or_disabled_observations_never_retain_success(self):
        collector = ObserverCollector("/run/orbis-observer/progress.sock")
        self.addCleanup(collector.close)
        for state, available in (("ready", True), ("stale", True), ("unavailable", True), ("ready", False)):
            value = {"state": state, "ageMs": 123, "sample": {"available": available, "progress": progress()}}
            with patch("orbis_sentinel.observer.TelemetryCollector.snapshot", return_value=value):
                result = collector.snapshot()
            expected = state == "ready" and available
            self.assertEqual(result["available"], expected)
            self.assertEqual(result["progress"], progress() if expected else None)


if __name__ == "__main__":
    unittest.main()
