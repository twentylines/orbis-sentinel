"""Independent progress survives an unavailable Host without broadening access."""
from contextlib import redirect_stderr
import io
import json
import socket
import threading
import unittest
from unittest.mock import patch

from orbis_sentinel import observer, runtime
from orbis_sentinel.collector import TelemetryCollector

HOST = '/run/orbis-observer/progress.sock'
UPGRADE = '/run/orbis-upgrade/progress.sock'
ID = '12345678-1234-4123-8123-123456789abc'
OTHER = '23456789-1234-4123-8123-123456789abc'


def progress(identifier=ID, *, state='running', tag='v0.9.2', phase=None):
    return {'version': 1, 'job': {'id': identifier, 'state': state, 'targetTag': tag, 'phase': phase}}


def envelope(value, *, state='ready', available=True):
    return {'state': state, 'ageMs': 123, 'sample': {'available': available, 'progress': value}}


class IndependentProgressTests(unittest.TestCase):
    def setUp(self):
        self.collector = observer.ObserverCollector(HOST, upgrade_socket=UPGRADE)
        self.addCleanup(self.collector.close)

    def snapshot(self, host, upgrade):
        with patch.object(TelemetryCollector, 'snapshot', autospec=True,
                side_effect=lambda owner: upgrade if owner is self.collector.upgrade else host):
            return self.collector.snapshot()

    def test_fresh_independent_progress_is_visible_with_an_unavailable_host(self):
        result = self.snapshot(envelope(None, state='unavailable', available=False), envelope(progress()))
        self.assertTrue(result['available'])
        self.assertEqual(result['progress'], progress())

    def test_same_operation_uses_independent_component_phase(self):
        expected = progress(phase='installing')
        result = self.snapshot(envelope(progress(phase='downloading')), envelope(expected))
        self.assertEqual(result['progress'], expected)

    def test_stale_failed_empty_and_malformed_independent_samples_cannot_hide_host_progress(self):
        for value in [envelope(progress(), state='stale'), envelope(progress(), available=False),
                      envelope({'version': 1, 'job': None}), envelope({'version': 1, 'job': {'invalid': True}})]:
            with self.subTest(sample=value):
                result = self.snapshot(envelope(progress()), value)
                self.assertEqual(result['progress'], progress())

    def test_independent_terminal_result_cannot_hide_a_different_active_host_job(self):
        current = progress(OTHER)
        result = self.snapshot(envelope(current), envelope(progress(state='complete')))
        self.assertEqual(result['progress'], current)

    def test_two_different_active_operation_ids_are_not_combined(self):
        result = self.snapshot(envelope(progress(OTHER)), envelope(progress()))
        self.assertFalse(result['available'])
        self.assertIsNone(result['progress'])

    def test_same_id_with_a_different_target_is_unavailable(self):
        result = self.snapshot(envelope(progress(tag='v0.9.3')), envelope(progress()))
        self.assertFalse(result['available'])
        self.assertIsNone(result['progress'])

    def test_new_independent_operation_can_replace_an_old_terminal_host_sample(self):
        result = self.snapshot(envelope(progress(OTHER, state='complete')), envelope(progress()))
        self.assertEqual(result['progress'], progress())

    def test_default_profile_has_no_extra_worker_and_uses_original_progress(self):
        default = observer.ObserverCollector(HOST)
        self.addCleanup(default.close)
        self.assertIsNone(default.upgrade)
        with patch.object(TelemetryCollector, 'snapshot', return_value=envelope(progress())) as snapshot:
            self.assertEqual(default.snapshot()['progress'], progress())
        snapshot.assert_called_once()

    def test_same_socket_and_normalized_alias_are_refused(self):
        for path in (HOST, '/run/orbis-observer/../orbis-observer/progress.sock'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                observer.ObserverCollector(HOST, upgrade_socket=path)

    def test_fourth_worker_start_failure_closes_every_owned_collector(self):
        with patch.object(TelemetryCollector, 'start', side_effect=[None, None, None, RuntimeError('spawn refused')]), \
                self.assertRaises(RuntimeError):
            self.collector.start()
        self.assertTrue(all(owner.closed for owner in [self.collector, self.collector.components,
                                                       self.collector.handoffs, self.collector.upgrade]))

    def test_independent_close_failure_still_closes_host_workers(self):
        with patch.object(self.collector.upgrade, 'close', side_effect=RuntimeError('close refused')), \
                self.assertRaises(RuntimeError):
            self.collector.close()
        self.assertTrue(self.collector.closed)
        self.assertTrue(self.collector.components.closed)
        self.assertTrue(self.collector.handoffs.closed)
        self.collector.upgrade.close()

    def test_independent_worker_reads_only_progress_while_host_read_is_stalled(self):
        class Finished(BaseException):
            pass
        entered, release = threading.Event(), threading.Event()
        calls, errors = [], []

        class Client:
            def __init__(self, path):
                self.path = path
            def read(self, *, deadline):
                calls.append(self.path)
                if self.path == HOST:
                    entered.set()
                    if not release.wait(2):
                        raise AssertionError('Host fixture was not released')
                    raise ValueError('Host unavailable')
                return progress()

        output, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        host_output, host_receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.addCleanup(receiver.close)
        self.addCleanup(host_receiver.close)
        receiver.settimeout(1)

        def host():
            try:
                observer._observer_worker(host_output, (HOST,), 1)
            except Finished:
                pass
            except BaseException as error:
                errors.append(error)

        with patch.object(observer, 'ObserverClient', Client), patch.object(observer.time, 'sleep', side_effect=Finished):
            thread = threading.Thread(target=host)
            thread.start()
            try:
                self.assertTrue(entered.wait(1))
                with self.assertRaises(Finished):
                    observer._upgrade_worker(output, (UPGRADE,), 1)
                sample = json.loads(receiver.recv(65536))['sample']
                self.assertEqual(sample['progress'], progress())
                self.assertTrue(sample['available'])
                self.assertTrue(thread.is_alive())
            finally:
                release.set()
                thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(calls, [HOST, UPGRADE])
        self.assertEqual(output.fileno(), -1)


class UpgradeArgumentsTests(unittest.TestCase):
    def test_independent_reader_requires_host_observer_and_status_mode(self):
        modes = [['--socket', '/run/sentinel/api.sock'], ['--systemd-socket'],
                 ['--recovery-profile', '/etc/sentinel/config.json'],
                 ['--verify-host-source', 'a'*64], ['--review-host-source', 'a'*64],
                 ['--review-recovery-worker', 'a'*64], ['--apply-recovery-worker', 'a'*64],
                 ['--review-recovery-listener', 'a'*64], ['--apply-recovery-listener', 'a'*64],
                 ['--prepare-recovery-listener-backend', 'a'*64], ['--apply-builtin-recovery-listener', 'a'*64],
                 ['--listener-https-probe'], ['--recovery-https-edge'],
                 ['--review-recovery-https', 'a'*64], ['--apply-recovery-https', 'a'*64],
                 ['--export-recovery-https-ca', 'a'*64], ['--bootstrap', 'prepare-plan']]
        for mode in modes:
            with self.subTest(mode=mode), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as failure:
                runtime.main([*mode, '--upgrade-observer-socket', UPGRADE])
            self.assertEqual(failure.exception.code, 2)

    def test_status_service_routes_only_progress_to_optional_worker(self):
        with patch.object(runtime, 'TelemetryCollector'), patch.object(runtime, 'ObserverCollector') as collector, \
                patch.object(runtime, 'SentinelServer') as server, patch.object(runtime.threading, 'Event') as stop, \
                patch.object(runtime.threading, 'Thread'), patch.object(runtime.signal, 'signal'):
            stop.return_value.wait.return_value = True
            self.assertEqual(runtime.main(['--socket', '/run/sentinel/api.sock', '--observer-socket', HOST,
                                          '--upgrade-observer-socket', UPGRADE]), 0)
            collector.assert_called_once_with(HOST, upgrade_socket=UPGRADE)
            providers = server.call_args.args[1]
            self.assertIs(providers['/sentinel/api/v1/progress'], collector.return_value.snapshot)
            self.assertIs(providers['/sentinel/api/v1/handoff-status'], collector.return_value.handoff_snapshot)
            self.assertIs(server.call_args.kwargs['capture_provider'], collector.return_value.capture_snapshot)

    def test_empty_host_observer_is_not_silently_ignored_with_independent_progress(self):
        with patch.object(runtime, 'TelemetryCollector') as collector, redirect_stderr(io.StringIO()), \
                self.assertRaises(SystemExit) as failure:
            runtime.main(['--socket', '/run/sentinel/api.sock', '--observer-socket', '',
                          '--upgrade-observer-socket', UPGRADE])
        self.assertEqual(failure.exception.code, 2)
        collector.assert_not_called()
