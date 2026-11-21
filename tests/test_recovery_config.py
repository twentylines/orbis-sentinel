import json
import os
from pathlib import Path
import tempfile
import stat
import struct
import unittest
from types import SimpleNamespace
from unittest import mock

from orbis_sentinel import recovery_config as config
from orbis_sentinel import recovery_cli as cli
from orbis_sentinel import runtime


class RecoveryConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'recovery.json'
        self.value = {'schema': 'orbis.sentinel-recovery-config.v1', 'origin': 'https://recovery.example',
                      'directory': str(self.root / 'sessions'), 'imageId': 'sha256:' + 'a' * 64,
                      'listenPort': 19112, 'statusSocket': str(self.root / 'status.sock')}
        owner = mock.patch.object(config, '_OWNER_UID', os.getuid())
        owner.start()
        self.addCleanup(owner.stop)
        self.write()

    def write(self):
        self.path.write_text(json.dumps(self.value))
        self.path.chmod(0o600)

    def test_reads_immutable_snapshot_and_closes_descriptors(self):
        with config.RecoveryConfig(self.path) as opened:
            self.assertEqual(dict(opened.data), self.value)
            opened.verify()
            with self.assertRaises(TypeError):
                opened.data['listenPort'] = 19113
        self.assertIsNone(opened._file)
        self.assertEqual(opened._directories, [])
        with self.assertRaises(ValueError):
            opened.verify()

    def test_changed_bytes_mode_and_replaced_inode_are_refused(self):
        for mutation in ('bytes', 'mode', 'replace'):
            with self.subTest(mutation=mutation):
                self.write()
                with config.RecoveryConfig(self.path) as opened:
                    if mutation == 'bytes':
                        self.path.write_text(json.dumps({**self.value, 'listenPort': 19113}))
                    elif mutation == 'mode':
                        self.path.chmod(0o640)
                    else:
                        replacement = self.root / 'replacement'
                        replacement.write_bytes(self.path.read_bytes())
                        replacement.chmod(0o600)
                        replacement.replace(self.path)
                    with self.assertRaises(ValueError):
                        opened.verify()

    def test_linked_shared_oversized_or_unprotected_file_is_refused(self):
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):
            config.RecoveryConfig(self.path)
        self.write()
        linked = self.root / 'linked'
        linked.symlink_to(self.path)
        with self.assertRaises(ValueError):
            config.RecoveryConfig(linked)
        linked.unlink()
        os.link(self.path, linked)
        with self.assertRaises(ValueError):
            config.RecoveryConfig(self.path)
        linked.unlink()
        self.path.write_bytes(b'a' * 16385)
        with self.assertRaises(ValueError):
            config.RecoveryConfig(self.path)

    def test_bad_schema_fields_https_port_and_image_are_refused(self):
        for field, value in [('schema', 'other'), ('origin', 'http://localhost'), ('origin', 'https://user@recovery.example'),
                             ('origin', 'https://recovery.example/path'), ('listenPort', True), ('listenPort', 0),
                             ('listenPort', 65536), ('directory', '../sessions'), ('imageId', 'ghcr.io/orbis:latest')]:
            with self.subTest(field=field, value=value):
                self.path.write_text(json.dumps({**self.value, field: value}))
                with self.assertRaises(ValueError):
                    config.RecoveryConfig(self.path)
        self.path.write_text(json.dumps({**self.value, 'extra': True}))
        with self.assertRaises(ValueError):
            config.RecoveryConfig(self.path)
        self.path.write_text('{"schema":"one","schema":"two"}')
        with self.assertRaises(ValueError):
            config.RecoveryConfig(self.path)

    def test_launcher_uses_only_the_protected_configuration_and_restores_signals(self):
        with mock.patch.object(cli, '_require_root'), mock.patch.object(cli, 'run_recovery') as run:
            self.assertEqual(cli.main(self.path), 0)
        self.assertEqual(run.call_args.kwargs['address'], ('127.0.0.1', 19112))
        self.assertEqual(run.call_args.kwargs['image_id'], self.value['imageId'])
        with mock.patch.object(cli, '_read_observation', return_value={'observed': True}) as read:
            self.assertEqual(run.call_args.kwargs['progress'](), {'observed': True})
        read.assert_called_once_with(self.value['statusSocket'], '/sentinel/api/v1/progress')
        with self.assertRaises(ValueError):
            run.call_args.kwargs['check']()

    def test_launcher_failure_is_generic_and_does_not_echo_profile_or_secrets(self):
        with mock.patch.object(cli, '_require_root', side_effect=RuntimeError('synthetic-private-error')):
            with mock.patch.object(cli.sys, 'stderr') as error:
                self.assertEqual(cli.main(self.path), 1)
        self.assertNotIn('synthetic-private-error', repr(error.write.call_args_list))
        self.assertNotIn(str(self.path), repr(error.write.call_args_list))

    def test_status_launcher_dispatch_cannot_combine_other_service_modes(self):
        with mock.patch.object(cli, 'main', return_value=0) as recovery:
            self.assertEqual(runtime.main(['--recovery-profile', str(self.path)]), 0)
            recovery.assert_called_once_with(str(self.path))
        for extra in (['--socket', '/other'], ['--systemd-socket'], ['--disk-path', '/'], ['--observer-socket', '/other']):
            with mock.patch.object(cli, 'main') as recovery, mock.patch.object(runtime.sys, 'stderr'):
                with self.assertRaises(SystemExit):
                    runtime.main(['--recovery-profile', str(self.path), *extra])
                recovery.assert_not_called()

    def test_status_response_requires_exact_length_and_unambiguous_headers(self):
        body = b'{"schema":"observed"}'
        response = b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body
        self.assertEqual(cli._status_response(response), {'schema': 'observed'})
        for invalid in (response.replace(b'200 OK', b'503 Unavailable'), response[:-1],
                        response.replace(b'\r\n\r\n', b'\r\nTransfer-Encoding: chunked\r\n\r\n'),
                        response.replace(b'\r\n\r\n', b'\r\nContent-Length: 1\r\n\r\n'),
                        response.replace(b'\r\n\r\n', b'\r\nContent-Encoding: gzip\r\n\r\n'),
                        b'HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n{"a":1,"a":2}'):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    cli._status_response(invalid)

    def test_status_socket_rejects_noncanonical_paths_before_connecting(self):
        for path in ('relative', '/tmp/../tmp/socket', '/a' + 'b' * 108):
            with self.subTest(path=path), mock.patch.object(cli.socket, 'socket') as connect:
                with self.assertRaises(ValueError):
                    cli.read_status(path)
                connect.assert_not_called()

    def test_observation_route_is_fixed_and_cannot_relay_a_request(self):
        for route in ('/v1/restart', '/sentinel/api/v1/status?file=x', '/sentinel/api/v1/progress/../status'):
            with self.subTest(route=route), mock.patch.object(cli.socket, 'socket') as connect, self.assertRaises(ValueError):
                cli._read_observation(self.value['statusSocket'], route)
            connect.assert_not_called()

    def test_progress_read_uses_the_enrolled_socket_and_only_its_fixed_get(self):
        path = '/run/sentinel/status.sock'
        directory = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0)
        endpoint = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_uid=0, st_gid=0, st_dev=1, st_ino=2,
                                   st_nlink=1, st_size=0, st_mtime_ns=1, st_ctime_ns=1)
        body = b'{"schema":"observed-progress"}'
        response = b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body
        with mock.patch.object(cli.os, 'lstat', side_effect=lambda value: endpoint if value == path else directory), \
                mock.patch.object(cli.socket, 'SO_PEERCRED', 17, create=True), \
                mock.patch.object(cli.socket, 'socket') as make, mock.patch.object(cli.select, 'select', return_value=([True], [], [])):
            connection = make.return_value.__enter__.return_value
            connection.getsockopt.return_value = struct.pack('3i', 10, 0, 0)
            connection.recv.side_effect = [response, b'']
            self.assertEqual(cli.read_progress(path), {'schema': 'observed-progress'})
            connection.connect.assert_called_once_with(path)
            connection.sendall.assert_called_once_with(b'GET /sentinel/api/v1/progress HTTP/1.1\r\nHost: sentinel\r\nConnection: close\r\n\r\n')
