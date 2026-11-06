import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from orbis_sentinel import image_exports as x, verification as v


class EngineReply:
    def __init__(self, body, status=200): self.body, self.status = body, status
    def read(self, count): return self.body[:count]


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='image-exports-')
        self.addCleanup(self.temp.cleanup)
        self.directory = self.temp.name
        self.id = 'sha256:' + 'a'*64
        self.selected = 'sha256:' + 'b'*64
        self.platform = {'os': 'linux', 'architecture': 'arm64', 'variant': 'v8'}
        self.original = {'Id': self.id, 'Os': 'linux', 'Architecture': 'arm64', 'Variant': 'v8', 'Config': {'Env': ['SECRET']}, 'Manifests': [{'Kind': 'image', 'Available': True, 'Descriptor': {'digest': self.selected, 'platform': {**self.platform, 'secret': 'SECRET'}, 'annotations': {'secret': 'SECRET'}}, 'ImageData': {'Platform': {**self.platform, 'secret': 'SECRET'}, 'other': 'SECRET'}}]}
        self.picked = {'Id': self.selected, 'Os': 'linux', 'Architecture': 'arm64', 'Variant': 'v8', 'Config': {'Env': ['SECRET']}}
        self.expected = {'images': {'controller': self.id, 'database': self.id, 'queue': self.id}, 'compatibility': {'os': 'linux', 'architecture': 'arm64'}}

    def test_engine_get_is_bounded_and_fixed_unix_socket(self):
        calls = []
        class Connection:
            def request(self, *args, **kwargs): calls.append((args, kwargs))
            def getresponse(self): return EngineReply(b'{"ok":true}')
            def close(self): calls.append('closed')
        with patch.object(x, '_Engine', return_value=Connection()):
            self.assertEqual(x.ImageExporter()._json_get('/version'), {'ok': True})
        self.assertEqual(calls[0], (('GET', '/version'), {'headers': {'Connection': 'close'}}))
        self.assertEqual(calls[-1], 'closed')
        for body, status in ((b'x'*(1024*1024+1), 200), (b'{}', 500), (b'', 200)):
            conn = Connection()
            conn.getresponse = lambda: EngineReply(body, status)
            with patch.object(x, '_Engine', return_value=conn), self.assertRaises(v.VerificationError): x.ImageExporter()._json_get('/version')
        sockets = []
        class Socket:
            def settimeout(self, timeout): self.timeout = timeout
            def connect(self, path): sockets.append(path)
        with patch.object(x.socket, 'socket', return_value=Socket()) as ctor:
            conn = x._Engine()
            conn.connect()
        ctor.assert_called_once_with(x.socket.AF_UNIX, x.socket.SOCK_STREAM)
        self.assertEqual(sockets, ['/var/run/docker.sock'])

    def test_inspection_requests_manifest_and_platform_and_projects_fields(self):
        exporter = x.ImageExporter()
        requests = []
        def get(path):
            requests.append(path)
            if path == '/version': return {'ApiVersion': '1.51'}
            return self.picked if 'platform=' in path else self.original
        with patch.object(exporter, '_json_get', side_effect=get):
            result = exporter.inspect_image(self.id)
            selected = exporter.inspect_image(self.id, 'linux/arm64/v8')
        self.assertEqual(requests[0], '/version')
        self.assertEqual(urlsplit(requests[1]).path, '/v1.51/images/' + self.id + '/json')
        self.assertEqual(parse_qs(urlsplit(requests[1]).query), {'manifests': ['true']})
        query = parse_qs(urlsplit(requests[2]).query)
        self.assertEqual(json.loads(query['platform'][0]), self.platform)
        self.assertNotIn('SECRET', json.dumps([result, selected]))
        self.assertEqual(result['Manifests'][0], {'Kind': 'image', 'Available': True, 'Descriptor': {'digest': self.selected, 'platform': self.platform}, 'ImageData': {'Platform': self.platform}})
        for invalid in ('latest', 'sha256:' + 'g'*64):
            with self.assertRaises(v.VerificationError): exporter.inspect_image(invalid)
        with self.assertRaises(v.VerificationError): exporter.inspect_image(self.id, 'linux/arm64/../../x')

    def test_deduplicates_expected_ids_and_platform_and_persists_no_env(self):
        exporter = x.ImageExporter()
        inspect_calls, saves = [], []
        def inspect(image, platform=None):
            inspect_calls.append((image, platform))
            return exporter.inspect_image_orig(image, platform)
        def get(path):
            if path == '/version': return {'ApiVersion': '1.51'}
            return self.picked if 'platform=' in path else self.original
        def save(image, destination, platform=None):
            saves.append((image, os.path.basename(destination), platform))
            with open(destination, 'wb') as stream: stream.write(b'archive')
            return 7
        exporter.inspect_image_orig = exporter.inspect_image
        with patch.object(exporter, '_json_get', side_effect=get), patch.object(exporter, 'inspect_image', side_effect=inspect), patch.object(exporter, 'save_image', side_effect=save):
            exporter.export(self.directory, self.expected)
        self.assertEqual(inspect_calls, [(self.id, None), (self.id, 'linux/arm64'), (self.id, None)])
        self.assertEqual(saves, [(self.id, 'image-' + self.id[7:] + '.tar', 'linux/arm64/v8')])
        with open(os.path.join(self.directory, 'exports.json')) as stream: body = stream.read()
        self.assertNotIn('SECRET', body)
        self.assertEqual(len(json.loads(body)['images']), 1)

    def test_distinct_expected_ids_are_saved_once_and_wrong_platform_is_refused(self):
        other = 'sha256:' + 'c'*64
        expected = dict(self.expected, images={'controller': self.id, 'database': other, 'queue': self.id})
        exporter = x.ImageExporter()
        saved = []
        def inspect(image, platform=None):
            return {'Id': image, 'Os': 'linux', 'Architecture': 'arm64'}
        def save(image, destination, platform=None):
            saved.append((image, platform))
            return 1
        with patch.object(exporter, 'inspect_image', side_effect=inspect), patch.object(exporter, 'save_image', side_effect=save):
            exporter.export(self.directory, expected)
        self.assertEqual(saved, [(self.id, None), (other, None)])
        os.unlink(os.path.join(self.directory, 'exports.json'))
        with patch.object(exporter, 'inspect_image', return_value={'Id': self.id, 'Os': 'linux', 'Architecture': 'amd64'}), patch.object(exporter, 'save_image') as save_mock:
            with self.assertRaises(v.VerificationError): exporter.export(self.directory, self.expected)
            save_mock.assert_not_called()

    def test_changed_inspection_rejected_and_evidence_retained(self):
        exporter = x.ImageExporter()
        original = {'Id': self.id, 'Os': 'linux', 'Architecture': 'arm64'}
        with patch.object(exporter, 'inspect_image', side_effect=[original, dict(original, Variant='v8')]), patch.object(exporter, 'save_image', return_value=7):
            with self.assertRaises(v.VerificationError): exporter.export(self.directory, self.expected)
        self.assertNotIn('exports.json', os.listdir(self.directory))

    def test_fixed_local_save_command_only(self):
        exporter = x.ImageExporter()
        captured = []
        original = subprocess.Popen
        def spawn(args, **kwargs):
            captured.append(args)
            return original(['/usr/bin/printf', 'archive'], **kwargs)
        target = os.path.join(self.directory, 'archive.tar')
        with patch.object(x.subprocess, 'Popen', side_effect=spawn):
            self.assertEqual(exporter.save_image(self.id, target, 'linux/arm64/v8'), 7)
        self.assertEqual(captured, [['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock', 'image', 'save', '--platform', 'linux/arm64/v8', self.id]])
        with open(target, 'rb') as stream: self.assertEqual(stream.read(), b'archive')
        with self.assertRaises(FileExistsError): exporter.save_image(self.id, target)

    def test_inventory_worker_no_socket_or_network(self):
        worker = x.InventoryWorker()
        calls = []
        with patch.object(worker, '_run', side_effect=lambda args: (calls.append(args) or 0, b'a'*64)):
            self.assertEqual(worker.create('worker', 'nonce', 'sha256:'+'c'*64, '/private/data', '/unused', '{}'), 'a'*64)
        args = calls[0]
        self.assertEqual(args[args.index('--network')+1], 'none')
        self.assertEqual(args[args.index('--cap-drop')+1], 'ALL')
        self.assertIn('--read-only', args)
        self.assertIn('--pull=never', args)
        self.assertIn('/app/core-capture-image-inventory.mjs', args)
        self.assertNotIn('docker.sock', ' '.join(args))
        mounts = [args[i+1] for i, a in enumerate(args[:-1]) if a == '--mount']
        self.assertEqual(len(mounts), 2)
        self.assertTrue(mounts[0].endswith(',readonly'))
        self.assertTrue(mounts[1].endswith('dst=/data/image-inventory-output'))
