import hashlib
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from orbis_sentinel import sealing as s, verification as v
from test_verification import FakeDocker


class SealingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = self.temp.name
        self.id = '11111111-1111-4111-8111-111111111111'
        self.base = os.path.join(self.root, 'data/backups/time-machine')
        self.pointdir = os.path.join(self.base, 'points', self.id)
        for path in (self.pointdir, os.path.join(self.base, 'keys'), os.path.join(self.base, 'core-publish-input', self.id, 'images'), os.path.join(self.base, 'core-verification')):
            os.makedirs(path, mode=0o700)
        for path, dirs, files in os.walk(self.root):
            os.chmod(path, 0o700)
        self.digest = lambda x: hashlib.sha256(x).hexdigest()
        self.key = b'k' * 32
        self.original = {'version': 3, 'id': self.id, 'ownerId': 7, 'createdAt': 8, 'status': 'capturing', 'envelope': {'keyId': self.digest(self.key)}}
        self.expect = {'pointId': self.id, 'sourceSha256': '1'*64, 'checkpointSha256': '2'*64, 'captureReceiptSha256': '3'*64, 'resourceCount': 1, 'images': {'controller': 'sha256:'+'c'*64, 'database': 'sha256:'+'d'*64, 'queue': 'sha256:'+'d'*64}, 'compatibility': {'os': 'linux', 'architecture': 'amd64', 'database': {'engine': 'postgresql', 'major': 16}, 'storageFormat': 'physical-pgdata.v1'}, 'checkpoint': {'bytes': 1, 'sha256': self.digest(b'x')}}
        self.write(os.path.join(self.pointdir, 'point.json'), json.dumps(self.original).encode())
        self.write(os.path.join(self.pointdir, 'capture-draft.orbis'), b'draft')
        self.write(os.path.join(self.base, 'keys/master-v1.key'), self.key)
        self.write(os.path.join(self.base, 'core-publish-input', self.id, 'checkpoint.tar'), b'x')
        self.write(os.path.join(self.base, 'core-publish-input', self.id, 'images/inventory.json'), b'{}')
        self.docker = FakeDocker({})
        self.docker.start = self.seal

    def tearDown(self):
        self.temp.cleanup()

    def write(self, path, data):
        with open(path, 'wb') as f:
            f.write(data)
        os.chmod(path, 0o600)

    def seal(self, container):
        core, meta = b'c'*100, b'meta'
        point = dict(self.original, status='sealed', archiveBytes=len(core), archiveSha256=self.digest(core), metadataSha256=self.digest(meta))
        body = json.dumps(point).encode()
        self.write(os.path.join(self.pointdir, 'point.json'), body)
        self.write(os.path.join(self.pointdir, 'metadata.orbis'), meta)
        self.write(os.path.join(self.pointdir, 'core.orbis'), core)
        pub = {'schema': 'orbis.core-capture-publication.v1', 'pointId': self.id, 'ownerId': 7, 'createdAt': 8, 'pointSha256': self.digest(body), 'pointReservationSha256': self.digest(v._canonical({k: point[k] for k in ('version', 'id', 'ownerId', 'createdAt', 'envelope')}).encode()), 'metadataSha256': self.digest(meta), 'cipherBytes': len(core), 'cipherSha256': self.digest(core), 'manifestSha256': '5'*64, 'imageInventorySha256': '6'*64, 'captureReceiptSha256': self.expect['captureReceiptSha256'], 'sourceSha256': self.expect['sourceSha256'], 'checkpointSha256': self.expect['checkpointSha256'], 'checkpoint': self.expect['checkpoint'], 'resourceCount': 1, 'imageCount': 2}
        if getattr(self, 'wrong_proof', False):
            pub['pointReservationSha256'] = 'f'*64
        return 0, json.dumps(pub).encode()

    def run_seal(self):
        layout = s._layout
        with patch.object(s.sys, 'platform', 'linux'), patch.object(s.os, 'geteuid', return_value=0), patch.object(v, '_secure_scratch'), patch.object(s, '_layout', side_effect=lambda root, exp, owner, sealed=False: layout(root, exp, os.stat(root).st_uid, sealed)):
            return s.seal_prepared_capture(workspace_directory=self.root, image_id='sha256:'+'c'*64, expectation=self.expect, owner_id=7, created_at=8, runner=self.docker)

    def test_success_and_refusal_to_overwrite(self):
        self.assertEqual(self.run_seal()['pointId'], self.id)
        self.assertFalse(self.docker.present)
        with self.assertRaises(v.VerificationError):
            self.run_seal()

    def test_original_binding_and_partial_refusal(self):
        self.original['envelope']['keyId'] = 'a'*64
        self.write(os.path.join(self.pointdir, 'point.json'), json.dumps(self.original).encode())
        with self.assertRaises(v.VerificationError):
            self.run_seal()
        self.assertFalse(self.docker.calls)
        self.original['envelope']['keyId'] = self.digest(self.key)
        self.write(os.path.join(self.pointdir, 'point.json'), json.dumps(self.original).encode())
        self.write(os.path.join(self.pointdir, 'metadata.orbis'), b'partial')
        with self.assertRaises(v.VerificationError):
            self.run_seal()
        self.assertFalse(self.docker.calls)

    def test_wrong_proof_rejected_after_cleanup(self):
        self.wrong_proof = True
        with self.assertRaises(v.VerificationError):
            self.run_seal()
        self.assertFalse(self.docker.present)
        self.assertTrue(os.path.exists(os.path.join(self.pointdir, 'core.orbis')))

    def test_cleanup_uncertainty_is_preserved(self):
        self.docker.wrong = True
        with self.assertRaises(v.CleanupIndeterminate):
            self.run_seal()
        self.assertTrue(self.docker.present)

    def test_fixed_container_confinement(self):
        transport = s._Sealer()
        captured = []
        with patch.object(transport, '_run', side_effect=lambda args: (captured.extend(args) or 0, b'a'*64)):
            transport.create('name', 'nonce', 'sha256:'+'c'*64, os.path.join(self.root, 'data'), '', v._canonical(self.expect))
        self.assertIn('--network', captured)
        self.assertEqual(captured[captured.index('--network') + 1], 'none')
        self.assertIn('--cap-drop', captured)
        self.assertIn('ALL', captured)
        self.assertIn('/app/core-capture-seal.mjs', captured)
        self.assertIn('--seal', captured)
        mounts = [captured[i+1] for i, x in enumerate(captured[:-1]) if x == '--mount']
        self.assertEqual(len(mounts), 4)
        self.assertTrue(all(m.endswith(',readonly') for m in mounts[1:]))
        self.assertNotIn('docker.sock', ' '.join(captured))


if __name__ == '__main__':
    unittest.main()
