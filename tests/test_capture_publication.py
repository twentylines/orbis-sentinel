import copy
import json
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import test_capture_catalog as fixture
from orbis_sentinel import capture_catalog as c, capture_publication as p, verification as v


class PreparedPublicationTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.CatalogTests('runTest')
        self.f.setUp()
        self.addCleanup(self.f.tearDown)
        self.f.expected['checkpoint'] = {'bytes': 10, 'sha256': fixture.sha(b'checkpoint')}
        self.checkpoint = os.path.join(self.f.tmp.name, 'checkpoint')
        with open(self.checkpoint, 'wb') as stream: stream.write(b'checkpoint')
        os.chmod(self.checkpoint, 0o600)
        self.fd = os.open(self.checkpoint, os.O_RDONLY)
        self.addCleanup(os.close, self.fd)
        self.seal_calls = 0
        self.verify_calls = 0
        self.image_calls = 0
        self.proof = None

    def prepare(self, cat):
        cat.reserve(**self.f.args)
        _, fd = self.f.draft_fixture()
        try: self.f.retain(cat, fd)
        finally: os.close(fd)
        os.unlink(self.f.keypath)
        for name in os.listdir(os.path.join(self.f.source, 'point')):
            os.unlink(os.path.join(self.f.source, 'point', name))
        os.rmdir(os.path.join(self.f.source, 'point'))
        os.rmdir(self.f.source)

    def images(self, control, image, expected, **kwargs):
        self.image_calls += 1
        directory = os.path.join(control, 'data', 'image-inventory-output', 'images')
        os.makedirs(directory, mode=0o700)
        return directory, {}

    def sealer(self, **kwargs):
        self.seal_calls += 1
        root = kwargs['workspace_directory']
        self.assertTrue(os.path.basename(root).startswith('catalog-'))
        point = os.path.join(root, 'data/backups/time-machine/points', self.f.reservation['id'])
        payload = {'metadata.orbis': b'metadata', 'core.orbis': b'x'*100}
        point_json = v._canonical({**self.f.reservation, 'status': 'sealed'}).encode()
        payload['point.json'] = point_json
        for name, body in payload.items():
            with open(os.path.join(point, name), 'wb') as stream: stream.write(body)
            os.chmod(os.path.join(point, name), 0o600)
        self.proof = {'schema': 'orbis.core-capture-publication.v1', 'pointId': self.f.reservation['id'], 'ownerId': 1, 'createdAt': 2, 'pointSha256': fixture.sha(point_json), 'pointReservationSha256': fixture.sha(v._canonical(self.f.reservation).encode()), 'metadataSha256': fixture.sha(payload['metadata.orbis']), 'cipherBytes': 100, 'cipherSha256': fixture.sha(payload['core.orbis']), 'manifestSha256': 'a'*64, 'imageInventorySha256': 'b'*64, 'captureReceiptSha256': 'f'*64, 'sourceSha256': 'c'*64, 'checkpointSha256': 'e'*64, 'checkpoint': self.f.expected['checkpoint'], 'resourceCount': 1, 'imageCount': 1}
        return self.proof

    def verifier(self, **kwargs):
        self.verify_calls += 1
        self.assertEqual(os.pread(kwargs['master_key_fd'], 32, 0), self.f.key)
        data = kwargs['data_directory']
        point = os.path.join(data, 'backups/time-machine/points', self.f.reservation['id'])
        self.core_inode = os.stat(os.path.join(point, 'core.orbis')).st_ino
        files = {}
        for name in os.listdir(point):
            with open(os.path.join(point, name), 'rb') as stream: body = stream.read()
            files[name] = {'sha256': fixture.sha(body), 'bytes': len(body)}
        return SimpleNamespace(snapshot_id=os.path.basename(os.path.dirname(data)), publication={'schema': 'orbis.core-capture-catalog-publication.v1', 'core': self.proof, 'keyId': fixture.sha(self.f.key), 'files': files})

    def publish(self, cat, **kwargs):
        args = {'expectation': self.f.expected, 'checkpoint_fd': self.fd, 'preparation_sha256': '1'*64, 'source_hold_sha256': '2'*64, 'terminal_sha256': '3'*64, 'sealer': self.sealer, 'verifier': self.verifier}
        args.update(kwargs)
        with patch('orbis_sentinel.image_exports.prepare_images', side_effect=self.images):
            return cat.publish_prepared(self.f.reservation['id'], **args)

    def test_success_original_source_gone_claim_binding_and_retry(self):
        with c.CaptureCatalog(self.f.root) as cat:
            self.prepare(cat)
            os.lseek(self.fd, 5, os.SEEK_SET)
            result = self.publish(cat)
            self.assertEqual(os.lseek(self.fd, 0, os.SEEK_CUR), 5)
            self.assertEqual(result['dataState'], 'verified')
            claimpath = os.path.join(self.f.root, 'publications', self.f.reservation['id'] + '.json')
            with open(claimpath) as stream: claim = json.load(stream)
            binding = cat._record(self.f.reservation['id'])
            self.assertEqual(claim['bindingSha256'], fixture.sha(v._canonical(binding).encode()))
            self.assertEqual(claim['expectation'], self.f.expected)
            self.assertEqual((claim['preparationSha256'], claim['sourceHoldSha256'], claim['terminalSha256']), ('1'*64, '2'*64, '3'*64))
            self.assertRegex(claim['workspace'], r'^catalog-[0-9a-f]{32}$')
            objectpoint = os.path.join(self.f.root, 'objects', self.f.reservation['id'], 'point')
            self.assertEqual(os.stat(os.path.join(objectpoint, 'core.orbis')).st_ino, self.core_inode)
            self.assertNotIn('master-v1.key', os.listdir(objectpoint))
            for name in os.listdir(objectpoint):
                with open(os.path.join(objectpoint, name), 'rb') as stream: self.assertNotIn(self.f.key, stream.read())
            self.assertEqual(self.publish(cat, checkpoint_fd=-1), result)
            self.assertEqual((self.image_calls, self.seal_calls, self.verify_calls), (1, 1, 1))
            for change in ({'terminal_sha256': '4'*64}, {'source_hold_sha256': '4'*64}, {'preparation_sha256': '4'*64}):
                with self.assertRaises(c.CatalogError): self.publish(cat, **change)
            for key in ('sourceSha256', 'captureReceiptSha256'):
                changed = copy.deepcopy(self.f.expected)
                changed[key] = '4'*64
                with self.assertRaises(c.CatalogError): self.publish(cat, expectation=changed)

    def assert_failed_attempt(self, exc, outcome):
        with c.CaptureCatalog(self.f.root) as cat:
            self.prepare(cat)
            with self.assertRaises(outcome):
                self.publish(cat, sealer=lambda **kwargs: (_ for _ in ()).throw(exc))
            self.assertEqual(cat.get(self.f.reservation['id'])['dataState'], 'reserved')
            self.assertEqual(len(os.listdir(os.path.join(self.f.root, 'publications'))), 1)
            self.assertTrue(cat.pending_work()['stages'][0].startswith('catalog-'))
            with self.assertRaises(c.CatalogError): self.publish(cat)
            self.assertEqual(self.seal_calls, 0)

    def test_failed_sealer_preserves_claim_and_no_replay(self):
        self.assert_failed_attempt(v.VerificationError('failure'), c.CatalogError)

    def test_uncertain_cleanup_preserves_claim_and_no_replay(self):
        self.assert_failed_attempt(v.CleanupIndeterminate('uncertain'), v.CleanupIndeterminate)

    def test_mismatched_proof_does_not_commit_or_replay(self):
        def wrong(**kwargs):
            result = self.verifier(**kwargs)
            result.publication['core'] = dict(result.publication['core'], manifestSha256='d'*64)
            return result
        with c.CaptureCatalog(self.f.root) as cat:
            self.prepare(cat)
            with self.assertRaises(c.CatalogError): self.publish(cat, verifier=wrong)
            self.assertEqual(cat.get(self.f.reservation['id'])['dataState'], 'reserved')
            self.assertEqual(os.listdir(os.path.join(self.f.root, 'objects')), [])
            with self.assertRaises(c.CatalogError): self.publish(cat)
            self.assertEqual((self.image_calls, self.seal_calls, self.verify_calls), (1, 1, 1))

    def test_committed_ack_loss_retries_without_external_execution(self):
        with c.CaptureCatalog(self.f.root) as cat:
            self.prepare(cat)
            real = os.rename
            def rename(*args, **kwargs):
                real(*args, **kwargs)
                if kwargs.get('dst_dir_fd') == cat._children['objects'][0]: raise OSError('lost ack')
            with patch.object(c.os, 'rename', side_effect=rename):
                with self.assertRaises(Exception): self.publish(cat)
            self.assertEqual(self.publish(cat, checkpoint_fd=-1)['dataState'], 'verified')
            self.assertEqual((self.image_calls, self.seal_calls, self.verify_calls), (1, 1, 1))

    def test_checkpoint_descriptor_is_private_readonly_stable_and_offset_independent(self):
        dest = os.path.join(self.f.tmp.name, 'copied')
        os.lseek(self.fd, 4, os.SEEK_SET)
        p._copy_descriptor(self.fd, dest, 100, self.f.expected['checkpoint'])
        with open(dest, 'rb') as stream: self.assertEqual(stream.read(), b'checkpoint')
        self.assertEqual(os.lseek(self.fd, 0, os.SEEK_CUR), 4)
        os.unlink(dest)
        writable = os.open(self.checkpoint, os.O_RDWR)
        try:
            with self.assertRaises(c.CatalogError): p._copy_descriptor(writable, dest, 100)
        finally: os.close(writable)
        os.link(self.checkpoint, self.checkpoint + '-link')
        with self.assertRaises(c.CatalogError): p._copy_descriptor(self.fd, dest, 100)
        os.unlink(self.checkpoint + '-link')
        os.chmod(self.checkpoint, 0o644)
        with self.assertRaises(c.CatalogError): p._copy_descriptor(self.fd, dest, 100)
        os.chmod(self.checkpoint, 0o600)
        original = os.pread
        def mutate(fd, size, offset):
            data = original(fd, size, offset)
            if offset == 0:
                with open(self.checkpoint, 'ab') as stream: stream.write(b'x')
            return data
        with patch.object(p.os, 'pread', side_effect=mutate):
            with self.assertRaises(c.CatalogError): p._copy_descriptor(self.fd, dest, 100)
