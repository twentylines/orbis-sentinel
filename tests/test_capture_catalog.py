import hashlib
import json
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from orbis_sentinel import capture_catalog as c
from orbis_sentinel import verification as v


def sha(data):
    return hashlib.sha256(data).hexdigest()


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='catalog-test-')
        self.root = os.path.join(self.tmp.name, 'catalog')
        os.mkdir(self.root, 0o700)
        self.patches = [patch.object(c, '_OWNER_UID', os.geteuid()), patch.object(c.sys, 'platform', 'linux'), patch.object(v, '_secure_scratch'), patch.object(c, '_persistent'), patch.object(v, '_mount_id', return_value=1), patch.object(v, '_require_disjoint'), patch.object(c, '_nested_mounts', return_value=[])]
        for p in self.patches:
            p.start()
        self.key = b'K' * 32
        self.keypath = os.path.join(self.tmp.name, 'key')
        with open(self.keypath, 'wb') as f:
            f.write(self.key)
        os.chmod(self.keypath, 0o600)
        self.keyfd = os.open(self.keypath, os.O_RDONLY)
        self.reservation = {'version': 3, 'id': '12345678-1234-4123-8123-123456789abc', 'ownerId': 1, 'createdAt': 2, 'envelope': {'version': 1, 'keyId': sha(self.key), 'nonce': 'a'*24, 'tag': 'b'*32, 'value': 'c'*86}}
        self.source = os.path.join(self.tmp.name, 'source')
        os.mkdir(self.source, 0o700)
        self.args = dict(job_id='a'*32, installation_id='b'*64, source_sha256='c'*64, recovery_image_id='sha256:'+'d'*64, reservation=self.reservation, key_fd=self.keyfd, data_directory=self.source)
        self.expected = {'pointId': self.reservation['id'], 'sourceSha256': 'c'*64, 'checkpointSha256': 'e'*64, 'captureReceiptSha256': 'f'*64, 'resourceCount': 1, 'images': dict.fromkeys(('controller', 'database', 'queue'), 'sha256:'+'a'*64), 'compatibility': {'os': 'linux', 'architecture': 'amd64', 'database': {'engine': 'postgresql', 'major': 16}, 'storageFormat': 'physical-pgdata.v1'}, 'checkpoint': {'bytes': 1, 'sha256': 'e'*64}}
        self.calls = 0

    def tearDown(self):
        os.close(self.keyfd)
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def verifier(self, **kw):
        self.calls += 1
        self.assertEqual(os.pread(kw['master_key_fd'], 32, 0), self.key)
        snap = 'catalog-' + ('%032x' % self.calls)
        point = os.path.join(kw['scratch_directory'], snap, 'data', 'backups', 'time-machine', 'points', self.reservation['id'])
        os.makedirs(point, mode=0o700)
        current = point
        while current != kw['scratch_directory']:
            os.chmod(current, 0o700)
            current = os.path.dirname(current)
        point_json = v._canonical({**self.reservation, 'status': 'sealed'}).encode()
        payload = {'point.json': point_json, 'metadata.orbis': b'metadata', 'core.orbis': b'x'*100, 'wallpaper.orbis': b'wallpaper', 'icons.orbis': b'icons', 'capture-draft.orbis': b'draft'}
        for name, body in payload.items():
            with open(os.path.join(point, name), 'wb') as f:
                f.write(body)
            os.chmod(os.path.join(point, name), 0o600)
        files = {n: {'bytes': len(b), 'sha256': sha(b)} for n, b in payload.items()}
        core = {'schema': 'orbis.core-capture-publication.v1', 'pointId': self.reservation['id'], 'ownerId': 1, 'createdAt': 2, 'pointSha256': sha(point_json), 'pointReservationSha256': sha(v._canonical(self.reservation).encode()), 'metadataSha256': sha(payload['metadata.orbis']), 'cipherBytes': 100, 'cipherSha256': sha(payload['core.orbis']), 'manifestSha256': 'a'*64, 'imageInventorySha256': 'b'*64, 'captureReceiptSha256': 'f'*64, 'sourceSha256': 'c'*64, 'checkpointSha256': 'e'*64, 'checkpoint': self.expected['checkpoint'], 'resourceCount': 1, 'imageCount': 1}
        return SimpleNamespace(snapshot_id=snap, publication={'schema': 'orbis.core-capture-catalog-publication.v1', 'core': core, 'keyId': sha(self.key), 'files': files})

    def test_reserve_publish_reopen_and_retry(self):
        with c.CaptureCatalog(self.root) as cat:
            self.assertEqual(cat.reserve(**self.args)['dataState'], 'reserved')
            self.assertEqual(cat.reserve(**self.args)['dataState'], 'reserved')
            with self.assertRaises(c.CatalogError):
                cat.reserve(**{**self.args, 'job_id': 'b'*32})
            result = cat.publish(self.reservation['id'], data_directory='/unused', expectation=self.expected, verifier=self.verifier)
            self.assertEqual(result['dataState'], 'verified')
            self.assertEqual(len(result['files']), 6)
            self.assertNotIn('master-v1.key', os.listdir(os.path.join(self.root, 'objects', self.reservation['id'], 'point')))
        os.unlink(self.keypath)
        with c.CaptureCatalog(self.root) as cat:
            self.assertEqual(cat.list()[0], result)
            self.assertEqual(cat.publish(self.reservation['id'], data_directory='/gone', expectation=self.expected, verifier=self.verifier), result)
            self.assertEqual(self.calls, 1)
            self.assertEqual(cat.pending_work()['count'], 1)

    def test_bad_keys_and_reservation(self):
        with c.CaptureCatalog(self.root) as cat:
            os.chmod(self.keypath, 0o644)
            with self.assertRaises(c.CatalogError): cat.reserve(**self.args)
            os.chmod(self.keypath, 0o600)
            os.link(self.keypath, self.keypath + '-link')
            with self.assertRaises(c.CatalogError): cat.reserve(**self.args)
            os.unlink(self.keypath + '-link')
            with self.assertRaises(c.CatalogError): cat.reserve(**{**self.args, 'reservation': {**self.reservation, 'version': True}})

    def test_list_reads_records_without_rehashing_archive(self):
        with c.CaptureCatalog(self.root) as cat:
            cat.reserve(**self.args)
            result = cat.publish(self.reservation['id'], data_directory='/unused', expectation=self.expected, verifier=self.verifier)
            read = c._read
            def small_reads(parent, name, *args, **kwargs):
                self.assertIn(name, ('record.json', 'master-v1.key', 'point.json'))
                return read(parent, name, *args, **kwargs)
            with patch.object(c, '_read', side_effect=small_reads):
                self.assertEqual(cat.list(), [result])
                self.assertEqual(cat.get(self.reservation['id']), result)
            self.assertEqual(result['integrity'], 'recorded')

    def test_cleanup_uncertainty_does_not_become_generic_failure(self):
        def uncertain(**kwargs):
            raise v.CleanupIndeterminate('Capture verifier cleanup needs review')
        with c.CaptureCatalog(self.root) as cat:
            cat.reserve(**self.args)
            with self.assertRaises(v.CleanupIndeterminate):
                cat.publish(self.reservation['id'], data_directory='/unused', expectation=self.expected, verifier=uncertain)
            self.assertEqual(cat.get(self.reservation['id'])['dataState'], 'reserved')

    def test_close_releases_descriptors_after_root_integrity_failure(self):
        cat = c.CaptureCatalog(self.root)
        descriptors = list(cat._fds)
        os.chmod(self.root, 0o755)
        with self.assertRaises(c.CatalogError): cat.close()
        for descriptor in descriptors:
            with self.assertRaises(OSError): os.fstat(descriptor)
        os.chmod(self.root, 0o700)

    def test_overlapping_source_is_refused_before_key_custody(self):
        with c.CaptureCatalog(self.root) as cat:
            with patch.object(v, '_require_disjoint', side_effect=v.VerificationError('overlap')):
                with self.assertRaises(c.CatalogError): cat.reserve(**self.args)
            self.assertEqual(cat.list(), [])
            self.assertEqual(cat.pending_work()['count'], 0)

    def test_nested_source_mount_is_checked_before_reservation(self):
        child = os.path.join(self.source, 'alias')
        os.mkdir(child, 0o700)
        def refuse_alias(data, *args):
            if data == child: raise v.VerificationError('alias overlap')
        with c.CaptureCatalog(self.root) as cat:
            with patch.object(c, '_nested_mounts', return_value=[child]), patch.object(v, '_require_disjoint', side_effect=refuse_alias):
                with self.assertRaises(c.CatalogError): cat.reserve(**self.args)
            self.assertEqual(cat.list(), [])
            self.assertEqual(cat.pending_work()['count'], 0)

    def test_exclusive_lock_and_corruption(self):
        with c.CaptureCatalog(self.root) as cat:
            cat.reserve(**self.args)
            with self.assertRaises(c.CatalogError): c.CaptureCatalog(self.root)
            key = os.path.join(self.root, 'reservations', self.reservation['id'], 'master-v1.key')
            os.unlink(key)
            os.symlink(self.keypath, key)
            with self.assertRaises(c.CatalogError): cat.list()

    def test_bad_publication_retains_work(self):
        def bad(**kw):
            result = self.verifier(**kw)
            result.publication['files']['core.orbis']['sha256'] = '0'*64
            return result
        with c.CaptureCatalog(self.root) as cat:
            cat.reserve(**self.args)
            with self.assertRaises(c.CatalogError): cat.publish(self.reservation['id'], data_directory='/unused', expectation=self.expected, verifier=bad)
            self.assertEqual(cat.get(self.reservation['id'])['dataState'], 'reserved')
            self.assertEqual(cat.pending_work()['count'], 1)

    def test_commit_ack_loss_does_not_reverify(self):
        real_rename = os.rename
        def rename(*args, **kwargs):
            real_rename(*args, **kwargs)
            if kwargs.get('dst_dir_fd') == cat._children['objects'][0]:
                raise OSError('injected acknowledgement loss')
        with c.CaptureCatalog(self.root) as cat:
            cat.reserve(**self.args)
            with patch.object(c.os, 'rename', side_effect=rename):
                with self.assertRaises(c.CatalogError): cat.publish(self.reservation['id'], data_directory='/unused', expectation=self.expected, verifier=self.verifier)
            self.assertEqual(cat.publish(self.reservation['id'], data_directory='/gone', expectation=self.expected, verifier=self.verifier)['dataState'], 'verified')
            self.assertEqual(self.calls, 1)

    def test_before_object_commit_keeps_evidence_and_retry(self):
        real_rename = os.rename
        def rename(*args, **kwargs):
            if kwargs.get('dst_dir_fd') == cat._children['objects'][0]:
                raise OSError('injected before commit')
            return real_rename(*args, **kwargs)
        with c.CaptureCatalog(self.root) as cat:
            cat.reserve(**self.args)
            with patch.object(c.os, 'rename', side_effect=rename):
                with self.assertRaises(c.CatalogError):
                    cat.publish(self.reservation['id'], data_directory='/unused', expectation=self.expected, verifier=self.verifier)
            self.assertEqual(cat.get(self.reservation['id'])['dataState'], 'reserved')
            self.assertEqual(cat.pending_work()['count'], 2)
            self.assertEqual(cat.publish(self.reservation['id'], data_directory='/unused', expectation=self.expected, verifier=self.verifier)['dataState'], 'verified')

    def test_reservation_ack_loss_and_retry(self):
        real_rename = os.rename
        def rename(*args, **kwargs):
            real_rename(*args, **kwargs)
            if kwargs.get('dst_dir_fd') == cat._children['reservations'][0]:
                raise OSError('injected acknowledgement loss')
        with c.CaptureCatalog(self.root) as cat:
            with patch.object(c.os, 'rename', side_effect=rename):
                with self.assertRaises(c.CatalogError):
                    cat.reserve(**self.args)
            self.assertEqual(cat.reserve(**self.args)['dataState'], 'reserved')
            self.assertEqual(len(cat.list()), 1)

    def test_reservation_failure_before_rename_retains_stage(self):
        real_rename = os.rename
        def rename(*args, **kwargs):
            if kwargs.get('dst_dir_fd') == cat._children['reservations'][0]:
                raise OSError('injected before commit')
            return real_rename(*args, **kwargs)
        with c.CaptureCatalog(self.root) as cat:
            with patch.object(c.os, 'rename', side_effect=rename):
                with self.assertRaises(c.CatalogError):
                    cat.reserve(**self.args)
            self.assertEqual(cat.list(), [])
            self.assertEqual(cat.pending_work()['count'], 1)
            self.assertEqual(cat.reserve(**self.args)['dataState'], 'reserved')

    def test_inherited_instance_rejects_fork(self):
        if not hasattr(os, 'fork'):
            self.skipTest('fork unavailable')
        with c.CaptureCatalog(self.root) as cat:
            read_fd, write_fd = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.close(read_fd)
                try:
                    cat.list()
                except c.CatalogError:
                    os.write(write_fd, b'R')
                else:
                    os.write(write_fd, b'F')
                os._exit(0)
            os.close(write_fd)
            self.assertEqual(os.read(read_fd, 1), b'R')
            os.close(read_fd)
            _, status = os.waitpid(pid, 0)
            self.assertEqual(status, 0)


if __name__ == '__main__':
    unittest.main()
