import hashlib
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from orbis_sentinel import verification as v


class FakeDocker:
    def __init__(self, publication):
        self.publication = publication
        self.calls = []
        self.present = False
        self.identity = 'a' * 64
        self.wrong = False
        self.timeout = False
        self.partial = False

    def create(self, name, nonce, image, data, staging, encoded):
        self.calls.append(('create', name))
        self.name, self.nonce, self.image = name, nonce, image
        self.present = True
        if self.partial:
            raise TimeoutError()
        return self.identity

    def find(self, name, nonce):
        self.calls.append(('find', name))
        return self.identity if self.present else None

    def exists(self, container):
        self.calls.append(('exists', container))
        return self.exists_flag()

    def exists_flag(self):
        return self.present

    def inspect(self, container):
        self.calls.append(('inspect', container))
        return {'Id': container, 'Name': '/' + self.name, 'Image': 'sha256:' + ('b' if self.wrong else 'c') * 64, 'Config': {'Labels': {'orbis.sentinel.verifier': self.nonce}}, 'State': {'Running': False, 'ExitCode': 0}}

    def start(self, container):
        self.calls.append(('start', container))
        if self.timeout:
            raise TimeoutError()
        return 0, json.dumps(self.publication).encode()

    def remove(self, container):
        self.calls.append(('remove', container))
        self.present = False


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = self.temp.name
        self.data = os.path.join(self.base, 'data')
        self.scratch = os.path.join(self.base, 'scratch')
        self.point_id = '11111111-1111-4111-8111-111111111111'
        self.pointdir = os.path.join(self.data, 'backups', 'time-machine', 'points', self.point_id)
        self.keys = os.path.join(self.data, 'backups', 'time-machine', 'keys')
        os.makedirs(self.pointdir, mode=0o700)
        os.makedirs(self.keys, mode=0o700)
        os.mkdir(self.scratch, 0o700)
        for root, dirs, files in os.walk(self.data):
            os.chmod(root, 0o700)
        self.key, self.core, self.meta = b'k' * 32, b'c' * 100, b'metadata'
        digest = lambda x: hashlib.sha256(x).hexdigest()
        self.expect = {'pointId': self.point_id, 'sourceSha256': '1' * 64, 'checkpointSha256': '2' * 64, 'captureReceiptSha256': '3' * 64, 'resourceCount': 1, 'images': {'controller': 'sha256:' + 'c' * 64, 'database': 'sha256:' + 'd' * 64, 'queue': 'sha256:' + 'd' * 64}, 'compatibility': {'os': 'linux', 'architecture': 'amd64', 'database': {'engine': 'postgresql', 'major': 16}, 'storageFormat': 'physical-pgdata.v1'}, 'checkpoint': {'bytes': 1, 'sha256': '4' * 64}}
        self.point = {'version': 3, 'id': self.point_id, 'ownerId': 7, 'createdAt': 8, 'status': 'sealed', 'envelope': {'keyId': digest(self.key)}, 'archiveBytes': len(self.core), 'archiveSha256': digest(self.core), 'metadataSha256': digest(self.meta)}
        self.pointbytes = json.dumps(self.point).encode()
        for path, body in ((os.path.join(self.pointdir, 'point.json'), self.pointbytes), (os.path.join(self.pointdir, 'core.orbis'), self.core), (os.path.join(self.pointdir, 'metadata.orbis'), self.meta), (os.path.join(self.keys, 'master-v1.key'), self.key)):
            with open(path, 'wb') as f:
                f.write(body)
            os.chmod(path, 0o600)
        self.publication = {'schema': 'orbis.core-capture-publication.v1', 'pointId': self.point_id, 'ownerId': 7, 'createdAt': 8, 'pointSha256': digest(self.pointbytes), 'pointReservationSha256': digest(v._canonical({k: self.point[k] for k in ('version', 'id', 'ownerId', 'createdAt', 'envelope')}).encode()), 'metadataSha256': digest(self.meta), 'cipherBytes': len(self.core), 'cipherSha256': digest(self.core), 'manifestSha256': '5'*64, 'imageInventorySha256': '6'*64, 'captureReceiptSha256': self.expect['captureReceiptSha256'], 'sourceSha256': self.expect['sourceSha256'], 'checkpointSha256': self.expect['checkpointSha256'], 'checkpoint': self.expect['checkpoint'], 'resourceCount': 1, 'imageCount': 2}
        self.docker = FakeDocker(self.publication)
        self.real_snapshot = v._snapshot
        self.uid = os.geteuid()

    def tearDown(self):
        self.temp.cleanup()

    def run_verify(self, **kwargs):
        args = dict(data_directory=self.data, scratch_directory=self.scratch, image_id='sha256:' + 'c'*64, expectation=self.expect, owner_id=7, created_at=8, runner=self.docker)
        args.update(kwargs)
        with patch.object(v.sys, 'platform', 'linux'), patch.object(v.os, 'geteuid', return_value=0), patch.object(v, '_snapshot', side_effect=lambda d, s, e, owner: self.real_snapshot(d, s, e, self.uid)), patch.object(v, '_secure_scratch'), patch.object(v, '_require_disjoint'):
            return v.verify_saved_capture(**args)

    def test_mount_coordinates_use_descriptor_identity_and_bind_root(self):
        descriptor = os.open(self.data, os.O_RDONLY | os.O_DIRECTORY)
        try:
            item = os.fstat(descriptor)
            device = str(os.major(item.st_dev)) + ':' + str(os.minor(item.st_dev))
            body = '42 1 ' + device + ' /original/data /alias rw - ext4 /dev/test rw\n'
            with patch.object(v, '_mount_id', return_value=42):
                self.assertEqual(v._mount_coordinates('/alias/inner', descriptor, body),
                                 ((os.major(item.st_dev), os.minor(item.st_dev)), '/original/data/inner'))
                for invalid in (body + body, body.replace('42 1', '43 1'), body.replace(' /alias ', ' /elsewhere '),
                                body.replace(device, '999:999')):
                    with self.subTest(invalid=invalid), self.assertRaises(v.VerificationError):
                        v._mount_coordinates('/alias/inner', descriptor, invalid)
        finally:
            os.close(descriptor)

    def test_bind_alias_overlap_is_rejected_in_both_directions(self):
        for coordinates in ((((1, 2), '/data'), ((1, 2), '/data/inside')),
                            (((1, 2), '/data/inside'), ((1, 2), '/data')),
                            (((1, 2), '/data'), ((1, 2), '/data'))):
            with self.subTest(coordinates=coordinates), patch.object(v, '_kernel_read', return_value='kernel'), \
                    patch.object(v, '_mount_coordinates', side_effect=coordinates), self.assertRaises(v.VerificationError):
                v._require_disjoint('/source', 10, '/scratch', 11)
        with patch.object(v, '_kernel_read', return_value='kernel'), \
                patch.object(v, '_mount_coordinates', side_effect=[((1, 2), '/data'), ((1, 2), '/scratch')]):
            v._require_disjoint('/source', 10, '/scratch', 11)

    def test_success_retains_snapshot_and_removes_only_verifier(self):
        result = self.run_verify()
        self.assertEqual(result.publication, self.publication)
        self.assertTrue(os.path.isfile(os.path.join(self.scratch, result.snapshot_id, 'data', 'backups', 'time-machine', 'keys', 'master-v1.key')))
        for action, target in self.docker.calls:
            self.assertTrue(target.startswith('orbis-sentinel-verifier-') if action in ('create', 'find') else target == self.docker.identity)
        self.assertFalse(self.docker.present)
        summary_file = os.path.join(self.scratch, result.snapshot_id, 'verification.json')
        with open(summary_file, encoding='utf8') as stream:
            summary = json.load(stream)
        self.assertEqual(summary, {
            'schema': 'orbis-sentinel.capture-data-verification.v1',
            'snapshotId': result.snapshot_id, 'imageId': 'sha256:' + 'c' * 64,
            'expectation': self.expect, 'ownerId': 7, 'createdAt': 8,
            'publication': self.publication,
        })
        self.assertEqual(os.stat(summary_file).st_mode & 0o777, 0o600)

    def test_reject_invalid_expectation_image_owner_and_result(self):
        for change in ({'image_id': 'latest'}, {'owner_id': 9}, {'expectation': dict(self.expect, extra=1)}):
            with self.subTest(change=change), self.assertRaises(v.VerificationError):
                self.run_verify(**change)
        self.publication['checkpoint'] = {'bytes': True, 'sha256': '4' * 64}
        with self.assertRaises(v.VerificationError):
            self.run_verify()
        self.publication['checkpoint'] = self.expect['checkpoint']
        self.publication['imageCount'] = 3
        with self.assertRaises(v.VerificationError):
            self.run_verify()
        self.assertFalse(self.docker.present)

    def test_symlink_hardlink_and_private_layout(self):
        path = os.path.join(self.pointdir, 'core.orbis')
        os.unlink(path)
        os.symlink(os.path.join(self.pointdir, 'metadata.orbis'), path)
        with self.assertRaises(v.VerificationError):
            self.run_verify()
        os.unlink(path)
        os.link(os.path.join(self.pointdir, 'metadata.orbis'), path)
        with self.assertRaises(v.VerificationError):
            self.run_verify()
        os.chmod(self.scratch, 0o755)
        with self.assertRaises(v.VerificationError):
            self.run_verify()

    def test_known_extra_is_not_copied(self):
        extra = os.path.join(self.pointdir, 'capture-draft.orbis')
        with open(extra, 'wb') as stream:
            stream.write(b'draft')
        os.chmod(extra, 0o600)
        result = self.run_verify()
        self.assertFalse(os.path.exists(os.path.join(self.scratch, result.snapshot_id, 'data', 'backups', 'time-machine', 'points', self.point_id, 'capture-draft.orbis')))

    def test_source_modification_after_copy_is_rejected(self):
        original = v._copy
        def modify_after_copy(parent, name, destination, maximum, owner, exact=None):
            result = original(parent, name, destination, maximum, owner, exact)
            if name == 'point.json':
                with open(os.path.join(self.pointdir, name), 'ab') as stream:
                    stream.write(b' ')
            return result
        with patch.object(v, '_copy', side_effect=modify_after_copy):
            with self.assertRaises(v.VerificationError):
                self.run_verify()
        self.assertFalse(self.docker.calls)

    def test_duplicate_result_fields_rejected(self):
        original = self.docker.start
        def duplicate(container):
            original(container)
            return 0, b'{"schema":"x","schema":"y"}'
        self.docker.start = duplicate
        with self.assertRaises(v.VerificationError):
            self.run_verify()
        self.assertFalse(self.docker.present)

    def test_timeout_and_partial_creation_remove_owned_container(self):
        for mode in ('timeout', 'partial'):
            with self.subTest(mode=mode):
                self.docker = FakeDocker(self.publication)
                setattr(self.docker, mode, True)
                with self.assertRaises(v.VerificationError):
                    self.run_verify()
                self.assertFalse(self.docker.present)
                self.assertIn(('remove', self.docker.identity), self.docker.calls)

    def test_missing_container_after_create_failure_is_indeterminate(self):
        def failure(*args):
            raise TimeoutError()
        self.docker.create = failure
        with self.assertRaises(v.CleanupIndeterminate):
            self.run_verify()
        self.assertTrue(os.listdir(self.scratch))

    def test_ownership_refusal_retains_container(self):
        self.docker.wrong = True
        with self.assertRaises(v.CleanupIndeterminate):
            self.run_verify()
        self.assertTrue(self.docker.present)
        self.assertNotIn(('remove', self.docker.identity), self.docker.calls)


if __name__ == '__main__':
    unittest.main()
