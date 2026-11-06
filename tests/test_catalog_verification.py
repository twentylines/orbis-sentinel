import copy
import hashlib
import json
import os
import shutil
import unittest
from unittest.mock import patch

from orbis_sentinel import catalog_verification as cv
from orbis_sentinel import verification as v
import test_verification as fixtures


class CatalogVerificationTests(unittest.TestCase):
    setUp = fixtures.VerificationTests.setUp
    tearDown = fixtures.VerificationTests.tearDown

    def prepare(self):
        self.real_snapshot_point = v._snapshot_point
        self.retained_key = os.path.join(self.base, 'retained.key')
        shutil.copyfile(os.path.join(self.keys, 'master-v1.key'), self.retained_key)
        os.chmod(self.retained_key, 0o600)
        self.keyfd = os.open(self.retained_key, os.O_RDONLY)
        self.addCleanup(os.close, self.keyfd)
        shutil.rmtree(self.keys)
        for name in ('capture-draft.orbis', 'wallpaper.orbis', 'icons.orbis'):
            with open(os.path.join(self.pointdir, name), 'wb') as stream:
                stream.write(name.encode())
            os.chmod(os.path.join(self.pointdir, name), 0o600)
        files = {}
        for name in os.listdir(self.pointdir):
            with open(os.path.join(self.pointdir, name), 'rb') as stream:
                body = stream.read()
            files[name] = {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
        self.catalog_publication = {'schema': 'orbis.core-capture-catalog-publication.v1',
                                    'core': self.publication,
                                    'keyId': hashlib.sha256(self.key).hexdigest(), 'files': files}
        self.docker = fixtures.FakeDocker(self.catalog_publication)

    def run_catalog(self):
        with patch.object(cv.sys, 'platform', 'linux'), patch.object(cv.os, 'geteuid', return_value=0), \
                patch.object(v, '_snapshot_point', side_effect=lambda d, s, e, owner, **kw:
                             self.real_snapshot_point(d, s, e, self.uid, **kw)), \
                patch.object(v, '_secure_scratch'), patch.object(v, '_require_disjoint'):
            return cv.verify_catalog_capture(data_directory=self.data, scratch_directory=self.scratch,
                                             image_id='sha256:' + 'c' * 64, expectation=self.expect,
                                             owner_id=7, created_at=8, master_key_fd=self.keyfd,
                                             runner=self.docker)

    def test_retained_key_and_all_assets_survive_without_original_key_directory(self):
        self.prepare()
        os.lseek(self.keyfd, 9, os.SEEK_SET)
        result = self.run_catalog()
        self.assertEqual(os.lseek(self.keyfd, 0, os.SEEK_CUR), 9)
        self.assertEqual(result.publication, self.catalog_publication)
        self.assertRegex(result.snapshot_id, r'^catalog-[a-f0-9]{32}$')
        root = os.path.join(self.scratch, result.snapshot_id)
        directory = os.path.join(root, 'data/backups/time-machine/points', self.point_id)
        self.assertEqual(set(os.listdir(directory)), set(self.catalog_publication['files']))
        with open(os.path.join(root, 'catalog-verification.json'), encoding='utf8') as stream:
            self.assertEqual(json.load(stream)['publication'], self.catalog_publication)
        self.assertFalse(self.docker.present)
        self.assertTrue(all(target.startswith('orbis-sentinel-verifier-') if action in ('create', 'find')
                            else target == self.docker.identity for action, target in self.docker.calls))

    def test_exact_inventory_and_key_binding(self):
        self.prepare()
        good = copy.deepcopy(self.catalog_publication)
        for defect in ('missing', 'extra', 'size', 'digest', 'key', 'core'):
            with self.subTest(defect=defect):
                bad = copy.deepcopy(good)
                if defect == 'missing': del bad['files']['icons.orbis']
                if defect == 'extra': bad['files']['other'] = bad['files']['icons.orbis']
                if defect == 'size': bad['files']['icons.orbis']['bytes'] = True
                if defect == 'digest': bad['files']['icons.orbis']['sha256'] = '0' * 64
                if defect == 'key': bad['keyId'] = '0' * 64
                if defect == 'core': bad['core']['ownerId'] = 99
                self.docker = fixtures.FakeDocker(bad)
                with self.assertRaises(v.VerificationError): self.run_catalog()
                self.assertFalse(self.docker.present)

    def test_untrusted_retained_key_refused_before_container_start(self):
        self.prepare()
        os.chmod(self.retained_key, 0o644)
        with self.assertRaises(v.VerificationError): self.run_catalog()
        self.assertFalse(self.docker.calls)

    def test_cleanup_uncertainty_is_preserved(self):
        self.prepare()
        self.docker.wrong = True
        with self.assertRaises(v.CleanupIndeterminate): self.run_catalog()
        self.assertTrue(self.docker.present)

    def test_catalog_command_is_fixed(self):
        self.assertEqual(cv._CatalogDocker._WORKER, '/app/core-capture-catalog.mjs')
        self.assertEqual(v._Docker._WORKER, '/app/core-capture-publication.mjs')


if __name__ == '__main__':
    unittest.main()
