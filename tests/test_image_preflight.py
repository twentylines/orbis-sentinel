import json
import os
import tempfile
import unittest
from unittest.mock import patch

from orbis_sentinel import capture_catalog as c
from orbis_sentinel import image_preflight as p
from orbis_sentinel import verification as v

IMAGE = 'sha256:' + 'a' * 64
CID = 'b' * 64


class Runner:
    def __init__(self):
        self.output = {k: json.dumps(value) for k, value in p._CAPABILITIES.items()}
        self.container = None
        self.wrong_image = False
        self.uncertain = False
        self.on_start = lambda: None

    def create(self, name, nonce, image, data, staging, encoded):
        self.name, self.nonce, self.image = name, nonce, image
        self.container = CID
        return CID

    def inspect(self, container):
        return {'Id': container, 'Name': '/' + self.name, 'Image': 'sha256:' + 'c' * 64 if self.wrong_image else self.image, 'Config': {'Labels': {'orbis.sentinel.verifier': self.nonce}}, 'State': {'Running': False, 'ExitCode': 0}}

    def start(self, container):
        self.on_start()
        return 0, json.dumps(self.output).encode()

    def remove(self, container):
        if self.uncertain:
            raise RuntimeError('unknown')
        self.container = None

    def exists(self, container): return self.container is not None
    def find(self, name, nonce): return self.container


class ImagePreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='image-preflight-')
        self.root = os.path.join(self.tmp.name, 'catalog')
        os.mkdir(self.root, 0o700)
        self.patches = [patch.object(c, '_OWNER_UID', os.geteuid()), patch.object(v, '_secure_scratch'), patch.object(c, '_persistent'), patch.object(v, '_mount_id', return_value=1), patch.object(p.sys, 'platform', 'linux')]
        for item in self.patches: item.start()
        self.cat = c.CaptureCatalog(self.root)
        self.root_patch = patch.object(p.os, 'geteuid', return_value=0)
        self.root_patch.start()
        self.runner = Runner()

    def tearDown(self):
        if not self.cat._closed:
            try: self.cat.close()
            except c.CatalogError: pass
        self.root_patch.stop()
        for item in reversed(self.patches): item.stop()
        self.tmp.cleanup()

    def run_check(self): return p.check_publication_image(self.cat, IMAGE, self.runner)

    def test_success_and_retained_receipt(self):
        result = self.run_check()
        self.assertEqual(result, {'schema': 'orbis-sentinel.capture-image-preflight.v1', 'imageId': IMAGE, 'workers': p._CAPABILITIES, 'lifecycleAuthority': False})
        names = os.listdir(os.path.join(self.root, 'work'))
        self.assertEqual(len(names), 1)
        self.assertRegex(names[0], r'^preflight-[0-9a-f]{32}$')
        self.assertEqual(os.listdir(os.path.join(self.root, 'work', names[0])), ['verifier-receipt.jsonl'])
        self.assertIsNone(self.runner.container)

    def test_missing_old_malformed_and_duplicate_capabilities(self):
        for bad in (None, '{}', '{"version":1,"version":1}', json.dumps({**p._CAPABILITIES['publication'], 'version': True})):
            with self.subTest(bad=bad):
                self.runner.output['publication'] = bad
                with self.assertRaises(c.CatalogError): self.run_check()
                self.assertIsNone(self.runner.container)
        del self.runner.output['publication']
        with self.assertRaises(c.CatalogError): self.run_check()

    def test_wrong_ownership_and_uncertain_cleanup(self):
        self.runner.wrong_image = True
        with self.assertRaises(v.CleanupIndeterminate): self.run_check()
        self.runner.wrong_image = False
        self.runner.container = None
        self.runner.uncertain = True
        with self.assertRaises(v.CleanupIndeterminate): self.run_check()

    def test_gates(self):
        for image in ('latest', 'sha256:' + 'A' * 64, None):
            with self.assertRaises(v.VerificationError): p.check_publication_image(self.cat, image, self.runner)
        with patch.object(p.sys, 'platform', 'darwin'):
            with self.assertRaises(v.VerificationError): self.run_check()
        with patch.object(p.os, 'geteuid', return_value=1):
            with self.assertRaises(v.VerificationError): self.run_check()

    def test_catalog_and_work_identity_rechecked(self):
        def swap():
            path = os.path.join(self.root, 'work')
            os.rename(path, path + '-old')
            os.mkdir(path, 0o700)
        self.runner.on_start = swap
        with self.assertRaises(c.CatalogError): self.run_check()
        self.assertIsNone(self.runner.container)

    def test_work_entry_identity_rechecked(self):
        def swap():
            work = os.path.join(self.root, 'work')
            name = os.listdir(work)[0]
            os.rename(os.path.join(work, name), os.path.join(work, name + '-old'))
            os.mkdir(os.path.join(work, name), 0o700)
        self.runner.on_start = swap
        with self.assertRaises(c.CatalogError): self.run_check()
        self.assertIsNone(self.runner.container)

    def test_fixed_docker_arguments_without_mounts(self):
        transport = p._PreflightDocker()
        calls = []
        def run(args, timeout=30):
            calls.append((args, timeout))
            return 0, CID.encode()
        transport._run = run
        transport.create('fixed', 'a' * 32, IMAGE, '/ignored', '/ignored', '')
        args = calls[0][0]
        for flag in ('--pull=never', '--read-only', '--cap-drop', '--network', '--ipc', '--security-opt', '--entrypoint'):
            self.assertIn(flag, args)
        self.assertNotIn('--mount', args)
        self.assertNotIn('-v', args)
        self.assertEqual(args[-4:], ['/usr/local/bin/node', IMAGE, '-e', p._SCRIPT])
        for worker in p._CAPABILITIES: self.assertIn(worker, p._SCRIPT)
        self.assertIn('--capability', p._SCRIPT)
        transport.start(CID)
        self.assertEqual(calls[-1][1], 60)


if __name__ == '__main__': unittest.main()
