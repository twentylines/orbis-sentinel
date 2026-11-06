import hashlib
import os
import unittest

import test_capture_publication as publication_fixture
from orbis_sentinel import capture_catalog as c, capture_export as export, verification as v


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.f = publication_fixture.PreparedPublicationTests('runTest')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.cat = c.CaptureCatalog(self.f.f.root)
        self.addCleanup(self.cat.close)
        self.f.prepare(self.cat)
        result = self.f.publish(self.cat)
        self.point = self.f.f.reservation['id']
        self.args = dict(file_name='core.orbis',
                         publication_sha256=hashlib.sha256(v._canonical(result['publication']).encode()).hexdigest(),
                         preparation_sha256='1'*64, source_hold_sha256='2'*64, terminal_sha256='3'*64)
        self.path = os.path.join(self.f.f.root, 'objects', self.point, 'point', 'core.orbis')

    def open(self, **changes):
        return export.open_published_file(self.cat, self.point, **{**self.args, **changes})

    def test_stream_exact_bytes_after_source_and_original_key_removed(self):
        with self.open() as reader:
            self.assertEqual((reader.bytes, reader.sha256), (100, hashlib.sha256(b'x'*100).hexdigest()))
            body = reader.read(31) + reader.read(65536)
            self.assertEqual(reader.read(1), b'')
            reader.complete()
        self.assertEqual(body, b'x'*100)
        self.assertNotIn(self.f.f.key, body)

    def test_names_bindings_and_publication_hash_fail_closed(self):
        for changes in ({'file_name': 'master-v1.key'}, {'file_name': '../core.orbis'},
                        {'file_name': 'record.json'}, {'file_name': 'icons.orbis'},
                        {'publication_sha256': '4'*64}, {'preparation_sha256': '4'*64},
                        {'source_hold_sha256': '4'*64}, {'terminal_sha256': '4'*64}):
            with self.subTest(changes=changes), self.assertRaises(c.CatalogError):
                with self.open(**changes): pass

    def test_incomplete_and_invalid_size_fail(self):
        with self.assertRaises(c.CatalogError):
            with self.open() as reader: reader.read(1)
        for size in (0, -1, 65537, True):
            with self.subTest(size=size), self.assertRaises(c.CatalogError):
                with self.open() as reader: reader.read(size)

    def test_mutation_and_path_replacement_fail(self):
        with self.assertRaises(c.CatalogError):
            with self.open() as reader:
                reader.read(1)
                with open(self.path, 'r+b') as stream: stream.write(b'y')
                reader.read(65536)
                reader.complete()

    def test_path_swap_fails(self):
        with self.assertRaises(c.CatalogError):
            with self.open() as reader:
                reader.read(100)
                os.rename(self.path, self.path + '.old')
                with open(self.path, 'wb') as stream: stream.write(b'x'*100)
                os.chmod(self.path, 0o600)
                reader.complete()

    def test_claim_replacement_fails(self):
        path = os.path.join(self.f.f.root, 'publications', self.point + '.json')
        with self.assertRaises(c.CatalogError):
            with self.open() as reader:
                reader.read(100)
                os.rename(path, path + '.old')
                with open(path + '.old', 'rb') as source, open(path, 'wb') as target:
                    target.write(source.read())
                os.chmod(path, 0o600)
                reader.complete()

    def test_catalog_replacement_fails(self):
        root = self.f.f.root
        with self.assertRaises(c.CatalogError):
            with self.open() as reader:
                reader.read(100)
                os.rename(root, root + '-old')
                os.mkdir(root, 0o700)
                try: reader.complete()
                finally:
                    os.rmdir(root)
                    os.rename(root + '-old', root)
