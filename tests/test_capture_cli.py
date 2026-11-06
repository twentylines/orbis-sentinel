import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from orbis_sentinel import capture_cli as cli
from orbis_sentinel import verification as v


class CaptureCliTests(unittest.TestCase):
    def invoke(self, operation, request, *, root=True, failure=None):
        input_stream = io.TextIOWrapper(io.BytesIO(v._canonical(request).encode()))
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors), \
                patch.object(cli.sys, 'stdin', input_stream), patch.object(cli.sys, 'platform', 'linux'), \
                patch.object(cli.os, 'geteuid', return_value=0 if root else 501), \
                patch.object(cli, 'CaptureCatalog') as factory, patch.object(cli, 'check_publication_image') as preflight:
            catalog = factory.return_value.__enter__.return_value
            catalog.reserve.return_value = {'id': 'test', 'dataState': 'reserved'}
            catalog.retain_draft.return_value = {'id': 'test', 'dataState': 'retained-unverified'}
            catalog.publish_prepared.return_value = {'id': 'test', 'dataState': 'verified', 'lifecycleState': 'unobserved'}
            catalog.reserve.side_effect = failure
            catalog.publish_prepared.side_effect = failure
            preflight.return_value = {'schema': 'test-preflight', 'imageId': request.get('recoveryImageId')}
            if operation in {'check-publication-image', 'reserve-for-publication'}:
                preflight.side_effect = failure
            if operation == 'reserve-for-publication':
                def checked_reserve(**kwargs):
                    self.assertTrue(preflight.called, 'Custody preceded image preflight')
                    return {'id': 'test', 'dataState': 'reserved'}
                catalog.reserve.side_effect = checked_reserve
            args = (['--' + operation, '--key-fd', '3'] if operation in {'reserve', 'reserve-for-publication'} else
                    ['--check-publication-image'] if operation == 'check-publication-image' else ['--publish', '--checkpoint-fd', '5']
                    if operation == 'publish' else ['--retain-draft', '--point-fd', '4'])
            status = cli.main(args)
        return status, output.getvalue(), errors.getvalue(), factory, catalog

    def reservation(self):
        return {'schema': 'orbis-sentinel.capture-reserve.v1', 'catalogDirectory': '/catalog',
                'dataDirectory': '/orbis', 'sourceDirectories': ['/external/backups'], 'jobId': 'a' * 32, 'installationId': 'b' * 64,
                'sourceSha256': 'c' * 64, 'recoveryImageId': 'sha256:' + 'd' * 64,
                'reservation': {'id': 'test'}}

    def test_reserve_passes_only_the_received_key_descriptor(self):
        request = self.reservation()
        status, output, errors, factory, catalog = self.invoke('reserve', request)
        self.assertEqual(status, 0)
        self.assertFalse(errors)
        factory.assert_called_once_with('/catalog')
        catalog.reserve.assert_called_once_with(job_id=request['jobId'], installation_id=request['installationId'],
                                               source_sha256=request['sourceSha256'], recovery_image_id=request['recoveryImageId'],
                                               reservation=request['reservation'], key_fd=3, data_directory='/orbis',
                                               additional_data_directories=['/external/backups'])
        self.assertEqual(json.loads(output)['result']['dataState'], 'reserved')
        self.assertNotIn('/catalog', output)

    def test_draft_handoff_keeps_lifecycle_binding(self):
        request = {'schema': 'orbis-sentinel.capture-retain-draft.v1', 'catalogDirectory': '/catalog',
                   'pointId': 'test', 'preparationSha256': 'a' * 64, 'sourceHoldSha256': 'b' * 64}
        status, output, errors, _, catalog = self.invoke('retain-draft', request)
        self.assertEqual(status, 0)
        self.assertFalse(errors)
        catalog.retain_draft.assert_called_once_with('test', point_fd=4, preparation_sha256='a' * 64,
                                                    source_hold_sha256='b' * 64)
        self.assertEqual(json.loads(output)['result']['dataState'], 'retained-unverified')

    def test_publication_reservation_checks_the_image_before_key_custody(self):
        request = {**self.reservation(), 'schema': 'orbis-sentinel.capture-reserve-for-publication.v1'}
        status, output, errors, _, catalog = self.invoke('reserve-for-publication', request)
        self.assertEqual(status, 0, errors)
        self.assertEqual(json.loads(output)['result'], {'custody': {'id': 'test', 'dataState': 'reserved'},
                                                        'imagePreflight': {'schema': 'test-preflight', 'imageId': request['recoveryImageId']}})
        catalog.reserve.assert_called_once()

    def test_failed_or_uncertain_preflight_never_receives_the_key(self):
        request = {**self.reservation(), 'schema': 'orbis-sentinel.capture-reserve-for-publication.v1'}
        for error, code in ((ValueError('private failure'), 1), (v.CleanupIndeterminate('private failure'), 2)):
            with self.subTest(code=code):
                status, output, errors, _, catalog = self.invoke('reserve-for-publication', request, failure=error)
                self.assertEqual(status, code)
                self.assertFalse(output)
                self.assertNotIn('private failure', errors)
                catalog.reserve.assert_not_called()

    def test_check_does_not_accept_key_or_reservation_fields(self):
        request = {'schema': 'orbis-sentinel.capture-check-publication-image.v1', 'catalogDirectory': '/catalog',
                   'recoveryImageId': self.reservation()['recoveryImageId']}
        status, output, errors, _, catalog = self.invoke('check-publication-image', request)
        self.assertEqual(status, 0, errors)
        self.assertEqual(json.loads(output)['operation'], 'check-publication-image')
        catalog.reserve.assert_not_called()
        status, _, _, factory, _ = self.invoke('check-publication-image', {**request, 'key': 'forbidden'})
        self.assertEqual(status, 1)
        factory.assert_not_called()

    def test_new_capability_is_separate_from_legacy_custody(self):
        for option, expected in (('--capability', cli.CAPABILITY), ('--publication-capability', cli.PUBLICATION_CAPABILITY),
                                 ('--image-check-capability', cli.IMAGE_CHECK_CAPABILITY), ('--export-capability', cli.EXPORT_CAPABILITY)):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(cli.main([option]), 0)
            self.assertEqual(json.loads(output.getvalue()), expected)

    def test_export_stdout_is_exact_binary_and_late_failure_is_not_success(self):
        request = {'schema': 'orbis-sentinel.capture-export-file.v1', 'catalogDirectory': '/catalog',
                   'pointId': 'test', 'fileName': 'core.orbis', 'publicationSha256': 'a' * 64,
                   'preparationSha256': 'b' * 64, 'sourceHoldSha256': 'c' * 64, 'terminalSha256': 'd' * 64}
        for late_failure in (False, True):
            raw = io.BytesIO()
            output = io.TextIOWrapper(raw, encoding='utf8')
            errors = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors), \
                    patch.object(cli.sys, 'stdin', io.TextIOWrapper(io.BytesIO(v._canonical(request).encode()))), \
                    patch.object(cli.sys, 'platform', 'linux'), patch.object(cli.os, 'geteuid', return_value=0), \
                    patch.object(cli, 'CaptureCatalog') as catalog, patch.object(cli, 'open_published_file') as opened:
                reader = opened.return_value.__enter__.return_value
                reader.read.side_effect = [b'\x00\xffciphertext', b'']
                if late_failure:
                    opened.return_value.__exit__.side_effect = ValueError('/private/secret')
                status = cli.main(['--export-file'])
                output.flush()
                self.assertEqual(raw.getvalue(), b'\x00\xffciphertext')
                self.assertEqual(status, 1 if late_failure else 0)
                self.assertNotIn('/private/secret', errors.getvalue())
                reader.complete.assert_called_once()
                catalog.return_value.__enter__.return_value.reserve.assert_not_called()
            output.detach()

    def test_publication_passes_checkpoint_and_original_authority_bindings(self):
        request = {'schema': 'orbis-sentinel.capture-publish.v1', 'catalogDirectory': '/catalog',
                   'pointId': 'test', 'preparationSha256': 'a' * 64, 'sourceHoldSha256': 'b' * 64,
                   'terminalSha256': 'c' * 64, 'expectation': {'pointId': 'test'}}
        status, output, errors, _, catalog = self.invoke('publish', request)
        self.assertEqual(status, 0)
        self.assertFalse(errors)
        catalog.publish_prepared.assert_called_once_with('test', checkpoint_fd=5, expectation=request['expectation'],
                                                        preparation_sha256='a' * 64, source_hold_sha256='b' * 64,
                                                        terminal_sha256='c' * 64)
        self.assertEqual(json.loads(output)['result']['lifecycleState'], 'unobserved')

    def test_uncertain_publication_cleanup_is_a_distinct_exit(self):
        request = {'schema': 'orbis-sentinel.capture-publish.v1', 'catalogDirectory': '/catalog',
                   'pointId': 'test', 'preparationSha256': 'a' * 64, 'sourceHoldSha256': 'b' * 64,
                   'terminalSha256': 'c' * 64, 'expectation': {'pointId': 'test'}}
        status, output, errors, _, _ = self.invoke('publish', request, failure=v.CleanupIndeterminate('private details'))
        self.assertEqual(status, 2)
        self.assertFalse(output)
        self.assertNotIn('private details', errors)

    def test_unsupported_or_unprivileged_requests_do_not_open_catalog(self):
        for request, root in ((self.reservation(), False), ({**self.reservation(), 'execute': True}, True)):
            with self.subTest(root=root):
                status, output, _, factory, _ = self.invoke('reserve', request, root=root)
                self.assertEqual(status, 1)
                self.assertFalse(output)
                factory.assert_not_called()

    def test_failure_does_not_print_paths_or_secret_values(self):
        status, output, errors, _, _ = self.invoke('reserve', self.reservation(), failure=ValueError('/private/secret'))
        self.assertEqual(status, 1)
        self.assertFalse(output)
        self.assertNotIn('/private/secret', errors)

    def test_launcher_is_isolated_from_user_startup_and_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            marker = root / 'unexpected-startup'
            (root / 'sitecustomize.py').write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\n')
            source = Path(__file__).resolve().parents[1]
            bundle = root / 'bundle'
            shutil.copytree(source / 'src', bundle / 'src', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
            (bundle / 'bin').mkdir()
            launcher = bundle / 'bin/orbis-sentinel-capture'
            shutil.copyfile(source / 'bin/orbis-sentinel-capture', launcher)
            launcher.chmod(0o755)
            result = subprocess.run([str(launcher), '--capability'], env={**os.environ, 'PYTHONPATH': str(root),
                                    'PYTHONUSERBASE': str(root), 'PATH': str(root)},
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), cli.CAPABILITY)
            self.assertFalse(marker.exists())
            self.assertEqual(list(bundle.rglob('__pycache__')), [])


if __name__ == '__main__':
    unittest.main()
