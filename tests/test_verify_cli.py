import contextlib
import io
import json
import os
import shutil
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from orbis_sentinel import verify_cli as cli
from orbis_sentinel.verification import CleanupIndeterminate, VerificationError, VerificationResult


class VerificationCliTests(unittest.TestCase):
    def test_direct_launcher_ignores_user_python_and_path_configuration(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            marker = root / 'unexpected-startup'
            (root / 'sitecustomize.py').write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\n')
            python = root / 'python3'
            python.write_text('#!/bin/sh\ntouch ' + str(marker) + '\nexit 90\n')
            python.chmod(0o700)
            source = Path(__file__).resolve().parents[1]
            bundle = root / 'bundle'
            shutil.copytree(source / 'src', bundle / 'src', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
            (bundle / 'bin').mkdir()
            launcher = bundle / 'bin/orbis-sentinel-verify'
            shutil.copyfile(source / 'bin/orbis-sentinel-verify', launcher)
            launcher.chmod(0o755)
            result = subprocess.run([str(launcher), '--help'], env={**os.environ, 'PATH': str(root),
                                    'PYTHONPATH': str(root), 'PYTHONUSERBASE': str(root)},
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(marker.exists())
            self.assertEqual(list(bundle.rglob('__pycache__')), [])

    def test_private_expectation_reads_and_rejects_ambiguous_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / "expectation.json"
            source.write_text('{"pointId":"example"}')
            source.chmod(0o600)
            self.assertEqual(cli._read_expectation(str(source), os.geteuid()), {"pointId": "example"})
            source.write_text('{"pointId":"one","pointId":"two"}')
            with self.assertRaises(ValueError):
                cli._read_expectation(str(source), os.geteuid())
            source.write_text('{"value":NaN}')
            with self.assertRaises(ValueError):
                cli._read_expectation(str(source), os.geteuid())
            source.write_bytes(b"x" * 8193)
            with self.assertRaises(ValueError):
                cli._read_expectation(str(source), os.geteuid())
            source.write_text('{}')
            source.chmod(0o644)
            with self.assertRaises(ValueError):
                cli._read_expectation(str(source), os.geteuid())
            source.chmod(0o600)
            link = root / "symlink.json"
            link.symlink_to(source)
            with self.assertRaises(ValueError):
                cli._read_expectation(str(link), os.geteuid())
            link.unlink()
            os.link(source, link)
            with self.assertRaises(ValueError):
                cli._read_expectation(str(source), os.geteuid())

    def invoke(self, error=None, root=True):
        args = ["--data-directory", "/private-catalog/data", "--scratch-directory", "/private-catalog/scratch",
                "--image-id", "sha256:" + "a" * 64, "--expectation-file", "/private-catalog/expectation.json",
                "--owner-id", "7", "--created-at", "8"]
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors), \
                patch.object(cli.sys, "platform", "linux"), patch.object(cli.os, "geteuid", return_value=0 if root else 501), \
                patch.object(cli, "_read_expectation", return_value={"pointId": "example"}) as reader, \
                patch.object(cli, "verify_saved_capture", return_value=VerificationResult({"pointId": "example"}, "capture-example"),
                             side_effect=error) as verifier:
            status = cli.main(args)
        return status, output.getvalue(), errors.getvalue(), reader, verifier

    def test_success_returns_only_verified_publication_and_relative_snapshot(self):
        status, output, errors, _, verifier = self.invoke()
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output), {"schema": "orbis-sentinel.capture-verification.v1",
                                            "publication": {"pointId": "example"}, "snapshotId": "capture-example"})
        self.assertEqual(errors, "")
        verifier.assert_called_once_with(data_directory="/private-catalog/data", scratch_directory="/private-catalog/scratch",
                                         image_id="sha256:" + "a" * 64, expectation={"pointId": "example"}, owner_id=7, created_at=8)

    def test_nonroot_is_rejected_before_reading_or_execution(self):
        status, output, _, reader, verifier = self.invoke(root=False)
        self.assertEqual(status, 1)
        self.assertEqual(output, "")
        reader.assert_not_called()
        verifier.assert_not_called()

    def test_failure_distinguishes_uncertain_cleanup_without_printing_secrets(self):
        for error, expected in ((VerificationError("sensitive detail"), 1),
                                (CleanupIndeterminate("sensitive detail"), 2)):
            with self.subTest(error=type(error).__name__):
                status, output, errors, _, _ = self.invoke(error=error)
                self.assertEqual(status, expected)
                self.assertEqual(output, "")
                self.assertNotIn("sensitive detail", errors)


if __name__ == "__main__":
    unittest.main()
