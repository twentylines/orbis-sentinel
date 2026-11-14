import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

import test_build_release as fixtures


packaging = Path(__file__).resolve().parents[1] / "packaging"
spec = importlib.util.spec_from_file_location("qualify_release", packaging / "qualify_release.py")
delivery = importlib.util.module_from_spec(spec)
with mock.patch.object(sys, "path", [str(packaging), *sys.path]):
    spec.loader.exec_module(delivery)


class QualificationTests(unittest.TestCase):
    def setUp(self):
        fixtures.ReleaseTests.setUp(self)
        self.output = self.root / "qualified"

    def qualify(self):
        return delivery.qualify_release(self.source, self.output)

    def test_checked_archive_and_checksum_are_the_only_delivery_files(self):
        result = self.qualify()
        archive = Path(result["artifact"])
        self.assertFalse(result["activated"])
        self.assertEqual(result["entrypointChecks"], 3)
        self.assertEqual(result["sha256"], hashlib.sha256(archive.read_bytes()).hexdigest())
        self.assertEqual(Path(result["checksum"]).read_text(), f"{result['sha256']}  {archive.name}\n")
        self.assertEqual({p.name for p in archive.parent.iterdir()}, {archive.name, archive.name + ".sha256"})

    def test_existing_output_is_not_reused_or_erased(self):
        self.output.mkdir()
        marker = self.output / "keep"
        marker.write_text("retained")
        with self.assertRaises(FileExistsError):
            self.qualify()
        self.assertEqual(marker.read_text(), "retained")

    def test_content_review_rejects_private_home_paths_without_printing_them(self):
        private = "/Users/local-reader/Documents/private"
        (self.source / "web/private.js").write_text(json.dumps(private))
        with self.assertRaisesRegex(ValueError, "private home path") as error:
            self.qualify()
        self.assertNotIn(private, str(error.exception))
        self.assertNotIn("local-reader", str(error.exception))

    def test_linux_and_json_escaped_windows_home_paths_are_rejected(self):
        for index, value in enumerate(["/home/local-reader/private", r"C:\Users\local-reader\private"]):
            with self.subTest(index=index):
                (self.source / "web/private.js").write_text(json.dumps(value))
                with self.assertRaisesRegex(ValueError, "private home path"):
                    delivery.qualify_release(self.source, self.root / f"private-path-{index}")

    def test_content_review_rejects_credentials_and_private_records(self):
        for name, value in [("token.js", "ghp_" + "a" * 30), ("note.js", "provider-thread:private")]:
            with self.subTest(name=name):
                target = self.source / "web" / name
                target.write_text(json.dumps(value))
                with self.assertRaisesRegex(ValueError, "content review"):
                    delivery.qualify_release(self.source, self.root / name)
                target.unlink()

    def test_a_failed_packaged_entrypoint_blocks_qualification(self):
        (self.source / "bin/orbis-sentinel-verify").write_text("raise SystemExit(3)\n")
        with self.assertRaisesRegex(ValueError, "entrypoint"):
            self.qualify()

    def test_packaged_checks_do_not_inherit_python_or_component_configuration(self):
        original = delivery.subprocess.run
        environments = []

        def run(*args, **kwargs):
            environments.append(kwargs["env"])
            return original(*args, **kwargs)

        with mock.patch.dict(os.environ, {"PYTHONPATH": "untrusted", "ORBIS_SENTINEL_SOCKET": "private"}), mock.patch.object(delivery.subprocess, "run", run):
            self.qualify()
        self.assertEqual(len(environments), 3)
        self.assertTrue(all(set(env) == {"PATH", "TMPDIR", "PYTHONDONTWRITEBYTECODE"} for env in environments))
        self.assertTrue(all(Path(env["TMPDIR"]).is_relative_to(self.output) for env in environments))

    def test_archive_mutation_after_staging_blocks_qualification(self):
        original = delivery.subprocess.run
        changed = False

        def run(*args, **kwargs):
            nonlocal changed
            result = original(*args, **kwargs)
            if not changed:
                changed = True
                next((self.output / "archive").glob("*.tar.gz")).write_bytes(b"changed")
            return result

        with mock.patch.object(delivery.subprocess, "run", run), self.assertRaisesRegex(ValueError, "archive changed"):
            self.qualify()

    def test_checksum_mutation_after_staging_blocks_qualification(self):
        original = delivery.subprocess.run

        def run(*args, **kwargs):
            result = original(*args, **kwargs)
            next((self.output / "archive").glob("*.sha256")).write_text("wrong\n")
            return result

        with mock.patch.object(delivery.subprocess, "run", run), self.assertRaisesRegex(ValueError, "checksum file changed"):
            self.qualify()

    def test_entrypoint_timeout_blocks_qualification(self):
        with mock.patch.object(delivery.subprocess, "run", side_effect=subprocess.TimeoutExpired("help", 15)), self.assertRaises(subprocess.TimeoutExpired):
            self.qualify()

    def test_command_failure_does_not_print_payload_or_exception_details(self):
        (self.source / "web/private.js").write_text(json.dumps("/Users/local-reader/secret"))
        result = subprocess.run(
            [sys.executable, str(packaging / "qualify_release.py"), "--source", str(self.source), "--output", str(self.output)],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "Package qualification failed; no service was activated.\n")


if __name__ == "__main__":
    unittest.main()
