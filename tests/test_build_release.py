import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("build_release", Path(__file__).resolve().parents[1] / "packaging/build_release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"], prefix="sentinel-release-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        files = {
            "LICENSE": "license\n",
            "src/orbis_sentinel/__init__.py": '__version__ = "0.1.0-dev.10"\n',
            "src/orbis_sentinel/runtime.py": "def main():\n    return 0\n",
            "web/capture.html": "<!doctype html><title>Captures</title>",
            "packaging/systemd/orbis-sentinel.service": "[Service]\nDynamicUser=yes\n",
            "packaging/systemd/orbis-sentinel.socket": "[Socket]\nListenStream=/run/orbis-sentinel/api.sock\n",
            "packaging/systemd/orbis-sentinel.service.d/observer.conf": "[Service]\nSupplementaryGroups=orbis-observer\n",
            "packaging/sysusers.d/orbis-sentinel-observer.conf": "g orbis-observer -\n",
        }
        files.update({f"bin/{name}": "#!/usr/bin/env python3\nraise SystemExit(0)\n" for name in release.ENTRYPOINTS})
        for name, text in files.items():
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)

    def test_reproducible_payload_manifest_and_permissions(self):
        first = release.build_release(self.source, self.root / "one")
        for path in self.source.rglob("*"):
            os.utime(path, (1234567, 1234567))
        second = release.build_release(self.source, self.root / "two")
        self.assertEqual(Path(first["artifact"]).read_bytes(), Path(second["artifact"]).read_bytes())
        self.assertEqual(first["sha256"], second["sha256"])
        with tarfile.open(first["artifact"]) as archive:
            manifest = json.load(archive.extractfile("release.json"))
            self.assertEqual(manifest["version"], "0.1.0-dev.10")
            for entry in archive.getmembers():
                self.assertEqual((entry.uid, entry.gid, entry.mtime), (0, 0, 0))
                self.assertEqual(entry.mode, 0o755 if entry.isdir() or entry.name.startswith("bin/") else 0o644)
                if entry.isdir():
                    continue
                if entry.name != "release.json":
                    data = archive.extractfile(entry).read()
                    self.assertEqual(manifest["files"][entry.name], {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
            self.assertIn("packaging/systemd/orbis-sentinel.service.d/observer.conf", archive.getnames())

    def test_extraction_preserves_public_directory_access_under_private_umask(self):
        result = release.build_release(self.source, self.root / "out")
        destination = self.root / "installed"
        destination.mkdir()
        previous = os.umask(0o077)
        try:
            subprocess.run(["tar", "-xzpf", result["artifact"], "-C", str(destination)], check=True)
        finally:
            os.umask(previous)
        for path in destination.rglob("*"):
            expected = 0o755 if path.is_dir() or path.parent == destination / "bin" else 0o644
            self.assertEqual(path.stat().st_mode & 0o777, expected, str(path.relative_to(destination)))

    def test_excludes_local_configuration_tests_and_generated_files(self):
        for name in (".env", "HANDOFF.md", "tests/private.py", "src/orbis_sentinel/__pycache__/private.py", "web/.env.json"):
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("private fixture")
        result = release.build_release(self.source, self.root / "out")
        with tarfile.open(result["artifact"]) as archive:
            self.assertFalse(any("private" in name or ".env" in name or "HANDOFF" in name for name in archive.getnames()))

    def test_rejects_linked_file(self):
        path = self.source / "web/capture.html"
        path.unlink()
        path.symlink_to(self.source / "LICENSE")
        with self.assertRaises(OSError):
            release.build_release(self.source, self.root / "out")

    def test_rejects_linked_directory(self):
        (self.source / "src/orbis_sentinel/linked").symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "Linked release directories"):
            release.build_release(self.source, self.root / "out")

    def test_rejects_linked_entrypoint_directory(self):
        target = self.root / "external-bin"
        (self.source / "bin").rename(target)
        (self.source / "bin").symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "Linked release directories"):
            release.build_release(self.source, self.root / "out")

    def test_rejects_missing_entrypoint(self):
        (self.source / "bin/orbis-sentinel-verify").unlink()
        with self.assertRaises(FileNotFoundError):
            release.build_release(self.source, self.root / "out")

    def test_rejects_invalid_python_and_version(self):
        version = self.source / "src/orbis_sentinel/__init__.py"
        version.write_text('__version__ = "../invalid"\n')
        with self.assertRaises(ValueError):
            release.build_release(self.source, self.root / "out")
        version.write_text("def incomplete(\n")
        with self.assertRaises(SyntaxError):
            release.build_release(self.source, self.root / "out")

    def test_does_not_overwrite_existing_release(self):
        result = release.build_release(self.source, self.root / "out")
        original = Path(result["artifact"]).read_bytes()
        with self.assertRaises(FileExistsError):
            release.build_release(self.source, self.root / "out")
        self.assertEqual(Path(result["artifact"]).read_bytes(), original)

    def test_rejects_syntax_newer_than_supported_python(self):
        (self.source / "src/orbis_sentinel/runtime.py").write_text("type Alias = str\n")
        with self.assertRaises(SyntaxError):
            release.build_release(self.source, self.root / "out")

    def test_enforces_payload_bounds(self):
        with mock.patch.object(release, "MAX_FILE_BYTES", 16), self.assertRaisesRegex(ValueError, "bounded regular files"):
            release.build_release(self.source, self.root / "one")
        with mock.patch.object(release, "MAX_TOTAL_BYTES", 1), self.assertRaisesRegex(ValueError, "size bound"):
            release.build_release(self.source, self.root / "two")

    def test_rejects_changed_bytes_even_when_metadata_is_restored(self):
        path = self.source / "src/orbis_sentinel/runtime.py"
        before = path.stat()
        original = release.tarfile.TarFile.addfile
        changed = False

        def addfile(archive, member, fileobj=None):
            nonlocal changed
            original(archive, member, fileobj)
            if not changed:
                changed = True
                path.write_bytes(path.read_bytes().replace(b"return 0", b"return 1"))
                os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))

        with mock.patch.object(release.tarfile.TarFile, "addfile", addfile), self.assertRaisesRegex(ValueError, "source changed"):
            release.build_release(self.source, self.root / "out")
        self.assertFalse(list((self.root / "out").glob("*.tar.gz")))


if __name__ == "__main__":
    unittest.main()
