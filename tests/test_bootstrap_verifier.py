import contextlib
import fcntl
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


packaging = Path(__file__).resolve().parents[1] / "packaging"
module = importlib.util.spec_from_file_location("bootstrap_verifier", packaging / "bootstrap_verifier.py")
bootstrap = importlib.util.module_from_spec(module)
with mock.patch.object(sys, "path", [str(packaging), *sys.path]):
    module.loader.exec_module(bootstrap)


def elf(machine=62):
    value = bytearray(64)
    value[:7] = b"\x7fELF\x02\x01\x01"
    value[18:20] = machine.to_bytes(2, "little")
    return bytes(value) + b"synthetic verifier; never execute\n"


class VerifierBootstrapTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"], prefix="verifier-bootstrap-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cache = self.root / "cache"
        self.cache.mkdir(mode=0o755)
        with mock.patch.object(bootstrap.platform, "system", return_value="Linux"), \
                mock.patch.object(bootstrap.platform, "machine", return_value="x86_64"):
            self.spec = bootstrap.verifier_spec()
        self.binary, self.licence = elf(), b"synthetic test licence\n"
        self.spec.update(binaryBytes=len(self.binary), binarySha256=hashlib.sha256(self.binary).hexdigest(),
                         licenseBytes=len(self.licence), licenseSha256=hashlib.sha256(self.licence).hexdigest())
        patch = mock.patch.object(bootstrap, "verifier_spec", return_value=self.spec)
        patch.start()
        self.addCleanup(patch.stop)
        self.archive = self.root / "input.tar.gz"
        self.make_archive()

    def entries(self):
        return [(self.spec["prefix"] + "/bin/gh", self.binary, tarfile.REGTYPE),
                (self.spec["prefix"] + "/LICENSE", self.licence, tarfile.REGTYPE)]

    def make_archive(self, entries=None, trailing=b""):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, data, kind in self.entries() if entries is None else entries:
                entry = tarfile.TarInfo(name)
                entry.type = kind
                entry.mode = 0o755 if name.endswith("/gh") else 0o644
                entry.size = len(data) if kind == tarfile.REGTYPE else 0
                entry.linkname = "outside-target" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
                archive.addfile(entry, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
        self.archive.write_bytes(gzip.compress(output.getvalue() + trailing, mtime=0))
        self.pin_input()

    def pin_input(self):
        data = self.archive.read_bytes()
        self.spec.update(archiveBytes=len(data), archiveSha256=hashlib.sha256(data).hexdigest())

    def prepare(self):
        return bootstrap.bootstrap_verifier(self.archive, self.cache)

    def assert_unpublished(self):
        self.assertFalse(any(path.name.startswith("gh-") for path in self.cache.iterdir()))

    def replace_lock(self):
        lock = self.cache / ".verifier-bootstrap.lock"
        lock.rename(self.cache / ".old-lock")
        lock.touch(mode=0o600)

    def test_verified_cache_contains_only_pinned_binary_licence_and_receipt_without_execution(self):
        with mock.patch.object(subprocess, "Popen") as execution:
            tool = self.prepare()
        execution.assert_not_called()
        self.assertEqual(tool.read_bytes(), self.binary)
        self.assertEqual((tool.parent / "LICENSE").read_bytes(), self.licence)
        self.assertEqual(set(path.name for path in tool.parent.iterdir()), {"gh", "LICENSE", "receipt.json"})
        self.assertEqual(stat.S_IMODE(tool.parent.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(tool.stat().st_mode), 0o555)
        self.assertEqual(stat.S_IMODE((tool.parent / "LICENSE").stat().st_mode), 0o444)
        receipt = json.loads((tool.parent / "receipt.json").read_bytes())
        self.assertEqual(receipt["archiveSha256"], self.spec["archiveSha256"])
        self.assertEqual(receipt["binarySha256"], self.spec["binarySha256"])
        self.assertEqual(receipt["architecture"], "amd64")
        self.assertFalse(any(path.name.startswith(".verifier-input-") for path in self.cache.iterdir()))
        self.assertFalse(any(path.name.startswith(".verifier-stage-") for path in self.cache.iterdir()))

    def test_reuse_rechecks_complete_cache_without_requiring_input_archive(self):
        first = self.prepare()
        identity = first.stat().st_ino
        self.archive.unlink()
        self.assertEqual(self.prepare(), first)
        self.assertEqual(first.stat().st_ino, identity)

    def test_wrong_input_size_or_checksum_fails_before_extracting(self):
        original = self.archive.read_bytes()
        for content in (original + b"x", bytes([original[0] ^ 1]) + original[1:]):
            with self.subTest(size=len(content)):
                self.archive.write_bytes(content)
                with self.assertRaises((bootstrap.BootstrapError, OSError)):
                    self.prepare()
                self.assert_unpublished()
                self.assertFalse(any(path.name.startswith(".verifier-stage-") for path in self.cache.iterdir()))

    def test_symlink_hardlink_fifo_and_directory_inputs_are_rejected_without_blocking(self):
        source = self.archive.with_name("retained-input")
        self.archive.rename(source)
        for kind in ("symlink", "hardlink", "fifo", "directory"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    self.archive.symlink_to(source)
                elif kind == "hardlink":
                    os.link(source, self.archive)
                elif kind == "fifo":
                    os.mkfifo(self.archive)
                else:
                    self.archive.mkdir()
                try:
                    with self.assertRaises((bootstrap.BootstrapError, OSError)):
                        self.prepare()
                    self.assert_unpublished()
                finally:
                    self.archive.rmdir() if kind == "directory" else self.archive.unlink()

    def test_source_replaced_with_equal_bytes_during_snapshot_is_rejected(self):
        original_read = bootstrap.os.read
        identity = self.archive.stat().st_ino
        changed = False

        def replace(descriptor, size):
            nonlocal changed
            data = original_read(descriptor, size)
            if not changed and os.fstat(descriptor).st_ino == identity:
                changed = True
                self.archive.rename(self.root / "old-input")
                self.archive.write_bytes((self.root / "old-input").read_bytes())
            return data

        with mock.patch.object(bootstrap.os, "read", side_effect=replace):
            with self.assertRaises(bootstrap.BootstrapError):
                self.prepare()
        self.assertTrue(changed)
        self.assert_unpublished()

    def test_unsafe_duplicate_and_special_archive_members_are_rejected(self):
        prefix = self.spec["prefix"]
        bad = [("../escape", b"x", tarfile.REGTYPE),
               ("/absolute", b"x", tarfile.REGTYPE),
               (prefix + "/../escape", b"x", tarfile.REGTYPE),
               (prefix + "//extra", b"x", tarfile.REGTYPE),
               (prefix + "/back\\slash", b"x", tarfile.REGTYPE),
               (prefix + "/control\nname", b"x", tarfile.REGTYPE),
               (prefix + "/link", b"", tarfile.SYMTYPE),
               (prefix + "/link", b"", tarfile.LNKTYPE),
               (prefix + "/fifo", b"", tarfile.FIFOTYPE),
               (prefix + "/device", b"", tarfile.CHRTYPE),
               self.entries()[0]]
        for index, member in enumerate(bad):
            with self.subTest(member=member[0], kind=member[2]):
                self.cache = self.root / ("unsafe-" + str(index))
                self.cache.mkdir(mode=0o755)
                self.make_archive(self.entries() + [member])
                with self.assertRaises((bootstrap.BootstrapError, OSError, tarfile.TarError)):
                    self.prepare()
                self.assert_unpublished()
        self.assertFalse((self.root / "escape").exists())

    def test_missing_binary_or_licence_never_publishes(self):
        for index in (0, 1):
            with self.subTest(missing=index):
                self.make_archive(self.entries()[index:index + 1])
                with self.assertRaises(bootstrap.BootstrapError):
                    self.prepare()
                self.assert_unpublished()

    def test_pinned_archive_does_not_replace_binary_or_licence_hash_checks(self):
        for index in (0, 1):
            with self.subTest(changed=index):
                entries = self.entries()
                name, content, kind = entries[index]
                entries[index] = (name, bytes([content[0] ^ 1]) + content[1:], kind)
                self.make_archive(entries)
                with self.assertRaises(bootstrap.BootstrapError):
                    self.prepare()
                self.assert_unpublished()

    def test_wrong_elf_architecture_is_rejected_even_when_hashes_match(self):
        self.binary = elf(183)
        self.spec["binarySha256"] = hashlib.sha256(self.binary).hexdigest()
        self.make_archive()
        with self.assertRaises(bootstrap.BootstrapError):
            self.prepare()
        self.assert_unpublished()

    def test_bounded_entries_and_expansion_include_bytes_after_tar_end(self):
        with mock.patch.object(bootstrap, "MAX_ENTRIES", 1):
            with self.assertRaises(bootstrap.BootstrapError):
                self.prepare()
        self.make_archive(trailing=b"\0" * 40000)
        with mock.patch.object(bootstrap, "MAX_EXPANDED_BYTES", 20000):
            with self.assertRaises(bootstrap.BootstrapError):
                self.prepare()
        self.assert_unpublished()

    def test_gzip_crc_failure_never_publishes(self):
        data = bytearray(self.archive.read_bytes())
        data[-8] ^= 1
        self.archive.write_bytes(data)
        self.pin_input()
        with self.assertRaises((OSError, bootstrap.BootstrapError)):
            self.prepare()
        self.assert_unpublished()

    def test_modified_cache_bytes_permissions_and_inventory_are_not_repaired_or_replaced(self):
        for index, change in enumerate(("content", "permissions", "extra", "receipt", "hardlink", "symlink")):
            with self.subTest(change=change):
                self.cache = self.root / ("tamper-" + str(index))
                self.cache.mkdir(mode=0o755)
                tool = self.prepare()
                if change == "content":
                    tool.chmod(0o755)
                    tool.write_bytes(b"x" * len(self.binary))
                    tool.chmod(0o555)
                elif change == "permissions":
                    tool.chmod(0o5755)
                elif change == "extra":
                    (tool.parent / "unexpected").write_bytes(b"preserve me")
                elif change == "receipt":
                    receipt = tool.parent / "receipt.json"
                    receipt.chmod(0o644)
                    receipt.write_text("{}\n")
                    receipt.chmod(0o444)
                elif change == "hardlink":
                    os.link(tool, self.root / "linked-tool")
                else:
                    tool.rename(self.root / "retained-tool")
                    tool.symlink_to(self.root / "retained-tool")
                before = tool.lstat()
                with self.assertRaises((OSError, bootstrap.BootstrapError)):
                    self.prepare()
                self.assertEqual(tool.lstat().st_ino, before.st_ino)

    def test_equal_byte_cache_replacement_during_hashing_is_rejected(self):
        tool = self.prepare()
        identity = tool.stat().st_ino
        original_read, changed = bootstrap.os.read, False

        def replace(descriptor, size):
            nonlocal changed
            data = original_read(descriptor, size)
            if not changed and os.fstat(descriptor).st_ino == identity:
                changed = True
                tool.rename(self.root / "previous-tool")
                tool.write_bytes(self.binary)
                tool.chmod(0o555)
            return data

        with mock.patch.object(bootstrap.os, "read", side_effect=replace):
            with self.assertRaises(bootstrap.BootstrapError):
                self.prepare()
        self.assertTrue(changed)

    def test_cache_directory_symlink_is_rejected(self):
        tool = self.prepare()
        retained = self.root / "retained-cache"
        tool.parent.rename(retained)
        tool.parent.symlink_to(retained, target_is_directory=True)
        with self.assertRaises(OSError):
            self.prepare()
        self.assertEqual((retained / "gh").read_bytes(), self.binary)

    def test_untrusted_or_noncanonical_cache_ancestry_is_rejected(self):
        for value in (Path("cache"), self.cache / ".." / self.cache.name):
            with self.subTest(value=str(value)):
                with self.assertRaises(ValueError):
                    bootstrap.bootstrap_verifier(self.archive, value)
        self.cache.chmod(0o777)
        with self.assertRaises(ValueError):
            self.prepare()

    def test_parent_replacement_during_extraction_retains_both_namespaces(self):
        original_extract = bootstrap._extract
        retained = self.root / "old-cache"

        def replace(*arguments):
            original_extract(*arguments)
            self.cache.rename(retained)
            self.cache.mkdir(mode=0o755)
            (self.cache / "unrelated").write_bytes(b"keep")

        with mock.patch.object(bootstrap, "_extract", side_effect=replace):
            with self.assertRaises(ValueError):
                self.prepare()
        self.assertEqual((self.cache / "unrelated").read_bytes(), b"keep")
        self.assertTrue(any(path.name.startswith(".verifier-stage-") for path in retained.iterdir()))
        self.assert_unpublished()

    def test_prepared_directory_replacement_is_rejected(self):
        original_extract = bootstrap._extract

        def replace(*arguments):
            original_extract(*arguments)
            stage = next(self.cache.glob(".verifier-stage-*"))
            stage.rename(self.root / "retained-stage")
            stage.mkdir(mode=0o700)

        with mock.patch.object(bootstrap, "_extract", side_effect=replace):
            with self.assertRaises(bootstrap.BootstrapError):
                self.prepare()
        self.assert_unpublished()
        self.assertEqual((self.root / "retained-stage/gh").read_bytes(), self.binary)

    def test_destination_appearing_at_publication_is_not_overwritten(self):
        original_rename = bootstrap._rename_exclusive

        def occupy(parent, source, target):
            path = self.cache / target
            path.mkdir()
            (path / "unrelated").write_bytes(b"keep")
            original_rename(parent, source, target)

        with mock.patch.object(bootstrap, "_rename_exclusive", side_effect=occupy):
            with self.assertRaises(OSError):
                self.prepare()
        candidate = next(self.cache.glob("gh-*"))
        self.assertEqual((candidate / "unrelated").read_bytes(), b"keep")
        self.assertTrue(any(self.cache.glob(".verifier-stage-*")))

    def test_lock_contention_and_unsafe_lock_paths_fail_closed(self):
        lock = self.cache / ".verifier-bootstrap.lock"
        lock.touch(mode=0o600)
        with lock.open("rb") as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                self.prepare()
        for kind in ("nonempty", "permissions", "symlink", "fifo", "hardlink"):
            with self.subTest(kind=kind):
                lock.unlink()
                if kind == "symlink":
                    lock.symlink_to(self.archive)
                elif kind == "fifo":
                    os.mkfifo(lock, 0o600)
                elif kind == "hardlink":
                    os.link(self.archive, lock)
                else:
                    lock.touch(mode=0o644 if kind == "permissions" else 0o600)
                    if kind == "permissions":
                        lock.chmod(0o644)
                    if kind == "nonempty":
                        lock.write_bytes(b"unrelated lock data")
                with self.assertRaises((OSError, bootstrap.BootstrapError)):
                    self.prepare()
                self.assert_unpublished()

    def test_lock_replacement_during_extraction_rejects_publication(self):
        original_extract = bootstrap._extract

        def replace(*arguments):
            original_extract(*arguments)
            self.replace_lock()

        with mock.patch.object(bootstrap, "_extract", side_effect=replace):
            with self.assertRaises(bootstrap.BootstrapError):
                self.prepare()
        self.assert_unpublished()

    def test_lock_replacement_during_cache_reuse_rejects_success(self):
        self.prepare()
        original_check = bootstrap._check_cache

        def replace(*arguments):
            result = original_check(*arguments)
            self.replace_lock()
            return result

        with mock.patch.object(bootstrap, "_check_cache", side_effect=replace):
            with self.assertRaises(bootstrap.BootstrapError):
                self.prepare()

    @unittest.skipUnless(os.geteuid() == 0, "requires a real foreign file owner")
    def test_foreign_cache_file_owner_is_rejected(self):
        tool = self.prepare()
        os.chown(tool, 65534, -1)
        with self.assertRaises(bootstrap.BootstrapError):
            self.prepare()


class VerifierSpecificationTests(unittest.TestCase):
    def test_only_reviewed_linux_architectures_have_download_pins(self):
        for machine, expected in (("x86_64", "amd64"), ("amd64", "amd64"), ("aarch64", "arm64"), ("arm64", "arm64")):
            with self.subTest(machine=machine), mock.patch.object(bootstrap.platform, "system", return_value="Linux"), \
                    mock.patch.object(bootstrap.platform, "machine", return_value=machine):
                spec = bootstrap.verifier_spec()
                self.assertEqual(spec["architecture"], expected)
                self.assertEqual(spec["url"], f"https://github.com/cli/cli/releases/download/v{bootstrap.VERSION}/{spec['filename']}")
                self.assertEqual(spec["binarySha256"], bootstrap.PINS[expected]["binarySha256"])
        for system, machine in (("Darwin", "arm64"), ("Linux", "riscv64"), ("Linux", "i686")):
            with self.subTest(system=system, machine=machine), mock.patch.object(bootstrap.platform, "system", return_value=system), \
                    mock.patch.object(bootstrap.platform, "machine", return_value=machine):
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.verifier_spec()

    def test_print_spec_is_unambiguous_and_does_not_bootstrap(self):
        with mock.patch.object(sys, "argv", ["bootstrap_verifier", "--print-spec"]), \
                mock.patch.object(bootstrap.platform, "system", return_value="Linux"), \
                mock.patch.object(bootstrap.platform, "machine", return_value="x86_64"), \
                mock.patch.object(bootstrap, "bootstrap_verifier") as prepare, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(bootstrap.main(), 0)
            self.assertEqual(json.loads(output.getvalue())["architecture"], "amd64")
            prepare.assert_not_called()
        with mock.patch.object(sys, "argv", ["bootstrap_verifier", "--print-spec", "--archive", "unused"]), \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                bootstrap.main()
            self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
