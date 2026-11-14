import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import unittest
from unittest import mock

import test_build_release as fixtures


spec = importlib.util.spec_from_file_location("stage_release", Path(__file__).resolve().parents[1] / "packaging/stage_release.py")
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


class StageTests(unittest.TestCase):
    def setUp(self):
        fixtures.ReleaseTests.setUp(self)
        self.releases = self.root / "releases"
        self.releases.mkdir(mode=0o755)
        self.package = fixtures.release.build_release(self.source, self.root / "out")
        self.artifact = Path(self.package["artifact"])

    def prepare(self, artifact=None, checksum=None, version=None):
        return stage.stage_release(
            artifact or self.artifact,
            self.releases,
            sha256=checksum or self.package["sha256"],
            version=version or self.package["version"],
        )

    def changed_archive(self, mutate):
        with tarfile.open(self.artifact) as archive:
            entries = [(copy.copy(member), archive.extractfile(member).read() if member.isfile() else None) for member in archive]
        entries = mutate(entries)
        path = self.root / "changed.tar.gz"
        with tarfile.open(path, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
            for member, data in entries:
                if data is not None:
                    member.size = len(data)
                archive.addfile(member, io.BytesIO(data) if data is not None else None)
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def reject_archive(self, mutate):
        artifact, checksum = self.changed_archive(mutate)
        with self.assertRaises((ValueError, OSError, tarfile.TarError, EOFError)):
            self.prepare(artifact, checksum)
        self.assertEqual(list(self.releases.iterdir()), [])

    def test_stages_existing_format_with_readable_permissions_without_activation(self):
        old = self.root / "old"
        old.mkdir()
        current = self.root / "current"
        current.symlink_to(old, target_is_directory=True)
        previous = os.umask(0o077)
        try:
            result = self.prepare()
        finally:
            os.umask(previous)
        self.assertFalse(result["activated"])
        self.assertEqual(result["sha256"], self.package["sha256"])
        self.assertEqual(current.readlink(), old)
        installed = Path(result["directory"])
        manifest = json.loads((installed / "release.json").read_text())
        observed = {f.relative_to(installed).as_posix() for f in installed.rglob("*") if f.is_file()}
        self.assertEqual(observed, set(manifest["files"]) | {"release.json"})
        for name, proof in manifest["files"].items():
            self.assertEqual(hashlib.sha256((installed / name).read_bytes()).hexdigest(), proof["sha256"])
        for path in (installed, *installed.rglob("*")):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o755 if path.is_dir() or path.parent == installed / "bin" else 0o644)
        self.assertEqual([f.name for f in self.releases.iterdir()], [self.package["version"]])

    def test_supports_older_archives_without_explicit_directory_headers(self):
        artifact, checksum = self.changed_archive(lambda entries: [(m, data) for m, data in entries if not m.isdir()])
        result = self.prepare(artifact, checksum)
        self.assertEqual(stat.S_IMODE((Path(result["directory"]) / "src/orbis_sentinel").stat().st_mode), 0o755)

    def test_requires_the_independently_approved_checksum(self):
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.prepare(checksum="0" * 64)
        self.assertEqual(list(self.releases.iterdir()), [])

    def test_rejects_mismatched_component_version(self):
        with self.assertRaisesRegex(ValueError, "identity"):
            self.prepare(version="0.1.0-dev.11")
        self.assertEqual(list(self.releases.iterdir()), [])

    def test_rejects_archive_source_symlink(self):
        linked = self.root / "linked.tar.gz"
        linked.symlink_to(self.artifact)
        with self.assertRaises(OSError):
            self.prepare(linked)
        self.assertEqual(list(self.releases.iterdir()), [])

    def test_rejects_source_path_replaced_during_the_snapshot(self):
        original = stage.os.read
        identity = self.artifact.stat().st_ino
        replaced = False

        def read(descriptor, size):
            nonlocal replaced
            data = original(descriptor, size)
            if not replaced and os.fstat(descriptor).st_ino == identity:
                replaced = True
                self.artifact.unlink()
                self.artifact.write_bytes(b"replacement must survive")
            return data

        with mock.patch.object(stage.os, "read", read), self.assertRaisesRegex(ValueError, "changed"):
            self.prepare()
        self.assertEqual(self.artifact.read_bytes(), b"replacement must survive")
        self.assertEqual(list(self.releases.iterdir()), [])

    def test_existing_version_and_current_are_not_overwritten(self):
        first = self.prepare()
        marker = Path(first["directory"]) / "marker"
        marker.write_text("keep")
        with self.assertRaises(FileExistsError):
            self.prepare()
        self.assertEqual(marker.read_text(), "keep")

    def test_no_replace_publication_preserves_a_concurrent_destination(self):
        original = stage._rename_exclusive

        def publish(parent, source, target):
            destination = self.releases / target
            destination.mkdir()
            (destination / "foreign").write_text("keep")
            return original(parent, source, target)

        with mock.patch.object(stage, "_rename_exclusive", publish), self.assertRaises(FileExistsError):
            self.prepare()
        self.assertEqual((self.releases / self.package["version"] / "foreign").read_text(), "keep")
        self.assertFalse(list(self.releases.glob(".stage-*")))

    def test_no_replace_publication_refuses_even_an_empty_concurrent_directory(self):
        original = stage._rename_exclusive

        def publish(parent, source, target):
            (self.releases / target).mkdir()
            return original(parent, source, target)

        with mock.patch.object(stage, "_rename_exclusive", publish), self.assertRaises(FileExistsError):
            self.prepare()
        self.assertEqual(list((self.releases / self.package["version"]).iterdir()), [])

    def test_parent_replacement_never_publishes_into_or_deletes_the_replacement(self):
        original = stage._rename_exclusive
        moved = self.root / "moved"

        def publish(parent, source, target):
            self.releases.rename(moved)
            self.releases.mkdir()
            (self.releases / "foreign").write_text("keep")
            return original(parent, source, target)

        with mock.patch.object(stage, "_rename_exclusive", publish), self.assertRaisesRegex(ValueError, "parent changed"):
            self.prepare()
        self.assertEqual([f.name for f in self.releases.iterdir()], ["foreign"])
        self.assertTrue((moved / self.package["version"] / "release.json").is_file())

    def test_refuses_writable_or_linked_release_parent(self):
        self.releases.chmod(0o777)
        with self.assertRaisesRegex(ValueError, "permissions"):
            self.prepare()
        self.releases.chmod(0o755)
        link = self.root / "link"
        link.symlink_to(self.releases, target_is_directory=True)
        with self.assertRaises(OSError):
            stage.stage_release(self.artifact, link, sha256=self.package["sha256"], version=self.package["version"])

    def test_partial_write_failure_removes_only_its_prepared_tree(self):
        unrelated = self.releases / "unrelated"
        unrelated.mkdir()
        (unrelated / "marker").write_text("keep")
        original = stage._write_file
        count = 0

        def write(*arguments):
            nonlocal count
            count += 1
            original(*arguments)
            if count == 2:
                raise OSError("injected write failure")

        with mock.patch.object(stage, "_write_file", write), self.assertRaisesRegex(OSError, "injected"):
            self.prepare()
        self.assertEqual([f.name for f in self.releases.iterdir()], ["unrelated"])
        self.assertEqual((unrelated / "marker").read_text(), "keep")

    def test_payload_changes_cannot_be_hidden_by_a_new_outer_checksum(self):
        self.reject_archive(lambda entries: [(m, b"changed" if m.name == "LICENSE" else data) for m, data in entries])

    def test_rejects_unlisted_payload(self):
        def mutate(entries):
            member = tarfile.TarInfo("web/extra.js")
            member.mode = 0o644
            return entries + [(member, b"unexpected")]
        self.reject_archive(mutate)

    def test_rejects_duplicate_payload(self):
        self.reject_archive(lambda entries: entries + [next((m, data) for m, data in entries if m.name == "LICENSE")])

    def test_rejects_traversal_links_devices_and_private_files(self):
        for name, kind in [("../outside", tarfile.REGTYPE), ("/outside", tarfile.REGTYPE), ("web/linked.js", tarfile.SYMTYPE), ("web/hard.js", tarfile.LNKTYPE), ("web/device.js", tarfile.CHRTYPE), ("web/.env.json", tarfile.REGTYPE)]:
            with self.subTest(name=name):
                def mutate(entries):
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    member.mode = 0o644
                    member.linkname = "../../outside" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
                    return entries + [(member, b"" if kind == tarfile.REGTYPE else None)]
                self.reject_archive(mutate)

    def test_rejects_unsafe_payload_permissions(self):
        def mutate(entries):
            for member, _ in entries:
                if member.name == "LICENSE":
                    member.mode = 0o666
            return entries
        self.reject_archive(mutate)

    def test_manifest_duplicate_keys_are_rejected(self):
        def mutate(entries):
            return [(m, data.replace(b'"format":1', b'"format":1,"format":1') if m.name == "release.json" else data) for m, data in entries]
        self.reject_archive(mutate)

    def test_declared_component_and_initializer_must_agree(self):
        def mutate(entries):
            result = []
            for member, data in entries:
                if member.name == "release.json":
                    value = json.loads(data)
                    value["version"] = "0.1.0-dev.11"
                    data = json.dumps(value).encode()
                result.append((member, data))
            return result
        artifact, checksum = self.changed_archive(mutate)
        with self.assertRaisesRegex(ValueError, "version"):
            self.prepare(artifact, checksum, version="0.1.0-dev.11")

    def test_payload_and_expansion_bounds_are_enforced(self):
        for name, bound in [("MAX_ARCHIVE_BYTES", 1), ("MAX_FILE_BYTES", 1), ("MAX_TOTAL_BYTES", 1), ("MAX_ENTRIES", 1), ("MAX_EXPANDED_BYTES", 512)]:
            with self.subTest(name=name), mock.patch.object(stage, name, bound), self.assertRaises(ValueError):
                self.prepare()
            self.assertEqual(list(self.releases.iterdir()), [])

    def test_source_changes_after_snapshot_do_not_change_the_staged_payload(self):
        original = stage._scan
        count = 0

        def scan(*arguments):
            nonlocal count
            result = original(*arguments)
            count += 1
            if count == 1:
                self.artifact.write_bytes(b"different source after snapshot")
            return result

        with mock.patch.object(stage, "_scan", scan):
            result = self.prepare()
        self.assertEqual((Path(result["directory"]) / "LICENSE").read_text(), "license\n")
        self.assertEqual(result["sha256"], self.package["sha256"])

    def test_rejects_hidden_trailing_archive_content(self):
        path = self.root / "trailing.tar.gz"
        path.write_bytes(gzip.compress(gzip.decompress(self.artifact.read_bytes()) + b"hidden content"))
        with self.assertRaisesRegex(ValueError, "trailing"):
            self.prepare(path, hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(list(self.releases.iterdir()), [])

    def test_zero_padding_cannot_bypass_the_expansion_bound(self):
        path = self.root / "padding.tar.gz"
        path.write_bytes(gzip.compress(gzip.decompress(self.artifact.read_bytes()) + bytes(128 * 1024)))
        with mock.patch.object(stage, "MAX_EXPANDED_BYTES", 64 * 1024), self.assertRaisesRegex(ValueError, "Expanded"):
            self.prepare(path, hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(list(self.releases.iterdir()), [])

    def test_missing_manifest_member_is_rejected(self):
        self.reject_archive(lambda entries: [(m, data) for m, data in entries if m.name != "LICENSE"])

    def test_manifest_types_and_component_contract_are_strict(self):
        for field in ["format", "component", "python", "bytes", "sha256"]:
            with self.subTest(field=field):
                def mutate(entries):
                    result = []
                    for member, data in entries:
                        if member.name == "release.json":
                            value = json.loads(data)
                            if field == "format":
                                value[field] = True
                            elif field == "component":
                                value[field] = "other-component"
                            elif field == "python":
                                value[field] = ">=3.12"
                            elif field == "bytes":
                                value["files"]["LICENSE"][field] = True
                            else:
                                value["files"]["LICENSE"][field] = "X" * 64
                            data = json.dumps(value).encode()
                        result.append((member, data))
                    return result
                self.reject_archive(mutate)

    def test_an_existing_version_symlink_is_not_followed(self):
        foreign = self.root / "foreign"
        foreign.mkdir()
        (foreign / "marker").write_text("keep")
        target = self.releases / self.package["version"]
        target.symlink_to(foreign, target_is_directory=True)
        with self.assertRaises(FileExistsError):
            self.prepare()
        self.assertEqual(target.readlink(), foreign)
        self.assertEqual((foreign / "marker").read_text(), "keep")

    def test_parent_permission_change_before_publication_is_rejected(self):
        original = stage._write_file

        def write(*arguments):
            original(*arguments)
            self.releases.chmod(0o777)

        try:
            with mock.patch.object(stage, "_write_file", write), self.assertRaisesRegex(ValueError, "permissions changed"):
                self.prepare()
        finally:
            self.releases.chmod(0o755)
        self.assertEqual(list(self.releases.iterdir()), [])

    def test_a_replaced_prepared_directory_is_not_removed_as_cleanup(self):
        original = stage.os.open
        replaced = False

        def opened(name, flags, *arguments, **keywords):
            nonlocal replaced
            if isinstance(name, str) and name.startswith(".stage-") and not replaced:
                replaced = True
                root = keywords["dir_fd"]
                os.rename(name, "held", src_dir_fd=root, dst_dir_fd=root)
                os.mkdir(name, dir_fd=root)
                (self.releases / name / "foreign").write_text("keep")
            return original(name, flags, *arguments, **keywords)

        with mock.patch.object(stage.os, "open", opened), self.assertRaisesRegex(ValueError, "changed"):
            self.prepare()
        replacement = next(self.releases.glob(".stage-*"))
        self.assertEqual((replacement / "foreign").read_text(), "keep")
        self.assertEqual(list((self.releases / "held").iterdir()), [])

    def test_actual_written_bytes_are_rechecked_before_publication(self):
        original = stage._write_file

        def write(root, name, data, mode):
            original(root, name, data, mode)
            if name == "LICENSE":
                descriptor = os.open("LICENSE", os.O_WRONLY, dir_fd=root)
                try:
                    os.write(descriptor, b"tampered")
                finally:
                    os.close(descriptor)

        with mock.patch.object(stage, "_write_file", write), self.assertRaisesRegex(ValueError, "verified release"):
            self.prepare()
        self.assertFalse((self.releases / self.package["version"]).exists())
        prepared = next(self.releases.glob(".stage-*"))
        self.assertEqual(stat.S_IMODE(prepared.stat().st_mode), 0o700)

    def test_unexpected_prepared_files_are_preserved_for_review(self):
        original = stage._write_file

        def write(root, name, data, mode):
            original(root, name, data, mode)
            if name == "LICENSE":
                descriptor = os.open("foreign", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=root)
                os.write(descriptor, b"keep")
                os.close(descriptor)

        with mock.patch.object(stage, "_write_file", write), self.assertRaisesRegex(ValueError, "inventory changed"):
            self.prepare()
        self.assertEqual((next(self.releases.glob(".stage-*")) / "foreign").read_text(), "keep")
        self.assertFalse((self.releases / self.package["version"]).exists())

    def test_source_name_replaced_at_publication_cannot_receive_a_success_receipt(self):
        original = stage._rename_exclusive

        def publish(parent, source, target):
            os.rename(source, "held-own", src_dir_fd=parent, dst_dir_fd=parent)
            os.mkdir(source, dir_fd=parent)
            (self.releases / source / "foreign").write_text("keep")
            return original(parent, source, target)

        with mock.patch.object(stage, "_rename_exclusive", publish), self.assertRaisesRegex(ValueError, "Published directory changed"):
            self.prepare()
        self.assertEqual((self.releases / self.package["version"] / "foreign").read_text(), "keep")
        self.assertTrue((self.releases / "held-own/release.json").is_file())


if __name__ == "__main__":
    unittest.main()
