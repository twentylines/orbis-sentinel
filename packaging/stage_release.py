"""Verify a pinned Sentinel archive and stage it without activating a service."""

from __future__ import annotations

import argparse
import ast
import ctypes
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import uuid


MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_BYTES = 72 * 1024 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
MAX_FILES = 512
MAX_ENTRIES = 8192
MAX_EXPANDED_BYTES = MAX_TOTAL_BYTES + MAX_ENTRIES * 512 + MAX_MANIFEST_BYTES + 10240
ENTRYPOINTS = ("orbis-sentinel", "orbis-sentinel-capture", "orbis-sentinel-verify")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?")
SHA256 = re.compile(r"[a-f0-9]{64}")
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


class StageError(ValueError):
    pass


def _identity(value):
    return value.st_dev, value.st_ino


class _Parent:
    def __init__(self, path: Path):
        if not path.is_absolute() or Path(os.path.abspath(path)) != path:
            raise StageError("Release parent must be an absolute canonical path")
        self.path = path
        self.handles = [os.open("/", DIRECTORY_FLAGS)]
        try:
            for part in path.parts[1:]:
                descriptor = os.open(part, DIRECTORY_FLAGS, dir_fd=self.handles[-1])
                self.handles.append(descriptor)
            for descriptor in self.handles:
                value = os.fstat(descriptor)
                if value.st_uid not in (0, os.geteuid()) or value.st_mode & 0o022:
                    raise StageError("Release parent has an untrusted owner or permissions")
            self.assert_current()
        except BaseException:
            self.close()
            raise

    @property
    def fd(self):
        return self.handles[-1]

    def assert_current(self):
        for descriptor in self.handles:
            value = os.fstat(descriptor)
            if value.st_uid not in (0, os.geteuid()) or value.st_mode & 0o022:
                raise StageError("Release parent permissions changed during staging")
        for parent, child, name in zip(self.handles, self.handles[1:], self.path.parts[1:]):
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISDIR(current.st_mode) or _identity(current) != _identity(os.fstat(child)):
                raise StageError("Release parent changed during staging")

    def close(self):
        for descriptor in reversed(self.handles):
            os.close(descriptor)
        self.handles.clear()


def _rename_exclusive(parent: int, source: str, target: str):
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "linux":
        function, flag = getattr(library, "renameat2", None), 1
    elif sys.platform == "darwin":
        function, flag = getattr(library, "renameatx_np", None), 4
    else:
        function, flag = None, 0
    if function is None:
        raise StageError("Atomic no-replace directory publication is unavailable")
    function.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    function.restype = ctypes.c_int
    if function(parent, os.fsencode(source), parent, os.fsencode(target), flag) != 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number))


def _remove_directory(parent: int, name: str, expected):
    descriptor = os.open(name, DIRECTORY_FLAGS, dir_fd=parent)
    try:
        if _identity(os.fstat(descriptor)) != expected:
            raise StageError("Prepared directory changed; retained for review")
        for child in os.listdir(descriptor):
            value = os.stat(child, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISDIR(value.st_mode):
                _remove_directory(descriptor, child, _identity(value))
            else:
                os.unlink(child, dir_fd=descriptor)
        if _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != expected:
            raise StageError("Prepared directory changed; retained for review")
        os.rmdir(name, dir_fd=parent)
    finally:
        os.close(descriptor)


def _snapshot_archive(path: Path, output, expected_sha256: str):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_ARCHIVE_BYTES:
            raise StageError("Archive must be a bounded regular file")
        digest = hashlib.sha256()
        copied = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            copied += len(chunk)
            if copied > MAX_ARCHIVE_BYTES:
                raise StageError("Archive exceeds its size bound")
            output.write(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
        current = os.stat(path, follow_symlinks=False)
        identity = lambda value: (_identity(value), value.st_size, value.st_mtime_ns)
        if identity(before) != identity(after) or identity(after) != identity(current) or copied != before.st_size:
            raise StageError("Archive changed while reading")
        if digest.hexdigest() != expected_sha256:
            raise StageError("Archive checksum does not match the approved checksum")
        output.flush()
        output.seek(0)
    finally:
        os.close(descriptor)


def _name(value: str):
    if not isinstance(value, str) or len(value.encode("utf-8")) > 256 or "\\" in value:
        raise StageError("Invalid archive path")
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or parsed.as_posix() != value or any(part in (".", "..") or part.startswith(".") for part in parsed.parts):
        raise StageError("Invalid archive path")
    if not parsed.parts or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise StageError("Invalid archive path")
    return parsed


def _allowed_file(name: str):
    value = _name(name)
    if ".env." in value.name or value.name.endswith(".env") or "__pycache__" in value.parts:
        return False
    if name in ("LICENSE", "release.json") or name in (f"bin/{entry}" for entry in ENTRYPOINTS):
        return True
    roots = {
        "src/orbis_sentinel/": {".py"},
        "web/": {".html", ".css", ".js", ".json", ".svg", ".png", ".jpg", ".webp", ".woff2", ".ico"},
        "packaging/systemd/": {".service", ".socket", ".conf"},
        "packaging/sysusers.d/": {".conf"},
    }
    return any(name.startswith(root) and value.suffix in suffixes for root, suffixes in roots.items())


class _BoundedReader:
    def __init__(self, source):
        self.source = source
        self.count = 0

    def read(self, size=-1):
        remaining = MAX_EXPANDED_BYTES - self.count
        result = self.source.read(min(size if size >= 0 else remaining + 1, remaining + 1))
        self.count += len(result)
        if self.count > MAX_EXPANDED_BYTES:
            raise StageError("Expanded archive exceeds its size bound")
        return result


def _pairs(entries):
    result = {}
    for name, value in entries:
        if name in result:
            raise StageError("Manifest contains duplicate keys")
        result[name] = value
    return result


def _scan(snapshot, sink=None):
    snapshot.seek(0)
    files, directories, seen = {}, set(), set()
    manifest, initializer = None, None
    total = 0
    with gzip.GzipFile(fileobj=snapshot, mode="rb") as compressed:
        with tarfile.open(fileobj=_BoundedReader(compressed), mode="r|") as archive:
            for entry in archive:
                name = entry.name
                _name(name)
                if name in seen or len(seen) >= MAX_ENTRIES:
                    raise StageError("Archive contains duplicate or excessive entries")
                seen.add(name)
                if entry.pax_headers or entry.uid != 0 or entry.gid != 0 or entry.mtime != 0:
                    raise StageError("Archive metadata does not match the release format")
                if entry.type == tarfile.DIRTYPE:
                    if entry.mode != 0o755 or entry.size != 0:
                        raise StageError("Invalid release directory")
                    directories.add(name)
                    continue
                if entry.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or not _allowed_file(name):
                    raise StageError("Archive contains an unsupported entry")
                limit = MAX_MANIFEST_BYTES if name == "release.json" else MAX_FILE_BYTES
                if entry.mode != (0o755 if name.startswith("bin/") else 0o644) or entry.size < 0 or entry.size > limit:
                    raise StageError("Invalid release file size or permissions")
                total += entry.size
                if total > MAX_TOTAL_BYTES + MAX_MANIFEST_BYTES or len(files) >= MAX_FILES + 1:
                    raise StageError("Release exceeds its payload bounds")
                data = archive.extractfile(entry).read(entry.size + 1)
                if len(data) != entry.size:
                    raise StageError("Release file is truncated")
                files[name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                if name == "release.json":
                    manifest = json.loads(data, object_pairs_hook=_pairs)
                if name == "src/orbis_sentinel/__init__.py":
                    if len(data) > 64 * 1024:
                        raise StageError("Version declaration exceeds its size bound")
                    initializer = data
                if sink:
                    sink(name, data, entry.mode)
            tail = 0
            while chunk := archive.fileobj.read(1024 * 1024):
                tail += len(chunk)
                if any(chunk):
                    raise StageError("Archive has unexpected trailing content")
            if tail < 512:
                raise StageError("Archive terminator is incomplete")
    parents = {parent.as_posix() for name in files for parent in PurePosixPath(name).parents if parent != PurePosixPath(".")}
    if not directories.issubset(parents):
        raise StageError("Archive contains an unused directory")
    return files, manifest, initializer


def _manifest(files, value, initializer, version):
    if not isinstance(value, dict) or set(value) != {"format", "component", "version", "python", "files"}:
        raise StageError("Invalid release manifest")
    if type(value["format"]) is not int or value["format"] != 1 or value["component"] != "orbis-sentinel" or value["python"] != ">=3.10" or value["version"] != version:
        raise StageError("Release identity does not match the approved component")
    declared = value["files"]
    if not isinstance(declared, dict) or not 0 < len(declared) <= MAX_FILES or "release.json" in declared:
        raise StageError("Invalid manifest inventory")
    for name, record in declared.items():
        if not _allowed_file(name) or not isinstance(record, dict) or set(record) != {"bytes", "sha256"}:
            raise StageError("Invalid manifest entry")
        if type(record["bytes"]) is not int or not 0 <= record["bytes"] <= MAX_FILE_BYTES or not isinstance(record["sha256"], str) or not SHA256.fullmatch(record["sha256"]):
            raise StageError("Invalid manifest entry")
    observed = {name: record for name, record in files.items() if name != "release.json"}
    if declared != observed or sum(record["bytes"] for record in declared.values()) > MAX_TOTAL_BYTES:
        raise StageError("Manifest does not match the complete payload")
    required = {"LICENSE", "src/orbis_sentinel/__init__.py", "packaging/systemd/orbis-sentinel.service", "packaging/systemd/orbis-sentinel.socket", *(f"bin/{name}" for name in ENTRYPOINTS)}
    if not required.issubset(declared) or initializer is None:
        raise StageError("Release is missing required files")
    versions = [node.value.value for node in ast.parse(initializer).body if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)]
    if versions != [version]:
        raise StageError("Payload version does not match the manifest")


def _write_file(root: int, name: str, data: bytes, mode: int):
    directories = []
    parent = root
    try:
        for part in PurePosixPath(name).parts[:-1]:
            try:
                os.mkdir(part, 0o755, dir_fd=parent)
            except FileExistsError:
                pass
            descriptor = os.open(part, DIRECTORY_FLAGS, dir_fd=parent)
            directories.append(descriptor)
            os.fchmod(descriptor, 0o755)
            parent = descriptor
        descriptor = os.open(PurePosixPath(name).name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fchmod(output.fileno(), mode)
            os.fsync(output.fileno())
        for descriptor in reversed(directories):
            os.fsync(descriptor)
    finally:
        for descriptor in reversed(directories):
            os.close(descriptor)


def _verify_tree(root: int, expected):
    observed, directories = {}, set()
    owner = os.fstat(root)
    if owner.st_uid != os.geteuid() or stat.S_IMODE(owner.st_mode) != 0o700:
        raise StageError("Prepared tree ownership or permissions changed")

    def visit(parent, prefix=""):
        for child in os.listdir(parent):
            name = f"{prefix}/{child}" if prefix else child
            _name(name)
            value = os.stat(child, dir_fd=parent, follow_symlinks=False)
            if value.st_uid != os.geteuid():
                raise StageError("Prepared tree ownership changed")
            if stat.S_ISDIR(value.st_mode):
                if stat.S_IMODE(value.st_mode) != 0o755:
                    raise StageError("Prepared directory permissions changed")
                descriptor = os.open(child, DIRECTORY_FLAGS, dir_fd=parent)
                try:
                    if _identity(os.fstat(descriptor)) != _identity(value):
                        raise StageError("Prepared directory identity changed")
                    directories.add(name)
                    visit(descriptor, name)
                    if _identity(os.stat(child, dir_fd=parent, follow_symlinks=False)) != _identity(value):
                        raise StageError("Prepared directory identity changed")
                finally:
                    os.close(descriptor)
            else:
                if name not in expected or not stat.S_ISREG(value.st_mode) or value.st_nlink != 1 or value.st_size != expected[name]["bytes"]:
                    raise StageError("Prepared file inventory changed")
                if stat.S_IMODE(value.st_mode) != (0o755 if name.startswith("bin/") else 0o644):
                    raise StageError("Prepared file permissions changed")
                descriptor = os.open(child, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    identity = lambda item: (_identity(item), item.st_mode, item.st_uid, item.st_gid, item.st_size, item.st_mtime_ns, item.st_nlink)
                    if identity(os.fstat(descriptor)) != identity(value):
                        raise StageError("Prepared file identity changed")
                    digest = hashlib.sha256()
                    read = 0
                    while chunk := os.read(descriptor, 1024 * 1024):
                        read += len(chunk)
                        if read > MAX_FILE_BYTES:
                            raise StageError("Prepared file exceeds its size bound")
                        digest.update(chunk)
                    if identity(os.fstat(descriptor)) != identity(value) or identity(os.stat(child, dir_fd=parent, follow_symlinks=False)) != identity(value):
                        raise StageError("Prepared file identity changed")
                    observed[name] = {"bytes": read, "sha256": digest.hexdigest()}
                finally:
                    os.close(descriptor)

    visit(root)
    parents = {parent.as_posix() for name in expected for parent in PurePosixPath(name).parents if parent != PurePosixPath(".")}
    if observed != expected or directories != parents:
        raise StageError("Prepared tree does not match the verified release")


def stage_release(artifact: Path, releases: Path, *, sha256: str, version: str):
    if not isinstance(sha256, str) or not SHA256.fullmatch(sha256) or not isinstance(version, str) or not VERSION.fullmatch(version):
        raise StageError("An approved checksum and component version are required")
    parent = _Parent(releases)
    temporary = f".stage-{uuid.uuid4().hex}"
    descriptor, identity, published, cleanup_safe = None, None, False, True
    try:
        try:
            os.stat(version, dir_fd=parent.fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError("This release version already exists")
        os.mkdir(temporary, 0o700, dir_fd=parent.fd)
        identity = _identity(os.stat(temporary, dir_fd=parent.fd, follow_symlinks=False))
        descriptor = os.open(temporary, DIRECTORY_FLAGS, dir_fd=parent.fd)
        if _identity(os.fstat(descriptor)) != identity:
            raise StageError("Prepared directory changed during creation")
        snapshot = os.open(".archive", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=descriptor)
        os.unlink(".archive", dir_fd=descriptor)
        with os.fdopen(snapshot, "w+b") as frozen:
            # Parsing and extraction use this anonymous snapshot, never a reopened source path.
            _snapshot_archive(artifact, frozen, sha256)
            first = _scan(frozen)
            _manifest(*first, version)
            second = _scan(frozen, lambda name, data, mode: _write_file(descriptor, name, data, mode))
            if first != second:
                raise StageError("Frozen release changed during staging")
        cleanup_safe = False
        _verify_tree(descriptor, first[0])
        cleanup_safe = True
        os.fchmod(descriptor, 0o755)
        os.fsync(descriptor)
        parent.assert_current()
        if _identity(os.stat(temporary, dir_fd=parent.fd, follow_symlinks=False)) != identity:
            raise StageError("Prepared directory changed before publication")
        _rename_exclusive(parent.fd, temporary, version)
        published = True
        os.fsync(parent.fd)
        final = os.stat(version, dir_fd=parent.fd, follow_symlinks=False)
        if not stat.S_ISDIR(final.st_mode) or _identity(final) != identity or final.st_uid != os.geteuid() or stat.S_IMODE(final.st_mode) != 0o755:
            raise StageError("Published directory changed; retained for review")
        parent.assert_current()
        return {"component": "orbis-sentinel", "version": version, "sha256": sha256, "directory": str(releases / version), "files": len(first[1]["files"]), "activated": False}
    finally:
        try:
            if descriptor is not None:
                os.close(descriptor)
            if identity is not None and not published and cleanup_safe:
                _remove_directory(parent.fd, temporary, identity)
        finally:
            parent.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--releases", type=Path, required=True)
    parser.add_argument("--sha256", required=True, help="Checksum supplied by already-approved release metadata")
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    try:
        result = stage_release(args.artifact, args.releases, sha256=args.sha256, version=args.version)
    except (ValueError, OSError, tarfile.TarError, EOFError):
        parser.exit(1, "Release staging failed; the running service was not changed.\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
