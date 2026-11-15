"""Prepare a pinned official GitHub CLI archive for Sentinel publisher verification."""

from __future__ import annotations

import argparse
import fcntl
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import stat
import tarfile
import uuid

from stage_release import _Parent, _rename_exclusive, DIRECTORY_FLAGS


VERSION = "2.103.3"
LICENSE_SHA256 = "6da4adc42392c8485e40b4251c7e332fc3352df1947c9ffade71dd60b14a7a4f"
PINS = {
    "amd64": {"archiveBytes": 15031972,
              "archiveSha256": "4c806978ffce1cec70853302a56d70ac6da4f19bae7adca4e1a8ab00633dd91d",
              "binaryBytes": 41070752,
              "binarySha256": "b768184570b12536be4ac1528893f6340d1c6a7b40b56ad45bca9cd0e87ad34d",
              "elfMachine": 62},
    "arm64": {"archiveBytes": 13661485,
              "archiveSha256": "ee32df2323c8847f5fac6cb6b4b69ca75828e9329a8f22f677021f7b3306ce63",
              "binaryBytes": 38142112,
              "binarySha256": "a82a52e1bbe05bcd485f8cbbd5aa67e11a76fce6bdad394a2d179e1c24cfe367",
              "elfMachine": 183},
}
MAX_EXPANDED_BYTES = 128 * 1024 * 1024
MAX_ENTRIES = 2048
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class BootstrapError(ValueError):
    pass


def verifier_spec():
    if platform.system() != "Linux":
        raise BootstrapError("Verifier archive bootstrap supports Linux hosts only")
    architecture = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine().lower())
    if architecture not in PINS:
        raise BootstrapError("No pinned verifier archive is available for this architecture")
    filename = f"gh_{VERSION}_linux_{architecture}.tar.gz"
    return {**PINS[architecture], "version": VERSION, "architecture": architecture,
            "filename": filename, "prefix": filename.removesuffix(".tar.gz"),
            "url": f"https://github.com/cli/cli/releases/download/v{VERSION}/{filename}",
            "licenseBytes": 1068, "licenseSha256": LICENSE_SHA256}


def _seal(value):
    return (value.st_dev, value.st_ino, value.st_uid, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _receipt(spec):
    return (json.dumps({"format": 1, "component": "github-cli", "version": spec["version"],
                        "architecture": spec["architecture"], "archiveSha256": spec["archiveSha256"],
                        "binarySha256": spec["binarySha256"], "licenseSha256": spec["licenseSha256"]},
                       sort_keys=True, separators=(",", ":")) + "\n").encode()


def _check_lock(parent, descriptor, identity):
    current = os.fstat(descriptor)
    if (_seal(current) != identity or current.st_size != 0 or
            _seal(os.stat(".verifier-bootstrap.lock", dir_fd=parent.fd, follow_symlinks=False)) != identity):
        raise BootstrapError("Verifier bootstrap lock changed")
    parent.assert_current()


def _elf(prefix, spec):
    if (len(prefix) < 20 or prefix[:7] != b"\x7fELF\x02\x01\x01" or
            int.from_bytes(prefix[18:20], "little") != spec["elfMachine"]):
        raise BootstrapError("Pinned verifier does not match the host architecture")


def _check_cache(parent, name, spec):
    descriptor = os.open(name, DIRECTORY_FLAGS, dir_fd=parent.fd)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISDIR(before.st_mode) or before.st_uid != os.geteuid() or
                stat.S_IMODE(before.st_mode) != 0o755 or set(os.listdir(descriptor)) != {"gh", "LICENSE", "receipt.json"}):
            raise BootstrapError("Verifier cache inventory or ownership changed")
        receipt = _receipt(spec)
        expected = {"gh": (spec["binaryBytes"], spec["binarySha256"], 0o555),
                    "LICENSE": (spec["licenseBytes"], spec["licenseSha256"], 0o444),
                    "receipt.json": (len(receipt), hashlib.sha256(receipt).hexdigest(), 0o444)}
        seals = {}
        for filename, (size, checksum, mode) in expected.items():
            source = os.open(filename, FILE_FLAGS, dir_fd=descriptor)
            try:
                info = os.fstat(source)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or
                        info.st_size != size or stat.S_IMODE(info.st_mode) != mode):
                    raise BootstrapError("Verifier cache file ownership or permissions changed")
                digest, total, prefix = hashlib.sha256(), 0, b""
                while chunk := os.read(source, 65536):
                    total += len(chunk)
                    if total > size:
                        raise BootstrapError("Verifier cache file exceeds its pinned size")
                    prefix = (prefix + chunk)[:20]
                    digest.update(chunk)
                if total != size or digest.hexdigest() != checksum or _seal(info) != _seal(os.fstat(source)):
                    raise BootstrapError("Verifier cache does not match the pinned release")
                if filename == "gh":
                    _elf(prefix, spec)
                seals[filename] = _seal(info)
            finally:
                os.close(source)
        for filename, identity in seals.items():
            if _seal(os.stat(filename, dir_fd=descriptor, follow_symlinks=False)) != identity:
                raise BootstrapError("Verifier cache changed while being checked")
        if (_seal(os.fstat(descriptor)) != _seal(before) or
                _seal(os.stat(name, dir_fd=parent.fd, follow_symlinks=False)) != _seal(before)):
            raise BootstrapError("Verifier cache directory changed while being checked")
        parent.assert_current()
        return parent.path / name / "gh"
    finally:
        os.close(descriptor)


def _snapshot(source, output, spec):
    descriptor = os.open(source, FILE_FLAGS)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != spec["archiveBytes"]:
            raise BootstrapError("Verifier input must be the bounded standalone pinned archive")
        digest, total = hashlib.sha256(), 0
        while chunk := os.read(descriptor, 65536):
            total += len(chunk)
            if total > spec["archiveBytes"]:
                raise BootstrapError("Verifier archive exceeds its pinned size")
            output.write(chunk)
            digest.update(chunk)
        if (total != before.st_size or digest.hexdigest() != spec["archiveSha256"] or
                _seal(before) != _seal(os.fstat(descriptor)) or
                _seal(before) != _seal(os.stat(source, follow_symlinks=False))):
            raise BootstrapError("Verifier archive changed or failed its pinned checksum")
        output.flush()
        output.seek(0)
    finally:
        os.close(descriptor)


class _LimitedReader:
    def __init__(self, source):
        self.source, self.count = source, 0

    def read(self, size=-1):
        remaining = MAX_EXPANDED_BYTES - self.count
        result = self.source.read(min(size if size >= 0 else remaining + 1, remaining + 1))
        self.count += len(result)
        if self.count > MAX_EXPANDED_BYTES:
            raise BootstrapError("Verifier archive expands beyond its limit")
        return result


def _write_file(parent, name, source, size, checksum, mode):
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    digest, total, prefix = hashlib.sha256(), 0, b""
    with os.fdopen(descriptor, "wb") as output:
        while chunk := source.read(65536):
            total += len(chunk)
            if total > size:
                raise BootstrapError("Verifier payload exceeds its pinned size")
            prefix = (prefix + chunk)[:20]
            output.write(chunk)
            digest.update(chunk)
        if total != size or digest.hexdigest() != checksum:
            raise BootstrapError("Verifier payload does not match the reviewed bytes")
        output.flush()
        os.fchmod(output.fileno(), mode)
        os.fsync(output.fileno())
    return prefix


def _extract(snapshot, output, spec):
    required = {spec["prefix"] + "/bin/gh": ("gh", spec["binaryBytes"], spec["binarySha256"], 0o555),
                spec["prefix"] + "/LICENSE": ("LICENSE", spec["licenseBytes"], spec["licenseSha256"], 0o444)}
    seen, extracted, total = set(), set(), 0
    with gzip.GzipFile(fileobj=snapshot, mode="rb") as compressed:
        limited = _LimitedReader(compressed)
        with tarfile.open(fileobj=limited, mode="r|") as archive:
            for member in archive:
                name = member.name.removesuffix("/") if member.isdir() else member.name
                path = PurePosixPath(name)
                if (len(seen) >= MAX_ENTRIES or name in seen or len(name.encode()) > 512 or
                        "\\" in name or path.is_absolute() or path.as_posix() != name or
                        any(part in (".", "..") for part in path.parts) or not path.parts or
                        path.parts[0] != spec["prefix"] or any(ord(char) < 32 or ord(char) == 127 for char in name) or
                        not (member.isfile() or member.isdir())):
                    raise BootstrapError("Verifier archive contains an unsafe or duplicate entry")
                seen.add(name)
                total += member.size
                if member.size < 0 or total > MAX_EXPANDED_BYTES:
                    raise BootstrapError("Verifier archive exceeds its payload limit")
                if name in required:
                    filename, size, checksum, mode = required[name]
                    if not member.isfile() or member.size != size:
                        raise BootstrapError("Verifier archive is missing its regular pinned payload")
                    prefix = _write_file(output, filename, archive.extractfile(member), size, checksum, mode)
                    if filename == "gh":
                        _elf(prefix, spec)
                    extracted.add(name)
        while limited.read(65536):
            pass
    if extracted != set(required):
        raise BootstrapError("Verifier archive is missing its binary or licence")
    receipt = _receipt(spec)
    _write_file(output, "receipt.json", io.BytesIO(receipt), len(receipt), hashlib.sha256(receipt).hexdigest(), 0o444)


def bootstrap_verifier(archive: Path, cache: Path):
    spec = verifier_spec()
    name = f"gh-{spec['version']}-linux-{spec['architecture']}-{spec['archiveSha256'][:12]}"
    parent = _Parent(cache)
    lock = None
    try:
        lock = os.open(".verifier-bootstrap.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=parent.fd)
        info = os.fstat(lock)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or
                info.st_size != 0 or stat.S_IMODE(info.st_mode) != 0o600):
            raise BootstrapError("Verifier cache lock has an untrusted identity")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        lock_identity = _seal(info)
        _check_lock(parent, lock, lock_identity)
        if os.path.lexists(parent.path / name):
            result = _check_cache(parent, name, spec)
            _check_lock(parent, lock, lock_identity)
            return result
        incoming = ".verifier-input-" + uuid.uuid4().hex
        descriptor = os.open(incoming, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent.fd)
        os.unlink(incoming, dir_fd=parent.fd)
        with os.fdopen(descriptor, "w+b") as snapshot:
            _snapshot(archive, snapshot, spec)
            parent.assert_current()
            temporary = ".verifier-stage-" + uuid.uuid4().hex
            os.mkdir(temporary, 0o700, dir_fd=parent.fd)
            output = os.open(temporary, DIRECTORY_FLAGS, dir_fd=parent.fd)
            try:
                identity = os.fstat(output)
                _extract(snapshot, output, spec)
                os.fchmod(output, 0o755)
                os.fsync(output)
                if ((identity.st_dev, identity.st_ino) !=
                        (os.stat(temporary, dir_fd=parent.fd, follow_symlinks=False).st_dev,
                         os.stat(temporary, dir_fd=parent.fd, follow_symlinks=False).st_ino)):
                    raise BootstrapError("Prepared verifier directory changed")
                _check_cache(parent, temporary, spec)
                _check_lock(parent, lock, lock_identity)
                _rename_exclusive(parent.fd, temporary, name)
                os.fsync(parent.fd)
                result = _check_cache(parent, name, spec)
                _check_lock(parent, lock, lock_identity)
                return result
            finally:
                os.close(output)
    finally:
        if lock is not None:
            os.close(lock)
        parent.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--print-spec", action="store_true", help="Print pinned download metadata for this Linux host")
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--cache", type=Path)
    args = parser.parse_args()
    if args.print_spec and (args.archive is not None or args.cache is not None):
        parser.error("--print-spec cannot be combined with --archive or --cache")
    if not args.print_spec and (args.archive is None or args.cache is None):
        parser.error("--archive and --cache are required for bootstrap")
    try:
        result = verifier_spec() if args.print_spec else {"verifier": str(bootstrap_verifier(args.archive, args.cache)), "activated": False}
    except (OSError, ValueError, tarfile.TarError):
        parser.exit(1, "Pinned verifier bootstrap failed; no service was activated.\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
