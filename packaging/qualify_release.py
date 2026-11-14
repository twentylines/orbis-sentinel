"""Build and check a Sentinel package before publishing its checksum or provenance."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

from build_release import build_release, ENTRYPOINTS
from stage_release import stage_release, MAX_ARCHIVE_BYTES


CONTENT_RULES = {
    "private home path": re.compile(rb"/Users/|/home/[^/\s\x27\x22]+/|[A-Za-z]:\\+Users\\+"),
    "credential": re.compile(
        rb"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----|\bgh[pousr]_[A-Za-z0-9]{20,}|"
        rb"\bgithub_pat_[A-Za-z0-9_]{20,}|\bAKIA[A-Z0-9]{16}\b|\bsk-[A-Za-z0-9]{20,}"
    ),
    "private development record": re.compile(rb"\.orbis-private/|provider-thread|native-thread|t3-context://"),
}


def check_content(directory: Path):
    for path in sorted(directory.rglob("*")):
        if not path.is_file():
            continue
        data = path.read_bytes()
        for label, pattern in CONTENT_RULES.items():
            if pattern.search(data):
                raise ValueError(f"Package content review failed: {path.relative_to(directory)} ({label})")


def archive_digest(path: Path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_ARCHIVE_BYTES or before.st_nlink != 1:
            raise ValueError("Package archive is not a bounded standalone file")
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            total += len(chunk)
            if total > MAX_ARCHIVE_BYTES:
                raise ValueError("Package archive exceeds its size bound")
            digest.update(chunk)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
        if identity(before) != identity(os.fstat(descriptor)) or identity(before) != identity(path.stat(follow_symlinks=False)):
            raise ValueError("Package archive changed during qualification")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def qualify_release(source: Path, output: Path):
    output = output.absolute()
    output.mkdir(mode=0o700)
    result = build_release(source, output / "archive")
    artifact = Path(result["artifact"])
    releases = output / "staged"
    releases.mkdir(mode=0o755)
    staged = stage_release(artifact, releases, sha256=result["sha256"], version=result["version"])
    if staged["activated"] or staged["files"] != result["files"]:
        raise ValueError("Package verification did not match the build")
    directory = Path(staged["directory"])
    check_content(directory)
    temporary = output / "tmp"
    temporary.mkdir(mode=0o700)
    environment = {"PATH": os.defpath, "TMPDIR": str(temporary), "PYTHONDONTWRITEBYTECODE": "1"}
    for entrypoint in ENTRYPOINTS:
        check = subprocess.run(
            [sys.executable, "-I", "-B", str(directory / "bin" / entrypoint), "--help"],
            cwd=output, env=environment, capture_output=True, timeout=15,
        )
        if check.returncode:
            raise ValueError(f"Packaged entrypoint failed its help check: {entrypoint}")
    if archive_digest(artifact) != result["sha256"]:
        raise ValueError("Package archive changed after verification")
    checksum = artifact.with_name(artifact.name + ".sha256")
    expected = f"{result['sha256']}  {artifact.name}\n"
    if checksum.is_symlink() or checksum.read_text() != expected:
        raise ValueError("Package checksum file changed after verification")
    return {**result, "checksum": str(checksum), "filename": artifact.name,
            "entrypointChecks": len(ENTRYPOINTS), "activated": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--output", type=Path, required=True, help="A new directory under a trusted project workspace")
    args = parser.parse_args()
    try:
        result = qualify_release(args.source, args.output)
    except (ValueError, OSError, subprocess.SubprocessError):
        parser.exit(1, "Package qualification failed; no service was activated.\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
