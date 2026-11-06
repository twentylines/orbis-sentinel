"""Operator entry point for data verification when Orbis is unavailable."""

import argparse
import json
import os
import stat
import sys

from .verification import CleanupIndeterminate, VerificationError, verify_saved_capture


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate expectation field")
        value[key] = item
    return value


def _invalid_number(_):
    raise ValueError("Invalid number")


def _read_expectation(path, owner=0):
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise ValueError("Expectation file must be canonical")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner
                or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) not in (0o400, 0o600)
                or not 1 <= before.st_size <= 8192):
            raise ValueError("Expectation file must be private")
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                raise ValueError("Expectation file changed")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        current = os.stat(path, follow_symlinks=False)
        keys = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                "st_size", "st_mtime_ns", "st_ctime_ns")
        if os.read(descriptor, 1) or any(
                getattr(before, key) != getattr(info, key)
                for info in (after, current) for key in keys):
            raise ValueError("Expectation file changed")
        return json.loads(b"".join(chunks), object_pairs_hook=_unique, parse_constant=_invalid_number)
    finally:
        os.close(descriptor)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Verify a saved capture without starting Orbis")
    parser.add_argument("--data-directory", required=True)
    parser.add_argument("--scratch-directory", required=True)
    parser.add_argument("--image-id", required=True, help="locally retained verified recovery image ID")
    parser.add_argument("--expectation-file", required=True, help="protected supervisor checkpoint expectation")
    parser.add_argument("--owner-id", required=True, type=int)
    parser.add_argument("--created-at", required=True, type=int)
    args = parser.parse_args(argv)
    if sys.platform != "linux" or os.geteuid() != 0:
        print("Capture verification requires the Linux recovery supervisor.", file=sys.stderr)
        return 1
    try:
        expected = _read_expectation(args.expectation_file)
        result = verify_saved_capture(
            data_directory=args.data_directory, scratch_directory=args.scratch_directory,
            image_id=args.image_id, expectation=expected,
            owner_id=args.owner_id, created_at=args.created_at,
        )
        print(json.dumps({"schema": "orbis-sentinel.capture-verification.v1",
                          "snapshotId": result.snapshot_id, "publication": result.publication},
                         sort_keys=True, separators=(",", ":"), allow_nan=False))
        return 0
    except CleanupIndeterminate:
        print("Verification stopped. A verifier may remain; recovery information was kept.", file=sys.stderr)
        return 2
    except (OSError, ValueError, VerificationError):
        print("Capture verification failed. Recovery information was kept.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
