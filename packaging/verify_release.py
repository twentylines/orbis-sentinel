"""Authenticate a Sentinel package with GitHub provenance before staging it.

The caller supplies the reviewed release digest, version and source revision.
GitHub CLI is the cryptographic verifier; this module adds the fixed publisher
policy and keeps the verified inputs pinned through archive staging.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time

from stage_release import MAX_ARCHIVE_BYTES, SHA256, VERSION, _Parent, stage_release


REPOSITORY = "twentylines/orbis-sentinel"
REPOSITORY_ID = "1445403366"
OWNER_ID = "46835486"
SOURCE_REF = "refs/heads/main"
WORKFLOW = REPOSITORY + "/.github/workflows/package.yml"
ISSUER = "https://token.actions.githubusercontent.com"
PREDICATE = "https://slsa.dev/provenance/v1"
MAX_BUNDLE_BYTES = 4 * 1024 * 1024
MAX_STDOUT_BYTES = 1024 * 1024
MAX_STDERR_BYTES = 64 * 1024
COMMIT = re.compile(r"[0-9a-f]{40}")


class VerificationError(ValueError):
    pass


def _seal(value):
    return (value.st_dev, value.st_ino, value.st_uid, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _digest(descriptor, maximum):
    digest, offset = hashlib.sha256(), 0
    while chunk := os.pread(descriptor, 65536, offset):
        offset += len(chunk)
        if offset > maximum:
            raise VerificationError("Verification input exceeds its size limit")
        digest.update(chunk)
    return digest.hexdigest()


class _Input:
    def __init__(self, source, parent, name, maximum, expected=None):
        self.parent, self.name, self.maximum = parent, name, maximum
        self.path = parent.path / name
        self.fd = None
        incoming = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            before = os.fstat(incoming)
            if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum or before.st_nlink != 1:
                raise VerificationError("Verification input must be a bounded standalone file")
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent.fd)
            with os.fdopen(descriptor, "wb") as output:
                copied = 0
                while chunk := os.read(incoming, 65536):
                    copied += len(chunk)
                    if copied > maximum:
                        raise VerificationError("Verification input exceeds its size limit")
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            if (_seal(before) != _seal(os.fstat(incoming)) or
                    _seal(before) != _seal(os.stat(source, follow_symlinks=False)) or copied != before.st_size):
                raise VerificationError("Verification input changed while being copied")
            self.fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent.fd)
            self.identity = _seal(os.fstat(self.fd))
            self.sha256 = _digest(self.fd, maximum)
            if expected is not None and self.sha256 != expected:
                raise VerificationError("Package checksum does not match the reviewed release")
            self.check()
        except BaseException:
            self.close()
            raise
        finally:
            os.close(incoming)

    def check(self):
        self.parent.assert_current()
        current = os.fstat(self.fd)
        if (not stat.S_ISREG(current.st_mode) or current.st_uid != os.geteuid() or
                stat.S_IMODE(current.st_mode) != 0o600 or current.st_nlink != 1 or
                _seal(current) != self.identity or
                _seal(os.stat(self.name, dir_fd=self.parent.fd, follow_symlinks=False)) != self.identity or
                _digest(self.fd, self.maximum) != self.sha256):
            raise VerificationError("Pinned verification input changed; retained for review")

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def _write(parent, name, data):
    parent.assert_current()
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent.fd)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def _run_verifier(command, environment, parent, descriptors, timeout=45):
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": MAX_STDOUT_BYTES, "stderr": MAX_STDERR_BYTES}
    child = subprocess.Popen(command, cwd=parent.path, env=environment, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
                             pass_fds=descriptors, start_new_session=True)
    deadline = time.monotonic() + timeout
    poller = selectors.DefaultSelector()
    poller.register(child.stdout, selectors.EVENT_READ, "stdout")
    poller.register(child.stderr, selectors.EVENT_READ, "stderr")
    try:
        while poller.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise VerificationError("Attestation verification timed out")
            for key, _ in poller.select(min(remaining, 0.2)):
                data = os.read(key.fileobj.fileno(), 65536)
                if not data:
                    poller.unregister(key.fileobj)
                    continue
                output = streams[key.data]
                available = limits[key.data] - len(output)
                output.extend(data[:available])
                if len(data) > available:
                    raise VerificationError("Attestation verifier exceeded its output limit")
        try:
            code = child.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as error:
            raise VerificationError("Attestation verification timed out") from error
        if code:
            raise VerificationError("Package provenance verification failed; no release was staged")
        return bytes(streams["stdout"])
    finally:
        try:
            # The verifier owns a private process group, including any children it started.
            if child.returncode is None:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            child.wait(timeout=5)
        finally:
            poller.close()
            child.stdout.close()
            child.stderr.close()
            for name, data in streams.items():
                _write(parent, "verification." + name, bytes(data))


def _publisher_policy(output, filename, digest, source_commit):
    try:
        records = json.loads(output)
        if not isinstance(records, list) or not records:
            raise ValueError("No verified provenance")
        expected = {
            "issuer": ISSUER, "sourceRepositoryURI": "https://github.com/" + REPOSITORY,
            "sourceRepositoryIdentifier": REPOSITORY_ID, "sourceRepositoryOwnerIdentifier": OWNER_ID,
            "sourceRepositoryDigest": source_commit, "sourceRepositoryRef": SOURCE_REF,
            "buildSignerURI": "https://github.com/" + WORKFLOW + "@" + SOURCE_REF,
            "buildSignerDigest": source_commit, "runnerEnvironment": "github-hosted",
        }
        for record in records:
            verified = record.get("verificationResult", {})
            certificate = verified.get("signature", {}).get("certificate", {})
            statement = verified.get("statement", {})
            if (all(certificate.get(key) == value for key, value in expected.items()) and
                    certificate.get("buildTrigger") in {"push", "workflow_dispatch"} and
                    statement.get("_type") == "https://in-toto.io/Statement/v1" and
                    statement.get("predicateType") == PREDICATE and
                    statement.get("subject") == [{"name": filename, "digest": {"sha256": digest}}]):
                return
    except (ValueError, TypeError, AttributeError, KeyError) as error:
        raise VerificationError("Verified provenance does not match the Sentinel publisher policy") from error
    raise VerificationError("Verified provenance does not match the Sentinel publisher policy")


def verify_release(artifact: Path, bundle: Path, releases: Path, workspace: Path, *,
                   sha256: str, version: str, source_commit: str, verifier: Path, reuse_existing=False):
    if (not isinstance(sha256, str) or not SHA256.fullmatch(sha256) or
            not isinstance(version, str) or len(version) > 128 or not VERSION.fullmatch(version) or
            not isinstance(source_commit, str) or not COMMIT.fullmatch(source_commit)):
        raise VerificationError("A reviewed checksum, version and full source revision are required")
    if workspace.is_relative_to(releases) or releases.is_relative_to(workspace):
        raise VerificationError("Verification workspace and releases must be separate directories")
    executable = verifier.resolve(strict=True)
    parents, sealed, tool_fd = [], [], None
    try:
        parents.append(_Parent(releases))
        parents.append(_Parent(executable.parent))
        tool_parent = parents[-1]
        tool_fd = os.open(executable.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=tool_parent.fd)
        tool = os.fstat(tool_fd)
        if (not stat.S_ISREG(tool.st_mode) or tool.st_uid not in (0, os.geteuid()) or
                tool.st_mode & 0o7022 or not tool.st_mode & 0o111 or tool.st_nlink != 1):
            raise VerificationError("Attestation verifier has an untrusted owner or permissions")
        parents.append(_Parent(workspace.parent))
        os.mkdir(workspace.name, 0o700, dir_fd=parents[-1].fd)
        parents.append(_Parent(workspace))
        work = parents[-1]
        for directory in ("inputs", "tmp", "cache", "config", "state", "data"):
            os.mkdir(directory, 0o700, dir_fd=work.fd)
        parents.append(_Parent(workspace / "inputs"))
        inputs = parents[-1]
        filename = f"orbis-sentinel-{version}.tar.gz"
        sealed.append(_Input(artifact, inputs, filename, MAX_ARCHIVE_BYTES, sha256))
        sealed.append(_Input(bundle, inputs, filename + ".sigstore.json", MAX_BUNDLE_BYTES))
        archive, provenance = sealed
        descriptor_root = "/proc/self/fd" if os.path.isdir("/proc/self/fd") else "/dev/fd"
        bundle_descriptor = f"{descriptor_root}/{provenance.fd}"
        # gh chooses its bundle decoder by extension; the alias still opens the pinned descriptor.
        os.symlink(bundle_descriptor, "provenance.json", dir_fd=work.fd)
        alias_identity = _seal(os.stat("provenance.json", dir_fd=work.fd, follow_symlinks=False))
        command = [str(executable), "attestation", "verify", f"{descriptor_root}/{archive.fd}",
                   "--bundle", str(workspace / "provenance.json"), "--repo", REPOSITORY,
                   "--signer-workflow", WORKFLOW, "--source-digest", source_commit,
                   "--signer-digest", source_commit, "--source-ref", SOURCE_REF,
                   "--cert-oidc-issuer", ISSUER, "--predicate-type", PREDICATE,
                   "--deny-self-hosted-runners", "--format", "json"]
        environment = {
            "PATH": os.defpath, "TMPDIR": str(workspace / "tmp"),
            "XDG_CACHE_HOME": str(workspace / "cache"), "XDG_CONFIG_HOME": str(workspace / "config"),
            "XDG_STATE_HOME": str(workspace / "state"), "XDG_DATA_HOME": str(workspace / "data"),
            "GH_CONFIG_DIR": str(workspace / "config"), "GH_HOST": "github.com",
            "GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1",
            "GH_NO_EXTENSION_UPDATE_NOTIFIER": "1", "NO_COLOR": "1",
        }
        for parent in parents:
            parent.assert_current()
        if _seal(os.stat(executable, follow_symlinks=False)) != _seal(tool):
            raise VerificationError("Attestation verifier changed before execution")
        output = _run_verifier(command, environment, work, tuple(item.fd for item in sealed))
        work.assert_current()
        if (_seal(os.stat("provenance.json", dir_fd=work.fd, follow_symlinks=False)) != alias_identity or
                os.readlink("provenance.json", dir_fd=work.fd) != bundle_descriptor):
            raise VerificationError("Pinned provenance alias changed during verification")
        tool_parent.assert_current()
        if _seal(os.fstat(tool_fd)) != _seal(tool) or _seal(os.stat(executable, follow_symlinks=False)) != _seal(tool):
            raise VerificationError("Attestation verifier changed during execution")
        for item in sealed:
            item.check()
        _publisher_policy(output, filename, sha256, source_commit)
        result = stage_release(archive.path, releases, sha256=sha256, version=version, reuse_existing=reuse_existing)
        for item in sealed:
            item.check()
        return {**result, "publisherVerified": True, "sourceCommit": source_commit,
                "repository": REPOSITORY, "repositoryId": REPOSITORY_ID, "ownerId": OWNER_ID,
                "workflow": WORKFLOW, "sourceRef": SOURCE_REF}
    finally:
        for item in sealed:
            item.close()
        if tool_fd is not None:
            os.close(tool_fd)
        for parent in reversed(parents):
            parent.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("artifact", "bundle", "releases", "workspace", "verifier"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("sha256", "version", "source-commit"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        result = verify_release(args.artifact, args.bundle, args.releases, args.workspace,
                                sha256=args.sha256, version=args.version,
                                source_commit=args.source_commit, verifier=args.verifier)
    except (OSError, ValueError, subprocess.SubprocessError):
        parser.exit(1, "Sentinel publisher verification or staging failed; no service was activated.\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
