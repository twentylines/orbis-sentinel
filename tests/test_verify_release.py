import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import unittest
from unittest import mock

import test_build_release as fixtures


packaging = Path(__file__).resolve().parents[1] / "packaging"
spec = importlib.util.spec_from_file_location("verify_release", packaging / "verify_release.py")
verify = importlib.util.module_from_spec(spec)
with mock.patch.object(sys, "path", [str(packaging), *sys.path]):
    spec.loader.exec_module(verify)

SOURCE = "1" * 40


class PublisherVerificationTests(unittest.TestCase):
    def setUp(self):
        fixtures.ReleaseTests.setUp(self)
        self.package = fixtures.release.build_release(self.source, self.root / "out")
        self.artifact = Path(self.package["artifact"])
        self.bundle = self.root / "bundle.json"
        self.bundle.write_bytes(b"synthetic provenance input\n")
        self.releases = self.root / "releases"
        self.releases.mkdir(mode=0o755)
        self.tool = self.root / "gh"
        self.tool.write_text("#!/bin/sh\nexit 0\n")
        self.tool.chmod(0o755)
        self.sequence = 0

    def verified(self):
        return [{"verificationResult": {
            "signature": {"certificate": {
                "issuer": verify.ISSUER,
                "sourceRepositoryURI": "https://github.com/" + verify.REPOSITORY,
                "sourceRepositoryIdentifier": verify.REPOSITORY_ID,
                "sourceRepositoryOwnerIdentifier": verify.OWNER_ID,
                "sourceRepositoryDigest": SOURCE,
                "sourceRepositoryRef": verify.SOURCE_REF,
                "buildSignerURI": "https://github.com/" + verify.WORKFLOW + "@" + verify.SOURCE_REF,
                "buildSignerDigest": SOURCE,
                "runnerEnvironment": "github-hosted",
                "buildTrigger": "push",
            }},
            "statement": {"_type": "https://in-toto.io/Statement/v1", "predicateType": verify.PREDICATE,
                          "subject": [{"name": self.artifact.name, "digest": {"sha256": self.package["sha256"]}}]},
        }}]

    def prepare(self, **changes):
        self.sequence += 1
        self.workspace = self.root / ("verification-" + str(self.sequence))
        arguments = dict(artifact=self.artifact, bundle=self.bundle, releases=self.releases,
                         workspace=self.workspace, sha256=self.package["sha256"],
                         version=self.package["version"], source_commit=SOURCE, verifier=self.tool)
        arguments.update(changes)
        return verify.verify_release(**arguments)

    def test_verified_publisher_stages_actual_archive_without_activation(self):
        observed = {}

        def verifier(command, environment, parent, descriptors):
            observed.update(command=command, environment=environment)
            self.assertEqual(os.pread(descriptors[0], self.artifact.stat().st_size, 0), self.artifact.read_bytes())
            self.assertEqual(os.pread(descriptors[1], self.bundle.stat().st_size, 0), self.bundle.read_bytes())
            self.assertTrue(command[3].endswith("/" + str(descriptors[0])))
            self.assertTrue(command[5].endswith("/provenance.json"))
            self.assertTrue(os.readlink(command[5]).endswith("/" + str(descriptors[1])))
            for name in ("TMPDIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME", "GH_CONFIG_DIR"):
                path = Path(environment[name])
                self.assertTrue(path.is_relative_to(parent.path))
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
            self.assertNotIn("GH_TOKEN", environment)
            self.assertNotIn("GITHUB_TOKEN", environment)
            self.assertNotIn("HOME", environment)
            return json.dumps(self.verified()).encode()

        with mock.patch.object(verify, "_run_verifier", side_effect=verifier):
            result = self.prepare()
        self.assertTrue(result["publisherVerified"])
        self.assertFalse(result["activated"])
        self.assertEqual(result["sourceCommit"], SOURCE)
        self.assertEqual(result["repositoryId"], verify.REPOSITORY_ID)
        self.assertTrue((Path(result["directory"]) / "release.json").is_file())
        self.assertEqual(list(self.releases.iterdir()), [Path(result["directory"])])
        for flag, expected in (("--repo", verify.REPOSITORY), ("--source-digest", SOURCE),
                               ("--signer-digest", SOURCE), ("--signer-workflow", verify.WORKFLOW),
                               ("--source-ref", verify.SOURCE_REF), ("--cert-oidc-issuer", verify.ISSUER),
                               ("--predicate-type", verify.PREDICATE)):
            self.assertEqual(observed["command"][observed["command"].index(flag) + 1], expected)
        self.assertIn("--deny-self-hosted-runners", observed["command"])
        self.assertEqual(stat.S_IMODE((self.workspace / "inputs" / self.artifact.name).stat().st_mode), 0o600)

    def test_real_child_reads_both_pinned_inputs_before_synthetic_policy_reply(self):
        self.tool.write_text(
            f"#!{sys.executable}\n"
            "import hashlib, os, sys\nfrom pathlib import Path\n"
            "archive, bundle = Path(sys.argv[3]), Path(sys.argv[5])\n"
            "assert bundle.suffix == '.json' and bundle.is_symlink()\n"
            f"assert hashlib.sha256(archive.read_bytes()).hexdigest() == {self.package['sha256']!r}\n"
            f"assert hashlib.sha256(bundle.read_bytes()).hexdigest() == {hashlib.sha256(self.bundle.read_bytes()).hexdigest()!r}\n"
            "assert os.readlink(bundle).startswith(('/proc/self/fd/', '/dev/fd/'))\n"
            f"print({json.dumps(self.verified())!r})\n"
        )
        result = self.prepare()
        self.assertTrue(result["publisherVerified"])
        self.assertFalse(result["activated"])
        self.assertEqual((self.workspace / "verification.stderr").read_bytes(), b"")
        self.assertTrue((Path(result["directory"]) / "release.json").is_file())

    def test_reusing_an_existing_version_requires_fresh_publisher_verification(self):
        with mock.patch.object(verify, '_run_verifier', return_value=json.dumps(self.verified()).encode()) as runner:
            first = self.prepare()
            second = self.prepare(reuse_existing=True)
        self.assertEqual(runner.call_count, 2)
        self.assertTrue(second['reused'])
        self.assertEqual(second['directory'], first['directory'])
        with mock.patch.object(verify, '_run_verifier', side_effect=verify.VerificationError('Bad signature')):
            with self.assertRaises(verify.VerificationError):
                self.prepare(reuse_existing=True)

    def test_wrong_publisher_identity_source_workflow_runner_and_issuer_never_stage(self):
        changes = {
            "issuer": "https://example.test/issuer", "sourceRepositoryURI": "https://github.com/other/project",
            "sourceRepositoryIdentifier": "2", "sourceRepositoryOwnerIdentifier": "3",
            "sourceRepositoryDigest": "2" * 40, "sourceRepositoryRef": "refs/heads/other",
            "buildSignerURI": "https://github.com/other/project/.github/workflows/package.yml@refs/heads/main",
            "buildSignerDigest": "2" * 40, "runnerEnvironment": "self-hosted", "buildTrigger": "pull_request",
        }
        for name, value in changes.items():
            with self.subTest(name=name):
                records = self.verified()
                records[0]["verificationResult"]["signature"]["certificate"][name] = value
                with mock.patch.object(verify, "_run_verifier", return_value=json.dumps(records).encode()):
                    with self.assertRaises(verify.VerificationError):
                        self.prepare()
                self.assertEqual(list(self.releases.iterdir()), [])

    def test_invalid_or_unrelated_verified_subjects_and_predicates_never_stage(self):
        for subject, predicate in (
                ([], verify.PREDICATE),
                ([{"name": "other.tar.gz", "digest": {"sha256": self.package["sha256"]}}], verify.PREDICATE),
                ([{"name": self.artifact.name, "digest": {"sha256": "0" * 64}}], verify.PREDICATE),
                ([{"name": self.artifact.name, "digest": {"sha256": self.package["sha256"]}}], "https://example.test/predicate")):
            records = self.verified()
            records[0]["verificationResult"]["statement"].update(subject=subject, predicateType=predicate)
            with mock.patch.object(verify, "_run_verifier", return_value=json.dumps(records).encode()):
                with self.assertRaises(verify.VerificationError):
                    self.prepare()
        for malformed in (b"null", b"{}", b"[]", b"[null]", b"not-json", b"\xff"):
            with mock.patch.object(verify, "_run_verifier", return_value=malformed):
                with self.assertRaises(verify.VerificationError):
                    self.prepare()
        self.assertEqual(list(self.releases.iterdir()), [])

    def test_failed_crypto_verification_preserves_originals_and_never_calls_stager(self):
        original = self.artifact.read_bytes(), self.bundle.read_bytes()
        with mock.patch.object(verify, "_run_verifier", side_effect=verify.VerificationError("Rejected")), \
                mock.patch.object(verify, "stage_release") as stage:
            with self.assertRaises(verify.VerificationError):
                self.prepare()
            stage.assert_not_called()
        self.assertEqual((self.artifact.read_bytes(), self.bundle.read_bytes()), original)
        self.assertTrue((self.workspace / "inputs" / self.artifact.name).is_file())

    def test_invalid_digest_bundle_size_symlinks_and_fifo_fail_before_verifier(self):
        with mock.patch.object(verify, "_run_verifier") as runner:
            with self.assertRaises(verify.VerificationError):
                self.prepare(sha256="0" * 64)
            linked = self.root / "linked"
            linked.symlink_to(self.bundle)
            with self.assertRaises(OSError):
                self.prepare(bundle=linked)
            fifo = self.root / "fifo"
            os.mkfifo(fifo)
            with self.assertRaises(verify.VerificationError):
                self.prepare(bundle=fifo)
            oversized = self.root / "large"
            with oversized.open("wb") as output:
                output.truncate(verify.MAX_BUNDLE_BYTES + 1)
            with self.assertRaises(verify.VerificationError):
                self.prepare(bundle=oversized)
            runner.assert_not_called()
        self.assertEqual(list(self.releases.iterdir()), [])

    def test_replaced_snapshot_with_identical_bytes_is_not_staged(self):
        def replace(command, environment, parent, descriptors):
            archive = parent.path / "inputs" / self.artifact.name
            archive.rename(archive.with_suffix(".old"))
            archive.write_bytes(self.artifact.read_bytes())
            archive.chmod(0o600)
            return json.dumps(self.verified()).encode()
        with mock.patch.object(verify, "_run_verifier", side_effect=replace):
            with self.assertRaises(verify.VerificationError):
                self.prepare()
        self.assertEqual(list(self.releases.iterdir()), [])

    def test_untrusted_original_replacement_after_snapshot_cannot_change_staged_bytes(self):
        def replace(command, environment, parent, descriptors):
            self.artifact.write_bytes(b"changed original")
            self.bundle.write_bytes(b"changed bundle")
            return json.dumps(self.verified()).encode()
        with mock.patch.object(verify, "_run_verifier", side_effect=replace):
            result = self.prepare()
        self.assertTrue(result["publisherVerified"])
        self.assertEqual(hashlib.sha256((self.workspace / "inputs" / self.artifact.name).read_bytes()).hexdigest(), self.package["sha256"])
        self.assertTrue((Path(result["directory"]) / "release.json").is_file())

    def test_replaced_provenance_alias_cannot_stage_a_release(self):
        def replace(command, environment, parent, descriptors):
            alias = Path(command[5])
            alias.unlink()
            alias.symlink_to(self.bundle)
            return json.dumps(self.verified()).encode()
        with mock.patch.object(verify, "_run_verifier", side_effect=replace):
            with self.assertRaises(verify.VerificationError):
                self.prepare()
        self.assertEqual(list(self.releases.iterdir()), [])

    def test_verifier_replacement_and_writable_tool_are_refused(self):
        def replace(command, environment, parent, descriptors):
            self.tool.rename(self.root / "old-gh")
            self.tool.write_text("#!/bin/sh\nexit 0\n")
            self.tool.chmod(0o755)
            return json.dumps(self.verified()).encode()
        with mock.patch.object(verify, "_run_verifier", side_effect=replace):
            with self.assertRaises(verify.VerificationError):
                self.prepare()
        self.tool.chmod(0o777)
        with mock.patch.object(verify, "_run_verifier") as runner:
            with self.assertRaises(verify.VerificationError):
                self.prepare()
            runner.assert_not_called()
        self.assertEqual(list(self.releases.iterdir()), [])

    def test_existing_version_and_workspace_are_preserved(self):
        existing = self.releases / self.package["version"]
        existing.mkdir()
        marker = existing / "retained"
        marker.write_bytes(b"recovery runtime")
        with mock.patch.object(verify, "_run_verifier", return_value=json.dumps(self.verified()).encode()):
            with self.assertRaises(FileExistsError):
                self.prepare()
        self.assertEqual(marker.read_bytes(), b"recovery runtime")
        occupied = self.root / "occupied"
        occupied.mkdir()
        (occupied / "retained").write_bytes(b"evidence")
        with mock.patch.object(verify, "_run_verifier") as runner:
            with self.assertRaises(FileExistsError):
                self.prepare(workspace=occupied)
            runner.assert_not_called()
        self.assertEqual((occupied / "retained").read_bytes(), b"evidence")

    def test_overlapping_workspace_or_invalid_review_is_refused_before_verification(self):
        with mock.patch.object(verify, "_run_verifier") as runner:
            for changes in ({"workspace": self.releases / "work"}, {"workspace": self.root},
                            {"source_commit": "main"}, {"sha256": "invalid"}, {"version": "../other"}):
                with self.assertRaises(verify.VerificationError):
                    self.prepare(**changes)
            runner.assert_not_called()


class VerifierProcessTests(unittest.TestCase):
    def setUp(self):
        fixtures.ReleaseTests.setUp(self)
        self.logs = self.root / "logs"
        self.logs.mkdir(mode=0o700)

    def run_verifier(self, command, timeout=2):
        parent = verify._Parent(self.logs)
        try:
            return verify._run_verifier(command, {"PATH": os.defpath, "TMPDIR": str(self.logs)}, parent, (), timeout=timeout)
        finally:
            parent.close()

    def test_success_and_private_diagnostics(self):
        self.assertEqual(self.run_verifier([sys.executable, "-I", "-B", "-c", "print('verified')"]), b"verified\n")
        self.assertEqual((self.logs / "verification.stdout").read_bytes(), b"verified\n")
        self.assertEqual(stat.S_IMODE((self.logs / "verification.stdout").stat().st_mode), 0o600)

    def test_failure_retains_bounded_private_error(self):
        with self.assertRaises(verify.VerificationError):
            self.run_verifier([sys.executable, "-I", "-B", "-c", "import sys;sys.stderr.write('rejected');sys.exit(1)"])
        self.assertEqual((self.logs / "verification.stderr").read_bytes(), b"rejected")

    def test_output_overrun_is_stopped_and_truncated_at_the_bound(self):
        with mock.patch.object(verify, "MAX_STDOUT_BYTES", 16):
            with self.assertRaises(verify.VerificationError):
                self.run_verifier([sys.executable, "-I", "-B", "-c", "import sys;sys.stdout.write('x'*1000000)"])
        self.assertEqual((self.logs / "verification.stdout").stat().st_size, 16)

    def test_timeout_stops_the_owned_process(self):
        created, original = [], subprocess.Popen
        def start(*args, **kwargs):
            child = original(*args, **kwargs)
            created.append(child)
            return child
        with mock.patch.object(verify.subprocess, "Popen", side_effect=start):
            with self.assertRaises(verify.VerificationError):
                self.run_verifier([sys.executable, "-I", "-B", "-c", "import time;time.sleep(30)"], timeout=0.05)
        self.assertIsNotNone(created[0].poll())


if __name__ == "__main__":
    unittest.main()
