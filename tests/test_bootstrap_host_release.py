"""Release crash/replay with real publication SQLite/files and fixture Host guard."""

from contextlib import contextmanager, redirect_stderr
import io
import json
import os
from types import SimpleNamespace
import unittest
from unittest import mock

from orbis_sentinel import bootstrap_host_release as release
from orbis_sentinel import bootstrap_host_transition as activation
from orbis_sentinel import bootstrap_publication as publication
from orbis_sentinel import bootstrap_source as source
from orbis_sentinel import runtime
from test_bootstrap_host_transition import portable_write
from test_bootstrap_publication import PairedPublicationTests


class HostReleaseTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture = PairedPublicationTests('runTest')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        f = fixture.fixture
        self.arguments = (f.op, fixture.packet['reviewSha256'], f.plan_sha)
        self.options = {'packet_sha': fixture.arguments['packetSha256'],
                        'approval_sha': source.digest((f.operation / 'activation-approval.json').read_bytes())}
        self.fail_write = None
        self.fail_stage = None
        self.fail_finish = False
        self.lose_reply = None
        self.calls, self.writes, self.events = [], [], []
        self.original_rows = fixture.rows()

        def put(authority, descriptor, name, body, *, previous):
            if self.fail_stage == name:
                self.fail_stage = None
                fd = os.open('.' + name + '.pending', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=descriptor)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(body)
                    stream.flush()
                    os.fsync(stream.fileno())
                raise OSError('Interrupted before final rename')
            portable_write(authority, descriptor, name, body, previous=previous)
            self.writes.append(name)
            if self.fail_write == name:
                self.fail_write = None
                raise OSError('Lost reply after durable file write')

        self.product = SimpleNamespace(_write_storage=put)
        case = self
        class Guard:
            def read(self):
                path = fixture.namespace / publication.FENCE
                if not path.exists():
                    return None
                if path.read_bytes() != publication._fence(fixture.packet):
                    raise ValueError('Crossed original fixture guard')
                return json.loads(path.read_bytes())

            def check(self, operation, review):
                if (operation, review) != (f.op, fixture.packet['reviewSha256']) or self.read() is None:
                    raise ValueError('The original fixture hold is absent')

            def finish(self, operation, review, *, verify_completed):
                if (operation, review) != (f.op, fixture.packet['reviewSha256']) or verify_completed() is not True:
                    raise ValueError('Unproved fixture completion')
                path = fixture.namespace / publication.FENCE
                if path.exists():
                    case.assertTrue((fixture.namespace / publication.INTENT).exists())
                    path.unlink()
                    fd = os.open(fixture.namespace, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    case.events.append('fence-retired-with-intent-held')
                    if case.fail_finish:
                        case.fail_finish = False
                        raise OSError('Lost retirement confirmation')

        @contextmanager
        def locked(root, context):
            self.assertEqual((str(root), context), (fixture.review['root'], fixture.review['context']))
            yield Guard()

        admission = SimpleNamespace(service=SimpleNamespace(root=fixture.review['root'], context=fixture.review['context'],
                                    state_dir=f.base), authority=None, host=SimpleNamespace(credential_fence_lock=locked),
                                    layout=SimpleNamespace(namespace=lambda _: fixture.namespace))

        @contextmanager
        def scope(operation, review, plan):
            if (operation, review, plan) != self.arguments:
                raise ValueError('Crossed retained scope')
            with source.PrivateDirectory(f.operation) as directory:
                yield directory, fixture.review, f.plan, admission, self.product, None, None, mock.Mock()

        self.actor = activation.HostActivation(mock.Mock())
        self.actor._scope = scope
        self.writer = release.HostPublicationRelease(self.actor)

        def call(operation, arguments):
            self.calls.append(operation)
            self.assertEqual(arguments, fixture.arguments)
            action = {'bootstrap-paired-publication-ready': 'ready', 'bootstrap-paired-publication-publish': 'publish'}[operation]
            result = fixture.root(action)
            if self.lose_reply == action:
                self.lose_reply = None
                raise OSError('Lost Root response')
            return result

        self.client = SimpleNamespace(call=call)
        @contextmanager
        def live(*args):
            yield self.client, fixture.binding.sha256, mock.Mock()
        self.writer._live = live

    def run_release(self):
        return self.writer.run(*self.arguments, **self.options)

    def assert_published(self):
        fixture = self.fixture
        self.assertFalse((fixture.namespace / publication.FENCE).exists())
        self.assertFalse((fixture.namespace / publication.INTENT).exists())
        self.assertTrue(fixture.proof_file.exists())
        after = fixture.rows()
        for original, current in zip(self.original_rows[:2], after[:2]):
            self.assertEqual(original[:-1], current[:-1])
            self.assertEqual(current[-1], 1)
        self.assertEqual(after[-1], (2, None, None, None))

    def test_complete_release_preserves_rows_and_exact_replay_has_no_extra_writes(self):
        result = self.run_release()
        self.assertEqual(result['phase'], 'paired-published')
        self.assert_published()
        self.assertEqual(self.events, ['fence-retired-with-intent-held'])
        self.assertEqual(self.writes, [release.READY_FILE, release.PUBLICATION_HOLD, publication.RETIRED_FENCE,
                                     publication.RETIRED_INTENT, publication.RELEASE_FILE])
        writes = list(self.writes)
        self.assertEqual(self.run_release(), result)
        self.assertEqual(self.writes, writes)
        self.assert_published()

    def test_missing_qualification_cannot_issue_ready_or_retire(self):
        self.fail_write = release.READY_FILE
        with self.assertRaises(OSError):
            self.run_release()
        before_calls, before_writes = list(self.calls), list(self.writes)
        self.fixture.qualification_file.unlink()
        with self.assertRaises((OSError, ValueError)):
            self.run_release()
        self.assertEqual(self.calls, before_calls)
        self.assertEqual(self.writes, before_writes)
        self.assertEqual(self.fixture.rows(), self.original_rows)
        self.fixture.assert_closed()

    def test_absent_fence_without_retirement_proof_never_counts_as_release(self):
        (self.fixture.namespace / publication.FENCE).unlink()
        with self.assertRaises(ValueError):
            self.run_release()
        self.assertEqual(self.calls, [])
        self.assertEqual(self.fixture.rows(), self.original_rows)

    def test_changed_qualification_after_ready_cannot_continue_retirement(self):
        self.fail_write = release.READY_FILE
        with self.assertRaises(OSError):
            self.run_release()
        changed = {**self.fixture.qualification, 'consumers': {'host': '8' * 64, 'main': '2' * 64, 'sentinel': '3' * 64}}
        self.fixture.write_document(self.fixture.qualification_file, changed)
        with self.assertRaises(ValueError):
            self.run_release()
        self.assertTrue((self.fixture.namespace / publication.FENCE).exists())
        self.assertEqual(self.fixture.rows(), self.original_rows)

    def test_lost_fence_retirement_reply_replays_the_saved_ready(self):
        self.fail_finish = True
        with self.assertRaises(OSError):
            self.run_release()
        self.fixture.assert_closed()
        self.assertFalse((self.fixture.namespace / publication.FENCE).exists())
        self.assertTrue((self.fixture.namespace / publication.INTENT).exists())
        self.run_release()
        self.assertEqual(self.calls.count('bootstrap-paired-publication-ready'), 1)
        self.assert_published()

    def test_release_receipt_cannot_precede_both_retirements(self):
        self.fail_write = release.READY_FILE
        with self.assertRaises(OSError):
            self.run_release()
        ready = source.decode((self.fixture.namespace / release.READY_FILE).read_bytes())
        self.fixture.write_document(self.fixture.namespace / publication.RELEASE_FILE,
            publication._release(ready, self.fixture.packet, self.fixture.completion))
        with self.assertRaises(ValueError):
            self.run_release()
        self.assertTrue((self.fixture.namespace / publication.FENCE).exists())
        self.assertTrue((self.fixture.namespace / publication.INTENT).exists())
        self.fixture.assert_closed()

    def test_lost_ready_and_publish_replies_reconcile_same_operation(self):
        self.lose_reply = 'ready'
        with self.assertRaises(OSError):
            self.run_release()
        self.assertFalse((self.fixture.namespace / release.READY_FILE).exists())
        self.fixture.assert_closed()
        self.lose_reply = 'publish'
        with self.assertRaises(OSError):
            self.run_release()
        self.assert_published()
        self.run_release()
        self.assert_published()

    def test_cli_release_requires_the_existing_exact_consent_hashes(self):
        args = ['--bootstrap', 'release-activation', '--bootstrap-operation', self.arguments[0],
                '--review-sha256', self.arguments[1], '--plan-sha256', self.arguments[2],
                '--activation-packet-sha256', self.options['packet_sha'],
                '--activation-approval-sha256', self.options['approval_sha']]
        with mock.patch.object(runtime, '_run_host_activation', return_value=0) as call:
            self.assertEqual(runtime.main(args), 0)
            self.assertEqual(call.call_args.args, ('release-activation', *self.arguments))
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                runtime.main(args[:-2])
            self.assertEqual(call.call_count, 1)


def interrupted_write_case(name):
    def test(self):
        self.fail_write = name
        with self.assertRaises(OSError):
            self.run_release()
        self.assertEqual(self.fixture.rows(), self.original_rows)
        self.fixture.assert_closed()
        self.run_release()
        self.assertEqual(self.calls.count('bootstrap-paired-publication-ready'), 1)
        self.assert_published()
    return test


def staged_write_case(name):
    def test(self):
        self.fail_stage = name
        with self.assertRaises(OSError):
            self.run_release()
        self.fixture.assert_closed()
        self.run_release()
        self.assert_published()
        self.assertFalse((self.fixture.namespace / ('.' + name + '.pending')).exists())
    return test


for _name in (release.READY_FILE, release.PUBLICATION_HOLD, publication.RETIRED_FENCE, publication.RETIRED_INTENT, publication.RELEASE_FILE):
    setattr(HostReleaseTests, 'test_interrupted_' + _name.replace('-', '_').replace('.', '_'), interrupted_write_case(_name))
    setattr(HostReleaseTests, 'test_staged_' + _name.replace('-', '_').replace('.', '_'), staged_write_case(_name))


if __name__ == '__main__':
    unittest.main(defaultTest='HostReleaseTests')
