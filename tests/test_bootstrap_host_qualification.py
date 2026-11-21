"""Real SQLite/file qualification with synthetic Host and paired-listener custody."""

import json
import os
import unittest
from unittest import mock

from orbis_sentinel import bootstrap_control, bootstrap_host_release as release
from orbis_sentinel import bootstrap_publication as publication, bootstrap_source as source, recovery_bootstrap
import test_bootstrap_host_release


class HostQualificationTests(unittest.TestCase):
    def setUp(self):
        self.case = case = test_bootstrap_host_release.HostReleaseTests('runTest')
        self.addCleanup(case.doCleanups)
        case.setUp()
        self.fixture = fixture = case.fixture
        fixture.qualification_file.unlink()
        fixture.qualification_evidence_file.unlink()
        self.calls = []
        original = case.client.call

        def call(operation, arguments):
            self.calls.append(operation)
            if operation != 'bootstrap-held-activation-reconcile':
                return original(operation, arguments)
            # The actual engine, source files and SQLite are used. Only live
            # systemd/paired transport custody is synthetic in this local test.
            with (mock.patch.object(fixture.fixture.engine, '_listener_setup_check'),
                  mock.patch.object(recovery_bootstrap, '_receiver_invocation', return_value=fixture.review['recovery']['process'])):
                response = fixture.control.handle({'schema': bootstrap_control._SCHEMA,
                    'operation': operation, 'arguments': arguments})
            self.assertTrue(response['ok'], response)
            self.assertEqual(fixture.rows(), case.original_rows)
            return response['result']

        case.client.call = call

    def test_actual_root_reconciliation_produces_all_three_bound_roles_before_ready(self):
        self.case.fail_write = publication.QUALIFICATION_FILE
        with self.assertRaises(OSError):
            self.case.run_release()
        self.assertEqual(self.calls, ['bootstrap-held-activation-reconcile'])
        self.assertEqual(self.fixture.rows(), self.case.original_rows)
        self.fixture.assert_closed()
        value = json.loads(self.fixture.qualification_evidence_file.read_bytes())
        qualification = json.loads(self.fixture.qualification_file.read_bytes())
        self.assertEqual(set(value['roles']), {'host', 'main', 'sentinel'})
        self.assertEqual(qualification['consumers'], {
            name: source.digest(source.encoded(role)) for name, role in value['roles'].items()})
        for role in value['roles'].values():
            self.assertEqual(role['completionSha256'], source.digest(source.encoded(self.fixture.completion)))
            self.assertEqual(role['packetSha256'], self.fixture.arguments['packetSha256'])
        self.case.run_release()
        self.case.assert_published()
        self.assertEqual(self.calls.count('bootstrap-held-activation-reconcile'), 1)

    def test_lost_ready_reply_reuses_the_existing_qualification(self):
        self.case.lose_reply = 'ready'
        with self.assertRaises(OSError):
            self.case.run_release()
        original = self.fixture.qualification_file.read_bytes()
        self.assertEqual(self.fixture.fixture.engine.status(operation_id=self.fixture.fixture.op)['phase'], 'publication-ready')
        self.case.run_release()
        self.case.assert_published()
        self.assertEqual(self.fixture.qualification_file.read_bytes(), original)
        self.assertEqual(self.calls.count('bootstrap-held-activation-reconcile'), 1)

    def test_failed_qualification_rename_sync_is_repaired_before_ready(self):
        namespace = self.fixture.namespace.stat()
        fsync = os.fsync
        attempts = []
        original = self.case.client.call

        def sync(fd):
            info = os.fstat(fd)
            if ((info.st_dev, info.st_ino) == (namespace.st_dev, namespace.st_ino)
                    and self.fixture.qualification_file.exists()):
                attempts.append(True)
                if len(attempts) == 1:
                    raise OSError('Interrupted qualification rename sync')
            fsync(fd)

        def control(operation, arguments):
            if operation == 'bootstrap-paired-publication-ready':
                self.assertGreater(len(attempts), 1)
            return original(operation, arguments)

        self.case.client.call = control
        with mock.patch.object(os, 'fsync', side_effect=sync):
            with self.assertRaisesRegex(OSError, 'qualification rename sync'):
                self.case.run_release()
            self.assertEqual(self.calls, ['bootstrap-held-activation-reconcile'])
            self.case.run_release()
        self.case.assert_published()
        self.assertGreater(len(attempts), 1)

    def test_a_root_reconciliation_error_does_not_write_qualification_or_retire(self):
        self.case.client.call = mock.Mock(side_effect=ValueError('Unavailable real Root readback'))
        with self.assertRaises(ValueError):
            self.case.run_release()
        self.assertFalse(self.fixture.qualification_file.exists())
        self.assertFalse(self.fixture.qualification_evidence_file.exists())
        self.assertEqual(self.case.writes, [])
        for name in (publication.FENCE, publication.INTENT):
            self.assertTrue((self.fixture.namespace / name).exists())

    def test_rehashed_role_tampering_is_rejected_by_ready(self):
        self.case.fail_write = publication.QUALIFICATION_FILE
        with self.assertRaises(OSError):
            self.case.run_release()
        evidence = json.loads(self.fixture.qualification_evidence_file.read_bytes())
        evidence['roles']['main']['descriptorSha256'] = '0' * 64
        self.fixture.write_document(self.fixture.qualification_evidence_file, evidence)
        qualification = json.loads(self.fixture.qualification_file.read_bytes())
        qualification['consumers']['main'] = source.digest(source.encoded(evidence['roles']['main']))
        self.fixture.write_document(self.fixture.qualification_file, qualification)
        self.fixture.root('ready', ok=False)
        self.assertEqual(self.fixture.rows(), self.case.original_rows)

    def test_changed_pair_after_root_readback_prevents_qualification_write(self):
        original = self.case.client.call

        def control(operation, arguments):
            result = original(operation, arguments)
            if operation == 'bootstrap-held-activation-reconcile':
                (self.fixture.fixture.root / publication.PAIRED_TRANSPORT_FILE).unlink()
            return result

        self.case.client.call = control
        with self.assertRaises((OSError, ValueError)):
            self.case.run_release()
        self.assertFalse(self.fixture.qualification_file.exists())
        self.assertFalse(self.fixture.qualification_evidence_file.exists())
        self.assertNotIn('bootstrap-paired-publication-ready', self.calls)
        self.assertTrue((self.fixture.namespace / publication.FENCE).exists())
        self.assertEqual(self.fixture.rows(), self.case.original_rows)

    def test_published_witness_retains_consumer_role_evidence(self):
        self.case.run_release()
        self.case.assert_published()
        with self.assertRaises((OSError, ValueError)), self.fixture.reader() as witness:
            witness.recheck()
            self.fixture.qualification_evidence_file.unlink()
            with self.assertRaises((OSError, ValueError)):
                witness.recheck()


def interrupted(name, *, staged):
    def test(self):
        if staged:
            self.case.fail_stage = name
        else:
            self.case.fail_write = name
        with self.assertRaises(OSError):
            self.case.run_release()
        self.assertNotIn('bootstrap-paired-publication-ready', self.calls)
        self.assertEqual(self.fixture.rows(), self.case.original_rows)
        self.case.run_release()
        self.case.assert_published()
        self.assertFalse((self.fixture.namespace / ('.' + name + '.pending')).exists())
    return test


for _name in (publication.QUALIFICATION_EVIDENCE_FILE, publication.QUALIFICATION_FILE):
    for _staged in (False, True):
        setattr(HostQualificationTests, 'test_interrupted_' + ('staged_' if _staged else '')
                + _name.replace('-', '_').replace('.', '_'), interrupted(_name, staged=_staged))
