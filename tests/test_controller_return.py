"""Actual sole-owner SQLite sessions and fixed return approvals; no transport."""

import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from orbis_sentinel.controller_return import ControllerReturnApprovals, return_scope
from orbis_sentinel.recovery_sessions import RecoverySessionError, _FRESH_MS
from orbis_sentinel.bootstrap_control import RootBootstrapControl, _SCHEMA, _OPERATIONS
from orbis_sentinel.recovery_bootstrap import RecoveryBootstrap
import test_recovery_sessions as session_fixture


SCOPE = {'planId': '11111111-2222-4333-8444-555555555555',
         'installationId': 'a' * 64, 'handoffSha256': 'b' * 64}


class ControllerReturnTests(unittest.TestCase):
    def setUp(self):
        self.fixture = session_fixture.RecoverySessionsTests('runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.owner = self.fixture.store
        self.elapsed = 0
        self.owner._return_monotonic = lambda: self.elapsed
        self.grants = ControllerReturnApprovals(self.owner, origin=self.fixture.origin)
        self.login = self.fixture.complete()

    def approve(self, **changes):
        return self.grants.approve(**{'token': self.login['token'], 'csrf': self.login['csrfToken'],
                                     'origin': self.fixture.origin, 'scope': SCOPE, **changes})

    def claim(self, approval, **changes):
        return self.grants.claim(**{'approval_id': approval['approvalId'], 'scope': SCOPE,
                                   'claim_id': 'c' * 64, **changes})

    def test_fresh_csrf_approval_is_bound_and_same_claim_replays(self):
        before = self.owner.session(token=self.login['token'], origin=self.fixture.origin, touch=False)
        approval = self.approve()
        duplicate = self.approve()
        self.assertEqual(duplicate['approvalId'], approval['approvalId'])
        self.assertLessEqual(duplicate['expiresAtMs'], approval['expiresAtMs'])
        first = self.claim(approval)
        replay = self.claim(approval)
        self.assertEqual({k: v for k, v in replay.items() if k != 'expiresAtMs'},
                         {k: v for k, v in first.items() if k != 'expiresAtMs'})
        self.assertLessEqual(replay['expiresAtMs'], first['expiresAtMs'])
        self.assertEqual((first['scope'], first['principal'], first['method']), (SCOPE, 'orbis-operator', 'password'))
        self.assertEqual(self.owner.session(token=self.login['token'], origin=self.fixture.origin, touch=False), before)
        with self.assertRaises(RecoverySessionError):
            self.claim(approval, claim_id='d' * 64)

    def test_each_scope_field_and_destination_is_exact(self):
        approval = self.approve()
        for field, changed in (('planId', '21111111-2222-4333-8444-555555555555'),
                               ('installationId', 'd' * 64), ('handoffSha256', 'd' * 64)):
            with self.subTest(field=field), self.assertRaises(RecoverySessionError):
                self.claim(approval, scope={**SCOPE, field: changed})
        for scope in ({**SCOPE, 'command': 'start'}, {**SCOPE, 'planId': SCOPE['planId'] + '?x=1'},
                      {**SCOPE, 'handoffSha256': 'short'}):
            with self.subTest(scope=scope), self.assertRaises(RecoverySessionError):
                self.approve(scope=scope)
        with self.assertRaises(RecoverySessionError):
            self.approve(origin='https://other.example')
        self.assertTrue(self.claim(approval)['approved'])

    def test_bad_csrf_missing_session_or_stale_signin_never_issues(self):
        for changes in ({'csrf': self.fixture.binding}, {'token': self.fixture.binding}):
            with self.subTest(changes=changes), self.assertRaises(RecoverySessionError):
                self.approve(**changes)
        self.fixture.now += _FRESH_MS + 1
        with self.assertRaises(RecoverySessionError):
            self.approve()
        self.assertEqual(self.owner._db.execute('SELECT count(*) FROM controller_return_approvals').fetchone()[0], 0)

    def test_logout_and_profile_revocation_invalidate_unaccepted_and_replayed_claims(self):
        approval = self.approve()
        self.claim(approval)
        self.owner.logout(token=self.login['token'], origin=self.fixture.origin, csrf=self.login['csrfToken'])
        with self.assertRaises(RecoverySessionError):
            self.claim(approval)
        self.login = self.fixture.complete()
        approval = self.approve()
        self.owner.revoke()
        with self.assertRaises(RecoverySessionError):
            self.claim(approval)

    def test_expiry_and_backward_clock_refuse_without_new_claim(self):
        approval = self.approve()
        self.fixture.now = approval['expiresAtMs']
        with self.assertRaises(RecoverySessionError):
            self.claim(approval)
        self.fixture.now -= 60001
        with self.assertRaises(RecoverySessionError):
            self.claim(approval)

    def test_approval_expires_at_fresh_session_boundary(self):
        self.fixture.now += _FRESH_MS - 10
        approval = self.approve()
        self.assertEqual(approval['expiresAtMs'], self.fixture.now + 10)
        self.fixture.now += 11
        with self.assertRaises(RecoverySessionError):
            self.claim(approval)

    def test_emergency_key_remains_independent_and_rotation_revokes_approval(self):
        key = self.fixture.prepare_key()
        self.fixture.activate_key(key)
        self.login = self.fixture.key_session(key['recoveryKey'])
        approval = self.approve()
        self.owner.revoke()
        self.assertEqual(self.claim(approval)['principal'], 'recovery-key')
        replacement = self.fixture.prepare_key(key['revision'])
        self.fixture.activate_key(replacement, key['revision'])
        with self.assertRaises(RecoverySessionError):
            self.claim(approval)

    def test_new_sessions_owner_discards_old_approval_and_login(self):
        approval = self.approve()
        self.owner.close()
        fresh = self.fixture.open()
        grants = ControllerReturnApprovals(fresh, origin=self.fixture.origin)
        with self.assertRaises(RecoverySessionError):
            grants.claim(approval_id=approval['approvalId'], scope=SCOPE, claim_id='c' * 64)
        self.assertEqual(fresh._db.execute('SELECT count(*) FROM controller_return_approvals').fetchone()[0], 0)

    def test_atomic_claim_rejects_second_decision_and_rolls_back_error(self):
        approval = self.approve()
        with patch.object(self.owner, '_verify', side_effect=[None, RecoverySessionError()]), self.assertRaises(RecoverySessionError):
            self.claim(approval)
        self.assertIsNone(self.owner._db.execute('SELECT claim FROM controller_return_approvals').fetchone()[0])
        self.claim(approval)
        with self.assertRaises(RecoverySessionError):
            self.claim(approval, claim_id='d' * 64)

    def test_bounded_pending_approvals_and_expired_cleanup(self):
        for index in range(128):
            self.approve(scope={**SCOPE, 'handoffSha256': format(index, '064x')})
        with self.assertRaises(RecoverySessionError):
            self.approve(scope={**SCOPE, 'handoffSha256': 'f' * 64})
        self.fixture.now += 60001
        approval = self.approve()
        self.assertTrue(self.claim(approval)['approved'])
        self.assertEqual(self.owner._db.execute('SELECT count(*) FROM controller_return_approvals').fetchone()[0], 1)

    def test_expired_approval_never_revives_after_wall_rollback(self):
        for consumed in (False, True):
            with self.subTest(consumed=consumed):
                approval = self.approve(scope={**SCOPE, 'handoffSha256': ('e' if consumed else 'f') * 64})
                scope = approval['scope']
                if consumed:
                    self.claim(approval, scope=scope)
                original = self.fixture.now
                self.fixture.now = approval['expiresAtMs']
                with self.assertRaises(RecoverySessionError):
                    self.claim(approval, scope=scope)
                self.fixture.now = original + 1
                with self.assertRaises(RecoverySessionError):
                    self.claim(approval, scope=scope)

    def test_stale_signin_cannot_become_fresh_after_wall_rollback(self):
        original = self.fixture.now
        self.fixture.now += _FRESH_MS + 1
        with self.assertRaises(RecoverySessionError):
            self.approve()
        self.fixture.now = original + 1
        with self.assertRaises(RecoverySessionError):
            self.approve()

    def test_elapsed_deadlines_work_with_frozen_or_backwards_wall_clock(self):
        approval = self.approve()
        self.elapsed += 60000000000
        with self.assertRaises(RecoverySessionError):
            self.claim(approval)
        self.elapsed += _FRESH_MS * 1000000
        with self.assertRaises(RecoverySessionError):
            self.approve()

    def test_duplicate_and_claim_share_lower_bound_and_one_decision_sample(self):
        approval = self.approve()
        self.fixture.now -= 1
        with self.assertRaises(RecoverySessionError):
            self.approve()
        with self.assertRaises(RecoverySessionError):
            self.claim(approval)
        self.fixture.now = approval['expiresAtMs']
        with patch.object(self.owner, '_now', return_value=self.fixture.now) as now, self.assertRaises(RecoverySessionError):
            self.claim(approval)
        self.assertEqual(now.call_count, 1)

    def test_wire_expiry_reflects_elapsed_remaining_time(self):
        approval = self.approve()
        self.elapsed += 59000000000
        result = self.claim(approval)
        self.assertEqual(result['expiresAtMs'], self.fixture.now + 1000)
        self.elapsed += 1000000000
        with self.assertRaises(RecoverySessionError):
            self.claim(approval)

    def test_root_control_claim_is_fixed_and_has_no_host_effect(self):
        approval = self.approve()
        bootstrap = RecoveryBootstrap.__new__(RecoveryBootstrap)
        bootstrap.store, bootstrap.origin = self.owner, self.fixture.origin
        controller = RootBootstrapControl(bootstrap)
        request = {'schema': _SCHEMA, 'operation': 'controller-return-claim',
                   'arguments': {'approvalId': approval['approvalId'], 'scope': SCOPE, 'claimId': 'c' * 64}}
        self.assertTrue(controller.handle(request)['result']['approved'])
        for extra in ('command', 'socket', 'container'):
            bad = copy.deepcopy(request)
            bad['arguments'][extra] = 'untrusted'
            self.assertFalse(controller.handle(bad)['ok'])
        self.assertNotIn('controller-return-start', _OPERATIONS)

    def test_scope_copy_and_concrete_store_requirement(self):
        checked = return_scope(SCOPE)
        checked['installationId'] = 'd' * 64
        self.assertEqual(SCOPE['installationId'], 'a' * 64)
        with self.assertRaises(ValueError):
            ControllerReturnApprovals(SimpleNamespace(), origin=self.fixture.origin)


if __name__ == '__main__':
    unittest.main()
