import hashlib
import json
import os
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest import mock

from orbis_sentinel import recovery_profiles as profiles
from orbis_sentinel import recovery_sessions as sessions


class RecoveryProfilesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        owner = mock.patch.object(sessions, '_OWNER_UID', os.getuid())
        owner.start()
        self.addCleanup(owner.stop)
        self.now = 1_800_000_000_000
        self.origin = 'https://orbis.example'
        self.store = sessions.RecoverySessions(self.temp.name, clock=lambda: self.now)
        self.addCleanup(self.store.close)
        self.inspect = mock.Mock(side_effect=self.description)
        self.verify = mock.Mock(side_effect=self.proof)
        self.profiles = self.open(self.store)
        self.prepared = self.profiles.prepare(self.body('b'))
        self.activate(self.prepared)

    def open(self, store):
        value = profiles.RecoveryProfiles(store, inspect=self.inspect, verify=self.verify)
        self.addCleanup(value.close)
        return value

    def body(self, revision, secret='synthetic-profile-material'):
        return json.dumps({'revision': revision * 64, 'privateValue': secret}).encode()

    def description(self, directory, digest):
        body = (Path(directory) / 'identity.json').read_bytes()
        self.assertEqual(hashlib.sha256(body).hexdigest(), digest)
        # A worker port fixture; real profile parsing and crypto run in native QA.
        return {'schema': 'orbis.sentinel-identity-description.v1', 'identitySha256': digest,
                'revision': json.loads(body)['revision'], 'accountId': 1, 'origin': self.origin,
                'totpEnabled': False, 'requireTotpAfterPasskey': False, 'credentials': {}}

    def proof(self, directory, digest, challenge, credentials):
        metadata = self.description(directory, digest)
        if credentials != {'method': 'password', 'password': 'synthetic-password'}:
            return {'schema': 'orbis.sentinel-authentication.v1', 'verified': False}
        return {'schema': 'orbis.sentinel-authentication.v1', 'verified': True, 'identitySha256': digest,
                'revision': metadata['revision'], 'accountId': 1, 'challenge': challenge, 'method': 'password',
                'verifiedAtMs': self.now, 'totpStep': None, 'credential': None}

    def begin(self, prepared):
        state = self.store.operator_status()
        return self.profiles.begin(prepared, expected_generation=state['generation'], expected_revision=state['revision'])

    def activate(self, prepared):
        pending = self.begin(prepared)
        return self.profiles.complete(prepared, change_token=pending['changeToken'], expected_generation=pending['generation'])

    def login(self):
        binding = secrets.token_urlsafe(32)
        nonce = self.store.challenge(method='password', origin=self.origin, browser_binding=binding)['challenge']
        return self.store.complete(challenge=nonce, browser_binding=binding, origin=self.origin,
                                   verifier=lambda digest, issued: self.profiles.verify(digest, issued, {'method': 'password', 'password': 'synthetic-password'}))

    def file(self, prepared=None):
        return Path(self.temp.name) / 'profiles' / (prepared or self.prepared).digest / 'identity.json'

    def key_session(self):
        key = self.store.prepare_recovery_key(origin=self.origin, expected_revision=None)
        self.store.activate_recovery_key(revision=key['revision'], recovery_key=key['recoveryKey'], expected_revision=None)
        binding = secrets.token_urlsafe(32)
        nonce = self.store.challenge(method='recovery-key', origin=self.origin, browser_binding=binding)['challenge']
        return self.store.complete_recovery_key(challenge=nonce, browser_binding=binding, origin=self.origin, recovery_key=key['recoveryKey'])

    def test_material_is_private_immutable_and_never_returned_in_prepared_metadata(self):
        file = self.file()
        self.assertEqual(file.read_bytes(), self.body('b'))
        self.assertEqual(file.stat().st_mode & 0o777, 0o600)
        for directory in (file.parent, file.parent.parent):
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        self.assertNotIn('synthetic-profile-material', repr(self.prepared))
        original = file.stat().st_ino
        same = self.profiles.prepare(self.body('b'))
        self.assertEqual(same.digest, self.prepared.digest)
        self.assertEqual(file.stat().st_ino, original)
        self.assertEqual(self.store.session(token=self.login()['token'], origin=self.origin)['accountId'], 1)

    def test_preflight_failure_happens_before_revocation_and_retains_failed_candidate(self):
        operator = self.login()
        body = self.body('c')
        self.inspect.side_effect = RuntimeError('Synthetic worker unavailable')
        with self.assertRaises(profiles.RecoveryProfileError):
            self.profiles.prepare(body)
        self.assertEqual(self.store.session(token=operator['token'], origin=self.origin)['accountId'], 1)
        candidate = Path(self.temp.name) / 'profiles' / hashlib.sha256(body).hexdigest() / 'identity.json'
        self.assertEqual(candidate.read_bytes(), body)
        self.assertEqual(self.file().read_bytes(), self.body('b'))

    def test_exact_staged_bytes_are_inspected_again_before_begin_and_completion(self):
        candidate = self.profiles.prepare(self.body('c'))
        self.inspect.reset_mock()
        pending = self.begin(candidate)
        self.assertEqual(self.store.operator_status()['state'], 'pending')
        self.assertEqual(self.inspect.call_count, 1)
        result = self.profiles.complete(candidate, change_token=pending['changeToken'], expected_generation=pending['generation'])
        self.assertEqual(result['revision'], 'c' * 64)
        self.assertEqual(self.inspect.call_count, 2)
        self.assertEqual(self.store.session(token=self.login()['token'], origin=self.origin)['accountId'], 1)

    def test_changed_worker_metadata_cannot_begin_or_activate_a_different_profile(self):
        candidate = self.profiles.prepare(self.body('c'))
        operator = self.login()
        original = self.description
        self.inspect.side_effect = lambda directory, digest: {**original(directory, digest), 'accountId': 2}
        with self.assertRaises(profiles.RecoveryProfileError):
            self.begin(candidate)
        self.assertEqual(self.store.session(token=operator['token'], origin=self.origin)['accountId'], 1)
        self.inspect.side_effect = original
        pending = self.begin(candidate)
        self.inspect.side_effect = lambda directory, digest: {**original(directory, digest), 'accountId': 2}
        with self.assertRaises(profiles.RecoveryProfileError):
            self.profiles.complete(candidate, change_token=pending['changeToken'], expected_generation=pending['generation'])
        self.inspect.side_effect = lambda directory, digest: {**original(directory, digest), 'passwordHash': 'untrusted'}
        with self.assertRaises(profiles.RecoveryProfileError):
            self.profiles.complete(candidate, change_token=pending['changeToken'], expected_generation=pending['generation'])
        self.assertEqual(self.store.operator_status()['state'], 'pending')

    def test_changed_file_is_never_overwritten_or_used_to_issue_a_session(self):
        self.file().write_bytes(self.body('c'))
        self.verify.reset_mock()
        with self.assertRaises(profiles.RecoveryProfileError):
            self.login()
        self.verify.assert_not_called()
        with self.assertRaises(profiles.RecoveryProfileError):
            self.profiles.prepare(self.body('b'))
        self.assertEqual(self.file().read_bytes(), self.body('c'))

    def test_incomplete_preparation_is_retained_and_does_not_replace_current_profile(self):
        body = self.body('c')
        digest = hashlib.sha256(body).hexdigest()
        candidate = Path(self.temp.name) / 'profiles' / digest
        candidate.mkdir(mode=0o700)
        with self.assertRaises(profiles.RecoveryProfileError):
            self.profiles.prepare(body)
        self.assertEqual(list(candidate.iterdir()), [])
        self.assertEqual(self.file().read_bytes(), self.body('b'))
        self.assertEqual(self.store.operator_status()['state'], 'enrolled')

    def test_linked_or_broadly_readable_profile_is_rejected_without_breaking_key_auth(self):
        emergency = self.key_session()
        file = self.file()
        for mode in (0o400, 0o640, 0o644):
            file.chmod(mode)
            with self.assertRaises(profiles.RecoveryProfileError):
                self.login()
        file.chmod(0o600)
        linked = Path(self.temp.name) / 'linked'
        os.link(file, linked)
        with self.assertRaises(profiles.RecoveryProfileError):
            self.login()
        linked.unlink()
        self.assertEqual(self.store.session(token=emergency['token'], origin=self.origin)['principal'], 'recovery-key')

    def test_symlinked_profile_file_or_directory_is_not_followed(self):
        file = self.file()
        saved = Path(self.temp.name) / 'saved-profile'
        file.rename(saved)
        file.symlink_to(saved)
        with self.assertRaises(profiles.RecoveryProfileError):
            self.login()
        file.unlink()
        saved.rename(file)
        directory = file.parent
        moved = directory.with_name('moved')
        directory.rename(moved)
        directory.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(profiles.RecoveryProfileError):
            self.login()

    def test_profile_mutation_during_worker_response_discards_its_proof(self):
        original = self.proof
        def changed(directory, digest, challenge, credentials):
            result = original(directory, digest, challenge, credentials)
            (Path(directory) / 'identity.json').write_bytes(self.body('c'))
            return result
        self.verify.side_effect = changed
        with self.assertRaises(profiles.RecoveryProfileError):
            self.login()
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM sessions').fetchone()[0], 0)

    def test_profile_directory_replacement_or_close_fails_before_worker_execution(self):
        base = Path(self.temp.name) / 'profiles'
        moved = base.with_name('moved')
        base.rename(moved)
        base.mkdir(mode=0o700)
        self.verify.reset_mock()
        with self.assertRaises(profiles.RecoveryProfileError):
            self.login()
        self.verify.assert_not_called()
        self.profiles.close()
        with self.assertRaises(profiles.RecoveryProfileError):
            self.profiles.prepare(self.body('c'))

    def test_owner_restart_recovers_profiles_without_persisting_process_local_preparations(self):
        digest = self.prepared.digest
        self.profiles.close()
        self.store.close()
        self.store = sessions.RecoverySessions(self.temp.name, clock=lambda: self.now)
        self.addCleanup(self.store.close)
        self.profiles = self.open(self.store)
        with self.assertRaises(profiles.RecoveryProfileError):
            self.begin(self.prepared)
        recovered = self.profiles.inspect_retained(digest)
        self.assertEqual(recovered.digest, digest)
        self.assertEqual(self.store.session(token=self.login()['token'], origin=self.origin)['accountId'], 1)

    def test_capacity_and_request_bounds_do_not_delete_or_replace_existing_material(self):
        with mock.patch.object(profiles, '_MAX_PROFILES', 2):
            self.profiles.prepare(self.body('c'))
            with self.assertRaises(profiles.RecoveryProfileError):
                self.profiles.prepare(self.body('d'))
            self.assertEqual(self.profiles.prepare(self.body('b')).digest, self.prepared.digest)
        for value in (None, {}, '', b'', b'x' * 65537):
            with self.assertRaises(profiles.RecoveryProfileError):
                self.profiles.prepare(value)
        self.assertEqual(self.file().read_bytes(), self.body('b'))

    def test_callback_cannot_expose_secrets_or_extra_authority_through_description(self):
        self.inspect.side_effect = lambda directory, digest: {**self.description(directory, digest), 'grant': 'restart'}
        with self.assertRaises(profiles.RecoveryProfileError):
            self.profiles.prepare(self.body('c'))
        self.assertEqual(self.store.operator_status()['state'], 'enrolled')
