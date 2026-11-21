"""Root counter state tests; native QA separately exercises the actual crypto worker."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest import mock

from orbis_sentinel import recovery_control as control
from orbis_sentinel import recovery_main_passkeys as main
from orbis_sentinel import recovery_profiles as profiles
from orbis_sentinel import recovery_sessions as sessions
from orbis_sentinel import recovery_incarnations as incarnations
from test_recovery_baseline import BaselineFixture
import test_recovery_worker as worker_tests

DIGEST = worker_tests.DIGEST


class MainPasskeyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='main-counter-')
        self.addCleanup(self.tmp.cleanup)
        patch = mock.patch.object(sessions, '_OWNER_UID', os.getuid())
        patch.start(); self.addCleanup(patch.stop)
        self.now = 1_800_000_000_000
        self.origin = 'https://recovery.example'
        self.key = 'cGFzc2tleQ'
        self.binding, self.ceremony = 'a' * 64, 'b' * 64
        self.counter, self.next_counter = 3, 4
        self.worker_calls = []
        self.before_proof = None
        self.proof_change = lambda value: value
        self.open()
        self.profile = self.profiles.prepare(b'{"syntheticProtectedProfile":true}')
        self.store.enroll(json.loads(self.profile._metadata))

    def describe(self, directory, digest):
        return {'schema':'orbis.sentinel-identity-description.v1','identitySha256':digest,'revision':'c'*64,
                'accountId':1,'origin':self.origin,'totpEnabled':True,'requireTotpAfterPasskey':True,
                'credentials':{self.key:self.counter}}

    def open(self):
        self.store = sessions.RecoverySessions(self.tmp.name, clock=lambda:self.now)
        self.addCleanup(self.store.close)
        self.profiles = profiles.RecoveryProfiles(self.store, inspect=self.describe, verify=lambda *a: None,
                                                  verify_counter=self.verify)
        self.addCleanup(self.profiles.close)
        self.app = main.RecoveryMainPasskeys(self.store,self.profiles,origin=self.origin)

    def verify(self,directory,digest,challenge,body):
        self.worker_calls.append((digest,challenge,copy.deepcopy(body)))
        self.assertIsNone(self.store._db.execute('SELECT record FROM main_passkey_challenges WHERE digest=?',
                         (sessions._token(challenge),)).fetchone())
        if self.before_proof: self.before_proof()
        return self.proof_change({'schema':'orbis.sentinel-passkey-counter.v1','verified':True,'accountId':1,
            'revision':'c'*64,'identitySha256':digest,'challenge':challenge,'verifiedAtMs':self.now,
            'credential':{'id':self.key,'previousCounter':self.counter,'newCounter':self.next_counter}})

    def challenge(self,**changes):
        return self.app.challenge(**{'admission_binding':self.binding,'purpose':'login','ceremony_binding':self.ceremony,**changes})

    def complete(self,issued,response=None,**changes):
        return self.app.complete(**{'challenge':issued['challenge'],'admission_binding':self.binding,'purpose':'login',
            'ceremony_binding':self.ceremony,'response':response or {'id':self.key,'signedFixture':True},**changes})

    def floor(self):
        return self.store._db.execute('SELECT counter FROM counters WHERE credential=?',(self.key,)).fetchone()[0]

    def test_counter_only_proof_advances_floor_without_root_session_or_totp_consumption(self):
        issued=self.challenge(); result=self.complete(issued)
        self.assertEqual(result['schema'],'orbis.sentinel-main-passkey-counter.v1')
        self.assertEqual((result['previousCounter'],result['newCounter']),(3,4))
        self.assertEqual(self.floor(),4)
        self.assertEqual(self.worker_calls[0][2],{'response':{'id':self.key,'signedFixture':True}})
        for table in ('sessions','factors','attempts','challenges'):
            self.assertEqual(self.store._db.execute('SELECT count(*) FROM '+table).fetchone()[0],0)
        self.assertEqual(self.store.operator_status(),{'generation':1,'revision':'c'*64,'state':'enrolled'})

    def test_exact_lost_reply_retry_uses_durable_receipt_without_repeating_crypto_or_counter(self):
        issued=self.challenge(); result=self.complete(issued)
        self.assertEqual(self.complete(issued),result)
        self.assertEqual(len(self.worker_calls),1)
        self.profiles.close();self.store.close();self.open()
        self.assertEqual(self.complete(issued),result)
        self.assertEqual(len(self.worker_calls),1)
        self.assertEqual(self.floor(),4)

    def test_retry_after_another_valid_advance_cannot_lower_current_floor(self):
        first=self.challenge(); result=self.complete(first)
        self.next_counter=5
        second=self.challenge();self.complete(second)
        self.assertEqual(self.complete(first),result)
        self.assertEqual(self.floor(),5)
        self.assertEqual(len(self.worker_calls),2)

    def test_receipt_is_bound_to_exact_assertion_controller_purpose_and_browser_action(self):
        issued=self.challenge();self.complete(issued)
        for changes in ({'response':{'id':self.key,'signedFixture':False}}, {'admission_binding':'d'*64},
                        {'purpose':'sensitive'},{'ceremony_binding':'e'*64}):
            with self.subTest(changes=changes),self.assertRaises(ValueError): self.complete(issued,**changes)
        self.assertEqual(self.floor(),4);self.assertEqual(len(self.worker_calls),1)

    def test_zero_counter_still_requires_fresh_consumed_root_nonce(self):
        self.counter=0;self.next_counter=0
        # This is an explicit new fixture authority; never reset an existing floor.
        self.profiles.close();self.store.close()
        self.tmp.cleanup();self.tmp=tempfile.TemporaryDirectory(prefix='main-zero-');self.addCleanup(self.tmp.cleanup)
        self.open();self.profile=self.profiles.prepare(b'{"zeroCounterFixture":true}');self.store.enroll(json.loads(self.profile._metadata))
        issued=self.challenge();self.complete(issued)
        self.assertEqual(self.floor(),0)
        with self.assertRaises(ValueError): self.complete(issued,response={'different':'assertion'})
        self.assertEqual(len(self.worker_calls),1)
        self.complete(self.challenge());self.assertEqual(len(self.worker_calls),2)

    def test_failed_crypto_consumes_nonce_and_has_no_receipt_or_floor_change(self):
        issued=self.challenge();self.proof_change=lambda value:{'schema':'orbis.sentinel-passkey-counter.v1','verified':False}
        with self.assertRaises(ValueError):self.complete(issued)
        with self.assertRaises(ValueError):self.complete(issued)
        self.assertEqual(len(self.worker_calls),1);self.assertEqual(self.floor(),3)
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM main_passkey_receipts').fetchone()[0],0)

    def test_root_session_authentication_proof_cannot_be_used_as_counter_proof(self):
        issued=self.challenge()
        self.proof_change=lambda value:{**value,'schema':'orbis.sentinel-authentication.v1','method':'passkey','totpStep':1}
        with self.assertRaises(ValueError):self.complete(issued)
        self.assertEqual(self.floor(),3)

    def test_proof_cannot_change_identity_nonce_account_time_or_credential(self):
        for change in ({'revision':'d'*64},{'identitySha256':'e'*64},{'challenge':secrets.token_urlsafe(32)},
                       {'accountId':True},{'verifiedAtMs':self.now-6000},
                       {'credential':{'id':'b3RoZXI','previousCounter':3,'newCounter':4}}):
            with self.subTest(change=change):
                issued=self.challenge();self.proof_change=lambda value,change=change:{**value,**change}
                with self.assertRaises(ValueError):self.complete(issued)
                self.assertEqual(self.floor(),3)

    def test_worker_cannot_supply_boolean_or_stale_counter_authority(self):
        for change in ({'previousCounter':4},{'previousCounter':True},{'newCounter':3},
                       {'newCounter':2},{'newCounter':True},{'newCounter':0x100000000},{'extra':1}):
            with self.subTest(change=change):
                self.proof_change=lambda value,change=change:{**value,'credential':{**value['credential'],**change}}
                with self.assertRaises(ValueError):self.complete(self.challenge())
                self.assertEqual(self.floor(),3)
        self.assertEqual(len(self.worker_calls),7)

    def test_missing_counter_worker_and_boolean_callback_never_grant_authority(self):
        self.profiles._verify_counter_worker=None
        with self.assertRaises(profiles.RecoveryProfileError):self.complete(self.challenge())
        self.profiles._verify_counter_worker=lambda *args:True
        with self.assertRaises(ValueError):self.complete(self.challenge())
        self.assertEqual(self.floor(),3)
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM sessions').fetchone()[0],0)

    def test_corrupt_receipt_numeric_alias_is_refused_without_crypto(self):
        issued=self.challenge();self.complete(issued)
        nonce=sessions._token(issued['challenge'])
        saved=json.loads(self.store._db.execute('SELECT record FROM main_passkey_receipts WHERE digest=?',(nonce,)).fetchone()[0])
        for key in ('generation','accountId','expiresAtMs'):
            value=copy.deepcopy(saved);value['result'][key]=True
            self.store._db.execute('UPDATE main_passkey_receipts SET record=? WHERE digest=?',(json.dumps(value),nonce))
            with self.subTest(key=key),self.assertRaises(ValueError):self.complete(issued)
        self.assertEqual(self.floor(),4);self.assertEqual(len(self.worker_calls),1)

    def test_current_floor_is_checked_after_worker_not_only_when_nonce_was_issued(self):
        issued=self.challenge()
        self.before_proof=lambda:self.store._transaction(lambda:self.store._db.execute('UPDATE counters SET counter=8 WHERE credential=?',(self.key,)))
        with self.assertRaises(ValueError):self.complete(issued)
        self.assertEqual(self.floor(),8)

    def test_authority_change_during_worker_refuses_proof_and_keeps_emergency_key(self):
        pending=self.store.prepare_recovery_key(origin=self.origin,expected_revision=None)
        self.store.activate_recovery_key(revision=pending['revision'],recovery_key=pending['recoveryKey'],expected_revision=None)
        issued=self.challenge()
        self.before_proof=lambda:self.store.revoke_operator(expected_generation=1,expected_revision='c'*64)
        with self.assertRaises(ValueError):self.complete(issued)
        self.assertEqual(self.floor(),3)
        self.assertTrue(self.store.authentication_options()['recoveryKey'])

    def test_emergency_key_can_authenticate_inside_counter_worker_without_main_namespace(self):
        pending=self.store.prepare_recovery_key(origin=self.origin,expected_revision=None)
        self.store.activate_recovery_key(revision=pending['revision'],recovery_key=pending['recoveryKey'],expected_revision=None)
        def emergency():
            binding=secrets.token_urlsafe(32)
            challenge=self.store.challenge(method='recovery-key',origin=self.origin,browser_binding=binding)
            result=self.store.complete_recovery_key(challenge=challenge['challenge'],browser_binding=binding,
                origin=self.origin,recovery_key=pending['recoveryKey'])
            self.assertEqual(self.store.session(token=result['token'],origin=self.origin,touch=False)['method'],'recovery-key')
        self.before_proof=emergency
        self.complete(self.challenge())
        self.assertEqual(self.floor(),4)

    def test_nonce_expiry_restart_and_generation_changes_refuse_without_worker(self):
        issued=self.challenge();self.now+=120001
        with self.assertRaises(ValueError):self.complete(issued)
        self.assertEqual(self.worker_calls,[])
        issued=self.challenge();self.profiles.close();self.store.close();self.open()
        with self.assertRaises(ValueError):self.complete(issued)
        self.assertEqual(self.worker_calls,[])
        issued=self.challenge();self.store.revoke_operator(expected_generation=1,expected_revision='c'*64)
        with self.assertRaises(ValueError):self.complete(issued)
        self.assertEqual(self.worker_calls,[])

    def test_main_challenge_capacity_and_rate_do_not_consume_recovery_challenge_quota(self):
        issued=[self.challenge() for _ in range(32)]
        with self.assertRaises(ValueError):self.challenge()
        self.assertTrue(self.store.challenge(method='passkey',origin=self.origin,browser_binding=secrets.token_urlsafe(32)))
        self.proof_change=lambda value:{'schema':'orbis.sentinel-passkey-counter.v1','verified':False}
        for item in issued[:10]:
            with self.assertRaises(ValueError):self.complete(item)
        with self.assertRaises(ValueError):self.complete(issued[10])
        self.assertEqual(len(self.worker_calls),10)
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM attempts').fetchone()[0],0)

    def test_expired_receipts_are_pruned_and_cannot_be_replayed_as_new_nonce(self):
        issued=self.challenge();self.complete(issued);self.now+=120001
        self.challenge()
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM main_passkey_receipts').fetchone()[0],0)
        with self.assertRaises(ValueError):self.complete(issued)

    def test_control_accepts_only_fixed_fields_and_never_exposes_recovery_session_tokens(self):
        app=control.RecoveryControl(sessions=self.store,profiles=self.profiles,origin=self.origin,main_passkeys=self.app)
        def call(operation,arguments):return app.handle({'schema':control._SCHEMA,'operation':operation,'arguments':arguments})
        args={'admissionBinding':self.binding,'purpose':'login','ceremonyBinding':self.ceremony}
        result=call('main-passkey-challenge',args)
        self.assertTrue(result['ok']);issued=result['result']
        result=call('main-passkey-complete',{**args,'challenge':issued['challenge'],'response':{'id':self.key}})
        self.assertTrue(result['ok']);self.assertNotIn('token',json.dumps(result));self.assertNotIn('csrf',json.dumps(result))
        self.assertFalse(call('main-passkey-challenge',{**args,'counter':9})['ok'])


class MainCounterFloorsTests(BaselineFixture,unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.factory.inspect_effective=self.effective

    def effective(self,directory,digest,counters):
        value=self.read(directory,digest)
        original=self.description(directory,digest)
        value['counter']=counters[self.credential]
        bound={key:item for key,item in value.items() if key!='revision'}
        return {'schema':'orbis.sentinel-effective-identity-content.v1','identitySha256':digest,
            'contentSha256':hashlib.sha256(incarnations._encoded(bound).encode()).hexdigest(),'description':original}

    def floors(self,body=None,**changes):
        return self.factory.counter_floors(body or self.body(),**{'expected_generation':1,'expected_revision':'a'*64,**changes})

    def advance(self,value=4):
        self.store._transaction(lambda:self.store._db.execute('UPDATE counters SET counter=? WHERE credential=?',(value,self.credential)))

    def test_stale_main_can_read_bound_floor_but_baseline_requires_actual_catchup(self):
        self.advance()
        result=self.floors()
        self.assertEqual(result['counters'],{self.credential:4})
        self.assertEqual(result['sourceSha256'],hashlib.sha256(self.body()).hexdigest())
        with self.assertRaises(profiles.RecoveryProfileError):self.check()
        self.assertEqual(self.check(self.body(counter=4))['generation'],1)
        self.assertEqual(self.store.operator_status()['revision'],'a'*64)

    def test_main_ahead_private_drift_wrong_realm_or_missing_floor_never_admits(self):
        self.advance()
        for body in (self.body(counter=5),self.body(private='wrong'),self.body(origin='https://other.example')):
            with self.subTest(body=body),self.assertRaises(profiles.RecoveryProfileError):self.floors(body)
        self.store._db.execute('DELETE FROM counters')
        with self.assertRaises(profiles.RecoveryProfileError):self.floors()

    def test_floor_advancing_after_effective_worker_inspection_refuses_snapshot(self):
        self.advance();original=self.effective;calls=[]
        def changing(*args):
            value=original(*args);calls.append(True)
            if len(calls)==1:self.advance(5)
            return value
        self.factory.inspect_effective=changing
        with self.assertRaises(profiles.RecoveryProfileError):self.floors()

    def test_old_worker_has_no_advanced_floor_fallback(self):
        self.advance();self.factory.inspect_effective=None
        with self.assertRaises(profiles.RecoveryProfileError):self.floors()
        with self.assertRaises(profiles.RecoveryProfileError):self.check(self.body(counter=4))

    def test_effective_proof_must_describe_original_profile_and_full_private_content(self):
        self.advance();original=self.effective
        def changed(directory,digest,counters):
            result=original(directory,digest,counters);result['description']['credentials'][self.credential]=4
            return result
        self.factory.inspect_effective=changed
        with self.assertRaises(profiles.RecoveryProfileError):self.floors()

    def test_control_floor_read_is_fixed_and_bound_without_authority_mutation(self):
        self.advance()
        app=control.RecoveryControl(sessions=self.store,profiles=self.profiles,origin=self.origin,incarnations=self.factory)
        args={'identityBase64':base64.b64encode(self.body()).decode('ascii'),'expectedGeneration':1,'expectedRevision':'a'*64}
        def call(fields):return app.handle({'schema':control._SCHEMA,'operation':'main-passkey-floors','arguments':fields})
        result=call(args)
        self.assertTrue(result['ok']);self.assertEqual(result['result'],self.floors())
        for fields in ({**args,'counters':{self.credential:9}},{**args,'expectedGeneration':2},
                       {**args,'identityBase64':base64.b64encode(self.body(counter=5)).decode('ascii')}):
            with self.subTest(fields=fields):self.assertFalse(call(fields)['ok'])
        self.assertEqual(self.store.operator_status(),{'generation':1,'revision':'a'*64,'state':'enrolled'})

    def test_bound_baseline_rechecks_floor_in_same_revocation_transaction(self):
        self.advance()
        with self.profiles._operation():
            proof=self.factory._baseline(self.body(counter=4),1,'a'*64)
        request={'baseline':proof.source,'origin':self.origin,'generation':1,'revision':'a'*64}
        self.advance(5)
        with self.assertRaises(profiles.RecoveryProfileError):
            self.store._transaction(lambda:incarnations._assert_baseline(self.store,proof,request))
        self.assertEqual(self.store.operator_status()['state'],'enrolled')


class MainCounterWorkerModesTests(unittest.TestCase):
    setUp=worker_tests.RecoveryWorkerTests.setUp
    open=worker_tests.RecoveryWorkerTests.open
    receipt=worker_tests.RecoveryWorkerTests.receipt

    def test_counter_worker_uses_distinct_mode_and_only_assertion_stdin(self):
        challenge=secrets.token_urlsafe(32);body={'response':{'id':'synthetic'}}
        self.adapter.verify_counter(self.directory,DIGEST,challenge,body)
        create=next(args for args,_ in self.runner.calls if args[0]=='create')
        self.assertEqual(create[-3:],['--verify-counter',DIGEST,challenge])
        start=next(options for args,options in self.runner.calls if args[0]=='start')
        self.assertEqual(json.loads(start['body']),body);self.assertEqual(start['limit'],8192)
        self.assertFalse(self.runner.present)

    def test_effective_worker_receives_only_exact_floor_vector_and_keeps_description_bound(self):
        counters={'c3ludGhldGlj':9};self.adapter.inspect_effective_content(self.directory,DIGEST,counters)
        create=next(args for args,_ in self.runner.calls if args[0]=='create')
        self.assertEqual(create[-2:],['--describe-effective-content',DIGEST])
        start=next(options for args,options in self.runner.calls if args[0]=='start')
        self.assertEqual(json.loads(start['body']),{'counters':counters});self.assertEqual(start['limit'],32768)
        self.assertFalse(self.runner.present)


if __name__=='__main__':unittest.main()
