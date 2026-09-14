"""Linux client verification tests for signed, device-bound licensing."""
import base64,copy,hashlib,json,secrets,sys,tempfile,unittest
from datetime import datetime,timedelta,timezone
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'appliance'))
from ota import transport,common

class ClientLicenceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.server=Ed25519PrivateKey.generate();public=self.server.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        for target,name,value in [(transport,'STATE',self.root),(common,'STATE',self.root),(common,'CONFIG',self.root/'config.json'),
            (transport,'LICENSE_IDENTITY',self.root/'identity.json'),(transport,'LICENSE_CACHE',self.root/'licence.json'),(transport,'LICENSE_HEALTH',self.root/'health.json'),(transport,'LICENSE_PUBLIC_KEY',public)]:
            p=patch.object(target,name,value);p.start();self.addCleanup(p.stop)
        p=patch.object(transport,'_hardware_fingerprint',return_value='1'*64);self.hardware=p.start();self.addCleanup(p.stop)
        common.write(common.CONFIG,{**common.DEFAULT,'contract_confirmed':True,'api_key':'a'*64,'appliance_id':'test-appliance'})
        self.key,self.public,self.fingerprint,_=transport._identity()
        at=datetime.now(timezone.utc)
        self.payload={'format':1,'product_id':'zenai','appliance_id':'test-appliance','key_fingerprint':self.fingerprint,'hardware_fingerprint':'1'*64,
            'issued_at':at.isoformat(),'refresh_by':(at+timedelta(hours=24)).isoformat(),'request_nonce':'b'*64,'revision':'revision',
            'licence':{'status':'trial','kind':'trial','expires_at':(at+timedelta(days=30)).isoformat(),'unlimited':True}}

    def envelope(self,payload=None):
        payload=payload or self.payload
        return {'payload':payload,'signature':base64.b64encode(self.server.sign(transport._canonical(payload))).decode()}

    def test_valid_signature_and_nonce(self):
        self.assertEqual(transport._verify_licence(self.envelope(),'test-appliance',self.fingerprint,'b'*64)['licence']['status'],'trial')

    def test_changed_expiry_rejected(self):
        envelope=self.envelope();envelope['payload']['licence']['expires_at']=None
        with self.assertRaises(ValueError):transport._verify_licence(envelope,'test-appliance',self.fingerprint)

    def test_other_device_rejected(self):
        with self.assertRaises(ValueError):transport._verify_licence(self.envelope(),'another-appliance',self.fingerprint)

    def test_cloned_hardware_rejected(self):
        self.hardware.return_value='2'*64
        with self.assertRaises(ValueError):transport._verify_licence(self.envelope(),'test-appliance',self.fingerprint)

    def test_other_product_rejected_even_with_valid_signature(self):
        self.payload['product_id']='ota'
        with self.assertRaises(ValueError):transport._verify_licence(self.envelope(),'test-appliance',self.fingerprint)

    def test_old_nonce_cannot_be_replayed_as_new_sync(self):
        with self.assertRaises(ValueError):transport._verify_licence(self.envelope(),'test-appliance',self.fingerprint,'c'*64)

    def test_cached_trial_expires_without_network(self):
        self.payload['licence']['expires_at']=(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
        common.write(transport.LICENSE_CACHE,self.envelope())
        self.assertEqual(transport.licence_status()['status'],'expired')

    def test_stale_cached_licence_shows_stale(self):
        self.payload['refresh_by']=(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
        common.write(transport.LICENSE_CACHE,self.envelope())
        self.assertTrue(transport.licence_status()['stale'])

    def test_invalid_cache_is_not_reported_active(self):
        common.write(transport.LICENSE_CACHE,{'payload':{},'signature':'invalid'})
        self.assertEqual(transport.licence_status()['status'],'verification_failed')

    def test_identity_persists_and_is_private(self):
        self.assertEqual(transport._identity()[2],self.fingerprint)
        self.assertEqual(transport.LICENSE_IDENTITY.stat().st_mode&0o777,0o600)

    def test_public_status_contains_no_private_keys_or_api_key(self):
        common.write(transport.LICENSE_CACHE,self.envelope())
        value=json.dumps(transport.licence_status())
        self.assertNotIn('a'*64,value);self.assertNotIn('private_key',value);self.assertNotIn('signature',value)

    def test_registration_signs_challenge_and_caches_bound_licence(self):
        common.write(common.CONFIG,{**common.DEFAULT,'contract_confirmed':True})
        proof={'purpose':'zenshield-enrollment-v1','challenge_id':'test-challenge','nonce':'e'*64,'public_key':self.public,'hardware_fingerprint':'1'*64}
        def request(c,route,data=None,event_id=None):
            if route.endswith('/challenge'):return {'product_id':'zenai','challenge_id':'test-challenge','message':base64.b64encode(transport._canonical(proof)).decode()}
            if route.endswith('/complete'):
                self.key.public_key().verify(base64.b64decode(data['signature']),transport._canonical(proof))
                payload=copy.deepcopy(self.payload);payload['request_nonce']=data['nonce']
                return {'product_id':'zenai','appliance_id':'test-appliance','api_key':'a'*64,'licence':self.envelope(payload)}
            payload=copy.deepcopy(self.payload);payload['request_nonce']=data['nonce']
            return {'product_id':'zenai','licence':self.envelope(payload)}
        with patch.object(transport,'request',side_effect=request):result=transport.sync_licence()
        self.assertEqual(result['status'],'trial');self.assertTrue(result['registered'])

if __name__=='__main__':unittest.main(verbosity=2)
