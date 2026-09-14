"""Adversarial contract tests; synthetic images never execute."""
import copy,hashlib,io,json,sys,tarfile,tempfile,unittest,uuid,urllib.error
from pathlib import Path
from datetime import datetime,timezone,timedelta
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'appliance'))
from ota.package import verify,InvalidPackage,digest
from ota.common import window_open
from ota import transport

class Packages(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.key=Ed25519PrivateKey.generate();self.pub=self.root/'release.pub'
        self.pub.write_bytes(self.key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        self.payload={'code/.version':b'0.2.1\n','code/migrations.json':b'[]','images/application.tar':b'synthetic image'}
        self.manifest={'format_version':3,'recipe':'zenshield-container-v1','product_id':'zenshield-test','arch':'amd64','os_min':'ubuntu-24.04','version':'0.2.1','min_version':'0.2.0','image':'zenshield:0.2.1','image_id':'sha256:'+'a'*64,'release_date':datetime.now(timezone.utc).isoformat(),'update_id':str(uuid.uuid4())}
    def tearDown(self):self.tmp.cleanup()
    def build(self,change=None,payload=None,extra=None,signature=None,inventory_change=False,tamper=False):
        payload=payload or self.payload;m={**self.manifest,**(change or {})}
        inventory=''.join(hashlib.sha256(v).hexdigest()+'  '+k+'\n' for k,v in sorted(payload.items())).encode()
        m['inventory_sha256']=hashlib.sha256(inventory).hexdigest()
        raw=json.dumps(m).encode();items={'manifest.json':raw,'manifest.json.sig':signature or self.key.sign(raw),'checksums.sha256':inventory+b'x' if inventory_change else inventory,**payload}
        if tamper:items['images/application.tar']=b'tampered image'
        archive=self.root/'release.zup'
        with tarfile.open(archive,'w:gz') as tar:
            for name,data in items.items():
                info=tarfile.TarInfo(name);info.size=len(data);tar.addfile(info,io.BytesIO(data))
            if extra:
                info=tarfile.TarInfo(extra[0]);info.type=extra[1];tar.addfile(info)
        return archive
    def check(self,archive,**kw):return verify(archive,self.pub,'zenshield-test','0.2.0',**kw)
    def test_valid_extract(self):
        dest=self.root/'verified';self.check(self.build(),destination=dest)
        self.assertEqual((dest/'code/.version').read_bytes(),b'0.2.1\n')
    def test_wrong_product(self):
        with self.assertRaises(InvalidPackage):self.check(self.build({'product_id':'zenplus'}))
    def test_signature(self):
        with self.assertRaises(InvalidPackage):self.check(self.build(signature=b'x'*64))
    def test_inventory_binding(self):
        with self.assertRaises(InvalidPackage):self.check(self.build(inventory_change=True))
    def test_payload_tampering(self):
        with self.assertRaises(InvalidPackage):self.check(self.build(tamper=True))
    def test_target_and_versions(self):
        for change in ({'arch':'arm64'},{'os_min':'ubuntu-22.04'},{'version':'0.2.0'},{'version':'0.1.0'},{'min_version':'0.3.0'},{'image':'zenshield:latest'}):
            with self.subTest(change=change),self.assertRaises(InvalidPackage):self.check(self.build(change))
    def test_date(self):
        for days in (-181,2):
            with self.subTest(days=days),self.assertRaises(InvalidPackage):self.check(self.build({'release_date':(datetime.now(timezone.utc)+timedelta(days=days)).isoformat()}))
    def test_paths_types_duplicates(self):
        for name,kind in [('../escape',tarfile.REGTYPE),('/absolute',tarfile.REGTYPE),('link',tarfile.SYMTYPE),('hard',tarfile.LNKTYPE),('dir',tarfile.DIRTYPE),('manifest.json',tarfile.REGTYPE)]:
            with self.subTest(name=name),self.assertRaises(InvalidPackage):self.check(self.build(extra=(name,kind)))
    def test_secrets_and_untracked(self):
        with self.assertRaises(InvalidPackage):self.check(self.build(payload={**self.payload,'code/.env':b'secret'}))
        with self.assertRaises(InvalidPackage):self.check(self.build(payload={**self.payload,'code/migrations/postgres/001.sql':b'SELECT 1'}))
    def test_offer_mismatch(self):
        archive=self.build();offer={k:self.manifest[k] for k in ('product_id','version','min_version','arch')};offer['package_sha256']=digest(archive);offer['product_id']='zenplus'
        with self.assertRaises(InvalidPackage):self.check(archive,offer=offer)
    def test_hash_mismatch(self):
        with self.assertRaises(InvalidPackage):self.check(self.build(),offer={'package_sha256':'0'*64})
    def test_missing_payload(self):
        with self.assertRaises(InvalidPackage):self.check(self.build(payload={'code/.version':b'0.2.1'}))
    def test_window_boundaries(self):
        c={'window_start':'23:00','window_end':'02:00'}
        for hour,expected in [(23,True),(0,True),(1,True),(2,False),(22,False)]:self.assertEqual(window_open(c,datetime(2026,1,1,hour,tzinfo=timezone.utc)),expected)
    def test_product_response_isolation(self):
        with self.assertRaises(ValueError):transport.product({'product_id':'zenshield','product_field':'product'},{'product':'zenplus'})
    def test_https_only(self):
        for value in ('http://zentryc.com','https://user:password@zentryc.com','https://zentryc.com/#secret'):
            with self.assertRaises(ValueError):transport.origin(value)
    def test_outbox_retry(self):
        with patch.object(transport,'STATE',self.root),patch.object(transport,'request',side_effect=ValueError('offline')):
            event=transport.queue_report({'release_id':'r1','version':'0.2.1'},'success','0.2.0');transport.flush({'api_key':'test','routes':{'report':'/api/report'}})
            self.assertTrue((self.root/'outbox'/(event+'.json')).exists())
        with patch.object(transport,'STATE',self.root),patch.object(transport,'request',return_value={}) as request:
            transport.flush({'api_key':'test','routes':{'report':'/api/report'}});self.assertEqual(request.call_args.args[-1],event)
            self.assertFalse((self.root/'outbox'/(event+'.json')).exists())
    def test_download_restarts_full_response(self):
        target=self.root/'download.zup';target.write_bytes(b'partial bytes')
        c={'ca_file':None,'origin':'https://api.example','download_origins':['https://api.example'],'api_key':'test','appliance_id':'test'}
        with patch.object(transport.urllib.request,'build_opener') as factory:
            factory.return_value.open.return_value=io.BytesIO(b'complete bytes')
            transport.download(c,{'package_url':'https://api.example/package','package_sha256':hashlib.sha256(b'complete bytes').hexdigest()},target)
            self.assertEqual(target.read_bytes(),b'complete bytes')
            self.assertIsNone(factory.return_value.open.call_args.args[0].get_header('Range'))
            self.assertEqual(factory.return_value.open.call_args.args[0].get_header('User-agent'),'zenshield-updater/1')
    def test_redirect_does_not_forward_credentials(self):
        c={'ca_file':None,'origin':'https://api.example','download_origins':['https://api.example','https://cdn.example'],'api_key':'test','appliance_id':'test'}
        with patch.object(transport.urllib.request,'build_opener') as factory:
            factory.return_value.open.side_effect=[urllib.error.HTTPError('https://api.example/package',302,'redirect',{'Location':'https://cdn.example/package'},None),io.BytesIO(b'bytes')]
            transport.download(c,{'package_url':'https://api.example/package','package_sha256':hashlib.sha256(b'bytes').hexdigest()},self.root/'download')
            first,second=factory.return_value.open.call_args_list
            self.assertEqual(first.args[0].get_header('Authorization'),'Bearer test')
            self.assertIsNone(second.args[0].get_header('Authorization'))
            self.assertEqual(second.args[0].get_header('User-agent'),'zenshield-updater/1')
    def test_untrusted_redirect_rejected(self):
        c={'ca_file':None,'origin':'https://api.example','download_origins':['https://api.example'],'api_key':'test','appliance_id':'test'}
        with patch.object(transport.urllib.request,'build_opener') as factory:
            factory.return_value.open.side_effect=urllib.error.HTTPError('https://api.example/package',302,'redirect',{'Location':'https://untrusted.example/package'},None)
            with self.assertRaises(ValueError):transport.download(c,{'package_url':'https://api.example/package'},self.root/'download')
            self.assertEqual(factory.return_value.open.call_count,1)

if __name__=='__main__':unittest.main(verbosity=2)
