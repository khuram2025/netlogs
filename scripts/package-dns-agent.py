"""Package only public agent artifacts. Configuration and credentials are never included."""
import hashlib,zipfile,shutil,sys
from pathlib import Path
root=Path(__file__).resolve().parents[1];publish=Path(sys.argv[1]);release=root/'appliance/dns-agent-release';release.mkdir(exist_ok=True)
files={'ZenShield.DnsAgent.exe':publish/'ZenShield.DnsAgent.exe',
       'Install-ZenShieldDnsAgent.ps1':root/'appliance/dns-agent/Install-ZenShieldDnsAgent.ps1',
       'README.md':root/'appliance/dns-agent/README.md',
       'packages.lock.json':root/'appliance/dns-agent/packages.lock.json'}
runtime=Path.home()/'.nuget/packages/microsoft.netcore.app.runtime.win-x64/10.0.12'
for name in ('LICENSE.TXT','THIRD-PARTY-NOTICES.TXT'):files[name]=runtime/name
manifest=''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+name+'\n' for name,p in files.items())
archive=release/'ZenShield-DNS-Agent-1.0.0.zip'
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
 for name,p in files.items():z.write(p,name)
 z.writestr('SHA256SUMS.txt',manifest)
(release/'SHA256SUMS.txt').write_text(manifest+hashlib.sha256(archive.read_bytes()).hexdigest()+'  '+archive.name+'\n')
shutil.copyfile(files['README.md'],release/'README.md')
print('Public DNS agent package created:',archive.name,'bytes:',archive.stat().st_size)
