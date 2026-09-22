#!/usr/bin/env python3
"""Deterministic Linux bundles; no downloads, install, signing or service changes."""
import argparse,hashlib,io,json,os,pathlib,subprocess,tarfile
p=argparse.ArgumentParser();p.add_argument('--out',required=True,type=pathlib.Path);p.add_argument('--arch',choices=['amd64','arm64'],required=True);args=p.parse_args()
root=pathlib.Path(__file__).resolve().parent.parent
version=subprocess.check_output(['go','env','GOVERSION'],text=True).strip()
if version!='go1.24.2':raise SystemExit('Use pinned Go 1.24.2')
args.out.mkdir(parents=True,exist_ok=True)
env=dict(os.environ,GOOS='linux',GOARCH=args.arch,CGO_ENABLED='0',GOTOOLCHAIN='local',GOPROXY='off',GOSUMDB='off')
subprocess.run(['go','mod','verify'],cwd=root,env=env,check=True)
files={}
for name in ['koinos-bridge-validator','vortex-operator','vortex-keys','vortex-candidate-check','vortex-host']:
 target=args.out/name
 subprocess.run(['go','build','-mod=readonly','-trimpath','-buildvcs=false','-ldflags=-buildid=','-o',str(target.resolve()),'./cmd/'+name],cwd=root,env=env,check=True)
 files[name]=target.read_bytes()
files['vortex-operator.service']=(root/'packaging/vortex-operator.service').read_bytes()
archive=args.out/('vortex-host-linux-'+args.arch+'.tar')
with tarfile.open(archive,'w',format=tarfile.USTAR_FORMAT) as tar:
 for name,data in sorted(files.items()):
  info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o600 if name.endswith('.service') else 0o700;info.mtime=0
  tar.addfile(info,io.BytesIO(data))
manifest={'platform':'linux-'+args.arch,'toolchain':version,'sourceCommit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'dirty':bool(subprocess.check_output(['git','status','--porcelain'],cwd=root)), 'goSumSha256':hashlib.sha256((root/'go.sum').read_bytes()).hexdigest(),'artifactSha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'size':archive.stat().st_size,'files':{k:hashlib.sha256(v).hexdigest() for k,v in files.items()},'approval':'unsigned development artifact; separate publisher signatures and local approval required'}
(args.out/'build.json').write_text(json.dumps(manifest,indent=2)+'\n');os.chmod(archive,0o600)
print(json.dumps(manifest,indent=2))
