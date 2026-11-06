import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync, copyFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, dirname, resolve} from 'node:path';
import {execFileSync, spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {gunzipSync} from 'node:zlib';
import {fileURLToPath} from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const audit = join(root,'scripts/audit-publication.mjs');
function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(),'p2p-publication-'));
  t.after(()=>rmSync(dir,{recursive:true,force:true}));
  return dir;
}
function put(dir,path,text,mode=0o600) {
  mkdirSync(dirname(join(dir,path)),{recursive:true});
  writeFileSync(join(dir,path),text,{mode});
}
function git(dir,...args) {
  return execFileSync('git',args,{cwd:dir,encoding:'utf8',stdio:['ignore','pipe','pipe']});
}
function repo(t) {
  const dir=fixture(t);
  git(dir,'init','-q');
  git(dir,'config','user.name','Project contributors');
  git(dir,'config','user.email','project@localhost.invalid');
  put(dir,'.gitignore','profile/\ndist/\n');
  put(dir,'README.md','A terminal messenger.\n');
  git(dir,'add','.'); git(dir,'commit','-qm','Initial source');
  return dir;
}
function scan(dir,...args) {
  return spawnSync(process.execPath,[audit,...args],{cwd:dir,encoding:'utf8'});
}

test('publication guard excludes ignored profiles and accepts example addresses',t=>{
  const dir=repo(t);
  put(dir,'profile/identity.key','local private material');
  put(dir,'profile/state.json','local private chat');
  put(dir,'example.md','/ip4/203.0.113.10 /ip6/2001:db8::1 person@example.org');
  const r=scan(dir,'--history'); assert.equal(r.status,0,r.stderr);
});

test('publication guard catches old personal data after the last tree is cleaned',t=>{
  const dir=repo(t);
  // Build the fixture string at runtime so this test has no live address itself.
  const address=[1,1,1,1].join('.');
  put(dir,'old.md',address); git(dir,'add','.'); git(dir,'commit','-qm','Old fixture');
  put(dir,'old.md','PUBLIC_IP'); git(dir,'add','.'); git(dir,'commit','-qm','Redact fixture');
  assert.equal(scan(dir).status,0);
  const r=scan(dir,'--history'); assert.equal(r.status,1);
  assert.match(r.stderr,/non-example IPv4/); assert(!r.stderr.includes(address));
});

test('intentional endpoint disclosure is allowed only in public-peers.txt, including identical history blobs',t=>{
  const dir=repo(t), id='12D3'+'KooW'+'A'.repeat(44);
  const entry='/ip4/'+[1,1,1,1].join('.')+'/tcp/80/ws/p2p/'+id+'\n';
  put(dir,'public-peers.txt',entry);
  git(dir,'add','.');git(dir,'commit','-qm','Community registry fixture');
  assert.equal(scan(dir,'--history').status,0);
  put(dir,'README.md',entry);
  git(dir,'add','.');git(dir,'commit','-qm','Accidental disclosure fixture');
  put(dir,'README.md','Clean latest tree');
  git(dir,'add','.');git(dir,'commit','-qm','Remove disclosure fixture');
  const r=scan(dir,'--history');assert.equal(r.status,1);assert.match(r.stderr,/README.md/);
  const token='github'+'_pat_'+'b'.repeat(30);
  put(dir,'public-peers.txt',entry+'# '+token+'\n');
  assert.match(scan(dir).stderr,/private key \/ token/);
});

test('publication guard reports secrets; private author metadata checks are optional',t=>{
  const dir=repo(t), token='github'+'_pat_'+'a'.repeat(30);
  put(dir,'credentials.txt',token);
  git(dir,'config','user.email',['person','private.invalid'].join('@'));
  git(dir,'add','.'); git(dir,'commit','-qm','Fixture credentials');
  const normal=scan(dir,'--history'); assert.equal(normal.status,1);
  assert.match(normal.stderr,/private key \/ token/);
  assert.doesNotMatch(normal.stderr,/author\/committer email/);
  const r=scan(dir,'--history','--private-authors'); assert.equal(r.status,1);
  assert.match(r.stderr,/private key \/ token/); assert.match(r.stderr,/author\/committer email/);
  assert(!r.stderr.includes(token)); assert(!r.stderr.includes('person@'));
});

test('release packaging excludes local profile, includes source and verifies every asset',t=>{
  const dir=repo(t);
  for(const name of ['audit-publication.mjs','build-release.mjs','run.sh','run.ps1']) {
    mkdirSync(join(dir,'scripts'),{recursive:true});
    copyFileSync(join(root,'scripts',name),join(dir,'scripts',name));
  }
  git(dir,'add','.'); git(dir,'commit','-qm','Release tools');
  put(dir,'profile/identity.key','do not package this');
  const bin=fixture(t);
  put(bin,'go',`#!/bin/sh
set -eu
[ "$CGO_ENABLED" = 0 ]
[ "$GOTELEMETRY" = off ]
out=
while [ "$#" -gt 0 ]; do if [ "$1" = -o ]; then shift; out=$1; fi; shift; done
printf '%s/%s fixture build' "$GOOS" "$GOARCH" > "$out"
`,0o700);
  const r=spawnSync(process.execPath,['scripts/build-release.mjs','v0.1.0'],{cwd:dir,encoding:'utf8',env:{...process.env,PATH:bin+':'+process.env.PATH}});
  assert.equal(r.status,0,r.stderr);
  const sums=readFileSync(join(dir,'dist/SHA256SUMS'),'utf8').trim().split('\n');
  assert.equal(sums.length,8);
  for(const line of sums) {
    const [hash,file]=line.split('  ');
    assert.equal(createHash('sha256').update(readFileSync(join(dir,'dist',file))).digest('hex'),hash);
  }
  const tar=gunzipSync(readFileSync(join(dir,'dist/p2pmessenger-v0.1.0-source.tar.gz'))).toString();
  assert(tar.includes('p2pmessenger-v0.1.0/scripts/run.sh'));
  assert(!tar.includes('do not package this'));
  put(dir,'README.md','Changed source');
  const dirty=spawnSync(process.execPath,['scripts/build-release.mjs','v0.1.1'],{cwd:dir,encoding:'utf8'});
  assert.notEqual(dirty.status,0); assert.match(dirty.stderr,/clean Git working tree/);
});

function launcher(t, os='Linux', arch='x86_64', corrupt=false) {
  const dir=fixture(t), capture=join(dir,'captured'), args=['--help','value with spaces','$(never executed)'];
  const payload='#!/bin/sh\nprintf \'%s\\n\' "$@" > "$P2P_CAPTURE"\n';
  put(dir,'asset',payload);
  const platform=os==='Darwin'?'darwin':'linux', cpu=arch==='arm64'?'arm64':'amd64';
  const hash=createHash('sha256').update(corrupt?'another payload':payload).digest('hex');
  put(dir,'manifest',`${hash}  p2pmessenger-${platform}-${cpu}\n`);
  put(dir,'bin/uname','#!/bin/sh\ncase "$1" in -s) printf "%s\\n" "$P2P_OS";; -m) printf "%s\\n" "$P2P_ARCH";; esac\n',0o700);
  put(dir,'bin/curl',`#!/bin/sh
set -eu
url= out=
while [ "$#" -gt 0 ]; do
 case "$1" in
  -o) shift; out=$1;;
  https://*) url=$1;;
 esac
 shift
done
case "$url" in
 https://github.com/example/project/releases/latest/download/*) ;;
 *) exit 90;;
esac
case "$url" in */SHA256SUMS) cp "$P2P_MANIFEST" "$out";; *) cp "$P2P_ASSET" "$out";; esac
`,0o700);
  const r=spawnSync('sh',[join(root,'scripts/run.sh'),...args],{encoding:'utf8',env:{...process.env,
    PATH:join(dir,'bin')+':'+process.env.PATH, XDG_CACHE_HOME:join(dir,'cache'), P2PMESSENGER_REPO:'example/project',
    P2PMESSENGER_VERSION:'latest',P2P_OS:os,P2P_ARCH:arch,P2P_CAPTURE:capture,P2P_ASSET:join(dir,'asset'),P2P_MANIFEST:join(dir,'manifest'),
  }});
  return {r,dir,capture,args};
}

test('Linux/macOS launcher selects platform, preserves arguments and cleans temporary binary',t=>{
  for(const [os,arch] of [['Linux','x86_64'],['Linux','arm64'],['Darwin','x86_64'],['Darwin','arm64']]) {
    const {r,dir,capture,args}=launcher(t,os,arch);
    assert.equal(r.status,0,r.stderr); assert.deepEqual(readFileSync(capture,'utf8').trim().split('\n'),args);
    assert.deepEqual(readdirSync(join(dir,'cache/p2pmessenger')),[]);
  }
});

test('launcher rejects corrupted download and unsupported systems before execution',t=>{
  const {r,dir}=launcher(t,'Linux','x86_64',true);
  assert.notEqual(r.status,0); assert.match(r.stderr,/Checksum mismatch/);
  assert.deepEqual(readdirSync(join(dir,'cache/p2pmessenger')),[]);
  const unknown=launcher(t,'Unknown','x86_64');
  assert.notEqual(unknown.r.status,0); assert.match(unknown.r.stderr,/Unsupported OS/);
});
