// Build only from a clean, audited commit. Run: node scripts/build-release.mjs v0.1.0
import {execFileSync} from 'node:child_process';
import {mkdirSync, readFileSync, writeFileSync, existsSync, readdirSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {gzipSync} from 'node:zlib';
import {join} from 'node:path';
const version = process.argv[2];
if (!/^v\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$/.test(version || '')) throw Error('Usage: node scripts/build-release.mjs v0.1.0');
const run = (cmd,args,opts={}) => execFileSync(cmd,args,{stdio:'inherit',...opts});
const status = execFileSync('git',['status','--porcelain','--untracked-files=normal'],{encoding:'utf8'}).trim();
if (status) throw Error('Commit the reviewed source first. Release builds require a clean Git working tree.');
run(process.execPath,['scripts/audit-publication.mjs','--history']);
if (existsSync('dist') && readdirSync('dist').length) throw Error('dist/ must be empty; move old artifacts elsewhere before building.');
mkdirSync('dist',{recursive:true});
const targets = [['linux','amd64'],['linux','arm64'],['darwin','amd64'],['darwin','arm64'],['windows','amd64']];
const assets = [];
for (const [os,arch] of targets) {
  const name = `p2pmessenger-${os}-${arch}${os === 'windows' ? '.exe' : ''}`;
  run('go',['build','-mod=readonly','-trimpath','-buildvcs=false','-ldflags=-s -w','-o',join('dist',name),'.'],{
    env:{...process.env,CGO_ENABLED:'0',GOOS:os,GOARCH:arch,GOTELEMETRY:'off'},
  });
  assets.push(name);
}
const source = `p2pmessenger-${version}-source.tar.gz`;
const tar = execFileSync('git',['archive','--format=tar',`--prefix=p2pmessenger-${version}/`,'HEAD'],{maxBuffer:64<<20});
writeFileSync(join('dist',source),gzipSync(tar));
assets.push(source);
for (const name of ['run.sh','run.ps1']) {
  writeFileSync(join('dist',name),readFileSync(join('scripts',name)));
  assets.push(name);
}
writeFileSync('dist/SHA256SUMS',assets.sort().map(name=>`${createHash('sha256').update(readFileSync(join('dist',name))).digest('hex')}  ${name}\n`).join(''));
console.log(`Built ${version}: ${assets.length} assets plus SHA256SUMS. No user profile or build-machine paths were packaged.`);
