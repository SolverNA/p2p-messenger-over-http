// End-to-end check: built daemon, WSS, CLI, persisted config and offline recovery.
// Run: go build -o messenger-tui . && node tests/smoke.mjs
import {spawn,execFileSync} from 'node:child_process';
import {mkdtempSync,readFileSync,rmSync,statSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
const dir=mkdtempSync(join(tmpdir(),'p2pmessenger-')),binary=join(process.cwd(),'messenger-tui');
const children=[];
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
// Stay outside Linux's usual ephemeral client-port range: an outbound libp2p
// connection could otherwise claim a just-probed port before the child binds.
const usedPorts=new Set();
async function freePort(){for(let i=0;i<100;i++){const p=20000+Math.floor(Math.random()*10000);if(usedPorts.has(p))continue;const s=net.createServer();try{await new Promise((resolve,reject)=>{s.once('error',reject);s.listen(p,'0.0.0.0',resolve)})}catch(e){if(e.code==='EADDRINUSE')continue;throw e}await new Promise(r=>s.close(r));usedPorts.add(p);return p}throw Error('no free test port')}
async function until(fn,ms=30000){const end=Date.now()+ms;let last;while(Date.now()<end){try{const v=await fn();if(v)return v}catch(e){last=e}await sleep(200)}throw last||Error('timed out')}
function control(name,q={op:'snapshot'}){return new Promise((resolve,reject)=>{const c=net.createConnection(join(dir,name,'control.sock'));let data='';c.setTimeout(7000);c.on('connect',()=>c.write(JSON.stringify(q)+'\n'));c.on('data',b=>data+=b);c.on('error',reject);c.on('timeout',()=>{c.destroy();reject(Error('local control timeout'))});c.on('end',()=>{try{const r=JSON.parse(data);if(r.error)throw Error(r.error);resolve(r)}catch(e){reject(e)}})})}
async function launch(name,extra=[]){
 const port=await freePort();let logs='';
 const legacy=name==='hub'&&process.env.P2P_LEGACY_HUB==='1';
 const mode=legacy?['--ui',`127.0.0.1:${await freePort()}`]:['--headless'];
 const family=process.env.P2P_IP6==='1'?['--ip-family','6']:[];
 const p=spawn(legacy?join(process.cwd(),'messenger'):binary,['--data',join(dir,name),...mode,...family,'--port',String(port),'--direct-port','0',...extra],{env:{...process.env,SSL_CERT_FILE:join(dir,'cert.pem')}});children.push(p);p.stderr.on('data',b=>logs+=b);p.stdout.on('data',b=>logs+=b);
 const initial=await until(async()=>{if(p.exitCode!==null)throw Error(logs);if(legacy){const m=logs.match(/Peer ID: (\S+)/);return m?{state:{peer:m[1]}}:null}return control(name)});
 assert.equal(statSync(join(dir,name)).mode&0o777,0o700);
 if(!legacy)assert.equal(statSync(join(dir,name,'control.sock')).mode&0o777,0o600);
 return {p,name,status:initial.state,port,logs:()=>logs,async stop(){if(p.exitCode!==null)return;const done=new Promise(r=>p.once('exit',r));p.kill('SIGTERM');await done}};
}
try{
 execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(dir,'tls.key'),'-out',join(dir,'cert.pem'),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],{stdio:'ignore'});
 const hub=await launch('hub',['--reachability','public','--tls-cert',join(dir,'cert.pem'),'--tls-key',join(dir,'tls.key')]);
 const bootstrap=`/${process.env.P2P_IP6==='1'?'dns6':'dns4'}/localhost/tcp/${hub.port}/tls/ws/p2p/${hub.status.peer}`;
 const a=await launch('alice',['--reachability','private','--bootstrap',bootstrap]);
 let b=await launch('bob',['--reachability','private','--bootstrap',bootstrap]);
 await until(async()=>(await control('alice')).state.connections.some(c=>c.peer===hub.status.peer));
 if(process.env.P2P_IP6==='1'){
  const s=(await control('alice')).state;
  assert(s.connections.filter(c=>c.peer===hub.status.peer).every(c=>c.address.startsWith('/ip6/')),'connection fell back to IPv4');
  assert(!s.addresses.some(a=>a.startsWith('/ip4/')),'IPv4 listener advertised in IPv6 mode');
 }
 const cliStatus=JSON.parse(execFileSync(binary,['--data',join(dir,'alice'),'--status'],{encoding:'utf8'}));assert.equal(cliStatus.peer,a.status.peer);
 const messageID=execFileSync(binary,['--data',join(dir,'alice'),'--send',b.status.peer,'--message','Привет из CLI!'],{encoding:'utf8'}).trim();assert.match(messageID,/^[a-f0-9]{32}$/);
 await until(async()=>(await control('alice')).state.messages.some(e=>e.status==='delivered'));
 assert.equal((await control('bob')).state.messages.length,1);
 const peer=b.status.peer,oldPort=b.port;await b.stop();
 await control('alice',{op:'send',to:peer,text:'Доставка после смены адреса'});
 await until(async()=>{const s=(await control('alice')).state,d=s.peers[peer];return d&&['unavailable','connect_failed','delivery_failed'].includes(d.status)&&d.next_attempt>Date.now()},30000);
 await a.stop();
 // Network flags intentionally omitted: bootstrap and mode must load from config.
 const a2=await launch('alice');assert.equal(a2.status.peer,a.status.peer);
 const saved=JSON.parse(readFileSync(join(dir,'alice','config.json'),'utf8'));assert.equal(saved.bootstrap,bootstrap);assert.equal(saved.reachability,'private');
 b=await launch('bob');assert.equal(b.status.peer,peer);assert.notEqual(b.port,oldPort);
 await until(async()=>(await control('alice')).state.messages.filter(e=>e.status==='delivered').length===2,60000);
 assert.equal((await control('bob')).state.messages.length,2);
 console.log('PASS: WSS bootstrap, CLI status/send, private control socket, offline status/retry, persisted config/keys/outbox, recovery on new address.'+(process.env.P2P_LEGACY_HUB==='1'?' Legacy web hub compatible.':'')+(process.env.P2P_IP6==='1'?' IPv6 transport confirmed.':''));
}catch(e){for(const p of children){if(p.exitCode===null)p.kill('SIGTERM')}throw e}
finally{await Promise.all(children.filter(p=>p.exitCode===null).map(p=>new Promise(r=>{p.once('exit',r);p.kill('SIGTERM')})));rmSync(dir,{recursive:true,force:true})}
