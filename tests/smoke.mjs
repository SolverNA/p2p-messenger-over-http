// End-to-end check of the actual executable, including trusted TLS and restart.
// Run: go build -o messenger . && node tests/smoke.mjs
import {spawn,execFileSync} from 'node:child_process';
import {mkdtempSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import net from 'node:net';
import http from 'node:http';
import assert from 'node:assert/strict';
import vm from 'node:vm';
const dir=mkdtempSync(join(tmpdir(),'p2pmessenger-'));
const children=[];
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function freePort(){const s=net.createServer();await new Promise(r=>s.listen(0,'127.0.0.1',r));const p=s.address().port;await new Promise(r=>s.close(r));return p}
async function until(fn,ms=30000){const end=Date.now()+ms;let last;while(Date.now()<end){try{const v=await fn();if(v)return v}catch(e){last=e}await sleep(200)}throw last||Error('timed out')}
async function launch(name,extra=[]){
 const ui=await freePort(),port=await freePort();let logs='';
 const p=spawn(join(process.cwd(),'messenger'),['--data',join(dir,name),'--ui',`127.0.0.1:${ui}`,'--port',String(port),'--direct-port','0',...extra],{env:{...process.env,SSL_CERT_FILE:join(dir,'cert.pem')}});children.push(p);p.stderr.on('data',b=>logs+=b);p.stdout.on('data',b=>logs+=b);
 const base=`http://127.0.0.1:${ui}`;
 const html=await until(async()=>{if(p.exitCode!==null)throw Error(logs);const r=await fetch(base);if(r.ok)return r.text()});
 new vm.Script(html.match(/<script nonce="[^"]+">([\s\S]*?)<\/script>/)[1]);
 const token=html.match(/const token='([^']+)'/)[1];
 async function api(path,body){const r=await fetch(base+path,{method:body?'POST':'GET',headers:{'X-Node-Token':token,'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});if(!r.ok)throw Error(await r.text());return r.json()}
 const status=await api('/api/status');
 return {p,base,api,status,port,logs:()=>logs,async stop(){if(p.exitCode!==null)return;const done=new Promise(r=>p.once('exit',r));p.kill('SIGTERM');await done}};
}
try{
 execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(dir,'tls.key'),'-out',join(dir,'cert.pem'),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],{stdio:'ignore'});
 const hub=await launch('hub',['--reachability','public','--tls-cert',join(dir,'cert.pem'),'--tls-key',join(dir,'tls.key')]);
 const bootstrap=`/dns4/localhost/tcp/${hub.port}/tls/ws/p2p/${hub.status.peer}`;
 const a=await launch('alice',['--reachability','private','--bootstrap',bootstrap]);
 let b=await launch('bob',['--reachability','private','--bootstrap',bootstrap]);
 await until(async()=>{const s=await a.api('/api/status');return s.connections.some(c=>c.peer===hub.status.peer)});
 assert.equal((await fetch(a.base+'/api/status')).status,403,'API must require token');
 assert.equal((await fetch(a.base+'/api/send',{method:'POST',headers:{'X-Node-Token':'invalid'}})).status,403);
 const hostileHostStatus=await new Promise((resolve,reject)=>{const req=http.get(a.base,{headers:{Host:'attacker.invalid'}},res=>{res.resume();resolve(res.statusCode)});req.on('error',reject)});
 assert.equal(hostileHostStatus,403,'reject DNS rebinding');
 assert.equal((await fetch(a.base+'/api/status',{headers:{'X-Node-Token':(await (await fetch(a.base)).text()).match(/const token='([^']+)'/)[1],Origin:'https://attacker.invalid'}})).status,403);
 await a.api('/api/send',{to:b.status.peer,text:'Первое сообщение через сеть с WSS-узлом'});
 await until(async()=>(await a.api('/api/messages')).some(e=>e.status==='delivered'));
 assert.equal((await b.api('/api/messages')).length,1);
 const peer=b.status.peer,oldPort=b.port;await b.stop();
 await a.api('/api/send',{to:peer,text:'Доставка после смены адреса'});
 await sleep(600);
 await a.stop(); // Outbox must survive a sender restart, too.
 const a2=await launch('alice',['--reachability','private','--bootstrap',bootstrap]);
 assert.equal(a2.status.peer,a.status.peer,'sender identity changed');
 b=await launch('bob',['--reachability','private','--bootstrap',bootstrap]);
 assert.equal(b.status.peer,peer,'recipient identity changed');assert.notEqual(b.port,oldPort);
 await until(async()=>(await a2.api('/api/messages')).filter(e=>e.status==='delivered').length===2,60000);
 assert.equal((await b.api('/api/messages')).length,2,'message lost or duplicated after restart');
 console.log('PASS: HTTPS/WSS bootstrap, API protection, UI script syntax, delivery, persistent identities/outbox, restart on new address.');
}catch(e){for(const p of children){if(p.exitCode===null)p.kill('SIGTERM')}throw e}
finally{await Promise.all(children.filter(p=>p.exitCode===null).map(p=>new Promise(r=>{p.once('exit',r);p.kill('SIGTERM')})));rmSync(dir,{recursive:true,force:true})}
