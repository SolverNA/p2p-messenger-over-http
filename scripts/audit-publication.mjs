// Heuristic publication guard. Prints locations, never secret contents.
// node scripts/audit-publication.mjs [--history] [--private-authors]
import {execFileSync} from 'node:child_process';
import {readFileSync, lstatSync} from 'node:fs';
const git = (...args) => execFileSync('git', args, {maxBuffer: 64 << 20});
const history = process.argv.includes('--history');
// Public Git author names/emails are intentional for this project. Opt in to
// stricter metadata checks when preparing an anonymous publication elsewhere.
const privateAuthors = process.argv.includes('--private-authors');
const findings = [];
const report = (where, kind) => findings.push(`${where}: ${kind}`);
const badPath = /(^|\/)(identity\.key|state\.json|config\.json|sequence\.json|node\.log|node\.lock|control\.sock|\.env(?:\..*)?|\.write-.*)$|\.(?:pem|key|exe|uu)$|(^|\/)(?:alice|bob|node-data|public-node|dist)\//i;
const rules = [
  ['private key / token', /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}/],
  ['absolute user path', /\/(?:home|Users)\/[A-Za-z0-9_.-]+\/|[A-Za-z]:\\Users\\[^\\\s]+\\/],
  ['persistent Peer ID (use PEER_ID in examples)', /\b12D3KooW[1-9A-HJ-NP-Za-km-z]{30,}\b/],
];
function inspect(path, raw, label) {
  if (badPath.test(path)) report(label, 'runtime data / credential / binary path');
  if (raw.includes(0)) { report(label, 'unexpected binary in source tree'); return; }
  const text = raw.toString('utf8');
  for (const [kind, pattern] of rules) if (pattern.test(text)) report(label, kind);
  for (const m of text.matchAll(/\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/g)) {
    if (!/(^|\.)example\.(?:com|org|net)$|(^|\.)users\.noreply\.github\.com$|^localhost\.invalid$/i.test(m[1])) {
      report(label, 'email address'); break;
    }
  }
  for (const m of text.matchAll(/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g)) {
    const a = m.slice(1).map(Number);
    if (a.some(x => x > 255)) continue;
    const [x,y,z] = a;
    // Historical Go tests used this fixed placeholder; it is not a live server.
    if (path.endsWith('_test.go') && a.every((value, index) => value === index + 1)) continue;
    // Test/example addresses, unspecified bindings and loopback are publishable.
    if (x === 127 || a.every(v => v === 0) || (x===192 && y===0 && z===2) || (x===198 && y===51 && z===100) || (x===203 && y===0 && z===113)) continue;
    report(label, 'non-example IPv4 address'); break;
  }
  // Literal IPv6 multiaddresses should only use loopback, wildcard or RFC 3849.
  for (const m of text.matchAll(/\/ip6\/([a-fA-F0-9:]+)/g)) {
    if (!['::', '::1'].includes(m[1]) && !m[1].toLowerCase().startsWith('2001:db8:')) {
      report(label, 'non-example IPv6 address'); break;
    }
  }
}
const files = git('ls-files', '--cached', '--others', '--exclude-standard', '-z').toString().split('\0').filter(Boolean);
for (const file of new Set(files)) {
  if (!lstatSync(file).isFile()) { report(file, 'symlink/non-regular file needs review'); continue; }
  inspect(file, readFileSync(file), file);
}
if (history) {
  const commits = git('rev-list', '--all').toString().trim().split('\n').filter(Boolean);
  const seen = new Set();
  for (const commit of commits) {
    if (privateAuthors) {
      const meta = git('show', '-s', '--format=%an%x00%ae%x00%cn%x00%ce', commit).toString().trim().split('\0');
      for (const i of [1,3]) if (!/^[^@]+@users\.noreply\.github\.com$|^[^@]+@localhost\.invalid$/i.test(meta[i])) {
        report(commit.slice(0,7), 'author/committer email is not a private noreply address'); break;
      }
    }
    const entries = git('ls-tree', '-rz', commit).toString().split('\0').filter(Boolean);
    for (const entry of entries) {
      const [head, path] = entry.split('\t');
      const [mode, type, oid] = head.split(' ');
      if (type !== 'blob' || mode === '120000') { report(`${commit.slice(0,7)}:${path}`, 'symlink/submodule needs review'); continue; }
      if (seen.has(oid)) continue;
      seen.add(oid);
      inspect(path, git('cat-file', 'blob', oid), `${commit.slice(0,7)}:${path}`);
    }
  }
}
if (findings.length) {
  console.error('Publication review required:\n' + findings.map(x=>'  '+x).join('\n'));
  console.error('No files were deleted. This heuristic scan cannot guarantee anonymity.');
  process.exitCode = 1;
} else console.log(`PASS: publication scan (${history ? 'working tree and all reachable history' : 'working tree'}). Heuristic only; review author names and metadata separately.`);
