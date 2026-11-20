// Register-driven runs. The rule that matters most: only a certificate the
// register named as due is ever probed, and only with its own config.
// A fake register and fake agents on loopback; nothing leaves the machine.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { execFile } from 'node:child_process';
import { mkdtemp, writeFile, readFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { webcrypto, type JsonWebKey } from 'node:crypto';

import { fetchDue, indexConfigs, plan } from '../src/due.ts';
import { assessorSigningString } from '../src/submit.ts';
import { keygen } from '../src/keygen.ts';
import { startBrokenAgent } from '../src/demo-agent.ts';

const execP = promisify(execFile);
const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));

async function keyPair() {
  const dir = await mkdtemp(join(tmpdir(), 'rth-due-key-'));
  const { privatePath, publicPath } = await keygen('due-test', dir);
  return { privatePath, priv: JSON.parse(await readFile(privatePath, 'utf8')), pub: JSON.parse(await readFile(publicPath, 'utf8')) };
}

async function verifies(pub: JsonWebKey, req: { method: string; path: string; headers: Record<string, string>; body: Uint8Array }) {
  const key = await webcrypto.subtle.importKey('jwk', { kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y },
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const msg = new TextEncoder().encode(await assessorSigningString(req.method, req.path,
    req.headers['x-assessor-timestamp'], req.headers['x-assessor-nonce'], req.body));
  return webcrypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, Buffer.from(req.headers['x-assessor-signature'], 'base64url'), msg);
}

test('the due list is asked for with a signed empty body', async () => {
  const { priv, pub } = await keyPair();
  let seen: { headers: Record<string, string>; body: Uint8Array } | null = null;
  const due = await fetchDue({
    endpoint: 'https://securedai.org/api/certification/probe',
    key: { assessorId: 'securedai', privateJwk: priv },
    fetcher: async (_url, init) => {
      seen = { headers: init.headers as Record<string, string>, body: init.body as Uint8Array };
      return new Response(JSON.stringify({ checked: 3, due: ['SAI-CERT-0001', 'SAI-CERT-0001'] }));
    },
  });
  assert.deepEqual(due, { checked: 3, due: ['SAI-CERT-0001'] });
  assert.equal(new TextDecoder().decode(seen!.body), '{}');
  assert.equal(seen!.headers['x-assessor-id'], 'securedai');
  assert.ok(await verifies(pub, { method: 'POST', path: '/api/certification/probe', ...seen! }));
});

test('a due list that is not one is refused, and so is plain http', async () => {
  const { priv } = await keyPair();
  const key = { assessorId: 'securedai', privateJwk: priv };
  const answering = (body: unknown) => async () => new Response(JSON.stringify(body));
  for (const bad of [{ due: [] }, { checked: 1, due: 'x' }, { checked: 1, due: ['../../etc'] }, { checked: 1, due: [7] }]) {
    await assert.rejects(fetchDue({ endpoint: 'https://securedai.org/api/certification/probe', key, fetcher: answering(bad) }), /not a due list/);
  }
  await assert.rejects(fetchDue({ endpoint: 'http://securedai.org/api/certification/probe', key, fetcher: answering({}) }), /plain http/);
  await assert.rejects(fetchDue({ endpoint: 'https://securedai.org/x', key,
    fetcher: async () => new Response('no', { status: 401 }) }), /did not accept the signature/);
});

test('only certificates the register named are planned, and only with exactly one config', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'rth-due-cfg-'));
  await writeFile(join(dir, 'a.json'), JSON.stringify({ certificate: 'CERT-A', headers: { Authorization: 'Bearer ${NOT_SET_HERE}' } }));
  await writeFile(join(dir, 'b.json'), JSON.stringify({ certificate: 'CERT-B' }));
  await writeFile(join(dir, 'c1.json'), JSON.stringify({ certificate: 'CERT-C' }));
  await writeFile(join(dir, 'c2.json'), JSON.stringify({ certificate: 'CERT-C' }));
  await writeFile(join(dir, 'notes.json'), JSON.stringify({ hello: 'world' }));
  await writeFile(join(dir, 'broken.json'), '{');
  await writeFile(join(dir, 'readme.txt'), 'not json');

  const index = await indexConfigs(dir);
  assert.equal(index.byCertificate.get('CERT-A'), join(dir, 'a.json'), 'indexing never needs the env');
  assert.equal(index.unreadable.length, 2);

  const p = plan({ checked: 5, due: ['CERT-A', 'CERT-C', 'CERT-D'] }, index);
  assert.deepEqual(p.run.map(r => r.certificate), ['CERT-A']);
  assert.deepEqual(p.missing, ['CERT-D']);
  assert.deepEqual(p.ambiguous.map(a => a.certificate), ['CERT-C']);
  assert.ok(!p.run.some(r => r.certificate === 'CERT-B'), 'a config that is not due is never run');
});

test('end to end: due --run probes the due certificate, leaves the rest alone, and submits signed', async () => {
  const { privatePath, pub } = await keyPair();
  const { server: agent, port: agentPort } = await startBrokenAgent(0);

  // A target that must never be touched: its certificate is not due.
  let untouched = 0;
  const bystander = http.createServer((_q, r) => { untouched++; r.end('{}'); });
  await new Promise<void>(r => bystander.listen(0, '127.0.0.1', () => r()));
  const bystanderPort = (bystander.address() as { port: number }).port;

  const submissions: Array<{ certificate: string; verified: boolean }> = [];
  const register = http.createServer((q, r) => {
    const chunks: Buffer[] = [];
    q.on('data', c => chunks.push(c));
    q.on('end', async () => {
      const body = new Uint8Array(Buffer.concat(chunks));
      const headers = Object.fromEntries(Object.entries(q.headers).map(([k, v]) => [k, String(v)]));
      const ok = await verifies(pub, { method: 'POST', path: '/api/certification/probe', headers, body });
      if (!ok) { r.statusCode = 401; return r.end('{"error":"unauthorized"}'); }
      const parsed = JSON.parse(Buffer.from(body).toString() || '{}');
      if (!parsed.action) return r.end(JSON.stringify({ checked: 3, due: ['CERT-DUE', 'CERT-NO-CONFIG'] }));
      submissions.push({ certificate: parsed.certificate, verified: ok });
      r.end(JSON.stringify({ recorded: true }));
    });
  });
  await new Promise<void>(r => register.listen(0, '127.0.0.1', () => r()));
  const registerUrl = `http://127.0.0.1:${(register.address() as { port: number }).port}/api/certification/probe`;

  const configs = await mkdtemp(join(tmpdir(), 'rth-due-run-'));
  const out = await mkdtemp(join(tmpdir(), 'rth-due-out-'));
  const auth = { scope: 'Bot', authorizedBy: 'T <ci@example.com>', date: '2026-11-19' };
  await writeFile(join(configs, 'due.json'), JSON.stringify({
    certificate: 'CERT-DUE', endpoint: `http://127.0.0.1:${agentPort}/chat`, bodyTemplate: { message: '{{prompt}}' },
    responsePath: 'reply', pauseMs: 0, authorization: auth }));
  await writeFile(join(configs, 'bystander.json'), JSON.stringify({
    certificate: 'CERT-NOT-DUE', endpoint: `http://127.0.0.1:${bystanderPort}/chat`, bodyTemplate: { message: '{{prompt}}' },
    pauseMs: 0, authorization: auth }));

  const cli = async (extra: string[]) => {
    try {
      const r = await execP(process.execPath, [CLI, 'due', '--configs', configs, '--register', registerUrl,
        '--assessor', 'securedai', '--assessor-key', privatePath, '--out-dir', out, ...extra]);
      return { code: 0, stdout: r.stdout, stderr: r.stderr };
    } catch (e) {
      const x = e as { code: number; stdout: string; stderr: string };
      return { code: x.code, stdout: x.stdout, stderr: x.stderr };
    }
  };

  try {
    // Listing only: nothing is probed and nothing is submitted.
    const listed = await cli([]);
    assert.match(listed.stdout, /securedai: 2 of 3 certificates due today/);
    assert.match(listed.stderr, /MISSING\s+CERT-NO-CONFIG/);
    assert.equal(listed.code, 2, 'a due certificate with no config is not a clean exit');
    assert.equal(submissions.length, 0);
    assert.equal((await readdir(out)).length, 0);

    const ran = await cli(['--run', '--submit']);
    assert.match(ran.stdout, /CERT-DUE: \d+ failed/);
    assert.equal(ran.code, 2, 'the missing config outranks the failed controls');
    assert.deepEqual(submissions, [{ certificate: 'CERT-DUE', verified: true }]);
    assert.equal(untouched, 0, 'a certificate that was not due was never probed');
    const files = (await readdir(out)).sort();
    assert.equal(files.length, 2);
    assert.ok(files[0].startsWith('CERT-DUE-') && files[0].endsWith('.html'));
  } finally {
    agent.close(); bystander.close(); register.close();
  }
});

test('--submit without --run is refused before anything is asked', async () => {
  await assert.rejects(execP(process.execPath, [CLI, 'due', '--configs', '.', '--submit']),
    (e: { code?: number; stderr?: string }) => e.code === 2 && /--submit needs --run/.test(e.stderr ?? ''));
});
