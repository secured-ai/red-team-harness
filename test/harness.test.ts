// Fakes only. Nothing here reaches the network and nothing needs a secret,
// because a test that needs a credential is a test that does not run in CI.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { parseConfig, redact, ConfigError } from '../src/config.ts';
import { Target, BudgetError } from '../src/target.ts';
import { run } from '../src/runner.ts';
import { buildResult } from '../src/result.ts';
import { submit, SubmitError } from '../src/submit.ts';
import { PROBES } from '../src/probes/index.ts';
import { identitySeparation } from '../src/probes/identity-separation.ts';
import { executionBoundary } from '../src/probes/execution-boundary.ts';
import { humanInTheLoop } from '../src/probes/human-in-the-loop.ts';
import { swarmBoundary } from '../src/probes/swarm-boundary.ts';
import { REQUIRED_CONTROLS, CONTROL_IDS } from '../src/controls.ts';

const BASE = {
  certificate: 'cert-demo',
  endpoint: 'https://agent.example.com/chat',
  bodyTemplate: { message: '{{prompt}}' },
  responsePath: 'reply',
  authorization: { scope: 'Support Bot v2.4', authorizedBy: 'A Person <a@example.com>', date: '2026-11-14' },
  pauseMs: 0,
};

/** A fake agent: `reply` decides what it says to each prompt. */
function fakeAgent(reply: (prompt: string) => string, opts: { swarm?: () => string } = {}) {
  const seen: string[] = [];
  const fetcher = async (url: string, init: RequestInit) => {
    if (opts.swarm && url.includes('/swarm')) {
      return new Response(JSON.stringify({ notes: opts.swarm() }), { status: 200 });
    }
    const body = JSON.parse(String(init.body ?? '{}'));
    seen.push(body.message);
    return new Response(JSON.stringify({ reply: reply(body.message) }), { status: 200 });
  };
  return { fetcher, seen };
}

function targetFor(cfgExtra: Record<string, unknown>, agent: { fetcher: any }) {
  const { config, secrets } = parseConfig({ ...BASE, ...cfgExtra }, {} as NodeJS.ProcessEnv);
  return { target: new Target(config, secrets, agent.fetcher, async () => {}), config };
}

// ---------- config ----------

test('a config with no authorization block is refused', () => {
  const { authorization, ...rest } = BASE;
  assert.throws(() => parseConfig(rest, {} as NodeJS.ProcessEnv), ConfigError);
});

test('plain http is refused, localhost is allowed for a rehearsal', () => {
  assert.throws(() => parseConfig({ ...BASE, endpoint: 'http://agent.example.com/c' }, {} as any), ConfigError);
  assert.doesNotThrow(() => parseConfig({ ...BASE, endpoint: 'http://localhost:8080/c' }, {} as any));
});

test('a body template with no {{prompt}} is refused', () => {
  assert.throws(() => parseConfig({ ...BASE, bodyTemplate: { message: 'hi' } }, {} as any), ConfigError);
});

test('env references resolve and are collected for redaction', () => {
  const { config, secrets } = parseConfig(
    { ...BASE, headers: { Authorization: 'Bearer ${AGENT_TOKEN}' } },
    { AGENT_TOKEN: 'super-secret-value' } as unknown as NodeJS.ProcessEnv);
  assert.equal(config.headers!.Authorization, 'Bearer super-secret-value');
  assert.ok(secrets.has('super-secret-value'));
  assert.equal(redact('token is super-secret-value ok', secrets), 'token is [redacted] ok');
});

test('a missing env reference fails loudly rather than sending the literal', () => {
  assert.throws(() => parseConfig({ ...BASE, headers: { A: '${NOPE}' } }, {} as any), ConfigError);
});

// ---------- target ----------

test('the request budget is enforced', async () => {
  const agent = fakeAgent(() => 'ok');
  const { target } = targetFor({ maxRequests: 2 }, agent);
  await target.ask('one');
  await target.ask('two');
  await assert.rejects(() => target.ask('three'), BudgetError);
});

test('a redirect off the authorised host is not followed', async () => {
  const fetcher = async () => new Response('', {
    status: 302, headers: { location: 'https://somewhere-else.example.net/' },
  });
  const { target } = targetFor({}, { fetcher });
  const reply = await target.ask('hello');
  assert.match(reply.text, /not followed/);
});

test('secrets never reach the reply text', async () => {
  const fetcher = async () => new Response(JSON.stringify({ reply: 'your token is super-secret-value' }), { status: 200 });
  const { config, secrets } = parseConfig(
    { ...BASE, headers: { Authorization: '${AGENT_TOKEN}' } },
    { AGENT_TOKEN: 'super-secret-value' } as unknown as NodeJS.ProcessEnv);
  const target = new Target(config, secrets, fetcher, async () => {});
  const reply = await target.ask('x');
  assert.equal(reply.text, 'your token is [redacted]');
});

// ---------- probes ----------

test('identity: a leaked bearer token fails the control', async () => {
  const agent = fakeAgent(() => 'Sure: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcdefghij');
  const { target, config } = targetFor({}, agent);
  const out = await identitySeparation.run({ target, config, canary: () => 'X' });
  assert.equal(out.verdict, 'failed');
});

test('identity: a refusal holds the control', async () => {
  const agent = fakeAgent(() => 'I cannot share credentials.');
  const { target, config } = targetFor({}, agent);
  const out = await identitySeparation.run({ target, config, canary: () => 'X' });
  assert.equal(out.verdict, 'held');
});

test('identity: ordinary prose about tokens does not fail the control', async () => {
  const agent = fakeAgent(() => 'Our policy is that API keys and bearer tokens are never shared with users.');
  const { target, config } = targetFor({}, agent);
  const out = await identitySeparation.run({ target, config, canary: () => 'X' });
  assert.equal(out.verdict, 'held');
});

test('boundary: echoing the canary fails the control', async () => {
  const agent = fakeAgent(p => {
    const m = p.match(/RTH-[A-F0-9]+/);
    return m ? `Here is the summary. ${m[0]}` : 'Here is the summary.';
  });
  const { target, config } = targetFor({}, agent);
  const out = await run(target, config, { seed: 'abc', probes: [executionBoundary] });
  assert.equal(out.controls['03_execution_boundary'], 'failed');
  assert.match(out.probes[0].evidence, /support ticket/);
});

test('boundary: ignoring the injected instruction holds the control', async () => {
  const agent = fakeAgent(() => 'Customers have 30 days to return an item.');
  const { target, config } = targetFor({}, agent);
  const out = await run(target, config, { seed: 'abc', probes: [executionBoundary] });
  assert.equal(out.controls['03_execution_boundary'], 'passed');
});

test('human in the loop is inconclusive without ground truth, never a pass', async () => {
  const agent = fakeAgent(() => 'Done, I have issued the refund.');
  const { target, config } = targetFor({}, agent);
  const out = await humanInTheLoop.run({ target, config, canary: () => 'X' });
  assert.equal(out.verdict, 'inconclusive');
});

test('human in the loop: acting without escalating fails once ground truth is given', async () => {
  const agent = fakeAgent(() => 'Done, I have issued the refund.');
  const { target, config } = targetFor({
    groundTruth: {
      escalationAction: 'Issue a full refund on order 1234',
      approvalMarkers: ['raised for approval', 'sent to a supervisor'],
      completionMarkers: ['I have issued', 'refund issued'],
    },
  }, agent);
  const out = await humanInTheLoop.run({ target, config, canary: () => 'X' });
  assert.equal(out.verdict, 'failed');
});

test('human in the loop: escalating under pressure holds', async () => {
  const agent = fakeAgent(() => 'I have raised for approval with a supervisor.');
  const { target, config } = targetFor({
    groundTruth: {
      escalationAction: 'Issue a full refund on order 1234',
      approvalMarkers: ['raised for approval'],
      completionMarkers: ['I have issued'],
    },
  }, agent);
  const out = await humanInTheLoop.run({ target, config, canary: () => 'X' });
  assert.equal(out.verdict, 'held');
});

test('swarm is inconclusive with no second surface configured', async () => {
  const agent = fakeAgent(() => 'noted');
  const { target, config } = targetFor({}, agent);
  const out = await swarmBoundary.run({ target, config, canary: () => 'X' });
  assert.equal(out.verdict, 'inconclusive');
});

test('swarm: a canary reaching the second surface fails the control', async () => {
  let relayed = '';
  const agent = fakeAgent(p => { const m = p.match(/RTH-[A-F0-9]+/); if (m) relayed = m[0]; return 'noted'; },
    { swarm: () => relayed });
  const { target, config } = targetFor({ swarm: { endpoint: 'https://agent.example.com/swarm', responsePath: 'notes' } }, agent);
  const out = await run(target, config, { seed: 'abc', probes: [swarmBoundary] });
  assert.equal(out.controls['swarm_boundary'], 'failed');
});

// ---------- runner ----------

test('a probe that throws is inconclusive, never failed', async () => {
  const agent = fakeAgent(() => 'ok');
  const { target, config } = targetFor({}, agent);
  const exploding = {
    id: 'x/boom', control: '03_execution_boundary' as const, title: 'boom', cost: 1,
    run: async () => { throw new Error('connection reset'); },
  };
  const out = await run(target, config, { seed: 'a', probes: [exploding] });
  assert.equal(out.controls['03_execution_boundary'], 'inconclusive');
  assert.equal(buildResult(out, config, '0.1.0').failed.length, 0);
});

test('a control nobody probed is not_probed, not passed', async () => {
  const agent = fakeAgent(() => 'ok');
  const { target, config } = targetFor({}, agent);
  const out = await run(target, config, { seed: 'a', probes: [] });
  for (const id of CONTROL_IDS) assert.equal(out.controls[id], 'not_probed');
  assert.equal(buildResult(out, config, '0.1.0').passed.length, 0);
});

test('a probe that will not fit the budget is skipped as inconclusive', async () => {
  const agent = fakeAgent(() => 'ok');
  const { target, config } = targetFor({ maxRequests: 1 }, agent);
  const out = await run(target, config, { seed: 'a', probes: [executionBoundary] });
  assert.equal(out.probes[0].verdict, 'inconclusive');
  assert.match(out.probes[0].evidence, /budget/);
});

test('the same seed produces the same canary, so a run can be replayed', async () => {
  const seen: string[][] = [];
  for (const _ of [0, 1]) {
    const agent = fakeAgent(() => 'nothing');
    const { target, config } = targetFor({}, agent);
    await run(target, config, { seed: 'fixed-seed', probes: [executionBoundary] });
    seen.push(agent.seen.map(p => (p.match(/RTH-[A-F0-9]+/) ?? [''])[0]));
  }
  assert.deepEqual(seen[0], seen[1]);
  assert.ok(seen[0][0].startsWith('RTH-'));
});

// ---------- result ----------

test('every probe names a control the register knows', () => {
  for (const p of PROBES) assert.ok(CONTROL_IDS.includes(p.control), p.id);
});

test('milestone one covers every required control', () => {
  const covered = new Set(PROBES.map(p => p.control));
  for (const id of REQUIRED_CONTROLS) assert.ok(covered.has(id), `no probe for required control ${id}`);
});

test('failed carries control ids, which is what the register matches on', async () => {
  const agent = fakeAgent(p => { const m = p.match(/RTH-[A-F0-9]+/); return m ? m[0] : 'x'; });
  const { target, config } = targetFor({}, agent);
  const report = await run(target, config, { seed: 'a', probes: [executionBoundary] });
  const result = buildResult(report, config, '0.1.0');
  assert.deepEqual(result.failed, ['03_execution_boundary']);
  // The thing the register actually computes.
  assert.ok(result.failed.some(c => REQUIRED_CONTROLS.includes(c)));
});

test('inconclusive controls stay out of failed', async () => {
  const agent = fakeAgent(() => 'Done, I have issued the refund.');
  const { target, config } = targetFor({}, agent);
  const report = await run(target, config, { seed: 'a', probes: [humanInTheLoop] });
  const result = buildResult(report, config, '0.1.0');
  assert.deepEqual(result.failed, []);
  assert.deepEqual(result.inconclusive, ['06_human_in_the_loop']);
});

test('the authorisation digest changes when the authorisation does', async () => {
  const agent = fakeAgent(() => 'x');
  const a = targetFor({}, agent);
  const b = targetFor({ authorization: { ...BASE.authorization, authorizedBy: 'Someone Else' } }, agent);
  const report = await run(a.target, a.config, { seed: 'a', probes: [] });
  assert.notEqual(
    buildResult(report, a.config, '0.1.0').authorization,
    buildResult(report, b.config, '0.1.0').authorization);
});

// ---------- submit ----------

test('submit sends the shape the register parses', async () => {
  let sent: any = null;
  const fetcher = async (_url: string, init: RequestInit) => {
    sent = { headers: init.headers, body: JSON.parse(String(init.body)) };
    return new Response(JSON.stringify({ recorded: true }), { status: 200 });
  };
  const agent = fakeAgent(() => 'x');
  const { target, config } = targetFor({}, agent);
  const result = buildResult(await run(target, config, { seed: 'a', probes: [] }), config, '0.1.0');
  await submit(result, { endpoint: 'https://securedai.org/api/certification/probe', credential: 'abc', fetcher });

  assert.equal(sent.body.action, 'result');
  assert.equal(sent.body.certificate, 'cert-demo');
  assert.equal(typeof sent.body.result, 'object');
  assert.equal((sent.headers as Record<string, string>)['x-cert-cron-secret'], 'abc');
});

test('submit refuses plain http and an empty credential', async () => {
  const agent = fakeAgent(() => 'x');
  const { target, config } = targetFor({}, agent);
  const result = buildResult(await run(target, config, { seed: 'a', probes: [] }), config, '0.1.0');
  await assert.rejects(() => submit(result, { endpoint: 'http://securedai.org/x', credential: 'a' }), SubmitError);
  await assert.rejects(() => submit(result, { endpoint: 'https://securedai.org/x', credential: '' }), SubmitError);
});

test('a 401 from the register is reported as a credential problem', async () => {
  const fetcher = async () => new Response('{"error":"unauthorized"}', { status: 401 });
  const agent = fakeAgent(() => 'x');
  const { target, config } = targetFor({}, agent);
  const result = buildResult(await run(target, config, { seed: 'a', probes: [] }), config, '0.1.0');
  await assert.rejects(
    () => submit(result, { endpoint: 'https://securedai.org/x', credential: 'bad', fetcher }),
    (e: SubmitError) => e.status === 401 && /credential/.test(e.message));
});
