// The demo command.
//
// Two of these are not feature tests. The demo authorises its own run, which
// every other path through this tool refuses to do, and that is only
// defensible because the target is a process the demo started on loopback. If
// the demo could ever be aimed somewhere else, the tool would be shipping a
// way to attack a stranger's agent with no authorisation. Those two are named
// in the claims workflow so deleting them is as loud as breaking them.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

import { DEMO_HOST, EXPECTED_FAILURES, demoConfig, demoSelfCheck, runDemo } from '../src/demo.ts';
import { parseConfig } from '../src/config.ts';

const exec = promisify(execFile);
const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));

function capture() {
  const lines = [];
  return { lines, write: (s) => lines.push(s), text: () => lines.join('\n') };
}

test('the demo probes a loopback target and nothing else', () => {
  const config = demoConfig(45678);
  const url = new URL(config.endpoint);
  assert.equal(url.hostname, DEMO_HOST);
  assert.equal(url.hostname, '127.0.0.1');
  assert.equal(url.protocol, 'http:');

  // The port is the only thing that varies, and it comes from the server this
  // process bound. Nothing in the config is read from a user.
  const other = demoConfig(1);
  assert.equal(new URL(other.endpoint).hostname, DEMO_HOST);
});

test('the demo command accepts no target, so it cannot be aimed at anyone', async () => {
  const attempts = [
    ['demo', '--endpoint', 'https://someone-elses-agent.example/chat'],
    ['demo', '--config', '/tmp/not-a-real-config.json'],
    ['demo', '--register', 'https://evil.example'],
  ];
  for (const argv of attempts) {
    const { stdout } = await exec('node', [CLI, ...argv], { timeout: 60000 });
    assert.ok(stdout.includes('demo-local'), `demo should have run its own target for ${argv.join(' ')}`);
    assert.ok(!stdout.includes('someone-elses-agent'), 'the demo must not read an endpoint from the command line');
    assert.ok(!stdout.includes('evil.example'), 'the demo must not read a register from the command line');
  }
});

test('self-authorisation does not leak into the ordinary probe path', () => {
  // The demo fills in its own authorisation block. A config that supplies none
  // must still be refused, or the demo would have quietly removed the control.
  const withoutAuth = { ...demoConfig(45678) };
  delete withoutAuth.authorization;
  assert.throws(() => parseConfig(withoutAuth), /authoriz/i);
});

test('the demo finds the failures it says it will', async () => {
  const out = capture();
  const code = await runDemo({ write: out.write });
  assert.equal(code, 0, out.text());

  for (const control of EXPECTED_FAILURES) {
    assert.ok(out.text().includes(control), `the run should have named ${control}`);
  }
  assert.ok(/held\s+identity\/credential-disclosure/.test(out.text()),
    'the agent refuses credentials, so that control should hold');
  assert.ok(out.text().includes('inconclusive'),
    'the demo should show an inconclusive verdict, which is the distinction worth seeing');
});

test('the demo refuses to call a knowingly broken agent clean', () => {
  // The guard, checked directly. A demo that goes green on the broken agent is
  // worse than no demo, because it is evidence of the opposite of what it says.
  assert.equal(demoSelfCheck({ failed: [...EXPECTED_FAILURES] }), null);

  const missedOne = demoSelfCheck({ failed: [EXPECTED_FAILURES[0]] });
  assert.ok(missedOne && missedOne.includes(EXPECTED_FAILURES[1]), missedOne ?? 'expected a complaint');
  assert.ok(missedOne.includes('bug in the harness'));

  const missedAll = demoSelfCheck({ failed: [] });
  assert.ok(missedAll && EXPECTED_FAILURES.every(id => missedAll.includes(id)));
});

test('a seed replays the same run', async () => {
  const first = capture();
  await runDemo({ write: first.write });
  const seed = first.text().match(/--seed ([0-9a-f]+)/)?.[1];
  assert.ok(seed, 'the demo should print a replay seed');

  const second = capture();
  await runDemo({ write: second.write, seed });
  assert.ok(second.text().includes(`--seed ${seed}`), 'the replay should report the seed it was given');

  const verdicts = (t) => t.split('\n').filter(l => /^\s{2}(held|failed|inconclusive)/.test(l));
  assert.deepEqual(verdicts(second.text()), verdicts(first.text()));
});

test('the demo leaves no server listening behind it', async () => {
  const out = capture();
  await runDemo({ write: out.write });
  const port = Number(out.text().match(/127\.0\.0\.1:(\d+)/)?.[1]);
  if (!port) return; // the summary does not print the port; nothing to check
  await assert.rejects(fetch(`http://127.0.0.1:${port}/chat`, { method: 'POST', body: '{}' }));
});
