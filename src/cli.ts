#!/usr/bin/env node
// red-team-harness probe --config target.json [--submit] [--seed hex] [--only id,id]
//
// Submission is opt in. The default run attacks the target, writes a report
// and posts nothing, because the version of this tool that suspends a live
// certificate by default is the version nobody will run twice.

import { writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { ConfigError, loadConfig } from './config.ts';
import { runDemo } from './demo.ts';
import { Target } from './target.ts';
import { run } from './runner.ts';
import { buildResult, summarise } from './result.ts';
import { submit, SubmitError } from './submit.ts';

const require = createRequire(import.meta.url);
const { version } = require('../package.json') as { version: string };

const USAGE = `red-team-harness ${version}

  red-team-harness demo
  red-team-harness probe --config <file> [options]

  demo                  probe a broken agent this command starts on loopback,
                        so you can see the output without a target of your own

  --config <file>       target configuration (required)
  --submit              post the result to the register (default: write a report only)
  --register <url>      register endpoint
                        (default: https://securedai.org/api/certification/probe)
  --credential <value>  submission credential (default: $CERT_SUBMIT_SECRET)
  --seed <hex>          replay a previous run exactly
  --only <id,id>        run only these probe ids
  --out <file>          write the report here (default: probe-report.json)
  --quiet               print the summary line only
`;

function parseArgs(argv: string[]): Record<string, string | boolean> {
  const out: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) { out._ = out._ ?? a; continue; }
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) { out[key] = true; }
    else { out[key] = next; i++; }
  }
  return out;
}

export async function main(argv: string[] = process.argv.slice(2)): Promise<number> {
  const args = parseArgs(argv);
  if (args.help || args.h || argv.length === 0) { process.stdout.write(USAGE); return 0; }
  if (args._ === 'demo') {
    // No endpoint, host or config is read here. The demo probes a server it
    // starts itself, which is the only reason it may authorise its own run.
    return runDemo({ seed: typeof args.seed === 'string' ? args.seed : undefined });
  }
  if (args._ !== 'probe') { process.stderr.write(`unknown command. ${USAGE}`); return 2; }
  if (typeof args.config !== 'string') { process.stderr.write(`--config is required\n`); return 2; }

  let config, secrets;
  try {
    ({ config, secrets } = await loadConfig(args.config));
  } catch (e) {
    if (e instanceof ConfigError) { process.stderr.write(`${e.message}\n`); return 2; }
    throw e;
  }

  const quiet = Boolean(args.quiet);
  const log = (s: string) => { if (!quiet) process.stderr.write(s + '\n'); };

  log(`probing ${new URL(config.endpoint).host} for ${config.certificate}`);
  log(`authorised by ${config.authorization.authorizedBy} on ${config.authorization.date}`);

  const target = new Target(config, secrets);
  const report = await run(target, config, {
    seed: typeof args.seed === 'string' ? args.seed : undefined,
    only: typeof args.only === 'string' ? args.only.split(',').map(s => s.trim()) : undefined,
  });
  const result = buildResult(report, config, version);

  const out = typeof args.out === 'string' ? args.out : 'probe-report.json';
  await writeFile(out, JSON.stringify(result, null, 2) + '\n', 'utf8');

  for (const p of result.probes) log(`  ${p.verdict.padEnd(12)} ${p.id}  ${p.evidence}`);
  process.stdout.write(summarise(result) + '\n');
  log(`report written to ${out}, replay with --seed ${result.seed}`);

  if (!args.submit) {
    log('not submitted. Pass --submit to post this to the register.');
    return result.failed.length ? 1 : 0;
  }

  const endpoint = typeof args.register === 'string'
    ? args.register : 'https://securedai.org/api/certification/probe';
  const credential = typeof args.credential === 'string'
    ? args.credential : (process.env.CERT_SUBMIT_SECRET ?? '');

  try {
    const ack = await submit(result, { endpoint, credential });
    log(`submitted: ${JSON.stringify(ack)}`);
  } catch (e) {
    if (e instanceof SubmitError) {
      process.stderr.write(`submission failed: ${e.message}\n`);
      process.stderr.write(`the report is still at ${out} and can be submitted again\n`);
      return 3;
    }
    throw e;
  }
  return result.failed.length ? 1 : 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().then(code => process.exit(code), err => {
    process.stderr.write(`${(err as Error).stack ?? err}\n`);
    process.exit(4);
  });
}
