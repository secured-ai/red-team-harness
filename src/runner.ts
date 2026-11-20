// Run the probe set and roll the outcomes up to controls.
//
// Two rules do the real work here.
//
// A probe that throws is inconclusive, never failed. A network timeout is not
// evidence that a control is missing, and treating it as evidence would mean a
// flaky connection could suspend a customer's certificate.
//
// A control is only passed when a probe actually ran and held. Absence of
// evidence is reported as absence of evidence, which is the difference between
// this and a scanner that prints green for everything it did not test.

import { createHash, randomBytes } from 'node:crypto';
import { CONTROL_IDS, type ControlId } from './controls.ts';
import { PROBES } from './probes/index.ts';
import type { Probe, ProbeRecord } from './probe.ts';
import type { TargetConfig } from './config.ts';
import { BudgetError, type Target } from './target.ts';

export interface RunOptions {
  /** Hex seed. Supplied for a replay, generated otherwise. */
  seed?: string;
  /** Limit the run to these probe ids. */
  only?: string[];
  probes?: Probe[];
  now?: () => Date;
}

export interface RunReport {
  seed: string;
  startedAt: string;
  finishedAt: string;
  requests: number;
  probes: ProbeRecord[];
  controls: Record<ControlId, 'passed' | 'failed' | 'inconclusive' | 'not_probed'>;
}

export function newSeed(): string {
  return randomBytes(16).toString('hex');
}

/** Deterministic from the seed, so a disputed run can be replayed exactly. */
function canaryFor(seed: string) {
  return (label: string) =>
    'RTH-' + createHash('sha256').update(`${seed}:${label}`).digest('hex').slice(0, 12).toUpperCase();
}

export async function run(
  target: Target, config: TargetConfig, opts: RunOptions = {},
): Promise<RunReport> {
  const seed = opts.seed ?? newSeed();
  const now = opts.now ?? (() => new Date());
  const startedAt = now().toISOString();
  const canary = canaryFor(seed);

  const chosen = (opts.probes ?? PROBES)
    .filter(p => !opts.only || opts.only.includes(p.id));

  const records: ProbeRecord[] = [];
  for (const probe of chosen) {
    const base = { id: probe.id, control: probe.control, title: probe.title };
    if (target.remaining < probe.cost) {
      records.push({ ...base, verdict: 'inconclusive',
        evidence: `skipped: needs ${probe.cost} requests and ${target.remaining} are left in the budget` });
      continue;
    }
    try {
      const session = (label: string) => `rth-${canary(`session:${label}`).slice(4).toLowerCase()}`;
      records.push({ ...base, ...(await probe.run({ target, canary, session, config })) });
    } catch (e) {
      const why = e instanceof BudgetError ? 'request budget exhausted' : (e as Error).message;
      // Deliberately inconclusive. See the note at the top of this file.
      records.push({ ...base, verdict: 'inconclusive', evidence: `did not complete: ${why}` });
    }
  }

  const controls = Object.fromEntries(CONTROL_IDS.map(id => {
    const mine = records.filter(r => r.control === id);
    if (mine.length === 0) return [id, 'not_probed'];
    if (mine.some(r => r.verdict === 'failed')) return [id, 'failed'];
    if (mine.every(r => r.verdict === 'held')) return [id, 'passed'];
    return [id, 'inconclusive'];
  })) as RunReport['controls'];

  return {
    seed, startedAt, finishedAt: now().toISOString(),
    requests: target.used, probes: records, controls,
  };
}
