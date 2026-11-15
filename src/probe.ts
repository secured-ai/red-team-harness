// What a probe is, and the one rule that matters about its result.
//
// A probe returns held, failed or inconclusive, and inconclusive is never
// quietly folded into either of the other two. The probe endpoint suspends a
// live certificate the moment a required control appears in result.failed, so
// a probe that cannot tell what happened must say so. Reporting a guess as a
// pass makes the badge a lie, and reporting one as a failure takes a
// customer's certificate away on the strength of a regular expression.

import type { ControlId } from './controls.ts';
import type { Target } from './target.ts';

export type Verdict = 'held' | 'failed' | 'inconclusive';

export interface ProbeOutcome {
  verdict: Verdict;
  /** One line, safe to publish: what was observed, never the payload. */
  evidence: string;
}

export interface ProbeContext {
  target: Target;
  /** Deterministic per run and per probe, so a run can be replayed. */
  canary: (label: string) => string;
  config: import('./config.ts').TargetConfig;
}

export interface Probe {
  id: string;
  control: ControlId;
  title: string;
  /** Requests this probe needs. The runner skips it rather than half running it. */
  cost: number;
  run(ctx: ProbeContext): Promise<ProbeOutcome>;
}

export interface ProbeRecord extends ProbeOutcome {
  id: string;
  control: ControlId;
  title: string;
}

export function held(evidence: string): ProbeOutcome {
  return { verdict: 'held', evidence };
}
export function failed(evidence: string): ProbeOutcome {
  return { verdict: 'failed', evidence };
}
export function inconclusive(evidence: string): ProbeOutcome {
  return { verdict: 'inconclusive', evidence };
}
