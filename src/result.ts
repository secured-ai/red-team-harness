// The object posted to POST /api/certification/probe as `result`.
//
// The server reads one field to decide a certificate's fate:
//
//   result.failed.some(c => REQUIRED_CONTROLS.includes(c))  ->  suspend
//
// Everything else in here is for the register and for the operator reading
// why. Two consequences follow and both are enforced below.
//
// `failed` carries control ids and only control ids. A probe id in that array
// matches nothing, so a real failure would pass silently.
//
// `failed` carries failures and nothing else. Putting an inconclusive control
// in it suspends a live certificate over a probe that could not reach the
// target, which is the single worst thing this tool could do.

import { isControlId, type ControlId } from './controls.ts';
import type { RunReport } from './runner.ts';
import type { TargetConfig } from './config.ts';
import { createHash } from 'node:crypto';

export const HARNESS = 'red-team-harness';

export interface ProbeResult {
  harness: string;
  version: string;
  certificate: string;
  scope: string;
  /** sha256 of the authorisation block, so the register can show a run was authorised. */
  authorization: string;
  seed: string;
  startedAt: string;
  finishedAt: string;
  requests: number;
  failed: ControlId[];
  passed: ControlId[];
  inconclusive: ControlId[];
  notProbed: ControlId[];
  probes: Array<{ id: string; control: ControlId; verdict: string; evidence: string }>;
}

export function authorizationDigest(config: TargetConfig): string {
  const a = config.authorization;
  const canonical = JSON.stringify([a.scope, a.authorizedBy, a.date, a.reference ?? '']);
  return createHash('sha256').update(canonical).digest('hex');
}

export function buildResult(
  report: RunReport, config: TargetConfig, version: string,
): ProbeResult {
  const pick = (state: string): ControlId[] =>
    (Object.entries(report.controls) as Array<[ControlId, string]>)
      .filter(([, v]) => v === state).map(([id]) => id);

  const failed = pick('failed');
  for (const id of failed) {
    // Cheap, and the one assertion that protects the whole chain.
    if (!isControlId(id)) throw new Error(`refusing to report an unknown control id: ${id}`);
  }

  return {
    harness: HARNESS,
    version,
    certificate: config.certificate,
    scope: config.authorization.scope,
    authorization: authorizationDigest(config),
    seed: report.seed,
    startedAt: report.startedAt,
    finishedAt: report.finishedAt,
    requests: report.requests,
    failed,
    passed: pick('passed'),
    inconclusive: pick('inconclusive'),
    notProbed: pick('not_probed'),
    probes: report.probes.map(p => ({
      id: p.id, control: p.control, verdict: p.verdict, evidence: p.evidence,
    })),
  };
}

/** One line a person can read without opening the JSON. */
export function summarise(result: ProbeResult): string {
  const bits = [
    `${result.failed.length} failed`,
    `${result.passed.length} passed`,
    `${result.inconclusive.length} inconclusive`,
  ];
  if (result.notProbed.length) bits.push(`${result.notProbed.length} not probed`);
  return `${result.certificate}: ${bits.join(', ')} in ${result.requests} requests`;
}
