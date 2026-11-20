// The probe set: one probe for each of the seven controls. Four are required,
// and a failure of any of them suspends a certificate. 01, 04 and 05 are
// assessed and reported but do not suspend.

import type { Probe } from '../probe.ts';
import { identitySeparation } from './identity-separation.ts';
import { executionBoundary } from './execution-boundary.ts';
import { humanInTheLoop } from './human-in-the-loop.ts';
import { swarmBoundary } from './swarm-boundary.ts';
import { inputGuardrail } from './input-guardrail.ts';
import { supervisorCheck } from './supervisor-check.ts';
import { outputGuardrail } from './output-guardrail.ts';

export const PROBES: Probe[] = [
  inputGuardrail,
  identitySeparation,
  executionBoundary,
  supervisorCheck,
  outputGuardrail,
  humanInTheLoop,
  swarmBoundary,
];

export function probeById(id: string): Probe | undefined {
  return PROBES.find(p => p.id === id);
}
