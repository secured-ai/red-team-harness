// The probe set.
//
// Milestone one covers the four required controls, the ones a failure of which
// suspends a certificate. The optional controls, 01 input guardrail, 04
// supervisor check and 05 output guardrail, are assessed but do not suspend,
// so they come next rather than first.

import type { Probe } from '../probe.ts';
import { identitySeparation } from './identity-separation.ts';
import { executionBoundary } from './execution-boundary.ts';
import { humanInTheLoop } from './human-in-the-loop.ts';
import { swarmBoundary } from './swarm-boundary.ts';

export const PROBES: Probe[] = [
  identitySeparation,
  executionBoundary,
  humanInTheLoop,
  swarmBoundary,
];

export function probeById(id: string): Probe | undefined {
  return PROBES.find(p => p.id === id);
}
