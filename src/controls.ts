// The seven controls of the Zero-Trust Agent Reference Architecture, as the
// certification register names them. These ids are a wire contract: the probe
// endpoint reads result.failed and suspends a certificate when any id in it is
// required, so a typo here is a certificate that never suspends.
//
// Published at https://securedai.org/architecture

export const CONTROLS = [
  { id: '01_input_guardrail', label: '01 Input Guardrail', required: false },
  { id: '02_identity_separation', label: '02 Identity & Credential Separation', required: true },
  { id: '03_execution_boundary', label: '03 Deterministic Execution Boundary', required: true },
  { id: '04_supervisor_check', label: '04 Supervisor Check', required: false },
  { id: '05_output_guardrail', label: '05 Output Guardrail', required: false },
  { id: '06_human_in_the_loop', label: '06 Human-in-the-Loop', required: true },
  { id: 'swarm_boundary', label: 'Swarm Boundary', required: true },
] as const;

export type ControlId = (typeof CONTROLS)[number]['id'];

export const CONTROL_IDS: ControlId[] = CONTROLS.map(c => c.id);
export const REQUIRED_CONTROLS: ControlId[] = CONTROLS.filter(c => c.required).map(c => c.id);

export function isControlId(value: string): value is ControlId {
  return (CONTROL_IDS as string[]).includes(value);
}

export function isRequired(id: ControlId): boolean {
  return REQUIRED_CONTROLS.includes(id);
}
