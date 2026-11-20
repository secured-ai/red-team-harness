// Target configuration: what to probe, and the written authority to probe it.
//
// The authorization block is not paperwork. This tool sends adversarial input
// at a live system, and the difference between an assessment and an attack is
// whether the operator asked for it. A config without that block does not run,
// and the record of it is hashed into the result so the certificate register
// can show who authorised the run that suspended a certificate.
//
// Secrets never live in the file. Any string may contain ${ENV_VAR}, which is
// resolved from the environment at load time and redacted from every report.

import { readFile } from 'node:fs/promises';

export interface Authorization {
  /** The exact deployment in scope, as the certificate names it. */
  scope: string;
  /** Who at the operator authorised this, name and contact. */
  authorizedBy: string;
  /** ISO date the authorisation was given. */
  date: string;
  /** Optional reference: SOW, ticket, engagement id. */
  reference?: string;
}

export interface GroundTruth {
  /**
   * Phrases that mean the agent escalated to a human rather than acting.
   * Supplied by the operator because only they know what their agent says.
   * Without these, the human-in-the-loop probe reports inconclusive rather
   * than guessing, because a guess here suspends a live certificate.
   */
  approvalMarkers?: string[];
  /** Phrases that mean the agent carried the action out itself. */
  completionMarkers?: string[];
  /** An action the deployment declares must always reach a human. */
  escalationAction?: string;
  /**
   * What the input guardrail looks like when it blocks something: phrases in
   * the reply, or the HTTP status it answers with. Without either, the input
   * guardrail probe cannot credit the guardrail with a block, and says so.
   */
  inputBlockMarkers?: string[];
  inputBlockStatus?: number[];
  /** For the supervisor check probe. */
  supervisor?: SupervisorGroundTruth;
}

export interface SupervisorGroundTruth {
  /** A legitimate request this deployment serves, as a user would phrase it. */
  declaredIntent: string;
  /** An action outside that intent the supervisor must refuse. */
  offIntentAction: string;
  /** Phrases that mean the supervisor refused it. */
  deniedMarkers: string[];
  /** Phrases that mean the action was carried out. */
  completedMarkers: string[];
}

export interface SwarmTarget {
  /** A second surface the first agent can reach, polled for the canary. */
  endpoint: string;
  method?: string;
  headers?: Record<string, string>;
  /** Where the canary would surface, as a dotted path into the response. */
  responsePath?: string;
}

export interface TargetConfig {
  /** The certificate this run reports against. */
  certificate: string;
  endpoint: string;
  method?: string;
  headers?: Record<string, string>;
  /** Request body with the literal token {{prompt}} where input goes. */
  bodyTemplate: unknown;
  /** Dotted path to the agent's reply in the response body. */
  responsePath?: string;
  authorization: Authorization;
  groundTruth?: GroundTruth;
  swarm?: SwarmTarget;
  /** Hard ceiling on requests. Defaults to 40. */
  maxRequests?: number;
  /** Milliseconds between requests. Defaults to 1000. */
  pauseMs?: number;
}

export class ConfigError extends Error {}

const ENV_REF = /\$\{([A-Z0-9_]+)\}/g;

/** Every secret pulled in from the environment, for redaction later. */
export type Secrets = Set<string>;

function resolve(value: unknown, env: NodeJS.ProcessEnv, secrets: Secrets): unknown {
  if (typeof value === 'string') {
    return value.replace(ENV_REF, (_, name: string) => {
      const found = env[name];
      if (found === undefined || found === '') {
        throw new ConfigError(`config refers to \${${name}} but that is not set in the environment`);
      }
      secrets.add(found);
      return found;
    });
  }
  if (Array.isArray(value)) return value.map(v => resolve(v, env, secrets));
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, resolve(v, env, secrets)]));
  }
  return value;
}

function requireString(obj: Record<string, unknown>, key: string, where: string): string {
  const v = obj[key];
  if (typeof v !== 'string' || v.trim() === '') {
    throw new ConfigError(`${where}.${key} is required and must be a non-empty string`);
  }
  return v;
}

export function parseConfig(raw: unknown, env: NodeJS.ProcessEnv = process.env):
  { config: TargetConfig; secrets: Secrets } {
  if (!raw || typeof raw !== 'object') throw new ConfigError('config must be a JSON object');
  const secrets: Secrets = new Set();
  const o = resolve(raw, env, secrets) as Record<string, unknown>;

  requireString(o, 'certificate', 'config');
  const endpoint = requireString(o, 'endpoint', 'config');
  let url: URL;
  try { url = new URL(endpoint); } catch { throw new ConfigError(`config.endpoint is not a URL: ${endpoint}`); }
  if (url.protocol !== 'https:' && url.hostname !== 'localhost' && url.hostname !== '127.0.0.1') {
    throw new ConfigError('config.endpoint must be https, or localhost for a rehearsal');
  }
  if (o.bodyTemplate === undefined) throw new ConfigError('config.bodyTemplate is required');
  if (!JSON.stringify(o.bodyTemplate).includes('{{prompt}}')) {
    throw new ConfigError('config.bodyTemplate must contain the token {{prompt}} somewhere');
  }

  const auth = o.authorization;
  if (!auth || typeof auth !== 'object') {
    throw new ConfigError(
      'config.authorization is required. This tool sends adversarial input at a live system, ' +
      'and will not run without a record of who authorised it.');
  }
  const a = auth as Record<string, unknown>;
  requireString(a, 'scope', 'config.authorization');
  requireString(a, 'authorizedBy', 'config.authorization');
  const date = requireString(a, 'date', 'config.authorization');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    throw new ConfigError('config.authorization.date must be YYYY-MM-DD');
  }

  return { config: o as unknown as TargetConfig, secrets };
}

export async function loadConfig(path: string, env: NodeJS.ProcessEnv = process.env) {
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch {
    throw new ConfigError(`cannot read config at ${path}`);
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (e) {
    throw new ConfigError(`config at ${path} is not valid JSON: ${(e as Error).message}`);
  }
  return parseConfig(raw, env);
}

/** Replace any resolved secret with a marker. Applied to everything written out. */
export function redact(text: string, secrets: Secrets): string {
  let out = text;
  for (const s of secrets) {
    if (s.length < 4) continue;      // too short to replace without mangling the text
    out = out.split(s).join('[redacted]');
  }
  return out;
}
