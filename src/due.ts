// Register-driven runs, for Level 3.
//
// The register decides when a certificate is due an adversarial run, at
// times the operator cannot predict, and does not run it. This asks the
// register, as the assessor, which of that assessor's certificates are due,
// and runs the probe set against each one that has a config here.
//
// Three rules keep it from becoming the thing the separation exists to
// prevent.
//
// It only ever probes a certificate the register named as due for this
// assessor, and only with a config whose certificate field is that id. A
// config for something else in the same folder is never touched.
//
// Every config still needs its authorization block. Being due is the
// register's schedule, not the operator's permission.
//
// A certificate that is due and has no config is reported loudly. It is a
// probe that will not happen, and at Level 3 a missed probe is something the
// assessor has to explain.

import { readdir, readFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { signSubmission, SubmitError, type AssessorKey } from './submit.ts';

export interface DueList {
  checked: number;
  due: string[];
}

export interface DueOptions {
  /** The register's probe endpoint. */
  endpoint: string;
  key: AssessorKey;
  fetcher?: (url: string, init: RequestInit) => Promise<Response>;
  now?: () => number;
}

const CERT_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/** Ask the register which of this assessor's certificates are due today. */
export async function fetchDue(opts: DueOptions): Promise<DueList> {
  const url = new URL(opts.endpoint);
  if (url.protocol !== 'https:' && url.hostname !== 'localhost' && url.hostname !== '127.0.0.1') {
    throw new SubmitError('refusing to talk to the register over plain http');
  }
  // An empty body asks for the due list. It is signed like a submission, so
  // the register answers only with this assessor's certificates.
  const body = new TextEncoder().encode('{}');
  const headers = await signSubmission('POST', url.pathname, body, opts.key, (opts.now ?? Date.now)());
  const res = await (opts.fetcher ?? fetch)(opts.endpoint, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body,
  });
  const text = await res.text();
  if (!res.ok) {
    const hint = res.status === 401
      ? ' (the register did not accept the signature: check the assessor id, the kid, that the key is not retired and that the clock is right)'
      : '';
    throw new SubmitError(`register returned ${res.status}${hint}`, res.status, text);
  }
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch { throw new SubmitError('the register did not answer with JSON'); }
  const p = parsed as Partial<DueList>;
  if (typeof p.checked !== 'number' || !Array.isArray(p.due) || p.due.some(d => typeof d !== 'string' || !CERT_ID.test(d))) {
    throw new SubmitError('the register answered with something that is not a due list');
  }
  return { checked: p.checked, due: [...new Set(p.due)] };
}

export interface ConfigIndex {
  /** certificate id to the one config file for it */
  byCertificate: Map<string, string>;
  /** certificate ids claimed by more than one file, which are never run */
  ambiguous: Map<string, string[]>;
  /** files that could not be read as a config at all */
  unreadable: string[];
}

/**
 * Index a folder of target configs by the certificate each names. Read as
 * plain JSON, without resolving ${ENV} references, so indexing never needs
 * the targets' credentials.
 */
export async function indexConfigs(dir: string): Promise<ConfigIndex> {
  const seen = new Map<string, string[]>();
  const unreadable: string[] = [];
  for (const name of (await readdir(dir)).filter(n => n.endsWith('.json')).sort()) {
    const path = join(dir, name);
    try {
      const raw = JSON.parse(await readFile(path, 'utf8')) as { certificate?: unknown };
      if (typeof raw.certificate !== 'string' || !raw.certificate) { unreadable.push(path); continue; }
      seen.set(raw.certificate, [...(seen.get(raw.certificate) ?? []), path]);
    } catch {
      unreadable.push(path);
    }
  }
  const byCertificate = new Map<string, string>();
  const ambiguous = new Map<string, string[]>();
  for (const [cert, paths] of seen) {
    if (paths.length === 1) byCertificate.set(cert, paths[0]); else ambiguous.set(cert, paths);
  }
  return { byCertificate, ambiguous, unreadable };
}

export interface Plan {
  /** due, with exactly one config: these run */
  run: Array<{ certificate: string; config: string }>;
  /** due, no config here: a probe that will not happen */
  missing: string[];
  /** due, more than one config claims it: refused rather than guessed */
  ambiguous: Array<{ certificate: string; configs: string[] }>;
}

/** What to run. Only ids the register named, and only with an unambiguous config. */
export function plan(due: DueList, index: ConfigIndex): Plan {
  const out: Plan = { run: [], missing: [], ambiguous: [] };
  for (const certificate of due.due) {
    const many = index.ambiguous.get(certificate);
    if (many) { out.ambiguous.push({ certificate, configs: many }); continue; }
    const config = index.byCertificate.get(certificate);
    if (config) out.run.push({ certificate, config }); else out.missing.push(certificate);
  }
  return out;
}

/** Where each run's result and report go: one pair per certificate per day. */
export async function outputPaths(dir: string, certificate: string, day: string) {
  await mkdir(dir, { recursive: true });
  const base = join(dir, `${certificate}-${day}`);
  return { json: `${base}.json`, html: `${base}.html` };
}

