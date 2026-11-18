// Hand the result to the certification register.
//
// POST /api/certification/probe
//   body     { action: "result", certificate: "<id>", result: { ... } }
//   headers  x-assessor-id, x-assessor-kid, x-assessor-timestamp,
//            x-assessor-nonce, x-assessor-signature
//
// Every submission is signed with the accredited assessor's own ES256 key.
// The register used to accept a single shared secret here, which meant any
// assessor holding it could post a failed required control against any
// certificate, including another assessor's client, and suspend it with no
// name attached. It now accepts a result only when it is signed by an active
// key of an active assessor, and only for a certificate bound to that
// assessor. A suspension caused by a result records who signed it and a digest
// of exactly the bytes they signed.
//
// What gets signed, exactly, since another implementation has to match it:
//
//   SAR1\n<METHOD>\n<path>\n<timestamp ms>\n<nonce>\n<sha256 hex of the body>
//
// ES256, signature in IEEE P1363 form (r || s), base64url, no padding.

import { webcrypto, type JsonWebKey } from 'node:crypto';
import type { ProbeResult } from './result.ts';

export const ASSESSOR_HEADERS = {
  id: 'x-assessor-id',
  kid: 'x-assessor-kid',
  timestamp: 'x-assessor-timestamp',
  nonce: 'x-assessor-nonce',
  signature: 'x-assessor-signature',
} as const;

export interface AssessorKey {
  /** The assessor's id in the register, for example "harbourline". */
  assessorId: string;
  /** Which of the assessor's keys this is. Taken from the JWK's kid if not given. */
  kid?: string;
  /** EC P-256 private JWK, as written by the register's tools/assessor.mjs keygen. */
  privateJwk: JsonWebKey & { kid?: string };
}

export interface SubmitOptions {
  endpoint: string;
  key: AssessorKey;
  fetcher?: (url: string, init: RequestInit) => Promise<Response>;
  now?: () => number;
}

export class SubmitError extends Error {
  readonly status?: number;
  readonly body?: string;
  constructor(message: string, status?: number, body?: string) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

const enc = new TextEncoder();

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const d = await webcrypto.subtle.digest('SHA-256', bytes);
  return Buffer.from(d).toString('hex');
}

export async function assessorSigningString(
  method: string, path: string, timestamp: string, nonce: string, body: Uint8Array,
): Promise<string> {
  return ['SAR1', method.toUpperCase(), path, timestamp, nonce, await sha256Hex(body)].join('\n');
}

/** The headers that authenticate one submission. Exported so it can be checked against the register. */
export async function signSubmission(
  method: string, path: string, body: Uint8Array, key: AssessorKey,
  now: number = Date.now(), nonce: string = Buffer.from(webcrypto.getRandomValues(new Uint8Array(18))).toString('base64url'),
): Promise<Record<string, string>> {
  const kid = key.kid ?? key.privateJwk.kid;
  if (!kid) throw new SubmitError('the assessor key has no kid: pass one, or use a JWK written by assessor.mjs keygen');
  if (!key.privateJwk.d) throw new SubmitError('the assessor key is a public key: submissions are signed with the private half');
  const privateKey = await webcrypto.subtle.importKey(
    'jwk', { kty: key.privateJwk.kty, crv: key.privateJwk.crv, x: key.privateJwk.x, y: key.privateJwk.y, d: key.privateJwk.d },
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const timestamp = String(now);
  const message = enc.encode(await assessorSigningString(method, path, timestamp, nonce, body));
  const signature = new Uint8Array(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, message));
  return {
    [ASSESSOR_HEADERS.id]: key.assessorId,
    [ASSESSOR_HEADERS.kid]: kid,
    [ASSESSOR_HEADERS.timestamp]: timestamp,
    [ASSESSOR_HEADERS.nonce]: nonce,
    [ASSESSOR_HEADERS.signature]: Buffer.from(signature).toString('base64url'),
  };
}

export async function submit(result: ProbeResult, opts: SubmitOptions): Promise<unknown> {
  if (!opts.key || !opts.key.assessorId || !opts.key.privateJwk) {
    throw new SubmitError('no assessor key: set ASSESSOR_ID and ASSESSOR_KEY_FILE, or pass --assessor and --assessor-key');
  }
  const url = new URL(opts.endpoint);
  if (url.protocol !== 'https:' && url.hostname !== 'localhost' && url.hostname !== '127.0.0.1') {
    throw new SubmitError('refusing to send a result over plain http');
  }

  // Serialise once and sign those bytes. The register verifies a digest of
  // the body it received, so the bytes signed and the bytes sent must be the
  // same object, not two serialisations that are probably identical.
  const body = enc.encode(JSON.stringify({ action: 'result', certificate: result.certificate, result }));
  const headers = await signSubmission('POST', url.pathname, body, opts.key, (opts.now ?? Date.now)());

  const res = await (opts.fetcher ?? fetch)(opts.endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body,
  });

  const text = await res.text();
  if (!res.ok) {
    const hint = res.status === 401
      ? ' (the register did not accept the signature: check the assessor id, the kid, that the key is not retired and that the clock is right)'
      : res.status === 404 ? ' (no such certificate for this assessor: it may not exist, or may not be bound to you)'
      : res.status === 400 ? ' (the register rejected the body)' : '';
    throw new SubmitError(`register returned ${res.status}${hint}`, res.status, text);
  }
  try { return JSON.parse(text); } catch { return text; }
}
