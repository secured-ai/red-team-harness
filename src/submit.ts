// Hand the result to the certification register.
//
// POST /api/certification/probe
//   header  x-cert-cron-secret: <credential>
//   body    { action: "result", certificate: "<id>", result: { ... } }
//
// Note on that header name. The register currently authenticates result
// submission with the same shared secret that drives its own scheduler, which
// means an assessor who can post a result can also enumerate which
// certificates are due and post results against any of them. That is a
// register-side design question, not something a client can fix, and it is
// written up in README.md under "A note to the register". This module takes
// whatever credential it is given and sends it under the header the register
// expects today, so it keeps working if that changes to a per-assessor key.

import type { ProbeResult } from './result.ts';

export interface SubmitOptions {
  endpoint: string;
  credential: string;
  fetcher?: (url: string, init: RequestInit) => Promise<Response>;
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

export async function submit(result: ProbeResult, opts: SubmitOptions): Promise<unknown> {
  if (!opts.credential) {
    throw new SubmitError('no credential: set CERT_SUBMIT_SECRET or pass --credential');
  }
  const url = new URL(opts.endpoint);
  if (url.protocol !== 'https:' && url.hostname !== 'localhost' && url.hostname !== '127.0.0.1') {
    throw new SubmitError('refusing to send a result over plain http');
  }

  const res = await (opts.fetcher ?? fetch)(opts.endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-cert-cron-secret': opts.credential,
    },
    body: JSON.stringify({
      action: 'result',
      certificate: result.certificate,
      result,
    }),
  });

  const text = await res.text();
  if (!res.ok) {
    const hint = res.status === 401
      ? ' (the register rejected the credential)'
      : res.status === 400 ? ' (the register rejected the body)' : '';
    throw new SubmitError(`register returned ${res.status}${hint}`, res.status, text);
  }
  try { return JSON.parse(text); } catch { return text; }
}
