// The one place that talks to the deployment under assessment.
//
// Every request goes through here so the limits are real rather than a
// convention probes are trusted to honour: a request ceiling, a pause between
// calls, and a refusal to follow a redirect to another host. A harness that
// can be walked off its target by a 302 is a harness that can be used to
// attack a third party, which is the thing this must never become.

import { redact, type Secrets, type TargetConfig } from './config.ts';

export interface Reply {
  text: string;
  status: number;
}

export class BudgetError extends Error {}

function at(obj: unknown, path: string | undefined): string {
  if (!path) return typeof obj === 'string' ? obj : JSON.stringify(obj);
  let cur: unknown = obj;
  for (const part of path.split('.')) {
    if (cur && typeof cur === 'object' && part in (cur as Record<string, unknown>)) {
      cur = (cur as Record<string, unknown>)[part];
    } else {
      return '';
    }
  }
  return typeof cur === 'string' ? cur : JSON.stringify(cur ?? '');
}

// {{session}} is optional. A deployment that keeps conversation state server
// side by a session or conversation id puts it in the template, and the
// multi-turn probes then send two turns under one id. Without it there is no
// way to send a real second turn, and those probes skip that step rather than
// pretend.
function fill(template: unknown, prompt: string, session: string): unknown {
  if (typeof template === 'string') return template.split('{{prompt}}').join(prompt).split('{{session}}').join(session);
  if (Array.isArray(template)) return template.map(t => fill(t, prompt, session));
  if (template && typeof template === 'object') {
    return Object.fromEntries(
      Object.entries(template as Record<string, unknown>).map(([k, v]) => [k, fill(v, prompt, session)]));
  }
  return template;
}

export interface AskOptions {
  /** Conversation id for this exchange. A fresh one is used when omitted. */
  session?: string;
}

export type Fetcher = (url: string, init: RequestInit) => Promise<Response>;

// Fields are declared and assigned rather than written as constructor
// parameter properties, which Node's type stripping does not support.
export class Target {
  readonly host: string;
  private spent = 0;
  private sessions = 0;
  private readonly ceiling: number;
  private readonly pauseMs: number;
  private readonly config: TargetConfig;
  private readonly secrets: Secrets;
  private readonly fetcher: Fetcher;
  private readonly sleep: (ms: number) => Promise<void>;

  constructor(
    config: TargetConfig,
    secrets: Secrets,
    fetcher: Fetcher = fetch,
    sleep: (ms: number) => Promise<void> = ms => new Promise(r => setTimeout(r, ms)),
  ) {
    this.config = config;
    this.secrets = secrets;
    this.fetcher = fetcher;
    this.sleep = sleep;
    this.host = new URL(config.endpoint).host;
    this.ceiling = config.maxRequests ?? 40;
    this.pauseMs = config.pauseMs ?? 1000;
  }

  get used(): number { return this.spent; }
  get budget(): number { return this.ceiling; }

  /** Requests left. Probes check this rather than discovering the ceiling mid-run. */
  get remaining(): number { return Math.max(0, this.ceiling - this.spent); }

  /** Whether the deployment can be held to one conversation across turns. */
  get supportsSessions(): boolean {
    return JSON.stringify(this.config.bodyTemplate).includes('{{session}}');
  }

  async ask(prompt: string, opts: AskOptions = {}): Promise<Reply> {
    // Each single-turn ask gets its own conversation, so one probe's attack
    // never leaks into the context of the next.
    const session = opts.session ?? `rth-${++this.sessions}`;
    return this.call(this.config.endpoint, {
      method: this.config.method ?? 'POST',
      headers: { 'Content-Type': 'application/json', ...(this.config.headers ?? {}) },
      body: JSON.stringify(fill(this.config.bodyTemplate, prompt, session)),
    }, this.config.responsePath);
  }

  /** Read the second surface, for the swarm probe. */
  async readSwarm(): Promise<Reply> {
    const swarm = this.config.swarm;
    if (!swarm) throw new Error('no swarm target configured');
    return this.call(swarm.endpoint, {
      method: swarm.method ?? 'GET',
      headers: { ...(swarm.headers ?? {}) },
    }, swarm.responsePath);
  }

  private async call(url: string, init: RequestInit, path?: string): Promise<Reply> {
    if (this.spent >= this.ceiling) {
      throw new BudgetError(`request ceiling of ${this.ceiling} reached`);
    }
    if (this.spent > 0) await this.sleep(this.pauseMs);
    this.spent++;

    const res = await this.fetcher(url, { ...init, redirect: 'manual' });

    // A redirect is not followed. If it points off the authorised host, following
    // it would mean sending attack traffic at someone who never agreed to it.
    if (res.status >= 300 && res.status < 400) {
      const to = res.headers.get('location') || '';
      let sameHost = false;
      try { sameHost = new URL(to, url).host === this.host; } catch { sameHost = false; }
      return { status: res.status, text: sameHost ? '' : `[redirect off the authorised host, not followed]` };
    }

    const body = await res.text();
    let parsed: unknown = body;
    try { parsed = JSON.parse(body); } catch { /* a plain text reply is fine */ }
    return { status: res.status, text: redact(at(parsed, path), this.secrets) };
  }
}
