// red-team-harness keygen --kid <kid>
//
// Generate the ES256 key an accredited assessor signs submissions with.
//
// It lives in the harness rather than only in the register's tooling because
// the assessor is the one who must run it: the private key is generated on the
// assessor's machine and never leaves it. If SecuredAI generated it and sent it
// over, SecuredAI would hold a key that can act as the assessor, and the
// assessor's results would stop being attributable to them alone.
//
// Writes two files: <kid>.private.jwk.json, kept and never sent, and
// <kid>.public.jwk.json, sent to SecuredAI for the assessor's register record.

import { webcrypto } from 'node:crypto';
import { chmodSync, existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const KID_RE = /^[A-Za-z0-9._-]{1,64}$/;

export interface KeygenResult { privatePath: string; publicPath: string }

export async function keygen(kid: string, dir = '.'): Promise<KeygenResult> {
  if (!kid || !KID_RE.test(kid)) throw new Error('--kid is required: letters, digits, dot, dash or underscore');
  const privatePath = join(dir, `${kid}.private.jwk.json`);
  const publicPath = join(dir, `${kid}.public.jwk.json`);
  // Never overwrite. Replacing a key that is already registered would leave
  // the assessor unable to sign until the register is updated, and silently
  // destroying a private key is not something a tool should do on a typo.
  for (const path of [privatePath, publicPath]) {
    if (existsSync(path)) throw new Error(`${path} already exists; choose a new kid rather than replacing a key`);
  }
  const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const priv = await webcrypto.subtle.exportKey('jwk', pair.privateKey);
  const pub = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
  writeFileSync(privatePath, JSON.stringify({ ...priv, kid }, null, 2) + '\n', { mode: 0o600 });
  try { chmodSync(privatePath, 0o600); } catch { /* filesystems without modes */ }
  writeFileSync(publicPath, JSON.stringify({ kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y, kid }, null, 2) + '\n');
  return { privatePath, publicPath };
}
