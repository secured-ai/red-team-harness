#!/usr/bin/env node
/**
 * Pack the package, install it the way a prospect would, and run the demo.
 *
 * The suite runs against the source tree, where Node happily strips the types
 * out of a .ts file. It cannot see the failure that matters most at publish
 * time: Node refuses to strip types for anything under node_modules, so a
 * package whose bin and exports point at its .ts sources throws
 * ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING on the first run. Forty passing
 * tests say nothing about that, because none of them load the package the way
 * an installed copy is loaded.
 *
 * That failure would land on exactly the people we most want it not to. The
 * demo exists so somebody evaluating this can see it work in one command, and
 * a broken tarball turns that into an error message on their first contact
 * with the product.
 *
 * So this builds the tarball, installs it into a scratch directory with no
 * path back to this repo, runs `red-team-harness demo` through the installed
 * bin, and checks the output is the real thing. It also imports the package
 * entry point, because the library half has the same failure mode.
 *
 * Run: npm run smoke
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const PKG = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const name = JSON.parse(readFileSync(join(PKG, 'package.json'), 'utf8')).name;

function exec(cmd, args, cwd, shell = false) {
  return execFileSync(cmd, args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'], shell });
}

/**
 * Run npm in a way that works on every platform.
 *
 * On Windows `npm` is a .cmd shim, and since the fix for CVE-2024-27980 Node
 * refuses to spawn .cmd files without a shell, so execFileSync('npm', ...)
 * fails with ENOENT. Going through npm's own entry point with this Node binary
 * avoids the shim. npm sets npm_execpath when it runs a script, so `npm run
 * smoke` takes that path.
 */
function npm(args, cwd) {
  if (process.env.npm_execpath) return exec(process.execPath, [process.env.npm_execpath, ...args], cwd);
  if (process.platform === 'win32') {
    return exec('npm.cmd', args.map(a => (/[\s"]/.test(a) ? `"${a}"` : a)), cwd, true);
  }
  return exec('npm', args, cwd);
}

const scratch = mkdtempSync(join(tmpdir(), 'rth-smoke-'));
let failed = false;
const check = (label, ok, detail = '') => {
  process.stdout.write(`  ${ok ? 'ok  ' : 'FAIL'}  ${label}\n`);
  if (!ok) { failed = true; if (detail) process.stdout.write(`        ${detail}\n`); }
};

try {
  process.stdout.write('packing...\n');
  const packed = npm(['pack', '--silent', '--pack-destination', scratch], PKG).trim().split('\n').pop();
  const tarball = join(scratch, packed);

  process.stdout.write(`installing ${packed} into a scratch directory...\n`);
  writeFileSync(join(scratch, 'package.json'), JSON.stringify({ name: 'smoke', private: true, type: 'module' }));
  npm(['install', '--silent', '--no-audit', '--no-fund', tarball], scratch);

  process.stdout.write('\nthe installed copy:\n');

  // The bin, which is what `npx red-team-harness demo` runs.
  const bin = join(scratch, 'node_modules', '.bin', process.platform === 'win32' ? 'red-team-harness.cmd' : 'red-team-harness');
  let out = '';
  let code = 0;
  try {
    out = exec(bin, ['demo'], scratch, process.platform === 'win32');
  } catch (e) {
    code = e.status ?? 1;
    out = `${e.stdout ?? ''}${e.stderr ?? ''}`;
  }
  check('the demo runs from the installed bin', code === 0, out.slice(0, 400));
  check('it reports a control holding', /held\s+identity\/credential-disclosure/.test(out));
  check('it reports the two controls the demo agent fails', /failed\s+boundary\/indirect-injection/.test(out) && /failed\s+escalation\/acts-without-a-human/.test(out));
  check('it keeps inconclusive separate from passed', /inconclusive/.test(out) && /1 passed/.test(out));

  // The library entry point, which has the same type-stripping failure mode.
  const probe = join(scratch, 'probe.mjs');
  writeFileSync(probe, `import * as api from '${name}';\n` +
    `const names = Object.keys(api).sort();\n` +
    `if (names.length === 0) { console.error('the package exported nothing'); process.exit(1); }\n` +
    `console.log(names.join(','));\n`);
  let exported = '';
  try {
    exported = exec(process.execPath, [probe], scratch).trim();
  } catch (e) {
    exported = '';
    check('importing the package works', false, `${e.stdout ?? ''}${e.stderr ?? ''}`.slice(0, 400));
  }
  if (exported) check(`importing the package works (${exported.split(',').length} exports)`, true);

  // Types ship, or every TypeScript consumer gets an implicit any.
  check('the type declarations are in the tarball',
    npm(['pack', '--silent', '--dry-run', '--json'], PKG).includes('dist/index.d.ts'));
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

process.stdout.write(failed ? '\nthe packaged install is broken\n' : '\nthe packaged install works\n');
process.exit(failed ? 1 : 0);
