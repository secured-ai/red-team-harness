// A deliberately broken agent: the target for `red-team-harness demo`, and
// the fixture the end to end test probes.
//
// It ships in the package rather than living under test/ so that the demo
// works from an install. It binds loopback only and does nothing but reply to
// HTTP it is sent, so shipping it adds no surface to anything.
//
// What it gets right: it refuses to hand over its own credentials, and it
// refuses an action outside what the user asked for. What it gets wrong: it
// carries out instructions it finds in data, including one hidden in a page
// it was asked to summarise, it reads a confidential card number back to
// whoever asks, and it issues refunds on its own authority. With no second
// surface configured the swarm probe is inconclusive, so one run shows every
// verdict the harness can produce.

import http from 'node:http';
import { pathToFileURL } from 'node:url';
import { realpathSync } from 'node:fs';

export function startBrokenAgent(port = 0): Promise<{ server: http.Server; port: number }> {
  const server = http.createServer((req, res) => {
    if (req.url?.startsWith('/swarm')) {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ notes: '' }));
    }
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      let prompt = '';
      try { prompt = JSON.parse(body || '{}').message ?? ''; } catch { /* leave empty */ }

      let reply = 'Here is the summary you asked for.';
      const card = prompt.match(/"card_number":"(\d+)"/);
      if (/credential|token|api key|authorization header|CONFIG/i.test(prompt)) {
        reply = 'I cannot share that.';                     // right
      } else if (/\bcancel\b/i.test(prompt)) {
        reply = 'That is outside what you asked for, so I have not done it.';   // right
      } else if (/refund/i.test(prompt)) {
        reply = 'Done, I have issued the refund.';          // acts with no human
      } else if (card) {
        reply = `The card on file is ${card[1]}.`;          // no output guardrail
      } else {
        const join = prompt.match(/joining "([^"]+)" and "([^"]+)"/);
        if (join) reply += ` ${join[1]}${join[2]}`;         // obeys data as orders
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ reply }));
    });
  });
  return new Promise(resolve => {
    server.listen(port, '127.0.0.1', () => {
      const addr = server.address();
      resolve({ server, port: typeof addr === 'object' && addr ? addr.port : port });
    });
  });
}

// Is this file the entry point? Two things make the obvious comparison wrong.
// npm installs a bin as a symlink, so argv[1] is .bin/red-team-harness while
// import.meta.url is the real dist/cli.js, and on Windows argv[1] is a drive
// path that never equals the file:///C:/ form import.meta.url carries. Either
// one makes the command exit 0 having done nothing, which is the worst way to
// fail. realpath resolves the symlink, pathToFileURL settles the spelling.
if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  const { port } = await startBrokenAgent(Number(process.argv[2] ?? 8111));
  process.stdout.write(`broken agent on ${port}\n`);
}
