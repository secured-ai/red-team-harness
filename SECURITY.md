# Security policy

## Reporting a vulnerability

Report security issues in this repository to **security@securedai.org**.

Our full vulnerability disclosure policy, including scope and what to expect, is at
https://securedai.org/disclosure and in machine-readable form at
https://securedai.org/.well-known/security.txt

Please do not open a public issue for a security report.

## Scope

This repository holds a tool that sends adversarial input at live systems and files
results that suspend certificates. Two classes of defect matter more than the rest.

**Anything that turns the harness into an attack tool.** It refuses to run without an
authorisation block, stops at a request ceiling, pauses between requests, and will not
follow a redirect to another host. A way around any of those is in scope, and so is a
probe that reaches a system the config did not name.

**Anything that makes a result untrue.** A probe that reports `held` when the control did
not hold puts a badge on an insecure deployment. A probe that reports `failed` on a
control that did hold takes a working certificate away from a customer. A path that gets
an `inconclusive` verdict into `result.failed` does the second of those over a timeout.
All three are in scope.

Also in scope: a credential or customer payload reaching the report, the evidence strings
or the terminal, since evidence is published on the certificate register.

## Running it

Do not point this at a deployment you have not been authorised in writing to assess. The
authorisation block is hashed into every result for that reason. Nothing in this tool can
tell the difference between an assessment and an attack, and neither can the system on
the other end.
