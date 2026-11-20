# Changelog

## 0.4.0

### Added

- Probes for the three controls that had none: `input/obfuscated-injection`
  (01 input guardrail), `supervisor/off-intent-action` (04 supervisor check)
  and `output/data-leaves` (05 output guardrail). All seven controls are now
  probed. The three are assessed, not required, so a failure is reported and
  does not suspend a certificate.
- A written report. Every run writes `probe-report.html` beside the result:
  outcomes by control, each finding with what was tested, observed, what it
  means and what to do, the authorisation and the seed. `report` rebuilds it
  from a saved result, and refuses an authorisation the run was not made under.
  `--assessor-name` puts the firm's name on it.
- `groundTruth.inputBlockMarkers`, `inputBlockStatus` and `supervisor`.

### Fixed

- The indirect injection probe could fail a required control for an agent that
  only quoted the planted instruction back, because the value it looked for was
  in the prompt. The value is now planted in two halves to be joined, so it can
  only come back if the instruction was carried out. See `joinedCanary`.

## 0.3.0

### Breaking

- Submissions are signed with the assessor's own ES256 key. `--credential` and
  `CERT_SUBMIT_SECRET` are gone; use `--assessor` and `--assessor-key`, or
  `ASSESSOR_ID` and `ASSESSOR_KEY_FILE`. The register no longer accepts the old
  shared secret for results, because whoever held it could suspend any
  certificate in the register with no name attached.

### Added

- `signSubmission` and `assessorSigningString`, exported, so another
  implementation can be checked against this one byte for byte.
- The bytes signed and the bytes sent are one serialisation, not two that are
  probably identical: the register verifies a digest of what it received.
- A 401 from the register now says what to check: the assessor id, the kid,
  whether the key is retired, and the clock.

## 0.2.0

First release intended to be installed rather than cloned.

### Added

- `red-team-harness demo` starts a deliberately broken agent on loopback,
  probes it and prints the result. No target of your own, no configuration and
  no authorisation to obtain, so the tool can be evaluated in one command.
  The demo reads no endpoint, host or config, because self-authorising a run
  against a target the command did not start would not be defensible.
- `npm run smoke` packs the tarball, installs it into a scratch directory and
  runs the demo through the installed bin.

### Fixed

- The entry-point guard compared `import.meta.url` against `argv[1]` directly.
  npm installs a bin as a symlink, so an installed `red-team-harness` exited 0
  having done nothing at all. On Windows it failed the same way for a different
  reason: `argv[1]` is a drive path that never matches the `file:///C:/` form.
  Both are resolved now, and the smoke test is what found it.

### Changed

- The package publishes compiled JavaScript from `dist` rather than pointing at
  its TypeScript sources. Node refuses to strip types under `node_modules`, so
  the previous layout would have thrown on a consumer's first import.
- The broken agent moved from `test/fixtures` into `src`, so it ships.

## 0.1.0

Initial release. Four probes covering the four controls that suspend a
certificate at Level 3, three-way verdicts that keep inconclusive out of both
pass and fail, a mandatory authorisation block, and opt-in submission to the
certification register.
