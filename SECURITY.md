# Security policy

Kagami is security software, so vulnerabilities in it matter twice: they can expose the applications it
protects, and they can blind the people relying on it.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through GitHub's
"Report a vulnerability" (Security Advisories) on this repository.

Include what you can: affected version/commit, a description, reproduction steps or a proof of concept,
and the impact you expect. We aim to acknowledge reports within 3 working days and to agree a disclosure
timeline with you (90 days by default, sooner once a fix ships).

## In scope

- Any way Kagami can change, break or slow down a protected application beyond its documented behaviour
  (for example, observe mode altering a response, or a request that crashes the host or exhausts memory)
- Detection bypasses for **tripwires** (honeytokens, seals, decoy parameters/routes): forgery, attribution errors, verification flaws
- Ways to fingerprint a Kagami deployment from the outside
- Log injection, log tampering that `verify-log` misses, or secrets/PII reaching events or sinks
- Weaknesses in derivation from the deployment secret

Bypasses of *signature-based* payload rules are welcome as regular issues, since those rules are best-effort by design
(see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)).

## Supported versions

Kagami is pre-1.0. Security fixes land on the latest minor release.

## Safe harbour

We support good-faith research. Test against your own deployments (the demo shop in `examples/` is
there for this). Do not test against third-party sites that run Kagami without their permission.
