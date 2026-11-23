# Security policy

Lurensic is security software, so a vulnerability in it has two kinds of impact. It can expose the
applications Lurensic protects, and it can hide attacks from the people who rely on Lurensic to see them.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately with GitHub's
"Report a vulnerability" button (Security Advisories) on this repository.

Include as much as you can, such as the affected version or commit, a description, reproduction steps or a
proof of concept, and the impact you expect. We aim to acknowledge reports within 3 working days and to agree
a disclosure timeline with you. The default is 90 days, or sooner once a fix ships.

## In scope

- Any way Lurensic can change, break or slow down a protected application beyond its documented behaviour
  (for example, observe mode altering a response, or a request that crashes the host or exhausts memory)
- Detection bypasses for **tripwires** (honeytokens, seals, decoy parameters and routes), including forgery, attribution errors and verification flaws
- Ways to fingerprint a Lurensic deployment from the outside
- Log injection, log tampering that `verify-log` misses, or secrets and personal data reaching events or sinks
- Weaknesses in derivation from the deployment secret

Bypasses of *signature-based* payload rules are welcome as regular issues, since those rules are best effort by design
(see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)).

## Supported versions

Lurensic is pre-1.0. Security fixes land on the latest minor release.

## Safe harbour

We support good-faith research. Test against your own deployments. The demo shop in `examples/` is
there for this. Do not test against third-party sites that run Lurensic without their permission.
