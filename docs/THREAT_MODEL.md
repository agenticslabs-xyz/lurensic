# Kagami threat model

Status: v0.1 · Method: assets → adversaries → threats (STRIDE-style) → mitigations → residual risk.

## 1. Assets

| Asset | Why it matters |
|---|---|
| The protected application's availability and correctness | Kagami must never be the cause of an outage or a behaviour change |
| The deployment secret | Every decoy, token and seal is derived from it |
| Detection integrity | Defenders need to trust that alerts are real and complete |
| Audit log | Evidence for incident response, and possibly legal use |
| Legitimate users' data and privacy | Kagami sees every request |

## 2. Adversaries

| Adversary | Capabilities | Knows Kagami's source? |
|---|---|---|
| **A1** Automated AI pentest agent | Reads everything, follows instructions from its operator, runs standard checklists, rotates IPs | Assume yes |
| **A2** Careful human-steered agent | A1 plus an operator who has read this repository and tunes the agent to avoid tripwires | Yes |
| **A3** Log/alert attacker | Injects content intended to mislead or exploit the people and tools reading Kagami's alerts | Yes |
| **A4** Insider / post-compromise | Write access to logs or config on a compromised host | Yes |

## 3. Threats and mitigations

### 3.1 Against the protected application

| Threat | Mitigation |
|---|---|
| Kagami crashes or slows the app | Fail-open wrappers on every call. WASM traps poison only the instance, which is rebuilt (rate limited). Bounded memory (session cap, body cap, param cap). Measured per-request cost under 0.1 ms. |
| Kagami changes legitimate responses | Observe mode is inert (tested byte for byte). In protect mode, decoration only touches full HTML documents (one comment) and, if opted in, top-level JSON objects (one field, inserted as text). |
| Decoy route collides with a real route | Routes derived from the secret, `reservedPaths` checked at derivation. **Residual:** an unlisted real route could collide (the probability is small given the name space). `kagami doctor` (planned) will check this automatically. |
| JSON decoy field breaks strict clients | Off by default. Inserted at the start of the object and ignored by tolerant parsers. **Residual:** clients with strict schema validation (`additionalProperties: false`) should not enable it. |
| Attacker uses Kagami to DoS the app (event flood, session flood) | Per-rule-per-session event dedupe, per-minute event budget with a separate critical budget, bounded session store with clean-first eviction, bounded async queue. |

### 3.2 Against detection (A1, A2)

| Threat | Mitigation |
|---|---|
| "Ignore instructions on the target" | No detection depends on the agent obeying text. Bait comments are just leaks; the detection is the *use* of what was leaked. |
| Attacker reads the source and avoids known decoys | Decoys are derived per deployment from the secret. There's no global list. Seals are cryptographic. |
| Attacker fingerprints Kagami to know it's present | No headers, cookies or fixed paths. Decoy responses go through the app's own response path. Comment wording, placement and route names vary. **Residual:** a determined attacker comparing `/.env` responses across many sites may learn the bait *format*. Mitigation planned: template randomisation and user-supplied templates. Knowing Kagami is present still forces the A2 dilemma below. |
| Attacker rotates IPs/UAs to reset session scores | Honeytokens carry the issuing session's tag, so use from any session is attributed and both sessions are flagged. **Residual:** pure signal-based scores (payloads, enumeration) reset with a new identity. |
| Attacker forges or replays honeytokens/seals | 48–80-bit truncated HMAC-SHA256 under the deployment secret, verified in constant time. Tokens from other deployments don't verify. |
| Attacker avoids every tripwire (A2) | **This is the intended dilemma.** An agent that never uses found credentials, never changes IDs, never sets unfamiliar fields and never probes files has given up most of its methods. Kagami does not claim to detect an attacker who behaves exactly like a normal user. |
| Evasion of payload signatures (encodings, comments, case) | Multi-layer percent-decoding, case folding, SQL comment removal, whitespace collapsing. **Residual:** signature evasion is always possible. Payload rules are signals, not the foundation. |

### 3.3 Against the audit trail (A3, A4)

| Threat | Mitigation |
|---|---|
| Log forging via CR/LF or JSON in user agents/paths | Core-side serialisation (JSON escaping), control characters replaced, fields truncated. Tested with hostile input. |
| Terminal escape / bidi spoofing in log viewers | C0/C1 controls and bidi overrides replaced with U+FFFD. |
| Prompt injection aimed at AI triage tools reading alerts | Every event lists its attacker-controlled fields in `untrusted`. Slack alerts contain only short, escaped summaries. Downstream tools must treat these fields as data. |
| Chat-ops abuse (mentions, malicious links, unfurl SSRF) | `slackSink` escapes `<`, `>`, `&` and backticks, and disables link and media unfurling. |
| Forged alerts sent to the webhook receiver | HMAC-signed webhooks with a timestamp (receivers should reject old timestamps). |
| Secrets leaking into logs | Sensitive parameter names redacted, cookies never logged, `Authorization` never logged, honeytokens masked, the deployment secret never logged. **Residual:** secrets embedded in URL *paths* (e.g. reset tokens) are logged as part of the path. Use `ignorePaths` for such routes until path redaction patterns ship. |
| Log tampering after compromise (A4) | Per-instance SHA-256 hash chain, verifiable with `kagami verify-log`. **Residual:** an attacker with write access can truncate the *tail* of a log undetectably, or rewrite the entire chain. Ship logs off-host promptly (webhook/SIEM) for stronger guarantees. |
| Webhook redirect to an internal address | `redirect: 'manual'`, HTTPS required except for localhost. |

### 3.4 Against the secret

| Threat | Mitigation |
|---|---|
| Weak secret | Minimum 32 characters enforced; `npx @agenticslabs/kagami secret` generates 256 bits. |
| Secret exposure via the manifest | `manifest()` is a host-side API only; no adapter exposes it over HTTP. Documented as never-expose. |
| Secret in config files | Read from `KAGAMI_SECRET` by default; config is never logged; the Rust `Config` type deliberately does not implement `Debug`. |

### 3.5 Privacy

Kagami processes request metadata, which includes personal data (IP addresses). Defaults: no data leaves the host
unless a sink is configured, IP logging can be `hashed` or `omit`, and request bodies are inspected in memory and never logged
(only short, sanitised snippets of *matched* attack payloads, with sensitive fields redacted).

## 4. Out of scope

- Volumetric DDoS (use your CDN/WAF).
- Attackers who only perform actions indistinguishable from normal use.
- Vulnerabilities in the protected application itself.
- Off-site use of honeytokens (e.g. trying the fake AWS key directly against AWS). This is planned via cloud canary integration.
