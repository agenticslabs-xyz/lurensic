# Kagami threat model

This threat model covers Kagami v0.1. It works through the assets, the adversaries, the threats (STRIDE style),
the mitigations and the residual risk.

## 1. Assets

| Asset | Why it matters |
|---|---|
| The protected application's availability and correctness | Kagami must never cause an outage or a change in behaviour |
| The deployment secret | Every decoy, token and seal is derived from it |
| Detection integrity | Defenders need to trust that alerts are real and complete |
| Audit log | Evidence for incident response, and possibly for legal use |
| Legitimate users' data and privacy | Kagami sees every request |

## 2. Adversaries

| Adversary | Capabilities | Knows Kagami's source? |
|---|---|---|
| **A1** Automated AI pentest agent | Reads everything, follows instructions from its operator, runs standard checklists, rotates IPs | Assume yes |
| **A2** Careful human-steered agent | Everything A1 can do, plus an operator who has read this repository and tunes the agent to avoid tripwires | Yes |
| **A3** Log and alert attacker | Injects content meant to mislead or exploit the people and tools that read Kagami's alerts | Yes |
| **A4** Insider or post-compromise attacker | Has write access to logs or config on a compromised host | Yes |

## 3. Threats and mitigations

### 3.1 Against the protected application

| Threat | Mitigation |
|---|---|
| Kagami crashes or slows the app | Every call is wrapped to fail open. A WASM trap disables only that instance, which is rebuilt (rate limited). Memory is bounded by the session cap, body cap and parameter cap. Measured cost is under 0.1 ms per request. |
| Kagami changes legitimate responses | Observe mode is inert (tested byte for byte). In protect mode, decoration only touches full HTML documents (one comment) and, if enabled, top-level JSON objects (one field, inserted as text). |
| A decoy route collides with a real route | Routes are derived from the secret and checked against `reservedPaths` when they are derived. **Residual risk.** An unlisted real route could collide, although the probability is small given the size of the name space. `kagami doctor` (planned) will check this automatically. |
| The JSON decoy field breaks strict clients | It is off by default. It is inserted at the start of the object and ignored by tolerant parsers. **Residual risk.** Clients with strict schema validation (`additionalProperties: false`) should not enable it. |
| An attacker uses Kagami to DoS the app with an event flood or session flood | Events are deduplicated per rule and session, there is a per-minute event budget with a separate critical budget, the session store is bounded with clean sessions evicted first, and the async queue is bounded. |

### 3.2 Against detection (A1, A2)

| Threat | Mitigation |
|---|---|
| The attacker tells the agent to ignore instructions on the target | No detection depends on the agent obeying text. Bait comments are only leaks. The detection is the *use* of what was leaked. |
| The attacker reads the source and avoids known decoys | Decoys are derived per deployment from the secret, so there is no global list. Seals are cryptographic. |
| The attacker fingerprints Kagami to learn that it is present | Kagami adds no headers, cookies or fixed paths. Decoy responses go through the app's own response path. Comment wording, placement and route names vary. **Residual risk.** A determined attacker who compares `/.env` responses across many sites may learn the bait *format*. Template randomisation and user-supplied templates are planned. Knowing Kagami is present still leaves the attacker with the A2 dilemma described below. |
| The attacker rotates IPs or user agents to reset session scores | Honeytokens carry the issuing session's tag, so their use from any session is attributed and both sessions are flagged. **Residual risk.** Scores built only from signals (payloads, enumeration) reset with a new identity. |
| The attacker forges or replays honeytokens or seals | Each uses a 48 to 80 bit truncated HMAC-SHA256 under the deployment secret, verified in constant time. Tokens from other deployments do not verify. |
| The attacker avoids every tripwire (A2) | **This is the intended dilemma.** An agent that never uses found credentials, never changes IDs, never sets unfamiliar fields and never probes files has given up most of its methods. Kagami does not claim to detect an attacker who behaves exactly like a normal user. |
| Evasion of payload signatures through encodings, comments or case | Kagami applies multi-layer percent decoding, case folding, SQL comment removal and whitespace collapsing. **Residual risk.** Signature evasion is always possible. Payload rules are signals and not the basis of detection. |

### 3.3 Against the audit trail (A3, A4)

| Threat | Mitigation |
|---|---|
| Log forging with CR and LF characters or JSON in user agents and paths | Events are serialised in the core with JSON escaping, control characters are replaced and fields are truncated. This is tested with hostile input. |
| Terminal escape sequences or bidi spoofing in log viewers | C0 and C1 control characters and bidi overrides are replaced with U+FFFD. |
| Prompt injection aimed at AI triage tools that read alerts | Every event lists its attacker-controlled fields in `untrusted`. Slack alerts contain only short, escaped summaries. Downstream tools must treat these fields as data. |
| Chat-ops abuse through mentions, malicious links or SSRF via link unfurling | `slackSink` escapes `<`, `>`, `&` and backticks, and disables link and media unfurling. |
| Forged alerts sent to the webhook receiver | Webhooks are signed with an HMAC and a timestamp. Receivers should reject old timestamps. |
| Secrets leaking into logs | Sensitive parameter names are redacted, cookies and `Authorization` headers are never logged, honeytokens are masked and the deployment secret is never logged. **Residual risk.** Secrets embedded in URL *paths*, such as password reset tokens, are logged as part of the path. Use `ignorePaths` for such routes until path redaction patterns ship. |
| Log tampering after a compromise (A4) | Each instance keeps a SHA-256 hash chain that `kagami verify-log` can verify. **Residual risk.** An attacker with write access can truncate the *end* of a log without detection, or rewrite the entire chain. Ship logs off the host promptly (webhook or SIEM) for stronger guarantees. |
| A webhook redirect to an internal address | Redirects are not followed (`redirect: 'manual'`), and HTTPS is required except for localhost. |

### 3.4 Against the secret

| Threat | Mitigation |
|---|---|
| A weak secret | A minimum of 32 characters is enforced, and `npx @agenticslabs/kagami secret` generates 256 bits. |
| Secret exposure through the manifest | `manifest()` is a host-side API only and no adapter exposes it over HTTP. The documentation says it must never be exposed. |
| The secret in config files | It is read from `KAGAMI_SECRET` by default, config is never logged, and the Rust `Config` type deliberately does not implement `Debug`. |

### 3.5 Privacy

Kagami processes request metadata, which includes personal data such as IP addresses. By default no data leaves the
host unless a sink is configured. IP logging can be set to `hashed` or `omit`. Request bodies are inspected in memory
and never logged. Only short, sanitised snippets of *matched* attack payloads are recorded, with sensitive fields redacted.

## 4. Out of scope

- Volumetric DDoS. Use your CDN or WAF for this.
- Attackers who only perform actions that cannot be told apart from normal use.
- Vulnerabilities in the protected application itself.
- Off-site use of honeytokens, such as trying the fake AWS key directly against AWS. Support for this is planned through cloud canary credentials.
