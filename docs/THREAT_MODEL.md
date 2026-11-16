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
| Kagami changes legitimate responses | Observe mode is inert (tested byte for byte). In protect mode, decoration only touches full HTML documents (one comment on selected pages) and, if enabled, top-level JSON objects (one field, inserted as text) and POST forms (one hidden input). **Residual risk.** With form decoys on, form handlers receive one extra field. Handlers that reject unknown fields should leave form decoys off. |
| A decoy route collides with a real route | Routes are derived from the secret and checked against `reservedPaths` when they are derived. **Residual risk.** An unlisted real route could collide, although the probability is small given the size of the name space. `kagami doctor` (planned) will check this automatically. |
| The JSON decoy field breaks strict clients | It is off by default. It is inserted at the start of the object and ignored by tolerant parsers. **Residual risk.** Clients with strict schema validation (`additionalProperties: false`) should not enable it. |
| An attacker uses Kagami to DoS the app with an event flood or session flood | Events are deduplicated per rule and session, there is a per-minute event budget with a separate critical budget, the session store is bounded with clean sessions evicted first, and the async queue is bounded. |

### 3.2 Against containment

Containment cuts a machine off from the application and can push the address to an edge firewall. The main risk
is containing someone who is not an attacker.

| Threat | Mitigation |
|---|---|
| An attacker gets an innocent address contained by forging a client address header | Kagami contains the address the adapter gives it, so the adapter must not trust forwarding headers from untrusted peers. With `clientAddress`, the core resolves the address itself. It follows `X-Forwarded-For` only through your own proxies and trusts `CF-Connecting-IP` only from Cloudflare's published ranges. Forged values that no proxy writes also raise `client.forged_forwarding`. |
| An attacker makes a real visitor's browser trip a wire, for example a hidden form on another site that posts a changed decoy field, or an image tag that loads a decoy route | A request marked `Sec-Fetch-Site: cross-site`, or carrying an `Origin` whose host differs from the request's, is logged but never contains its sender. **Residual risk.** A browser that sends neither header on a cross-site GET (very old browsers) could still be contained by a forged image request. Containment expires and `release` ends it early. |
| Several people share one address (an office NAT, carrier-grade NAT, a VPN exit) and one of them attacks | Everyone behind that address is contained with the attacker. Only tripwires contain by default, so this needs a real attack from that address. Use `allow` for your own offices and known shared exits. Containment expires after one day by default, and carrier-grade NAT addresses are never pushed to edge enforcers. |
| A false positive from accumulated signals, such as a customer who searches for `<script>` | Signals alone never contain unless `trigger: 'flagged'` is chosen. Tripwires are actions honest visitors cannot take by accident. |
| The shadow leaks another visitor's data to a contained attacker | Only responses a shared HTTP cache could store are kept. Requests with cookies or `Authorization`, responses with `Set-Cookie` or `Cache-Control: private` or `no-store` are never stored, and a page that reflects another visitor's query string is replayed only to a request with the same query string. |
| The shadow tells the attacker it has been contained | The shadow replays the app's own public responses and 404 pages with the same bait as live ones. **Residual risk.** An attacker comparing many requests may notice that query parameters stop having effects. By then it is already cut off from the application. |
| An attacker evades containment by changing address | A new address is a new machine. Containment covers an IPv6 /64, a honeytoken used from a new address also contains it, and tripwires usually fire within the first few dozen requests of a new machine. **Residual risk.** An attacker with many fresh addresses that never touches a tripwire stays uncontained. |
| An enforcer credential leaks | Enforcer credentials stay on the host. The Cloudflare enforcer needs only the "Account Filter Lists Edit" permission, reads its token from the environment, never logs it, and only changes list items it created itself. The broader token that `cloudflare setup` uses to add the WAF rule is meant for one run and then deletion, and setup only ever adds a rule, never replacing existing ones. Enforcers never receive private, loopback, documentation or carrier-grade NAT addresses. |
| An edge list fills up or the provider is unreachable | Enforcers run off the request path and fail without affecting requests. Failures are counted in `stats().enforcerErrors`. Entries expire, and the Cloudflare enforcer removes expired and duplicate entries every ten minutes. |

### 3.3 Against detection (A1, A2)

| Threat | Mitigation |
|---|---|
| The attacker tells the agent to ignore instructions on the target | No detection depends on the agent obeying text. Bait comments are only leaks. The detection is the *use* of what was leaked. |
| The attacker reads the source and avoids known decoys | Decoys are derived per deployment from the secret, so there is no global list. Seals are cryptographic. |
| The attacker fingerprints Kagami to learn that it is present | Kagami adds no headers, cookies or fixed paths. Decoy responses go through the app's own response path. Comment wording, placement and route names vary. **Residual risk.** A determined attacker who compares `/.env` responses across many sites may learn the bait *format*. Template randomisation and user-supplied templates are planned. Knowing Kagami is present still leaves the attacker with the A2 dilemma described below. |
| The attacker rotates IPs or user agents to reset session scores | Honeytokens carry the issuing source's tag, so their use from anywhere is attributed, and the suspicious sessions of the issuing source are flagged too. All tools on one machine share a source, so switching user agents does not change the bait an attacker sees. User agents that carry injected payloads share one session per address, so a scanner that injects into the header keeps its score. **Residual risk.** An attacker who sends a clean, random user agent with every request still starts a new session each time. Scores built only from signals (payloads, enumeration) reset with a new address. |
| The attacker forges client address headers (`X-Forwarded-For` and similar) to split its traffic into many apparent clients or to bypass IP checks | Kagami uses the address the host adapter gives it. The host must trust these headers only from its own proxies (`trust proxy` in Express). Forged values that no proxy writes raise `client.forged_forwarding`. **Lesson from the first live round.** In a local setup where Docker forwards traffic from the loopback address, trusting loopback proxies let the agent choose its own address on every request. The bench runner now trusts no forwarding headers. |
| A body the host's parser rejects skips middleware that runs after the parser | The Express adapter includes an error handler that inspects rejected requests from the raw text in the parser error and raises `request.malformed_body`. Other adapters must cover the same path. |
| The attacker compares two forms of the same request to find what Kagami adds | Any request that the app routes to the same handler must get the same Kagami treatment. **Lesson from the third live round.** Absolute-form targets (`GET http://host/healthz`) were matched on the full URL, so ignored paths got the JSON decoy field and the home page lost the bait comment. One comparison showed the agent both decoys. Kagami now normalises the target to its path and raises `request.absolute_target`, and a test compares both forms byte for byte. **Residual risk.** Other parser differences between Kagami and a framework, such as path parameters or unusual encodings, could do the same. New adapters should run the same comparison test. |
| The attacker forges or replays honeytokens or seals | Each uses a 48 to 80 bit truncated HMAC-SHA256 under the deployment secret, verified in constant time. Tokens from other deployments do not verify. |
| The attacker avoids every tripwire (A2) | **This is the intended dilemma.** An agent that never uses found credentials, never changes IDs, never sets unfamiliar fields and never probes files has given up most of its methods. Kagami does not claim to detect an attacker who behaves exactly like a normal user. |
| Evasion of payload signatures through encodings, comments or case | Kagami applies multi-layer percent decoding, case folding, SQL comment removal and whitespace collapsing. **Residual risk.** Signature evasion is always possible. Payload rules are signals and not the basis of detection. |

### 3.4 Against the audit trail (A3, A4)

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

### 3.5 Against the secret

| Threat | Mitigation |
|---|---|
| A weak secret | A minimum of 32 characters is enforced, and `npx @agenticslabs/kagami secret` generates 256 bits. |
| Secret exposure through the manifest | `manifest()` is a host-side API only and no adapter exposes it over HTTP. The documentation says it must never be exposed. |
| The secret in config files | It is read from `KAGAMI_SECRET` by default, config is never logged, and the Rust `Config` type deliberately does not implement `Debug`. |

### 3.6 Privacy

Kagami processes request metadata, which includes personal data such as IP addresses. By default no data leaves the
host unless a sink is configured. IP logging can be set to `hashed` or `omit`. Request bodies are inspected in memory
and never logged. Only short, sanitised snippets of *matched* attack payloads are recorded, with sensitive fields redacted.
With containment on, the addresses of contained machines are kept in memory for the containment period and passed to
the enforcers you configure, which may send them to a third party such as Cloudflare. The shadow keeps copies of
public responses in memory only.

## 4. Out of scope

- Volumetric DDoS. Use your CDN or WAF for this.
- Attackers who only perform actions that cannot be told apart from normal use.
- Vulnerabilities in the protected application itself.
- Off-site use of honeytokens, such as trying the fake AWS key directly against AWS. Support for this is planned through cloud canary credentials.
