# How Kagami works

## One request

Kagami sees every request before your application does, and every response after.

```mermaid
sequenceDiagram
    participant C as Client
    participant A as Adapter (Express)
    participant K as kagami-core
    participant App as Your app
    C->>A: request
    A->>K: inspect (method, path, query, headers, body, peer address)
    K->>K: resolve the client address
    K->>K: run the rules, update the session score
    K->>K: contain the machine if a tripwire fired
    alt contained, or a decoy or bait path
        K-->>A: answer it (shadow copy, decoy, fake file or 403)
        A-->>C: Kagami's answer, the app never runs
    else ordinary request
        K-->>A: pass, decorate the response if needed
        A->>App: request
        App-->>A: response
        A->>K: decorate (bait comment, decoy field) and report the response
        A-->>C: response
    end
    K-->>A: events, contained machines
    Note over A: events go to sinks, contained machines go to enforcers, both off the request path
```

The engine is the same in every language. It is Rust compiled to WebAssembly with no imports, so it has no clock, no
network and no file access. The adapter passes in the time and the request, and gets back a decision and events.

## Sessions and machines

Kagami tracks two things.

- A **machine** is one client address, or one IPv6 /64, because an IPv6 client usually controls its whole /64.
  Honeytokens and containment work on machines.
- A **session** is a machine plus a user agent. Scores and timelines work on sessions. A user agent full of injected
  payloads counts as one session per machine, so a scanner cannot reset its score by changing it.

```mermaid
flowchart TB
    M["Machine 203.0.113.9"] --> S1["Session<br/>curl/8.9"]
    M --> S2["Session<br/>python-requests"]
    M --> S3["Session<br/>every injected user agent"]
```

## Detection

| Kind | Examples | Effect |
|---|---|---|
| Tripwires | a planted credential used, a decoy field changed, a decoy route called, a sealed ID forged | The session is flagged at once. With containment on, the machine is cut off. |
| Signals | SQL injection, XSS, traversal and other payloads, scanner user agents, bursts of 404s or failed logins | Points add up to a score. 30 makes a session suspicious, 70 flags it. |

Honest visitors cannot touch a tripwire by accident. Each one is an action only an attacker takes, which is why
tripwires can start containment and signals by default cannot.

## Deception

In protect mode, the probes attackers always make get convincing answers.

```mermaid
flowchart LR
    A["Agent probes /.env"] --> F["Fake .env<br/>with a planted SMTP password"]
    F --> U["Agent tries the password<br/>on the login form"]
    U --> T(["honeytoken.used<br/>tripwire"])
    B["Agent reads the page source"] --> CM["Comment with a decoy route<br/>and a planted API key"]
    CM --> T2(["decoy.route or<br/>honeytoken.used"])
    J["Agent reads JSON or a form"] --> DF["Decoy field<br/>billing_access_level=default"]
    DF --> T3(["decoy.param<br/>when it sends admin"])
```

Every planted credential encodes, in a form only your server can verify, the machine it was handed to. When it is
used, even from another address, Kagami knows which machine found it.

Names and values are derived from your secret. Two Kagami deployments use different decoy routes, fields and
credentials, so there is no list an attacker can tell an agent to avoid.

## Containment

```mermaid
stateDiagram-v2
    [*] --> Clean
    Clean --> Suspicious: signals add up
    Suspicious --> Flagged: score reaches 70
    Clean --> Contained: tripwire
    Suspicious --> Contained: tripwire
    Flagged --> Contained: tripwire, or any flag with trigger flagged
    Contained --> Clean: expiry (one day) or release
```

A contained machine never reaches your application again until the containment ends. What it gets instead depends on
`action`.

- **shadow** (default). Copies of your public pages and your own 404s. The agent keeps attacking a copy and does
  not learn it was cut off. Only responses a shared HTTP cache could store are copied, so it sees nothing an
  anonymous visitor could not.
- **block**. A plain `403 Forbidden`.

Decoys and bait files keep answering a contained machine, so it stays busy with them.

## Enforcement

Containment inside the app protects the app. Enforcers push the same decision to whatever sits in front of it.

```mermaid
flowchart LR
    K["Kagami in the app"] -->|"each contained machine"| E{"Enforcers"}
    E --> F["blocklistFile<br/>plain, nginx or JSON"]
    E --> W["webhookEnforcer<br/>your endpoint"]
    F --> N["nginx, ipset, iptables,<br/>AWS WAF import"]
    F --> KE["kagami-enforcer"]
    KE --> CF["Cloudflare IP list<br/>blocked by a WAF rule"]
    W --> S["SOAR, serverless function,<br/>cloud WAF API"]
```

Enforcers only receive public addresses by default, so a loopback test or a private network is never pushed to an
edge firewall.
