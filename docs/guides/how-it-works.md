# How Lurensic works

## One request

Lurensic sees every request before your application does, and every response after.

```mermaid
sequenceDiagram
    participant C as Client
    participant A as Adapter (Express)
    participant K as lurensic-core
    participant App as Your app
    C->>A: request
    A->>K: inspect (method, path, query, headers, body, peer address, subject)
    K->>K: resolve the client address
    K->>K: run the rules, update the session score
    K->>K: contain the machine if a tripwire fired and containment is on
    alt contained, or a decoy or bait path
        K-->>A: answer it (shadow copy, decoy, fake file or 403)
        A-->>C: Lurensic's answer, the app never runs
    else ordinary request
        K-->>A: pass, decorate the response if needed
        A->>App: request
        App-->>A: response
        A->>K: decorate (bait comment, decoy field) and report the response
        A-->>C: response
    end
    K-->>A: events
    Note over A: events go to onDetect and the sinks, off the request path
```

The engine is the same in every language. It is Rust compiled to WebAssembly with no imports, so it has no clock, no
network and no file access. The adapter passes in the time and the request, and gets back a decision and events.

## Sessions and machines

Lurensic tracks two things.

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
used, even from another address, Lurensic knows which machine found it.

Names and values are derived from your secret. Two Lurensic deployments use different decoy routes, fields and
credentials, so there is no list an attacker can tell an agent to avoid.

The optional decoy API description lists only decoy routes and carries a sandbox key that is a honeytoken. An
agent that reads the description first, as most do, tests decoys and uses a planted credential. The session secret
in the fake `.env` is a decoy too. Any cookie or token signed with it is forged.

## The event

Every detection becomes one event, built and hash-chained inside the engine. The runtime hands it to your
`onDetect` function and to the sinks after the request. The event names the rule, the session and machine, the
address and, when your `subject` function returned one, your own account id. Your code decides the
response. The fields are described in the [README](../../README.md#the-event) and the schema in
[DESIGN.md](../DESIGN.md#8-audit-log).

## Containment (optional)

Containment is off by default. Most apps act on detections in `onDetect` instead.

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
    K["Lurensic in the app"] -->|"each contained machine"| E{"Enforcers"}
    E --> F["blocklistFile<br/>plain, nginx or JSON"]
    E --> W["webhookEnforcer<br/>your endpoint"]
    F --> N["nginx, ipset, iptables,<br/>AWS WAF import"]
    W --> S["SOAR, serverless function,<br/>cloud WAF API"]
```

Enforcers only receive public addresses by default, so a loopback test or a private network is never pushed to an
edge firewall.
