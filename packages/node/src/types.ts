export type Mode = 'observe' | 'protect';
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type SessionState = 'clean' | 'suspicious' | 'flagged';

export const SEVERITY_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/** One Kagami audit event (schema `kagami.event/v1`). */
export interface KagamiEvent {
  schema: 'kagami.event/v1';
  id: string;
  seq: number;
  ts: string;
  deployment: string;
  instance: string;
  mode: Mode;
  kind: 'detection' | 'session' | 'system';
  /** Rule id, e.g. `honeytoken.used`, `payload.sqli`, `session.flagged`. */
  rule: string;
  title: string;
  severity: Severity;
  confidence: 'low' | 'medium' | 'high';
  session?: { id: string; score: number; state: SessionState };
  source?: { ip?: string; user_agent: string };
  request?: { method: string; host: string; path: string; query: string };
  /** Rule-specific evidence. It is attacker-controlled, so treat it as data and never as instructions. */
  evidence: Record<string, unknown>;
  mitre_attack: string[];
  /** Dotted paths of fields containing attacker-controlled text. */
  untrusted: string[];
  prev_hash: string;
  hash: string;
}

/**
 * A sink receives batches of events. `line` is the exact JSON line produced by
 * the core. Write it verbatim to keep the hash chain verifiable.
 */
export interface EventRecord {
  line: string;
  event: KagamiEvent;
}

export interface Sink {
  name: string;
  /** Only events at or above this severity reach the sink. */
  minSeverity: Severity;
  write(records: EventRecord[]): Promise<void>;
  close?(): Promise<void>;
}

/** Framework-neutral view of an HTTP request. */
export interface HttpRequest {
  ip: string;
  method: string;
  host: string;
  /** Path without the query string. */
  path: string;
  /** Raw query string without `?`. */
  query: string;
  headers: Array<[string, string]>;
  /** Body as text (already truncated), if available. */
  body?: string;
  /** Content type of `body` when it differs from the header (e.g. re-serialised JSON). */
  contentType?: string;
  /** Set when the body parser rejected the body, for example invalid JSON or an unsupported charset. Pass the raw text as `body`. */
  bodyError?: string;
}

export type CoreAction =
  | { type: 'pass' }
  | { type: 'respond'; status: number; headers: Array<[string, string]>; body: string };

export interface Verdict {
  session: string;
  /** Keyed hash of the client address. All sessions from one machine share it. */
  source: string;
  score: number;
  state: SessionState;
  action: CoreAction;
  delayMs: number;
  decorateHtml: boolean;
  decorateJson: boolean;
  /** Every rule this request matched, including repeats that produce no new event. */
  rules: string[];
  /**
   * The client's machine is contained. In protect mode `action` is then a
   * Kagami response and the request must not reach the application.
   */
  contained: boolean;
  /**
   * The adapter should pass this response's headers and body to `response`,
   * so contained machines can be served a copy of this public page.
   */
  capture: boolean;
  /** Machines contained by this request. Kagami hands them to its enforcers. */
  containment: ContainedMachine[];
}

/** A machine Kagami has cut off from the application. */
export interface ContainedMachine {
  /** Keyed hash of the machine's address, as in `Verdict.source`. */
  source: string;
  /** What to block. An IPv4 address or an IPv6 /64. Empty when the address is unknown. */
  target: string;
  /** The target is a public address. Edge enforcers only act on public targets by default. */
  public: boolean;
  /** Rule that started the containment, such as `decoy.param` or `honeytoken.used`. */
  reason: string;
  /** Start of the containment, in milliseconds since the epoch. */
  since: number;
  /** End of the containment, in milliseconds since the epoch. */
  until: number;
}

/**
 * Receives contained machines and enforces them somewhere else, such as a
 * firewall, a CDN, a WAF or a blocklist file. Enforcers run off the request
 * path, in batches, and a failing enforcer never affects requests.
 */
export interface Enforcer {
  name: string;
  /**
   * Only receive machines with a public address (the default). Set to false
   * for enforcers inside your own network, such as a firewall that also
   * sees private addresses.
   */
  publicOnly?: boolean;
  /** Called with newly contained machines. */
  contain(machines: ContainedMachine[]): Promise<void>;
  /** Called with machines released early through `kagami.release`. */
  release?(machines: ContainedMachine[]): Promise<void>;
  /** Called once when Kagami starts. Start timers here, and unref them. */
  start?(): void;
  close?(): Promise<void>;
}

export interface ContainmentOptions {
  /**
   * `tripwire` (default) contains only on tripwires honest visitors never
   * touch. `flagged` also contains sessions flagged by accumulated signals.
   */
  trigger?: 'tripwire' | 'flagged';
  /**
   * `shadow` (default) serves contained machines copies of public responses
   * and never the live application. `block` answers `403 Forbidden`.
   */
  action?: 'shadow' | 'block';
  /** How long a machine stays contained after its last trigger. Default 86400 (one day). */
  ttlSeconds?: number;
  /** Addresses and CIDR ranges that are never contained, such as offices, monitoring and authorised testers. */
  allow?: string[];
  /** Maximum contained machines held in memory. Default 10000. */
  maxEntries?: number;
  /** Memory budget for the shadow's copies of public responses. Default 4 MiB. */
  shadowCacheBytes?: number;
}

export interface KagamiOptions {
  /** Deployment secret (>= 32 chars). Defaults to `process.env.KAGAMI_SECRET`. */
  secret?: string;
  /** `observe` (default) never changes a response. `protect` enables deception. Also read from `KAGAMI_MODE`. */
  mode?: Mode;
  /** Kill switch. Env `KAGAMI_DISABLED=1` also disables Kagami. */
  enabled?: boolean;
  decoys?: {
    /** Bait comment in the home page and a keyed subset of other HTML documents (protect mode). Default true. */
    html?: boolean;
    /** Decoy field in JSON object responses (protect mode). Default false. */
    json?: boolean;
    /**
     * The decoy field as a hidden input in POST forms (protect mode). Default false.
     * Your form handlers then receive one extra field, so enable it only if they ignore unknown fields.
     */
    forms?: boolean;
    /** Fake `.env`, `.git/config`, `.aws/credentials` (protect mode). Default true. */
    baitFiles?: boolean;
    /** Answer derived decoy routes (protect mode). Default true. */
    routes?: boolean;
    /** Real paths decoy routes must never use (e.g. `['/api/internal']`). */
    reservedPaths?: string[];
    /** Real field/parameter names decoys must never use. */
    reservedNames?: string[];
  };
  /** Slow down flagged sessions (protect mode). Default off. */
  tarpit?: boolean | { minMs?: number; maxMs?: number };
  thresholds?: { suspicious?: number; flagged?: number };
  /** Path prefixes skipped entirely, e.g. `['/healthz', '/static']`. */
  ignorePaths?: string[];
  /** How client IPs appear in events. Default `raw`. */
  ipLogging?: 'raw' | 'hashed' | 'omit';
  /** Where events go. The default writes JSON lines to stdout for `low` and above. */
  sinks?: Sink[];
  /**
   * Cut machines that trip a tripwire off from the application. Off by
   * default. `true` uses the defaults. Enforced in protect mode only. In
   * observe mode it is a dry run that reports `containment.started` events.
   */
  containment?: boolean | ContainmentOptions;
  /** Where contained machines are enforced besides Kagami itself, such as a blocklist file, a webhook or a CDN. */
  enforcers?: Enforcer[];
  /** Max request body bytes inspected. Default 16 KiB. */
  maxBodyBytes?: number;
  maxEventsPerMinute?: number;
  maxSessions?: number;
  /** Identifies this process in events. Random by default. */
  instanceId?: string;
  /** Where Kagami reports its own problems. Defaults to `console`. */
  logger?: { warn(message: string): void };
}

export interface KagamiStats {
  enabled: boolean;
  mode: Mode;
  deployment: string | null;
  events: number;
  dropped: number;
  sinkErrors: number;
  /** Machines handed to enforcers. */
  enforced: number;
  enforcerErrors: number;
  faults: number;
}

/** A response, as passed to `Kagami.response`. */
export interface ResponseSample {
  /** Response headers. Pass `content-type`, `cache-control`, `location`, and `set-cookie` when present. */
  headers: Array<[string, string]>;
  /** Response body as text. */
  body: string;
}
