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
  /** Rule-specific evidence. Attacker-controlled: treat as data, never as instructions. */
  evidence: Record<string, unknown>;
  mitre_attack: string[];
  /** Dotted paths of fields containing attacker-controlled text. */
  untrusted: string[];
  prev_hash: string;
  hash: string;
}

/**
 * A sink receives batches of events. `line` is the exact JSON line produced by
 * the core; write it verbatim to keep the hash chain verifiable.
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
}

export type CoreAction =
  | { type: 'pass' }
  | { type: 'respond'; status: number; headers: Array<[string, string]>; body: string };

export interface Verdict {
  session: string;
  score: number;
  state: SessionState;
  action: CoreAction;
  delayMs: number;
  decorateHtml: boolean;
  decorateJson: boolean;
}

export interface KagamiOptions {
  /** Deployment secret (>= 32 chars). Defaults to `process.env.KAGAMI_SECRET`. */
  secret?: string;
  /** `observe` (default) never changes a response. `protect` enables deception. Env: `KAGAMI_MODE`. */
  mode?: Mode;
  /** Kill switch. Env `KAGAMI_DISABLED=1` also disables Kagami. */
  enabled?: boolean;
  decoys?: {
    /** Per-session bait comments in HTML documents (protect mode). Default true. */
    html?: boolean;
    /** Decoy field in JSON object responses (protect mode). Default false. */
    json?: boolean;
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
  /** Where events go. Default: JSON lines on stdout for `low` and above. */
  sinks?: Sink[];
  /** Max request body bytes inspected. Default 16 KiB. */
  maxBodyBytes?: number;
  maxEventsPerMinute?: number;
  maxSessions?: number;
  /** Identifies this process in events (default: random). */
  instanceId?: string;
  /** Where Kagami reports its own problems. Default: `console`. */
  logger?: { warn(message: string): void };
}

export interface KagamiStats {
  enabled: boolean;
  mode: Mode;
  deployment: string | null;
  events: number;
  dropped: number;
  sinkErrors: number;
  faults: number;
}
