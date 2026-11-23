/**
 * Helpers for deciding how to respond to an event in `onDetect`.
 */
import type { LurensicEvent } from './types.js';

/**
 * True when a browser was sent to the request from another site, or from
 * another origin on the same site, as when a visitor is lured into clicking
 * a link or submitting a form there. Browsers set this themselves, so for an
 * honest visitor it is reliable. Scripts send nothing and are never lured.
 */
export function wasLured(event: LurensicEvent): boolean {
  const site = event.request?.site;
  return site === 'cross-site' || site === 'same-site';
}

/**
 * True when it is safe to act automatically on `event.subject`, such as
 * locking that account. False when the event names no account, when the
 * request was lured from another site (see `wasLured`), or when the evidence
 * was in a cookie, which a sibling subdomain can plant in a visitor's browser.
 *
 * Events it rejects are still real detections. Alert on them instead, and
 * block the address unless `wasLured` is true.
 */
export function safeToActOnSubject(event: LurensicEvent): boolean {
  if (!event.subject || wasLured(event)) return false;
  if ((event.evidence as { location?: unknown } | undefined)?.location === 'cookie') return false;
  return true;
}
