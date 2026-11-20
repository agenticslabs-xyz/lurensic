/**
 * Everything that runs on every supported runtime. The entry points add the
 * engine and the features that depend on the runtime.
 */
export { Kagami } from './kagami.js';
export { KagamiCoreError } from './core.js';
export { callbackSink, consoleSink, detectSink, escapeSlack, formatSlack, memorySink, slackSink, webhookSink } from './sinks.js';
export { verifyChain, type ChainResult } from './chain.js';
export { safeToActOnSubject, wasLured } from './act.js';
export { callbackEnforcer, formatBlocklist, webhookEnforcer, type BlocklistFormat } from './enforce.js';
export { FetchGuard, kagami, kagamiContext, peerAddress, subjectOf, type FetchAdapterOptions, type GuardedApp, type KagamiContext } from './fetch.js';
export { storeDriver, STORE_HELP, type StoreDriver } from './store.js';
export { SEVERITY_RANK } from './types.js';
export { BUILD_ID, PACKAGE_VERSION } from './build-info.js';
export { CLIENT_ADDRESS_PRESETS, resolveClientAddress, type ClientAddressPreset, type ClientAddressSetting } from './address.js';
export type {
  ContainedMachine,
  ContainmentOptions,
  CoreAction,
  Enforcer,
  EventRecord,
  HttpRequest,
  KagamiEvent,
  KagamiOptions,
  KagamiStats,
  Mode,
  ResponseSample,
  SessionState,
  Severity,
  Sink,
  Verdict,
} from './types.js';
