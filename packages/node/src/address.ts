/**
 * How Lurensic finds the visitor's address behind a proxy or CDN.
 *
 * A setting can be written out in full, or named by a preset for a setup we
 * have verified on a live host. On Render, Lurensic picks the Render preset by
 * itself, because Render sets `RENDER=true` for every service.
 */

/** Trusted hops in front of the app. */
export interface ClientAddressSetting {
  /** Addresses or CIDR ranges of your own proxies in front of the app, such as `127.0.0.1` for nginx on the same host. */
  trustedProxies?: string[];
  /** The app is behind Cloudflare. */
  cloudflare?: boolean;
  /** Replaces the built-in Cloudflare ranges. */
  cloudflareRanges?: string[];
}

/**
 * A named setup.
 * - `cloudflare` means Cloudflare connects to the app directly.
 * - `render` means a Render web service, with or without your own Cloudflare in front.
 * - `none` means no forwarding headers are trusted, and turns off the automatic Render setting.
 */
export type ClientAddressPreset = 'cloudflare' | 'render' | 'none';

export const CLIENT_ADDRESS_PRESETS: Readonly<Record<Exclude<ClientAddressPreset, 'none'>, Readonly<ClientAddressSetting>>> = {
  cloudflare: { cloudflare: true },
  // Render's edge is Cloudflare. Requests then pass Render's load balancer on
  // a private 10.x address and reach the app over loopback.
  render: { cloudflare: true, trustedProxies: ['::1', '127.0.0.1', '10.0.0.0/8'] },
};

export interface ResolvedClientAddress {
  /** The setting to use, or undefined when the adapter's own address is used. */
  setting?: ClientAddressSetting;
  /** Where it came from, for messages. */
  from: 'option' | 'LURENSIC_PROXY' | 'RENDER' | 'none';
  /** The preset used, when one was. */
  preset?: string;
}

function preset(name: string, warn: (m: string) => void, from: ResolvedClientAddress['from']): ResolvedClientAddress {
  const key = name.trim().toLowerCase();
  if (key === 'none') return { from, preset: 'none' };
  if (key in CLIENT_ADDRESS_PRESETS) {
    const p = CLIENT_ADDRESS_PRESETS[key as keyof typeof CLIENT_ADDRESS_PRESETS];
    return { setting: { ...p, ...(p.trustedProxies && { trustedProxies: [...p.trustedProxies] }) }, from, preset: key };
  }
  warn(
    `[lurensic] "${name}" is not a client address preset, so no forwarding headers are trusted. ` +
      `Use ${Object.keys(CLIENT_ADDRESS_PRESETS).join(', ')} or none, or write the setting out as an object.`,
  );
  return { from: 'none' };
}

/**
 * The client address setting, in this order. The `clientAddress` option, as
 * an object or a preset name, then `LURENSIC_PROXY`, then the Render preset
 * when `RENDER=true`. Otherwise none, and the adapter's own address is used.
 */
export function resolveClientAddress(
  option: ClientAddressPreset | ClientAddressSetting | undefined,
  env: Record<string, string | undefined>,
  warn: (m: string) => void,
): ResolvedClientAddress {
  if (option && typeof option === 'object') return { setting: option, from: 'option' };
  if (typeof option === 'string') return preset(option, warn, 'option');
  const named = env.LURENSIC_PROXY;
  if (typeof named === 'string' && named.trim() !== '') return preset(named, warn, 'LURENSIC_PROXY');
  if (env.RENDER === 'true') return preset('render', warn, 'RENDER');
  return { from: 'none' };
}

/** One sentence on where the visitor's address comes from, for the startup line. */
export function describeClientAddress(r: ResolvedClientAddress): string {
  if (r.preset === 'none') return `Visitor addresses come from the connection, because ${r.from === 'option' ? 'clientAddress' : r.from} is none.`;
  if (!r.setting) return 'No address setting is in use, so visitor addresses come from the framework or the connection.';
  if (r.from === 'RENDER') return 'Visitor addresses use the render preset, because RENDER=true.';
  if (r.from === 'LURENSIC_PROXY') return `Visitor addresses use the ${r.preset} preset from LURENSIC_PROXY.`;
  return r.preset ? `Visitor addresses use the ${r.preset} preset.` : 'Visitor addresses use the clientAddress setting.';
}
