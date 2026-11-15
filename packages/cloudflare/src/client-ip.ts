/**
 * The real client address behind Cloudflare.
 *
 * Cloudflare puts the visitor's address in `CF-Connecting-IP`. Anyone can
 * send that header, though. If an origin trusted it from any connection, an
 * attacker could forge it and get an innocent address contained and pushed
 * to the edge. This helper trusts the header only when the connection comes
 * from one of Cloudflare's published address ranges (directly, or through
 * proxies you name in `trustedProxies`).
 */
import { BlockList, isIP } from 'node:net';

/**
 * Cloudflare's published ranges, from https://www.cloudflare.com/ips-v4 and
 * https://www.cloudflare.com/ips-v6, retrieved 2026-11-16. Cloudflare
 * changes them rarely. Pass `ranges` to use a fresher list.
 */
export const CLOUDFLARE_RANGES: readonly string[] = [
  '173.245.48.0/20',
  '103.21.244.0/22',
  '103.22.200.0/22',
  '103.31.4.0/22',
  '141.101.64.0/18',
  '108.162.192.0/18',
  '190.93.240.0/20',
  '188.114.96.0/20',
  '197.234.240.0/22',
  '198.41.128.0/17',
  '162.158.0.0/15',
  '104.16.0.0/13',
  '104.24.0.0/14',
  '172.64.0.0/13',
  '131.0.72.0/22',
  '2400:cb00::/32',
  '2606:4700::/32',
  '2803:f800::/32',
  '2405:b500::/32',
  '2405:8100::/32',
  '2a06:98c0::/29',
  '2c0f:f248::/32',
];

/** Strip the IPv4-mapped prefix Node reports on dual-stack sockets. */
function plain(addr: string | undefined): string {
  const a = (addr ?? '').trim();
  return a.toLowerCase().startsWith('::ffff:') && isIP(a.slice(7)) === 4 ? a.slice(7) : a;
}

function blockList(ranges: readonly string[]): BlockList {
  const list = new BlockList();
  for (const r of ranges) {
    const [net, bits] = r.split('/');
    const type = isIP(net ?? '') === 6 ? 'ipv6' : 'ipv4';
    if (!isIP(net ?? '')) throw new TypeError(`Not an address range: ${r}`);
    if (bits === undefined) list.addAddress(net!, type);
    else list.addSubnet(net!, Number(bits), type);
  }
  return list;
}

function contains(list: BlockList, addr: string): boolean {
  const v = isIP(addr);
  return v !== 0 && list.check(addr, v === 6 ? 'ipv6' : 'ipv4');
}

export interface ClientIpOptions {
  /** Cloudflare's ranges. Defaults to `CLOUDFLARE_RANGES`. */
  ranges?: readonly string[];
  /**
   * Your own proxies between Cloudflare and the app (for example nginx on the
   * same host, `127.0.0.1`). For a connection from one of them, the last
   * `X-Forwarded-For` entry is treated as the peer and checked against
   * Cloudflare's ranges.
   */
  trustedProxies?: readonly string[];
}

interface RequestLike {
  socket?: { remoteAddress?: string };
  headers: Record<string, string | string[] | undefined>;
}

const header = (req: RequestLike, name: string): string | undefined => {
  const v = req.headers[name];
  return Array.isArray(v) ? v[v.length - 1] : v;
};

/**
 * Build a `clientIp` function for a Kagami adapter.
 *
 *   app.use(kagami({ clientIp: cloudflareClientIp() }))
 */
export function cloudflareClientIp(opts: ClientIpOptions = {}): (req: RequestLike) => string | undefined {
  const cf = blockList(opts.ranges ?? CLOUDFLARE_RANGES);
  const proxies = blockList(opts.trustedProxies ?? []);
  return (req) => {
    let peer = plain(req.socket?.remoteAddress);
    if (opts.trustedProxies?.length && contains(proxies, peer)) {
      const xff = (header(req, 'x-forwarded-for') ?? '').split(',').map((s) => plain(s)).filter(Boolean);
      const last = xff[xff.length - 1];
      if (last && isIP(last)) peer = last;
    }
    if (contains(cf, peer)) {
      const visitor = plain(header(req, 'cf-connecting-ip'));
      if (isIP(visitor)) return visitor;
    }
    return peer || undefined;
  };
}

/** Is this address one of Cloudflare's? */
export function isCloudflareAddress(addr: string, ranges: readonly string[] = CLOUDFLARE_RANGES): boolean {
  return contains(blockList(ranges), plain(addr));
}
