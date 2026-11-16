//! Client address handling for sources, allowlists and containment targets.
//!
//! IPv6 clients usually control a whole /64, so an attacker can change its
//! address on every request without leaving its network. Kagami therefore
//! treats an IPv6 /64 as one machine. IPv4-mapped IPv6 addresses
//! (`::ffff:203.0.113.9`, which Node reports for IPv4 clients on dual-stack
//! sockets) are treated as the IPv4 address they carry.

use std::net::{IpAddr, Ipv6Addr};

/// Cloudflare's published ranges, from https://www.cloudflare.com/ips-v4 and
/// https://www.cloudflare.com/ips-v6, retrieved 2026-11-16. They change
/// rarely. `client_ip.cloudflare_ranges` overrides them.
pub const CLOUDFLARE_RANGES: &[&str] = &[
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

/// Works out the real client address from the connection's peer address and
/// the forwarding headers, trusting headers only from known hops.
///
/// Anyone can send `X-Forwarded-For` or `CF-Connecting-IP`. Trusting them
/// from any connection would let an attacker choose its own address, and with
/// containment, get an innocent address blocked. So the walk starts at the
/// peer and moves left through `X-Forwarded-For` only while the current hop
/// is one of your own proxies. If the hop it stops at is a Cloudflare edge
/// address and Cloudflare is enabled, `CF-Connecting-IP` names the visitor.
pub struct Resolver {
    proxies: Vec<Cidr>,
    cloudflare: Vec<Cidr>,
}

impl Resolver {
    pub fn new(proxies: &[Cidr], cloudflare: &[Cidr]) -> Self {
        Resolver {
            proxies: proxies.to_vec(),
            cloudflare: cloudflare.to_vec(),
        }
    }

    pub fn is_active(&self) -> bool {
        !self.proxies.is_empty() || !self.cloudflare.is_empty()
    }

    /// `xff` and `cf_connecting_ip` are the raw header values, if present.
    pub fn resolve(&self, peer: &str, xff: Option<&str>, cf_connecting_ip: Option<&str>) -> String {
        let Some(mut current) = parse_ip(peer) else {
            return peer.trim().to_string();
        };
        let hops: Vec<IpAddr> = xff.unwrap_or("").split(',').filter_map(parse_ip).collect();
        let mut left = hops.len();
        while left > 0 && self.proxies.iter().any(|p| p.contains(&current)) {
            left -= 1;
            current = hops[left];
        }
        if self.cloudflare.iter().any(|c| c.contains(&current)) {
            if let Some(visitor) = cf_connecting_ip.and_then(parse_ip) {
                return visitor.to_string();
            }
        }
        current.to_string()
    }
}

/// Parse a client address as hosts report it. Accepts brackets, a port on
/// bracketed IPv6, and an IPv6 zone index.
pub fn parse_ip(raw: &str) -> Option<IpAddr> {
    let s = raw.trim();
    let s = match s.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(rest),
        None => s,
    };
    let s = s.split('%').next().unwrap_or(s);
    match s.parse::<IpAddr>().ok()? {
        IpAddr::V6(v6) => Some(match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        }),
        v4 => Some(v4),
    }
}

/// The unit that is treated as one machine. An IPv4 address, or an IPv6 /64
/// written as a CIDR. Unparseable input is returned unchanged, so hosts that
/// pass something other than an address still get stable sources.
pub fn machine(raw: &str) -> String {
    match parse_ip(raw) {
        Some(IpAddr::V4(v4)) => v4.to_string(),
        Some(IpAddr::V6(v6)) => {
            let s = v6.segments();
            let net = Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0);
            format!("{net}/64")
        }
        None => raw.trim().to_string(),
    }
}

/// Is this an address that no edge firewall should ever be asked to block?
/// Loopback, private, link-local, documentation, carrier-grade NAT,
/// multicast and unspecified addresses are never pushed to an enforcer.
pub fn is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (64..128).contains(&o[1]))
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0x0db8))
        }
    }
}

/// An address range from configuration, such as `203.0.113.0/24` or a single address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Cidr> {
        let (addr, prefix) = match s.trim().split_once('/') {
            Some((a, p)) => (a, Some(p.parse::<u8>().ok()?)),
            None => (s.trim(), None),
        };
        let net = parse_ip(addr)?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        if prefix > max {
            return None;
        }
        Some(Cidr { net, prefix })
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.net, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                masked_eq(u32::from(n) as u128, u32::from(*a) as u128, self.prefix, 32)
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                masked_eq(u128::from(n), u128::from(*a), self.prefix, 128)
            }
            _ => false,
        }
    }
}

fn masked_eq(a: u128, b: u128, prefix: u8, bits: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let shift = u32::from(bits - prefix);
    (a >> shift) == (b >> shift)
}

/// True when `raw` parses as an address inside any of `ranges`.
pub fn allowed(ranges: &[Cidr], raw: &str) -> bool {
    parse_ip(raw).is_some_and(|ip| ranges.iter().any(|r| r.contains(&ip)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machines() {
        assert_eq!(machine("::ffff:203.0.113.9"), "203.0.113.9");
        assert_eq!(machine(" 198.51.100.4 "), "198.51.100.4");
        assert_eq!(machine("2001:db8:1:2:3:4:5:6"), "2001:db8:1:2::/64");
        assert_eq!(machine("[2001:db8:1:2::9]:443"), "2001:db8:1:2::/64");
        assert_eq!(machine("fe80::1%eth0"), "fe80::/64");
        assert_eq!(machine("not-an-ip"), "not-an-ip");
        assert_eq!(machine("2001:db8:1:2:ffff::1"), machine("2001:db8:1:2::7"));
    }

    #[test]
    fn public_addresses() {
        for p in ["8.8.8.8", "2606:4700::1111", "::ffff:1.1.1.1"] {
            assert!(is_public(&parse_ip(p).unwrap()), "{p}");
        }
        for p in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.0.1",
            "172.20.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "198.18.0.1",
            "203.0.113.9",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!is_public(&parse_ip(p).unwrap()), "{p}");
        }
    }

    #[test]
    fn client_address_resolution() {
        let cidrs =
            |v: &[&str]| -> Vec<Cidr> { v.iter().map(|r| Cidr::parse(r).unwrap()).collect() };
        let cf = cidrs(CLOUDFLARE_RANGES);
        // Directly behind Cloudflare.
        let r = Resolver::new(&[], &cf);
        assert_eq!(
            r.resolve("::ffff:173.245.48.10", None, Some("8.8.8.8")),
            "8.8.8.8"
        );
        assert_eq!(
            r.resolve("2606:4700::1", None, Some("2001:4860::8888")),
            "2001:4860::8888"
        );
        // A forged header from anywhere else is ignored.
        assert_eq!(
            r.resolve("198.51.100.66", Some("1.2.3.4"), Some("8.8.8.8")),
            "198.51.100.66"
        );
        assert_eq!(
            r.resolve("173.245.48.10", None, Some("not-an-ip")),
            "173.245.48.10"
        );
        // Behind your own proxy, which appends the Cloudflare edge to X-Forwarded-For.
        let r = Resolver::new(&cidrs(&["127.0.0.1/32", "10.0.0.0/8"]), &cf);
        assert_eq!(
            r.resolve(
                "127.0.0.1",
                Some("6.6.6.6, 173.245.48.10, 10.0.0.5"),
                Some("8.8.8.8")
            ),
            "8.8.8.8"
        );
        // A client in front of the proxy cannot choose its address by sending its own header.
        assert_eq!(
            r.resolve("127.0.0.1", Some("6.6.6.6, 198.51.100.66"), None),
            "198.51.100.66"
        );
        // Only proxies, no Cloudflare.
        let r = Resolver::new(&cidrs(&["127.0.0.1"]), &[]);
        assert_eq!(
            r.resolve("127.0.0.1", Some("203.0.113.9"), Some("8.8.8.8")),
            "203.0.113.9"
        );
        assert_eq!(r.resolve("127.0.0.1", None, None), "127.0.0.1");
        assert!(!Resolver::new(&[], &[]).is_active());
    }

    #[test]
    fn cidr_ranges() {
        let r = Cidr::parse("203.0.113.0/24").unwrap();
        assert!(r.contains(&parse_ip("203.0.113.200").unwrap()));
        assert!(!r.contains(&parse_ip("203.0.114.1").unwrap()));
        assert!(Cidr::parse("10.0.0.1")
            .unwrap()
            .contains(&parse_ip("::ffff:10.0.0.1").unwrap()));
        let v6 = Cidr::parse("2001:db8::/32").unwrap();
        assert!(v6.contains(&parse_ip("2001:db8:ffff::1").unwrap()));
        assert!(!v6.contains(&parse_ip("2001:db9::1").unwrap()));
        assert!(Cidr::parse("0.0.0.0/0")
            .unwrap()
            .contains(&parse_ip("8.8.8.8").unwrap()));
        assert!(Cidr::parse("10.0.0.0/33").is_none());
        assert!(Cidr::parse("nope/8").is_none());
        assert!(allowed(&[r], "::ffff:203.0.113.5"));
    }
}
