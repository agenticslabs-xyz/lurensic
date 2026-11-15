//! Keyed derivation helpers. Everything secret-dependent in Kagami goes
//! through `Keys::mac`, with a distinct label per purpose (domain separation).

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// RFC 4648 base32 alphabet (used for AWS-style access key ids).
pub const ALPHA_AWS: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
/// Mixed-case alphabet for API keys, passwords and seals. 32 symbols so the
/// encoding stays exact (5 bits per char) while looking like a normal key.
pub const ALPHA_MIXED: &[u8; 32] = b"aB3cD4eF5gH6iJ7kL8mN9pQrStUvWxYz";

#[derive(Clone)]
pub struct Keys {
    root: [u8; 32],
}

impl Keys {
    pub fn new(secret: &str) -> Self {
        Keys {
            root: hmac_raw(b"kagami/v1/root", &[secret.as_bytes()]),
        }
    }

    /// HMAC-SHA256(root, label || 0x00 || len(p1) || p1 || len(p2) || p2 ...)
    pub fn mac(&self, label: &str, parts: &[&[u8]]) -> [u8; 32] {
        let mut m =
            HmacSha256::new_from_slice(&self.root).expect("HMAC accepts keys of any length");
        m.update(label.as_bytes());
        m.update(&[0]);
        for p in parts {
            m.update(&(p.len() as u32).to_be_bytes());
            m.update(p);
        }
        to_array(&m.finalize().into_bytes())
    }

    pub fn u32(&self, label: &str, parts: &[&[u8]]) -> u32 {
        let d = self.mac(label, parts);
        u32::from_be_bytes([d[0], d[1], d[2], d[3]])
    }

    pub fn pick<'a>(&self, label: &str, parts: &[&[u8]], options: &[&'a str]) -> &'a str {
        options[self.u32(label, parts) as usize % options.len()]
    }
}

fn hmac_raw(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
    for p in parts {
        m.update(p);
    }
    to_array(&m.finalize().into_bytes())
}

fn to_array(bytes: &[u8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(&bytes[..32]);
    a
}

pub fn sha256_hex(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    hex(&h.finalize())
}

pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 15) as usize] as char);
    }
    s
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let b = s.as_bytes();
    (0..b.len())
        .step_by(2)
        .map(|i| Some((hexval(b[i])? << 4) | hexval(b[i + 1])?))
        .collect()
}

pub fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Constant-time comparison.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    d == 0
}

/// Base32-encode with a custom alphabet. Input length must be a multiple of 5
/// so the output never carries padding bits (padding would be a fingerprint).
pub fn b32_encode(bytes: &[u8], alpha: &[u8; 32]) -> String {
    debug_assert!(bytes.len() % 5 == 0);
    let mut out = String::with_capacity(bytes.len() / 5 * 8);
    for chunk in bytes.chunks(5) {
        let mut buf = 0u64;
        for &b in chunk {
            buf = (buf << 8) | b as u64;
        }
        for i in (0..8).rev() {
            out.push(alpha[((buf >> (i * 5)) & 31) as usize] as char);
        }
    }
    out
}

pub fn b32_decode(s: &[u8], alpha: &[u8; 32]) -> Option<Vec<u8>> {
    if s.len() % 8 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 8 * 5);
    for chunk in s.chunks(8) {
        let mut buf = 0u64;
        for &c in chunk {
            let v = alpha.iter().position(|&a| a == c)? as u64;
            buf = (buf << 5) | v;
        }
        for i in (0..5).rev() {
            out.push(((buf >> (i * 8)) & 0xff) as u8);
        }
    }
    Some(out)
}

pub fn base64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alphabets_are_unique() {
        for alpha in [ALPHA_AWS, ALPHA_MIXED] {
            let mut v = alpha.to_vec();
            v.sort();
            v.dedup();
            assert_eq!(v.len(), 32);
        }
    }

    #[test]
    fn b32_roundtrip() {
        let data: Vec<u8> = (0..15u8).map(|i| i.wrapping_mul(37)).collect();
        for alpha in [ALPHA_AWS, ALPHA_MIXED] {
            let enc = b32_encode(&data, alpha);
            assert_eq!(enc.len(), 24);
            assert_eq!(b32_decode(enc.as_bytes(), alpha).unwrap(), data);
        }
    }

    #[test]
    fn base64_known_vector() {
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
    }

    #[test]
    fn domain_separation() {
        let k = Keys::new("x".repeat(32).as_str());
        assert_ne!(k.mac("a", &[b"bc"]), k.mac("ab", &[b"c"]));
        assert_ne!(k.mac("a", &[b"b", b"c"]), k.mac("a", &[b"bc"]));
    }
}
