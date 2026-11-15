//! Honeytokens and seals.
//!
//! A honeytoken carries the issuing session's tag plus a truncated MAC, so the
//! engine can verify it *statelessly* and attribute it to the session that
//! received it, even if it comes back from a different IP or user agent. No
//! token database is needed, and tokens from another deployment never verify.
//!
//! Token layouts (all lengths are multiples of 5 bytes, so there are no padding
//! characters to fingerprint):
//! * AWS-style access key: `AKIA` + base32(mac[6] || mask(tag[4]))               (16 chars)
//! * Mixed key/password:   base32m(mac[10] || mask(tag[4] || variant[1]))        (24 chars)
//!
//! `mac = HMAC(secret, label, header)`; `mask` XORs the header with a keystream
//! derived from the MAC, so no two tokens share visible structure.
//! * Seal:                 `value~` + base32m(mac(value)[10])           (16 chars)

use crate::crypto::{
    b32_decode, b32_encode, base64, ct_eq, hex, unhex, Keys, ALPHA_AWS, ALPHA_MIXED,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Variant {
    CommentApiKey = 1,
    EnvApiKey = 2,
    DbPassword = 3,
    AdminPassword = 4,
    GitDeployPassword = 5,
}

impl Variant {
    fn from_u8(v: u8) -> Option<Variant> {
        Some(match v {
            1 => Variant::CommentApiKey,
            2 => Variant::EnvApiKey,
            3 => Variant::DbPassword,
            4 => Variant::AdminPassword,
            5 => Variant::GitDeployPassword,
            _ => return None,
        })
    }

    pub fn label(self) -> &'static str {
        match self {
            Variant::CommentApiKey => "html_comment_api_key",
            Variant::EnvApiKey => "env_api_key",
            Variant::DbPassword => "env_database_password",
            Variant::AdminPassword => "env_admin_password",
            Variant::GitDeployPassword => "git_deploy_password",
        }
    }
}

pub type Tag = [u8; 4];

/// The first 4 bytes of a (hex) session id.
pub fn session_tag(session_id: &str) -> Tag {
    let mut t = [0u8; 4];
    if let Some(b) = session_id.get(..8).and_then(unhex) {
        t.copy_from_slice(&b);
    }
    t
}

/// XOR `header` with a keystream derived from the token's own MAC. The MAC
/// leads the token and differs per token, so tokens issued to the same
/// session share no visible prefix (no correlation for an attacker to spot),
/// while the server can still unmask the header and verify it.
fn mask_header(keys: &Keys, mac: &[u8], header: &mut [u8]) {
    let ks = keys.mac("honeytoken/mask", &[mac]);
    for (h, k) in header.iter_mut().zip(ks.iter()) {
        *h ^= k;
    }
}

pub fn mint_mixed(keys: &Keys, tag: Tag, variant: Variant) -> String {
    let mut header = [tag[0], tag[1], tag[2], tag[3], variant as u8];
    let m = keys.mac("honeytoken/mixed", &[&header]);
    mask_header(keys, &m[..10], &mut header);
    let mut b = [0u8; 15];
    b[..10].copy_from_slice(&m[..10]);
    b[10..].copy_from_slice(&header);
    b32_encode(&b, ALPHA_MIXED)
}

pub fn mint_aws_key_id(keys: &Keys, tag: Tag) -> String {
    let mut header = tag;
    let m = keys.mac("honeytoken/aws", &[&header]);
    mask_header(keys, &m[..6], &mut header);
    let mut b = [0u8; 10];
    b[..6].copy_from_slice(&m[..6]);
    b[6..].copy_from_slice(&header);
    format!("AKIA{}", b32_encode(&b, ALPHA_AWS))
}

pub fn aws_secret_key(keys: &Keys, tag: Tag) -> String {
    let m1 = keys.mac("honeytoken/aws-secret/1", &[&tag]);
    let m2 = keys.mac("honeytoken/aws-secret/2", &[&tag]);
    let mut b = [0u8; 30];
    b[..16].copy_from_slice(&m1[..16]);
    b[16..].copy_from_slice(&m2[..14]);
    base64(&b)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub kind: &'static str,
    pub tag: Tag,
    pub masked: String,
}

impl Found {
    pub fn issued_to(&self) -> String {
        hex(&self.tag)
    }
}

fn mask(s: &str) -> String {
    let n = s.len();
    if n <= 8 {
        return "****".into();
    }
    format!("{}…{}", &s[..4], &s[n - 4..])
}

/// Scan text for honeytokens minted by this deployment. Tokens are delimited
/// by non-alphanumeric characters, so only exact-length runs are verified.
pub fn scan(keys: &Keys, text: &str, out: &mut Vec<Found>) {
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if !b[i].is_ascii_alphanumeric() {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && b[i].is_ascii_alphanumeric() {
            i += 1;
        }
        let run = &b[start..i];
        let found = match run.len() {
            20 if run.starts_with(b"AKIA") => verify_aws(keys, run),
            24 => verify_mixed(keys, run),
            _ => None,
        };
        if let Some(f) = found {
            if !out.contains(&f) {
                out.push(f);
            }
        }
    }
}

fn verify_aws(keys: &Keys, run: &[u8]) -> Option<Found> {
    let b = b32_decode(&run[4..], ALPHA_AWS)?;
    let mut tag: Tag = b[6..10].try_into().ok()?;
    mask_header(keys, &b[..6], &mut tag);
    let m = keys.mac("honeytoken/aws", &[&tag]);
    if !ct_eq(&b[..6], &m[..6]) {
        return None;
    }
    let s = std::str::from_utf8(run).ok()?;
    Some(Found {
        kind: "aws_access_key",
        tag,
        masked: mask(s),
    })
}

fn verify_mixed(keys: &Keys, run: &[u8]) -> Option<Found> {
    let b = b32_decode(run, ALPHA_MIXED)?;
    let mut header: [u8; 5] = b[10..15].try_into().ok()?;
    mask_header(keys, &b[..10], &mut header);
    let m = keys.mac("honeytoken/mixed", &[&header]);
    if !ct_eq(&b[..10], &m[..10]) {
        return None;
    }
    let variant = Variant::from_u8(header[4])?;
    let tag: Tag = header[..4].try_into().ok()?;
    let s = std::str::from_utf8(run).ok()?;
    Some(Found {
        kind: variant.label(),
        tag,
        masked: mask(s),
    })
}

pub fn seal(keys: &Keys, value: &str) -> String {
    let m = keys.mac("seal", &[value.as_bytes()]);
    format!("{value}~{}", b32_encode(&m[..10], ALPHA_MIXED))
}

/// Returns the original value if the seal is authentic.
pub fn unseal(keys: &Keys, sealed: &str) -> Option<String> {
    let (value, sig) = sealed.rsplit_once('~')?;
    if sig.len() != 16 {
        return None;
    }
    let got = b32_decode(sig.as_bytes(), ALPHA_MIXED)?;
    let m = keys.mac("seal", &[value.as_bytes()]);
    ct_eq(&got, &m[..10]).then(|| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> Keys {
        Keys::new("test-secret-test-secret-test-secret!")
    }

    #[test]
    fn tokens_roundtrip_with_attribution() {
        let k = keys();
        let tag = [0xde, 0xad, 0xbe, 0xef];
        let api = mint_mixed(&k, tag, Variant::EnvApiKey);
        let aws = mint_aws_key_id(&k, tag);
        assert_eq!(api.len(), 24);
        assert_eq!(aws.len(), 20);
        let text =
            format!("Authorization: Bearer sk_live_{api}\nCredential={aws}/20261115/us-east-1");
        let mut found = vec![];
        scan(&k, &text, &mut found);
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|f| f.tag == tag));
        assert_eq!(found[0].kind, "env_api_key");
        assert_eq!(found[1].kind, "aws_access_key");
    }

    #[test]
    fn tokens_from_one_session_share_no_visible_structure() {
        let k = keys();
        let tag = [9, 9, 9, 9];
        let tokens: Vec<String> = [
            Variant::CommentApiKey,
            Variant::EnvApiKey,
            Variant::DbPassword,
            Variant::AdminPassword,
            Variant::GitDeployPassword,
        ]
        .into_iter()
        .map(|v| mint_mixed(&k, tag, v))
        .collect();
        for (i, a) in tokens.iter().enumerate() {
            for b in &tokens[i + 1..] {
                let common_prefix = a.chars().zip(b.chars()).take_while(|(x, y)| x == y).count();
                let common_suffix = a
                    .chars()
                    .rev()
                    .zip(b.chars().rev())
                    .take_while(|(x, y)| x == y)
                    .count();
                assert!(common_prefix < 3 && common_suffix < 3, "{a} vs {b}");
            }
        }
        // ...and the same session tag still verifies from every one of them.
        let mut found = vec![];
        scan(&k, &tokens.join(" "), &mut found);
        assert_eq!(found.len(), 5);
        assert!(found.iter().all(|f| f.tag == tag));
    }

    #[test]
    fn foreign_and_tampered_tokens_do_not_verify() {
        let k = keys();
        let other = Keys::new("another-deployment-secret-0123456789");
        let tag = [1, 2, 3, 4];
        let mut found = vec![];
        scan(
            &k,
            &mint_mixed(&other, tag, Variant::DbPassword),
            &mut found,
        );
        scan(&k, &mint_aws_key_id(&other, tag), &mut found);
        let mut t = mint_mixed(&k, tag, Variant::DbPassword).into_bytes();
        t[10] = if t[10] == b'a' { b'z' } else { b'a' };
        scan(&k, std::str::from_utf8(&t).unwrap(), &mut found);
        assert!(found.is_empty());
    }

    #[test]
    fn seals_detect_tampering() {
        let k = keys();
        let s = seal(&k, "1043");
        assert_eq!(unseal(&k, &s).as_deref(), Some("1043"));
        assert_eq!(unseal(&k, &s.replacen("1043", "1044", 1)), None);
        assert_eq!(unseal(&k, "1044"), None);
    }
}
