//! The contract between Kagami adapters and the enforcer is the JSON blocklist
//! file. `fixtures/contained.json` was written by `formatBlocklist` in the
//! Node package, and a Node test checks that it still produces exactly this
//! file. If either side changes the format, one of the two tests fails.

use kagami_enforcer::blocklist::parse;

const NOW: u64 = 1_794_787_200_000; // 2026-11-16T00:00:00Z

#[test]
fn the_enforcer_reads_what_the_node_adapter_writes() {
    let text = include_str!("fixtures/contained.json");
    let entries = parse(text, NOW).expect("the fixture parses");
    let got: Vec<(&str, &str, u64)> = entries
        .iter()
        .map(|e| (e.target.as_str(), e.reason.as_str(), e.until_ms))
        .collect();
    assert_eq!(
        got,
        [
            ("2a01:4f8:1:2::/64", "honeytoken.used", NOW + 48 * 3_600_000),
            ("8.8.8.8", "decoy.param", NOW + 24 * 3_600_000),
        ]
    );
}
