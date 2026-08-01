use std::fs;
use std::path::Path;

use netbraid::replay::{
    SavedPcapClaimScopeV0, SavedPcapCompletenessV0, SavedPcapConversationTriageV0,
    SavedPcapConversationUnsupportedReasonV0, SavedPcapWlanTriageV0,
    SavedPcapWlanUnsupportedReasonV0,
};

use super::{TailSecondsArg, load, render_human, render_json};

const INPUT: &str = include_str!("fixtures/positive-records.jsonl");
const PARTIAL_INPUT: &str = include_str!("fixtures/partial-records.jsonl");
const UNSUPPORTED_INPUT: &str = include_str!("fixtures/unsupported-records.jsonl");
const HUMAN: &str = include_str!("fixtures/positive-human.txt");
const PARTIAL_HUMAN: &str = include_str!("fixtures/partial-human.txt");
const JSON: &str = include_str!("fixtures/positive.json");
const TAIL_NS: u64 = 2_000;

#[test]
fn positive_review_matches_exact_human_and_json_goldens() {
    let triage = load(fixture_path(), INPUT.len() as u64, Some(TAIL_NS)).unwrap();

    assert_eq!(render_human(&triage), HUMAN);
    assert_eq!(render_json(&triage).unwrap(), JSON);
}

#[test]
fn review_is_read_only_and_preserves_exact_candidate_pivots() {
    let path = fixture_path();
    let before = fs::read(path).unwrap();
    let triage = load(path, before.len() as u64, Some(TAIL_NS)).unwrap();
    let after = fs::read(path).unwrap();

    assert_eq!(after, before);
    let json = render_json(&triage).unwrap();
    assert!(json.contains("wlan.fc.type == 0 && wlan.fc.subtype == 12"));
    assert!(json.contains(
        "(frame.section_number == 0) && (frame.interface_id == 0) && (frame.encap_type == 1)"
    ));
}

#[test]
fn review_without_tail_still_emits_exact_v1_without_a_trailing_member() {
    let triage = load(fixture_path(), INPUT.len() as u64, None).unwrap();
    let json: serde_json::Value = serde_json::from_str(&render_json(&triage).unwrap()).unwrap();

    assert_eq!(json["schema"], "netmon.saved_pcap_triage.v1");
    assert!(json.get("trailing_window").is_none());
    assert_eq!(
        json["source"]["receipt"]["run_id"],
        "run:1111111111111111111111111111111111111111111111111111111111111111"
    );
}

#[test]
fn review_rejects_input_beyond_the_explicit_byte_limit() {
    let error = load(fixture_path(), (INPUT.len() - 1) as u64, None)
        .unwrap_err()
        .to_string();

    assert!(error.contains("reading Netbraid evidence"));
}

#[test]
fn partial_review_qualifies_absence_and_preserves_quarantine_coverage() {
    let triage = load(
        partial_fixture_path(),
        PARTIAL_INPUT.len() as u64,
        Some(1_000_000_000),
    )
    .unwrap();
    let human = render_human(&triage);
    let json = render_json(&triage).unwrap();

    assert_eq!(human, PARTIAL_HUMAN);
    assert!(human.contains("COVERAGE PARTIAL PACKET SUBSET"));
    assert!(human.contains("1 emitted / 1 quarantined / 2 inspected"));
    assert!(human.contains(
        "wlan      insufficient / normalized packet subset / partial normalization without ieee80211 frame evidence"
    ));
    assert!(human.contains("field count 2 does not match registry field count 32"));
    assert!(
        human.contains(
            "negative abstained / normalization is partial; occurrence receipt is absent"
        )
    );
    assert!(human.contains("top      observed / 1 seen / 1 grouped / 0 excluded"));
    assert!(human.contains(
        "frame.time_epoch >= 1699999999.123456789 && frame.time_epoch <= 1700000000.123456789"
    ));
    assert!(json.contains("\"completeness\": \"partial_packet_subset\""));
    assert!(json.contains("\"status\": \"insufficient\""));
    assert!(json.contains("\"status\": \"abstained\""));
}

#[test]
fn complete_non_wlan_review_preserves_typed_unsupported() {
    let path = unsupported_fixture_path();
    let before = fs::read(path).unwrap();
    let first = load(path, before.len() as u64, None).unwrap();
    let second = load(path, UNSUPPORTED_INPUT.len() as u64, None).unwrap();

    assert_eq!(fs::read(path).unwrap(), before);
    assert_eq!(
        first.normalization.completeness,
        SavedPcapCompletenessV0::CompleteCapture
    );
    assert_eq!(render_json(&first).unwrap(), render_json(&second).unwrap());
    assert!(matches!(
        first.wlan,
        SavedPcapWlanTriageV0::Unsupported {
            scope: SavedPcapClaimScopeV0::CompleteCapture,
            reason: SavedPcapWlanUnsupportedReasonV0::NoIeee80211FrameEvidence,
        }
    ));
    assert!(matches!(
        first.top_capture_conversation,
        SavedPcapConversationTriageV0::Unsupported {
            scope: SavedPcapClaimScopeV0::CompleteCapture,
            reason: SavedPcapConversationUnsupportedReasonV0::NoEligibleIpTcpUdpPacketEnvelopes,
            packet_envelopes_seen: 1,
            packet_envelopes_excluded: 1,
            ..
        }
    ));
    for identity_field in [
        "\"observer_id\"",
        "\"ethernet\"",
        "\"ipv4\"",
        "\"ipv6\"",
        "\"ieee80211\"",
        "\"tcp\"",
        "\"udp\"",
    ] {
        assert!(!UNSUPPORTED_INPUT.contains(identity_field));
    }
}

#[test]
fn tail_seconds_are_exact_and_bounded_to_the_projection_domain() {
    assert_eq!(
        "0.000000001"
            .parse::<TailSecondsArg>()
            .unwrap()
            .nanoseconds(),
        1
    );
    assert_eq!(
        "2.000000001"
            .parse::<TailSecondsArg>()
            .unwrap()
            .nanoseconds(),
        2_000_000_001
    );
    for invalid in ["0", "0.000000000", ".5", "1.0000000001", "-1"] {
        assert!(
            invalid.parse::<TailSecondsArg>().is_err(),
            "{invalid:?} must not be accepted"
        );
    }
}

fn fixture_path() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/review/fixtures/positive-records.jsonl"
    ))
}

fn partial_fixture_path() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/review/fixtures/partial-records.jsonl"
    ))
}

fn unsupported_fixture_path() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/review/fixtures/unsupported-records.jsonl"
    ))
}
