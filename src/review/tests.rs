use std::fs;
use std::path::Path;

use netbraid::evidence::{
    CAPTURE_MANIFEST_SCHEMA_V0, CAPTURE_RUN_RECEIPT_SCHEMA_V0, CaptureArtifactRefV0,
    CaptureExtractorRefV0, CaptureFileMetadataV0, CaptureManifestV0, CaptureNormalizationV0,
    CaptureRunReceiptV0, CollectionPolicyV0, EthernetFieldsV0, Ieee80211FieldsV0, Ipv4FieldsV0,
    NORMALIZED_RECORDS_DIGEST_PROFILE_V0, NormalizationStateV0, PACKET_ENVELOPE_SCHEMA_V0,
    PACKET_QUARANTINE_SCHEMA_V0, PacketEnvelopeV0, PacketFrameV0, PacketQuarantineV0, TcpFieldsV0,
    ToolRunReceiptV0,
};
use netbraid::replay::{
    SavedPcapClaimScopeV0, SavedPcapCompletenessV0, SavedPcapConversationTriageV0,
    SavedPcapConversationUnsupportedReasonV0, SavedPcapWlanTriageV0,
    SavedPcapWlanUnsupportedReasonV0, parse_saved_capture_jsonl,
};

use super::{
    TailSecondsArg, compare_triage, load, render_comparison_human, render_comparison_json,
    render_human, render_json,
};

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
fn checked_review_jsonl_fixtures_are_reproducible_from_typed_records() {
    let mut positive_manifest = review_manifest(
        POSITIVE_CAPTURE_ID,
        100,
        "0.3.0",
        "TShark 4.6.7",
        POSITIVE_CONFIGURATION_SHA256,
        fixture_normalization(NormalizationStateV0::Complete, 10, 3, 0),
    );
    positive_manifest.observer_id = Some("fixture-observer".into());
    positive_manifest.acquired_time_unix_ms = Some(1_700_000_000_123);
    positive_manifest.acquisition_policy = Some(CollectionPolicyV0::passive_host_local());
    let positive_packets = vec![
        tcp_fixture_packet(
            POSITIVE_CAPTURE_ID,
            1,
            1_000,
            100,
            ("192.0.2.1", 40_000),
            ("198.51.100.2", 443),
            2,
        ),
        tcp_fixture_packet(
            POSITIVE_CAPTURE_ID,
            2,
            2_000,
            100,
            ("198.51.100.2", 443),
            ("192.0.2.1", 40_000),
            18,
        ),
        wlan_fixture_packet(POSITIVE_CAPTURE_ID),
    ];
    let first_pass = serialize_review_records(&positive_manifest, None, &positive_packets, &[]);
    let normalized_records_sha256 = parse_saved_capture_jsonl(first_pass.as_bytes())
        .unwrap()
        .normalized_records_sha256;
    let positive_receipt = positive_fixture_receipt(normalized_records_sha256);

    let partial_manifest = review_manifest(
        PARTIAL_CAPTURE_ID,
        164,
        "0.2.0",
        "TShark (Wireshark) 4.6.7",
        PARTIAL_CONFIGURATION_SHA256,
        fixture_normalization(NormalizationStateV0::Partial, 2, 1, 1),
    );
    let partial_packets = [tcp_fixture_packet(
        PARTIAL_CAPTURE_ID,
        1,
        1_700_000_000_123_456_789,
        54,
        ("192.0.2.1", 40_000),
        ("198.51.100.2", 443),
        2,
    )];
    let partial_quarantines = [PacketQuarantineV0 {
        schema: PACKET_QUARANTINE_SCHEMA_V0.into(),
        capture_id: PARTIAL_CAPTURE_ID.into(),
        source_line: 2,
        frame_number_hint: Some(2),
        reason: "field count 2 does not match registry field count 32".into(),
        raw_row: "2\tinvalid".into(),
    }];

    let unsupported_manifest = review_manifest(
        UNSUPPORTED_CAPTURE_ID,
        64,
        "0.3.0",
        "TShark 4.6.7",
        UNSUPPORTED_CONFIGURATION_SHA256,
        fixture_normalization(NormalizationStateV0::Complete, 10, 1, 0),
    );
    let unsupported_packets = [base_fixture_packet(
        UNSUPPORTED_CAPTURE_ID,
        1,
        1_000,
        64,
        147,
        &["data"],
    )];

    assert_eq!(
        serialize_review_records(
            &positive_manifest,
            Some(&positive_receipt),
            &positive_packets,
            &[],
        ),
        INPUT
    );
    assert_eq!(
        serialize_review_records(
            &partial_manifest,
            None,
            &partial_packets,
            &partial_quarantines,
        ),
        PARTIAL_INPUT
    );
    assert_eq!(
        serialize_review_records(&unsupported_manifest, None, &unsupported_packets, &[]),
        UNSUPPORTED_INPUT
    );
}

#[test]
fn identical_saved_evidence_candidates_corroborate_deterministically() {
    let left_path = fixture_path();
    let right_path = fixture_path();
    let before = fs::read(left_path).unwrap();
    let left = load(left_path, before.len() as u64, None).unwrap();
    let right = load(right_path, before.len() as u64, None).unwrap();
    let report = compare_triage(&left, &right).unwrap();

    let first_json = render_comparison_json(&report).unwrap();
    let second_json = render_comparison_json(&report).unwrap();
    assert_eq!(first_json, second_json);
    assert_eq!(fs::read(left_path).unwrap(), before);
    assert!(first_json.contains("\"schema\": \"linktop.saved_pcap_comparison.v0\""));
    assert!(first_json.contains("\"schema\": \"netmon.saved_pcap_fingerprint_hypothesis_set.v0\""));
    assert!(first_json.contains("\"hypothesis\": \"same_packet_shape\""));
    assert!(first_json.contains("\"status\": \"corroborated\""));
    assert!(!first_json.contains("192.0.2.1"));

    let human = render_comparison_human(&report);
    assert!(human.contains("compare   corroborated / equal bounded packet-shape basis"));
    assert!(human.contains("not same event, source, device"));
}

#[test]
fn distinct_observed_packet_shape_candidates_conflict_without_identity_claims() {
    let baseline = load(fixture_path(), INPUT.len() as u64, None).unwrap();
    let mut different = baseline.clone();
    let SavedPcapConversationTriageV0::Observed { conversation, .. } =
        &mut different.top_capture_conversation
    else {
        panic!("the positive fixture must retain an observed conversation");
    };
    conversation.total_original_frame_octets += 1;

    let report = compare_triage(&baseline, &different).unwrap();
    let json = render_comparison_json(&report).unwrap();
    let human = render_comparison_human(&report);

    assert!(json.contains("\"status\": \"conflicting\""));
    assert!(json.contains("\"hypothesis\": \"different_packet_shape\""));
    assert!(human.contains("compare   conflicting / different bounded packet-shape basis"));
    assert!(human.contains("not same event, source, device"));
}

#[test]
fn unsupported_saved_evidence_abstains_from_comparison() {
    let left = load(fixture_path(), INPUT.len() as u64, None).unwrap();
    let right = load(
        unsupported_fixture_path(),
        UNSUPPORTED_INPUT.len() as u64,
        None,
    )
    .unwrap();
    let report = compare_triage(&left, &right).unwrap();
    let json = render_comparison_json(&report).unwrap();
    let human = render_comparison_human(&report);

    assert!(json.contains("\"status\": \"not_comparable\""));
    assert!(json.contains("\"hypothesis\": \"unknown\""));
    assert!(json.contains("\"reason\": \"right_not_observed\""));
    assert!(human.contains("compare   not comparable / canonical right not observed"));
    assert!(human.contains(
        "compare  sha256:2222222222222222222222222222222222222222222222222222222222222222"
    ));
}

#[test]
fn comparison_keeps_cli_roles_distinct_from_canonical_hypothesis_order() {
    let observed = load(fixture_path(), INPUT.len() as u64, None).unwrap();
    let unsupported = load(
        unsupported_fixture_path(),
        UNSUPPORTED_INPUT.len() as u64,
        None,
    )
    .unwrap();

    let forward = compare_triage(&observed, &unsupported).unwrap();
    let reversed = compare_triage(&unsupported, &observed).unwrap();

    assert_eq!(forward.hypothesis, reversed.hypothesis);
    assert_eq!(
        reversed.input.source.capture_id,
        unsupported.source.manifest.capture_id
    );
    assert_eq!(
        reversed.compare_with.source.capture_id,
        observed.source.manifest.capture_id
    );

    let value: serde_json::Value =
        serde_json::from_str(&render_comparison_json(&reversed).unwrap()).unwrap();
    let keys = value
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        keys,
        [
            "compare_with",
            "hypothesis",
            "input",
            "limitations",
            "schema"
        ]
    );
    assert_eq!(
        value["input"]["source"]["capture_id"],
        "sha256:2222222222222222222222222222222222222222222222222222222222222222"
    );
    assert_eq!(
        value["compare_with"]["source"]["capture_id"],
        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    );

    let human = render_comparison_human(&reversed);
    assert!(human.contains(
        "input    sha256:2222222222222222222222222222222222222222222222222222222222222222"
    ));
    assert!(human.contains(
        "compare  sha256:0000000000000000000000000000000000000000000000000000000000000000"
    ));
    assert!(human.contains("compare   not comparable / canonical right not observed"));
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

const POSITIVE_CAPTURE_ID: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const PARTIAL_CAPTURE_ID: &str =
    "sha256:066432299ec4a059eb4efbf10c9e90fce4f47d8cc3e0e9f9f05c55210725d2a5";
const UNSUPPORTED_CAPTURE_ID: &str =
    "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const POSITIVE_CONFIGURATION_SHA256: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PARTIAL_CONFIGURATION_SHA256: &str =
    "sha256:f488bbcd8ea84a8cffd97498b000959f5673bb14787b240f4e34bc9bc4563042";
const UNSUPPORTED_CONFIGURATION_SHA256: &str =
    "sha256:3333333333333333333333333333333333333333333333333333333333333333";

fn review_manifest(
    capture_id: &str,
    size_bytes: u64,
    adapter_version: &str,
    tool_version: &str,
    configuration_sha256: &str,
    normalization: CaptureNormalizationV0,
) -> CaptureManifestV0 {
    CaptureManifestV0 {
        schema: CAPTURE_MANIFEST_SCHEMA_V0.into(),
        capture_id: capture_id.into(),
        artifact: CaptureArtifactRefV0 {
            content_sha256: capture_id.into(),
            size_bytes,
        },
        observer_id: None,
        acquired_time_unix_ms: None,
        extractor: CaptureExtractorRefV0 {
            adapter: "netbraid-adapter-tshark".into(),
            adapter_version: adapter_version.into(),
            tool: "tshark".into(),
            tool_version: tool_version.into(),
            configuration_sha256: configuration_sha256.into(),
            field_registry: "netmon.tshark.packet_envelope.v1".into(),
        },
        acquisition_policy: None,
        normalization,
    }
}

fn fixture_normalization(
    state: NormalizationStateV0,
    packet_limit: u64,
    packet_rows_emitted: u64,
    packet_rows_quarantined: u64,
) -> CaptureNormalizationV0 {
    CaptureNormalizationV0 {
        state,
        packet_limit,
        packet_limit_reached: false,
        packet_rows_emitted,
        packet_rows_quarantined,
    }
}

fn tcp_fixture_packet(
    capture_id: &str,
    number: u64,
    event_time_unix_ns: i64,
    length: u32,
    source: (&str, u16),
    destination: (&str, u16),
    flags: u16,
) -> PacketEnvelopeV0 {
    let mut packet = base_fixture_packet(
        capture_id,
        number,
        event_time_unix_ns,
        length,
        1,
        &["eth", "ethertype", "ip", "tcp"],
    );
    packet.ethernet = Some(EthernetFieldsV0 {
        source: Some("02:00:00:00:00:01".into()),
        destination: Some("02:00:00:00:00:02".into()),
    });
    packet.ipv4 = Some(Ipv4FieldsV0 {
        source: source.0.into(),
        destination: destination.0.into(),
        protocol: 6,
        total_length_octets: None,
    });
    packet.tcp = Some(TcpFieldsV0 {
        source_port: source.1,
        destination_port: destination.1,
        flags,
        stream_index: None,
    });
    packet
}

fn wlan_fixture_packet(capture_id: &str) -> PacketEnvelopeV0 {
    let mut packet = base_fixture_packet(capture_id, 3, 3_000, 50, 105, &["wlan"]);
    packet.ieee80211 = Some(Ieee80211FieldsV0 {
        frame_type: 0,
        frame_subtype: 12,
        transmitter: Some("02:00:00:00:00:01".into()),
        receiver: Some("02:00:00:00:00:02".into()),
        source: Some("02:00:00:00:00:01".into()),
        destination: Some("02:00:00:00:00:02".into()),
        bssid: Some("02:00:00:00:00:01".into()),
        ssid_hex: None,
    });
    packet
}

fn base_fixture_packet(
    capture_id: &str,
    number: u64,
    event_time_unix_ns: i64,
    length: u32,
    encapsulation_type: i16,
    protocols: &[&str],
) -> PacketEnvelopeV0 {
    PacketEnvelopeV0 {
        schema: PACKET_ENVELOPE_SCHEMA_V0.into(),
        record_id: format!("{capture_id}:frame:{number}"),
        capture_id: capture_id.into(),
        frame: PacketFrameV0 {
            number,
            event_time_unix_ns,
            original_len: length,
            captured_len: length,
            section_number: Some(0),
            interface_id: Some(0),
            encapsulation_type: Some(encapsulation_type),
            protocols: protocols
                .iter()
                .map(|protocol| (*protocol).into())
                .collect(),
        },
        ethernet: None,
        ipv4: None,
        ipv6: None,
        tcp: None,
        udp: None,
        ieee802154: None,
        ieee80211: None,
        wlan_radio: None,
    }
}

fn positive_fixture_receipt(normalized_records_sha256: String) -> CaptureRunReceiptV0 {
    CaptureRunReceiptV0 {
        schema: CAPTURE_RUN_RECEIPT_SCHEMA_V0.into(),
        run_id: "run:1111111111111111111111111111111111111111111111111111111111111111".into(),
        capture_id: POSITIVE_CAPTURE_ID.into(),
        started_time_unix_ns: 4_000,
        finished_time_unix_ns: 5_000,
        elapsed_ns: 1_000,
        file: CaptureFileMetadataV0 {
            file_type: "pcapng".into(),
            encapsulation: "ether".into(),
            timestamp_precision: "nanoseconds".into(),
            packet_count: 3,
            file_size_bytes: 100,
            original_data_size_bytes: 250,
            snaplen: None,
            inferred_snaplen_min: None,
            inferred_snaplen_max: None,
            duration_ns: Some(2_000),
            earliest_packet_time_unix_ns: Some(1_000),
            latest_packet_time_unix_ns: Some(3_000),
            capture_hardware: None,
            capture_operating_system: None,
            capture_application: None,
        },
        capinfos: fixture_tool_receipt(
            "capinfos",
            "Capinfos 4.6.7",
            &["$STAGED_CAPTURE"],
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        ),
        tshark: fixture_tool_receipt(
            "tshark",
            "TShark 4.6.7",
            &["-r", "$STAGED_CAPTURE"],
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        ),
        configuration_sha256: POSITIVE_CONFIGURATION_SHA256.into(),
        field_registry: "netmon.tshark.packet_envelope.v1".into(),
        normalized_records_digest_profile: NORMALIZED_RECORDS_DIGEST_PROFILE_V0.into(),
        normalized_records_sha256,
    }
}

fn fixture_tool_receipt(
    tool: &str,
    tool_version: &str,
    argument_template: &[&str],
    stdout_sha256: &str,
    stderr_sha256: &str,
) -> ToolRunReceiptV0 {
    ToolRunReceiptV0 {
        tool: tool.into(),
        configured_executable: tool.into(),
        tool_version: tool_version.into(),
        argument_template: argument_template
            .iter()
            .map(|argument| (*argument).into())
            .collect(),
        environment_policy: "netmon.wireshark.environment.v0".into(),
        exit_code: 0,
        stdout_sha256: stdout_sha256.into(),
        stderr_sha256: stderr_sha256.into(),
    }
}

fn serialize_review_records(
    manifest: &CaptureManifestV0,
    receipt: Option<&CaptureRunReceiptV0>,
    packets: &[PacketEnvelopeV0],
    quarantines: &[PacketQuarantineV0],
) -> String {
    let mut jsonl = String::new();
    push_jsonl_record(&mut jsonl, manifest);
    if let Some(receipt) = receipt {
        push_jsonl_record(&mut jsonl, receipt);
    }
    for packet in packets {
        push_jsonl_record(&mut jsonl, packet);
    }
    for quarantine in quarantines {
        push_jsonl_record(&mut jsonl, quarantine);
    }
    jsonl
}

fn push_jsonl_record(jsonl: &mut String, record: &impl serde::Serialize) {
    jsonl.push_str(&serde_json::to_string(record).unwrap());
    jsonl.push('\n');
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
