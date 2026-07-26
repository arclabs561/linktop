use anyhow::Result;
use chrono::{SecondsFormat, Utc};
use serde::Serialize;

use crate::model::{
    Health, InterfaceCounters, LinkSnapshot, MacScope, Peer, PeerPathFilter, PeerSnapshot,
    ProbePolicy, SnapshotProbe, SnapshotReport, SnapshotSummary,
};

pub const OBSERVATION_SCHEMA_V1: &str = "linktop.observation.v1";
pub const SPEED_EXPERIMENT_SCHEMA_V1: &str = "linktop.speed_experiment.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationSubject {
    Snapshot,
    Probe,
    Link,
    Peers,
}

#[derive(Debug, Serialize)]
pub struct Acquisition {
    pub policy: ProbePolicy,
    pub lifetime: &'static str,
}

#[derive(Debug, Serialize)]
pub struct Producer {
    pub name: &'static str,
    pub version: &'static str,
}

impl Producer {
    const LINKTOP: Self = Self {
        name: "linktop",
        version: env!("CARGO_PKG_VERSION"),
    };
}

#[derive(Debug, Serialize)]
pub struct ObservationDocument<E> {
    pub schema: &'static str,
    pub producer: Producer,
    pub subject: ObservationSubject,
    pub completed_at: String,
    pub acquisition: Acquisition,
    pub assessment: SnapshotSummary,
    pub evidence: E,
}

impl<E> ObservationDocument<E> {
    pub fn new(subject: ObservationSubject, assessment: SnapshotSummary, evidence: E) -> Self {
        Self::at(
            subject,
            assessment,
            evidence,
            Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        )
    }

    fn at(
        subject: ObservationSubject,
        assessment: SnapshotSummary,
        evidence: E,
        completed_at: String,
    ) -> Self {
        Self {
            schema: OBSERVATION_SCHEMA_V1,
            producer: Producer::LINKTOP,
            subject,
            completed_at,
            acquisition: Acquisition {
                policy: assessment.probe_policy,
                lifetime: "one_observation",
            },
            assessment,
            evidence,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct LinkEvidence<'a> {
    pub link: &'a LinkSnapshot,
    pub interface_counters: Option<&'a InterfaceCounters>,
}

#[derive(Debug, Serialize)]
pub struct HostPathEvidence<'a> {
    pub link: &'a LinkSnapshot,
    pub interface_counters: Option<&'a InterfaceCounters>,
    pub neighbors: &'a PeerSnapshot,
    pub probes: &'a [SnapshotProbe],
}

impl<'a> HostPathEvidence<'a> {
    pub fn new(report: &'a SnapshotReport) -> Self {
        Self {
            link: &report.link,
            interface_counters: report.interface_counters.as_ref(),
            neighbors: &report.neighbors,
            probes: &report.probes,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct PeerPathContext<'a> {
    pub host: &'a str,
    pub default_interface: Option<&'a str>,
    pub default_gateway: Option<&'a str>,
}

#[derive(Debug, Serialize)]
pub struct PeerObservation<'a> {
    pub address: &'a str,
    pub mac: Option<&'a str>,
    pub interface: Option<&'a str>,
    pub state: Option<&'a str>,
    pub binding_conflict: bool,
    pub mac_scope: Option<MacScope>,
    pub registrant: Option<&'a str>,
    pub is_default_gateway: bool,
}

impl<'a> PeerObservation<'a> {
    fn from_peer(peer: &'a Peer, gateway: Option<&str>) -> Self {
        Self {
            address: &peer.address,
            mac: peer.mac.as_deref(),
            interface: peer.interface.as_deref(),
            state: peer.state.as_deref(),
            binding_conflict: peer.binding_conflict,
            mac_scope: peer.mac_scope,
            registrant: peer.registrant.as_deref(),
            is_default_gateway: gateway == Some(peer.address.as_str()),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct PeerEvidence<'a> {
    pub path_context: PeerPathContext<'a>,
    pub health: Health,
    pub detail: &'a str,
    pub path_filter: PeerPathFilter,
    pub sources: &'a [String],
    pub failed_sources: &'a [String],
    pub oui_source: Option<&'a str>,
    pub peers: Vec<PeerObservation<'a>>,
}

impl<'a> PeerEvidence<'a> {
    pub fn new(link: &'a LinkSnapshot, snapshot: &'a PeerSnapshot) -> Self {
        Self {
            path_context: PeerPathContext {
                host: &link.host,
                default_interface: link.interface.as_deref(),
                default_gateway: link.gateway.as_deref(),
            },
            health: snapshot.health,
            detail: &snapshot.detail,
            path_filter: snapshot.path_filter,
            sources: &snapshot.sources,
            failed_sources: &snapshot.failed_sources,
            oui_source: snapshot.oui_source.as_deref(),
            peers: snapshot
                .peers
                .iter()
                .map(|peer| PeerObservation::from_peer(peer, link.gateway.as_deref()))
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SpeedExperimentDocument<E> {
    pub schema: &'static str,
    pub producer: Producer,
    pub subject: &'static str,
    pub completed_at: String,
    pub acquisition: Acquisition,
    pub evidence: E,
}

impl<E> SpeedExperimentDocument<E> {
    pub fn new(evidence: E) -> Self {
        Self::at(
            evidence,
            Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        )
    }

    fn at(evidence: E, completed_at: String) -> Self {
        Self {
            schema: SPEED_EXPERIMENT_SCHEMA_V1,
            producer: Producer::LINKTOP,
            subject: "speed",
            completed_at,
            acquisition: Acquisition {
                policy: ProbePolicy::Active,
                lifetime: "bounded_experiment",
            },
            evidence,
        }
    }
}

pub fn print_json(document: &impl Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(document)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::LatencyMetrics;
    use crate::model::{
        Address, EvidenceCoverage, NetworkConfiguration, PathStatus, ProbeKind, ProbeResult,
        SnapshotProbe, SnapshotReport, WifiTelemetry,
    };
    use crate::speed::{LoadedLatency, SpeedReport, TransferSummary};

    fn passive_summary(coverage: EvidenceCoverage) -> SnapshotSummary {
        SnapshotSummary {
            probe_policy: ProbePolicy::Passive,
            path_status: PathStatus::Untested,
            evidence_coverage: coverage,
            completed_probes: 0,
            total_probes: 0,
        }
    }

    fn test_link() -> LinkSnapshot {
        LinkSnapshot {
            host: "operator-host".into(),
            interface: Some("en0".into()),
            link_type: Some("wifi".into()),
            ssid: Some("lab".into()),
            ssid_restricted: false,
            wifi: Some(WifiTelemetry {
                signal_dbm: Some(-52.0),
                noise_dbm: Some(-91.0),
                signal_percent: Some(84.0),
                channel: Some(149),
                channel_width_mhz: Some(80),
                frequency_mhz: Some(5745),
                band: Some("5 GHz".into()),
                phy: Some("802.11ax".into()),
                tx_rate_mbps: Some(1200.0),
                rx_rate_mbps: Some(960.0),
                mcs: Some(11),
            }),
            gateway: Some("192.0.2.1".into()),
            public_ip: None,
            resolvers: vec!["192.0.2.53".into()],
            addresses: vec![Address {
                interface: "en0".into(),
                address: "192.0.2.10".into(),
                family: 4,
                is_default: true,
                is_temporary: false,
            }],
            network_configuration: Some(Box::new(NetworkConfiguration {
                connection_id: Some("lab-wifi".into()),
                associated_bssid: Some("00:11:22:33:44:55".into()),
                bssid_restricted: false,
                method: Some("DHCP".into()),
                state: Some("BOUND".into()),
                server: Some("192.0.2.1".into()),
                subnet_mask: Some("255.255.255.0".into()),
                lease_seconds: Some(86400),
                lease_started_at: Some("2026-07-26T12:00:00Z".into()),
                lease_expires_at: Some("2026-07-27T12:00:00Z".into()),
                router_arp_verified: Some(true),
                security: Some("WPA3 Personal".into()),
            })),
        }
    }

    fn test_counters() -> InterfaceCounters {
        InterfaceCounters {
            interface: "en0".into(),
            received_bytes: 123_456,
            transmitted_bytes: 78_901,
            received_packets: 1_234,
            transmitted_packets: 789,
            receive_errors: 2,
            transmit_errors: 3,
            drops: 4,
        }
    }

    fn test_metrics() -> LatencyMetrics {
        LatencyMetrics {
            sent: 4,
            received: 3,
            lost: 1,
            loss_rate: Some(0.25),
            rtt_min_ms: Some(8.0),
            rtt_mean_ms: Some(12.0),
            rtt_p50_ms: Some(11.0),
            rtt_p95_ms: Some(17.0),
            rtt_p99_ms: Some(17.8),
            rtt_max_ms: Some(18.0),
            rtt_sample_variance_ms2: Some(26.0),
            rtt_sample_stddev_ms: Some(5.1),
            mean_abs_adjacent_rtt_delta_ms: Some(5.0),
            positive_adjacent_rtt_delta_p95_ms: Some(7.0),
            rtt_delta_from_min_p95_ms: Some(9.0),
            rtt_delta_from_min_max_ms: Some(10.0),
            adjacent_rtt_pairs: 2,
        }
    }

    fn test_probe_result(detail: &str, latency_ms: f64) -> ProbeResult {
        ProbeResult {
            health: Health::Ok,
            detail: detail.into(),
            latency_ms: Some(latency_ms),
            metrics: Some(test_metrics()),
        }
    }

    fn test_peers() -> PeerSnapshot {
        PeerSnapshot {
            health: Health::Ok,
            detail: "1 cached binding".into(),
            path_filter: PeerPathFilter::Applied,
            sources: vec!["arp -an".into()],
            failed_sources: Vec::new(),
            oui_source: Some("IEEE OUI".into()),
            peers: vec![Peer {
                address: "192.0.2.1".into(),
                mac: Some("02:00:00:00:00:01".into()),
                interface: Some("en0".into()),
                state: Some("reachable".into()),
                binding_conflict: false,
                mac_scope: Some(MacScope::Local),
                registrant: None,
            }],
        }
    }

    fn assert_golden(document: &impl Serialize, expected: &str) {
        let expected = expected.replace("\r\n", "\n");
        assert_eq!(
            format!("{}\n", serde_json::to_string_pretty(document).unwrap()),
            expected
        );
    }

    #[test]
    fn observation_envelope_versions_subject_policy_and_assessment() {
        let link = test_link();
        let evidence = LinkEvidence {
            link: &link,
            interface_counters: None,
        };
        let document = ObservationDocument::at(
            ObservationSubject::Link,
            passive_summary(EvidenceCoverage::Partial),
            evidence,
            "2026-07-26T20:00:00Z".into(),
        );
        let value = serde_json::to_value(document).unwrap();

        assert_eq!(value["schema"], OBSERVATION_SCHEMA_V1);
        assert_eq!(value["producer"]["name"], "linktop");
        assert_eq!(value["producer"]["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(value["subject"], "link");
        assert_eq!(value["completed_at"], "2026-07-26T20:00:00Z");
        assert_eq!(value["acquisition"]["policy"], "passive");
        assert_eq!(value["acquisition"]["lifetime"], "one_observation");
        assert_eq!(value["assessment"]["path_status"], "untested");
        assert_eq!(value["assessment"]["evidence_coverage"], "partial");
        assert_eq!(value["evidence"]["link"]["interface"], "en0");
        assert!(value["evidence"]["interface_counters"].is_null());
    }

    #[test]
    fn golden_comparison_normalizes_checkout_line_endings() {
        assert_golden(
            &serde_json::json!({"field": "value"}),
            "{\r\n  \"field\": \"value\"\r\n}\r\n",
        );
    }

    #[test]
    fn peer_projection_makes_default_gateway_role_explicit() {
        let link = test_link();
        let snapshot = test_peers();
        let evidence = PeerEvidence::new(&link, &snapshot);
        let document = ObservationDocument::at(
            ObservationSubject::Peers,
            passive_summary(EvidenceCoverage::Complete),
            evidence,
            "2026-07-26T20:00:00Z".into(),
        );
        let value = serde_json::to_value(document).unwrap();

        assert_eq!(
            value["evidence"]["path_context"]["default_gateway"],
            "192.0.2.1"
        );
        assert_eq!(value["evidence"]["peers"][0]["is_default_gateway"], true);
    }

    #[test]
    fn speed_experiment_uses_a_distinct_versioned_active_contract() {
        let document = SpeedExperimentDocument::at(
            serde_json::json!({"duration_s": 10}),
            "2026-07-26T20:00:10Z".into(),
        );
        let value = serde_json::to_value(document).unwrap();

        assert_eq!(value["schema"], SPEED_EXPERIMENT_SCHEMA_V1);
        assert_eq!(value["producer"]["name"], "linktop");
        assert_eq!(value["subject"], "speed");
        assert_eq!(value["completed_at"], "2026-07-26T20:00:10Z");
        assert_eq!(value["acquisition"]["policy"], "active");
        assert_eq!(value["acquisition"]["lifetime"], "bounded_experiment");
        assert_eq!(value["evidence"]["duration_s"], 10);
    }

    #[test]
    fn v1_documents_match_exact_readable_golden_fixtures() {
        let link = test_link();
        let peers = test_peers();
        let snapshot_summary = passive_summary(EvidenceCoverage::Partial);
        let mut snapshot_link = link.clone();
        snapshot_link.wifi = None;
        snapshot_link.network_configuration = None;
        let snapshot_report = SnapshotReport {
            link: snapshot_link,
            interface_counters: None,
            neighbors: peers.clone(),
            probes: Vec::new(),
            summary: snapshot_summary,
        };
        let snapshot_document = ObservationDocument::at(
            ObservationSubject::Snapshot,
            snapshot_summary,
            HostPathEvidence::new(&snapshot_report),
            "2026-07-26T20:00:00Z".into(),
        );
        assert_golden(
            &snapshot_document,
            include_str!("output/fixtures/v1/snapshot.json"),
        );

        let probe_summary = SnapshotSummary {
            probe_policy: ProbePolicy::Active,
            path_status: PathStatus::Ok,
            evidence_coverage: EvidenceCoverage::Complete,
            completed_probes: 1,
            total_probes: ProbeKind::ALL.len(),
        };
        let mut probe_link = link.clone();
        probe_link.wifi = None;
        probe_link.network_configuration = None;
        let probe_report = SnapshotReport {
            link: probe_link,
            interface_counters: None,
            neighbors: peers.clone(),
            probes: vec![SnapshotProbe {
                kind: ProbeKind::Dns,
                health: Health::Ok,
                detail: "example.test resolved".into(),
                latency_ms: Some(12.0),
                metrics: Some(test_metrics()),
            }],
            summary: probe_summary,
        };
        let probe_document = ObservationDocument::at(
            ObservationSubject::Probe,
            probe_summary,
            HostPathEvidence::new(&probe_report),
            "2026-07-26T20:00:00Z".into(),
        );
        assert_golden(
            &probe_document,
            include_str!("output/fixtures/v1/probe.json"),
        );

        let link_counters = test_counters();
        let link_document = ObservationDocument::at(
            ObservationSubject::Link,
            snapshot_summary,
            LinkEvidence {
                link: &link,
                interface_counters: Some(&link_counters),
            },
            "2026-07-26T20:00:00Z".into(),
        );
        assert_golden(&link_document, include_str!("output/fixtures/v1/link.json"));

        let peer_document = ObservationDocument::at(
            ObservationSubject::Peers,
            passive_summary(EvidenceCoverage::Complete),
            PeerEvidence::new(&link, &peers),
            "2026-07-26T20:00:00Z".into(),
        );
        assert_golden(
            &peer_document,
            include_str!("output/fixtures/v1/peers.json"),
        );

        let speed_report = SpeedReport {
            tool: "iperf3",
            mode: "tcp",
            target: "192.0.2.20".into(),
            port: 5201,
            duration_s: 10,
            gateway_latency: LoadedLatency {
                baseline: Some(test_probe_result("gateway baseline complete", 12.0)),
                loaded: Some(test_probe_result("gateway under load complete", 24.0)),
            },
            transfer: TransferSummary {
                sent_bits_per_second: Some(1_000_000.0),
                received_bits_per_second: Some(900_000.0),
                retransmits: Some(1),
            },
        };
        let speed_document =
            SpeedExperimentDocument::at(&speed_report, "2026-07-26T20:00:10Z".into());
        assert_golden(
            &speed_document,
            include_str!("output/fixtures/v1/speed.json"),
        );
    }
}
