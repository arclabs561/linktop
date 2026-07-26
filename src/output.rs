use anyhow::Result;
use chrono::{SecondsFormat, Utc};
use serde::Serialize;

use crate::model::{
    Health, InterfaceCounters, LinkSnapshot, MacScope, Peer, PeerSnapshot, ProbePolicy,
    SnapshotProbe, SnapshotReport, SnapshotSummary,
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
    use crate::model::{
        Address, EvidenceCoverage, PathStatus, ProbeKind, SnapshotProbe, SnapshotReport,
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
            wifi: None,
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
            network_configuration: None,
        }
    }

    fn test_peers() -> PeerSnapshot {
        PeerSnapshot {
            health: Health::Ok,
            detail: "1 cached binding".into(),
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
        let snapshot_report = SnapshotReport {
            link: link.clone(),
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
        let probe_report = SnapshotReport {
            link: link.clone(),
            interface_counters: None,
            neighbors: peers.clone(),
            probes: vec![SnapshotProbe {
                kind: ProbeKind::Dns,
                health: Health::Ok,
                detail: "example.test resolved".into(),
                latency_ms: Some(12.0),
                metrics: None,
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

        let link_document = ObservationDocument::at(
            ObservationSubject::Link,
            snapshot_summary,
            LinkEvidence {
                link: &link,
                interface_counters: None,
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
                baseline: None,
                loaded: None,
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
