use anyhow::Result;
use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use std::io::{self, Write};
use std::time::{Duration, Instant};

use crate::metrics::LatencyMetrics;
use crate::model::{
    Address, App, AppProjection, CompletedPathWindow, EvidenceClaim, EvidenceCoverage,
    EvidenceLimitation, EvidenceProgress, EvidenceProgressState, Health, HistoryContext,
    InterfaceCounters, LinkSnapshot, LiveAssessment, LiveEvidence, LiveGatewayAssessmentEvidence,
    MacScope, MonitorMode, MonitorUpdate, PathStatus, PathUnderlay, Peer, PeerPathFilter,
    PeerSnapshot, ProbeKind, ProbePolicy, Situation, SnapshotProbe, SnapshotReport,
    SnapshotSummary,
};

pub const OBSERVATION_SCHEMA_V1: &str = "linktop.observation.v1";
pub const SPEED_EXPERIMENT_SCHEMA_V1: &str = "linktop.speed_experiment.v1";
pub const LIVE_OBSERVATION_SCHEMA_V1: &str = "linktop.live_observation.v1";
pub const READINESS_SCHEMA_V0: &str = "linktop.readiness.v0";
const LIVE_CHECKPOINT_INTERVAL: Duration = Duration::from_secs(5);

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u64>,
}

#[derive(Debug)]
pub struct AcquisitionWindow {
    started_at: String,
    started: Instant,
}

impl AcquisitionWindow {
    pub fn start() -> Self {
        Self {
            started_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            started: Instant::now(),
        }
    }

    fn elapsed_ms(&self) -> u64 {
        self.started.elapsed().as_millis().min(u64::MAX as u128) as u64
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessPurposeV0 {
    InteractiveUse,
    Calls,
    BulkTransfer,
    IdleBackground,
}

impl ReadinessPurposeV0 {
    pub const fn label(self) -> &'static str {
        match self {
            Self::InteractiveUse => "interactive_use",
            Self::Calls => "calls",
            Self::BulkTransfer => "bulk_transfer",
            Self::IdleBackground => "idle_background",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessStatusV0 {
    Ready,
    Degraded,
    Insufficient,
    NotTested,
}

impl ReadinessStatusV0 {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ready => "READY",
            Self::Degraded => "DEGRADED",
            Self::Insufficient => "INSUFFICIENT",
            Self::NotTested => "NOT_TESTED",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ReadinessAssessmentV0 {
    pub purpose: ReadinessPurposeV0,
    pub status: ReadinessStatusV0,
    pub evidence: Vec<&'static str>,
    pub reasons: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct ReadinessDocumentV0 {
    pub schema: &'static str,
    pub producer: Producer,
    pub completed_at: String,
    pub acquisition: Acquisition,
    pub path_status: PathStatus,
    pub evidence_coverage: EvidenceCoverage,
    pub assessments: Vec<ReadinessAssessmentV0>,
}

pub fn readiness_document(
    report: &SnapshotReport,
    window: &AcquisitionWindow,
) -> ReadinessDocumentV0 {
    let path_probes: Vec<_> = ProbeKind::PATH
        .iter()
        .map(|kind| report.probes.iter().find(|probe| probe.kind == *kind))
        .collect();
    let path_context_complete = report.link.interface.is_some()
        && report.link.gateway.is_some()
        && !report.link.resolvers.is_empty()
        && report
            .link
            .addresses
            .iter()
            .any(|address| address.is_default);
    let path_measurements_complete = path_probes
        .iter()
        .all(|probe| probe.is_some_and(|probe| probe.health == Health::Ok));
    let path_evidence = vec!["next_hop_rtt", "dns", "https"];
    let interactive = if path_probes
        .iter()
        .flatten()
        .any(|probe| probe.health == Health::Failed)
    {
        ReadinessAssessmentV0 {
            purpose: ReadinessPurposeV0::InteractiveUse,
            status: ReadinessStatusV0::Degraded,
            evidence: path_evidence,
            reasons: vec!["one or more path measurements failed"],
        }
    } else if !path_context_complete || !path_measurements_complete {
        ReadinessAssessmentV0 {
            purpose: ReadinessPurposeV0::InteractiveUse,
            status: ReadinessStatusV0::Insufficient,
            evidence: path_evidence,
            reasons: vec!["current path context or all path measurements are not complete"],
        }
    } else if path_probes
        .iter()
        .flatten()
        .any(|probe| probe.health == Health::Degraded)
    {
        ReadinessAssessmentV0 {
            purpose: ReadinessPurposeV0::InteractiveUse,
            status: ReadinessStatusV0::Degraded,
            evidence: path_evidence,
            reasons: vec!["one or more path measurements are degraded"],
        }
    } else {
        ReadinessAssessmentV0 {
            purpose: ReadinessPurposeV0::InteractiveUse,
            status: ReadinessStatusV0::Ready,
            evidence: path_evidence,
            reasons: vec!["fresh path context and all path measurements passed"],
        }
    };
    let assessments = vec![
        interactive,
        ReadinessAssessmentV0 {
            purpose: ReadinessPurposeV0::Calls,
            status: ReadinessStatusV0::NotTested,
            evidence: Vec::new(),
            reasons: vec!["no voice-specific measurement was collected"],
        },
        ReadinessAssessmentV0 {
            purpose: ReadinessPurposeV0::BulkTransfer,
            status: ReadinessStatusV0::NotTested,
            evidence: Vec::new(),
            reasons: vec!["no bounded load experiment was collected"],
        },
        ReadinessAssessmentV0 {
            purpose: ReadinessPurposeV0::IdleBackground,
            status: ReadinessStatusV0::NotTested,
            evidence: Vec::new(),
            reasons: vec!["no host process-accounting window was collected"],
        },
    ];
    ReadinessDocumentV0 {
        schema: READINESS_SCHEMA_V0,
        producer: Producer::LINKTOP,
        completed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        acquisition: Acquisition {
            policy: ProbePolicy::Active,
            lifetime: "bounded_readiness_snapshot",
            started_at: Some(window.started_at.clone()),
            elapsed_ms: Some(window.elapsed_ms()),
        },
        path_status: report.summary.path_status,
        evidence_coverage: report.summary.evidence_coverage,
        assessments,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveLineKind {
    Checkpoint,
    Transition,
    FinalSummary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveTrigger {
    Link,
    PathSettling,
    Wifi,
    Peers,
    Traffic,
    Workload,
    ProbeStarted,
    ProbeFinished,
    Notice,
}

impl From<&MonitorUpdate> for LiveTrigger {
    fn from(update: &MonitorUpdate) -> Self {
        match update {
            MonitorUpdate::Link { .. } => Self::Link,
            MonitorUpdate::PathSettling { .. } => Self::PathSettling,
            MonitorUpdate::Wifi { .. } => Self::Wifi,
            MonitorUpdate::Peers { .. } => Self::Peers,
            MonitorUpdate::Traffic { .. } => Self::Traffic,
            MonitorUpdate::Workload { .. } => Self::Workload,
            MonitorUpdate::ProbeStarted { .. } => Self::ProbeStarted,
            MonitorUpdate::ProbeFinished { .. } => Self::ProbeFinished,
            MonitorUpdate::Notice(_) => Self::Notice,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LiveAcquisition {
    pub policy: ProbePolicy,
    pub lifetime: &'static str,
    pub started_at: String,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct LiveObservationDocument {
    pub schema: &'static str,
    pub producer: Producer,
    pub line: LiveLineKind,
    pub sequence: u64,
    pub subject: MonitorMode,
    pub emitted_at: String,
    pub acquisition: LiveAcquisition,
    pub generation: u64,
    pub assessment: LiveAssessment,
    pub progress: Vec<EvidenceProgress>,
    pub evidence: LiveEvidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger: Option<LiveTrigger>,
}

#[derive(Debug)]
pub struct LiveObservationStream {
    started_at: String,
    started: Instant,
    policy: ProbePolicy,
    lifetime: &'static str,
    bounded: bool,
    sequence: u64,
    last_material_state: Option<LiveMaterialState>,
    last_emitted_elapsed: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq)]
struct LiveMaterialState {
    generation: u64,
    situation: Situation,
    path_status: PathStatus,
    evidence_coverage: EvidenceCoverage,
    progress: Vec<(
        EvidenceClaim,
        EvidenceProgressState,
        Vec<EvidenceLimitation>,
    )>,
    path: String,
    probes: Vec<LiveProbeMaterialState>,
    gateway_assessment: Option<LiveGatewayAssessmentEvidence>,
    neighbors: Option<PeerSnapshot>,
    completed_path_window: Option<CompletedPathWindow>,
    history_context: Option<HistoryContext>,
}

#[derive(Debug, Clone, PartialEq)]
struct LiveProbeMaterialState {
    kind: ProbeKind,
    health: Health,
    detail: String,
    latency_ms: Option<f64>,
    metrics: Option<LatencyMetrics>,
}

impl LiveMaterialState {
    fn from_projection(projection: &AppProjection) -> Self {
        Self {
            generation: projection.generation,
            situation: projection.assessment.situation,
            path_status: projection.assessment.path_status,
            evidence_coverage: projection.assessment.evidence_coverage,
            progress: projection
                .progress
                .iter()
                .map(|progress| (progress.claim, progress.state, progress.limitations.clone()))
                .collect(),
            path: format!("{:?}", projection.evidence.path),
            probes: projection
                .evidence
                .probes
                .iter()
                .map(|probe| LiveProbeMaterialState {
                    kind: probe.kind,
                    health: probe.health,
                    detail: probe.detail.clone(),
                    latency_ms: probe.latency_ms,
                    metrics: probe.metrics.clone(),
                })
                .collect(),
            gateway_assessment: projection.evidence.gateway_assessment.clone(),
            neighbors: projection.evidence.neighbors.clone(),
            completed_path_window: projection.evidence.completed_path_window.clone(),
            history_context: projection.evidence.history_context.clone(),
        }
    }
}

impl LiveObservationStream {
    pub fn start(policy: ProbePolicy, dwell: Option<Duration>) -> Self {
        Self {
            started_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            started: Instant::now(),
            policy,
            lifetime: if dwell.is_some() {
                "bounded_dwell"
            } else {
                "unbounded_stream"
            },
            bounded: dwell.is_some(),
            sequence: 0,
            last_material_state: None,
            last_emitted_elapsed: None,
        }
    }

    pub fn observe(
        &mut self,
        trigger: LiveTrigger,
        subject: MonitorMode,
        app: &App,
    ) -> Option<LiveObservationDocument> {
        self.observe_at(
            trigger,
            subject,
            app.projection(subject),
            Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            self.started.elapsed(),
        )
    }

    fn observe_at(
        &mut self,
        trigger: LiveTrigger,
        subject: MonitorMode,
        projection: AppProjection,
        emitted_at: String,
        elapsed: Duration,
    ) -> Option<LiveObservationDocument> {
        let material_state = LiveMaterialState::from_projection(&projection);
        let generation_changed = self
            .last_material_state
            .as_ref()
            .is_some_and(|previous| previous.generation != material_state.generation);
        let material_changed = self
            .last_material_state
            .as_ref()
            .is_none_or(|previous| previous != &material_state);
        let checkpoint_due = self
            .last_emitted_elapsed
            .is_none_or(|last| elapsed.saturating_sub(last) >= LIVE_CHECKPOINT_INTERVAL);
        self.last_material_state = Some(material_state);
        if !material_changed && !checkpoint_due {
            return None;
        }

        self.sequence = self.sequence.saturating_add(1);
        self.last_emitted_elapsed = Some(elapsed);
        Some(self.document_at(
            if generation_changed {
                LiveLineKind::Transition
            } else {
                LiveLineKind::Checkpoint
            },
            Some(trigger),
            subject,
            projection,
            emitted_at,
            elapsed,
        ))
    }

    pub fn final_summary(
        &mut self,
        subject: MonitorMode,
        app: &App,
    ) -> Option<LiveObservationDocument> {
        if !self.bounded {
            return None;
        }
        self.sequence = self.sequence.saturating_add(1);
        let projection = app.final_projection(subject);
        Some(self.document_at(
            LiveLineKind::FinalSummary,
            None,
            subject,
            projection,
            Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            self.started.elapsed(),
        ))
    }

    fn document_at(
        &self,
        line: LiveLineKind,
        trigger: Option<LiveTrigger>,
        subject: MonitorMode,
        projection: AppProjection,
        emitted_at: String,
        elapsed: Duration,
    ) -> LiveObservationDocument {
        LiveObservationDocument {
            schema: LIVE_OBSERVATION_SCHEMA_V1,
            producer: Producer::LINKTOP,
            line,
            sequence: self.sequence,
            subject,
            emitted_at,
            acquisition: LiveAcquisition {
                policy: self.policy,
                lifetime: self.lifetime,
                started_at: self.started_at.clone(),
                elapsed_ms: duration_ms(elapsed),
            },
            generation: projection.generation,
            assessment: projection.assessment,
            progress: projection.progress,
            evidence: projection.evidence,
            trigger,
        }
    }
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
    pub fn new(
        subject: ObservationSubject,
        assessment: SnapshotSummary,
        evidence: E,
        window: &AcquisitionWindow,
    ) -> Self {
        Self::at(
            subject,
            assessment,
            evidence,
            window.started_at.clone(),
            window.elapsed_ms(),
            Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        )
    }

    fn at(
        subject: ObservationSubject,
        assessment: SnapshotSummary,
        evidence: E,
        started_at: String,
        elapsed_ms: u64,
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
                started_at: Some(started_at),
                elapsed_ms: Some(elapsed_ms),
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
#[serde(rename_all = "snake_case")]
pub enum IdentifierVisibility {
    Observed,
    Restricted,
    Unavailable,
}

#[derive(Debug, Serialize)]
pub struct PathIdentifier<'a> {
    pub visibility: IdentifierVisibility,
    pub value: Option<&'a str>,
}

#[derive(Debug, Serialize)]
pub struct PeerPathContext<'a> {
    pub host: &'a str,
    pub default_interface: Option<&'a str>,
    pub default_gateway: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub underlay: Option<&'a PathUnderlay>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_evidence: Option<PeerLinkEvidence<'a>>,
}

#[derive(Debug, Serialize)]
pub struct PeerLinkEvidence<'a> {
    pub link_type: Option<&'a str>,
    pub network_name: PathIdentifier<'a>,
    pub association_id: Option<&'a str>,
    pub associated_bssid: PathIdentifier<'a>,
    pub addresses: &'a [Address],
    pub default_path_prefixes: Vec<String>,
    pub effective_resolvers: &'a [String],
}

impl<'a> PeerPathContext<'a> {
    fn new(link: &'a LinkSnapshot) -> Self {
        let configuration = link.network_configuration.as_deref();
        Self {
            host: &link.host,
            default_interface: link.interface.as_deref(),
            default_gateway: link.gateway.as_deref(),
            underlay: link.underlay.as_ref(),
            link_evidence: has_peer_link_evidence(link).then(|| PeerLinkEvidence {
                link_type: link.link_type.as_deref(),
                network_name: visible_identifier(link.ssid.as_deref(), link.ssid_restricted),
                association_id: configuration.and_then(|value| value.connection_id.as_deref()),
                associated_bssid: visible_identifier(
                    configuration.and_then(|value| value.associated_bssid.as_deref()),
                    configuration.is_some_and(|value| value.bssid_restricted),
                ),
                addresses: &link.addresses,
                default_path_prefixes: link.default_path_prefixes(),
                effective_resolvers: &link.resolvers,
            }),
        }
    }
}

fn has_peer_link_evidence(link: &LinkSnapshot) -> bool {
    link.link_type.is_some()
        || link.ssid.is_some()
        || link.ssid_restricted
        || link.network_configuration.is_some()
        || !link.addresses.is_empty()
        || !link.resolvers.is_empty()
}

fn visible_identifier(value: Option<&str>, restricted: bool) -> PathIdentifier<'_> {
    PathIdentifier {
        visibility: if value.is_some() {
            IdentifierVisibility::Observed
        } else if restricted {
            IdentifierVisibility::Restricted
        } else {
            IdentifierVisibility::Unavailable
        },
        value,
    }
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
            path_context: PeerPathContext::new(link),
            health: snapshot.health,
            detail: &snapshot.detail,
            path_filter: snapshot.path_filter,
            sources: &snapshot.sources,
            failed_sources: &snapshot.failed_sources,
            oui_source: snapshot.oui_source.as_deref(),
            peers: snapshot
                .peers
                .iter()
                .map(|peer| PeerObservation::from_peer(peer, link.observation_gateway()))
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
    pub fn new(evidence: E, window: &AcquisitionWindow) -> Self {
        Self::at(
            evidence,
            window.started_at.clone(),
            window.elapsed_ms(),
            Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        )
    }

    fn at(evidence: E, started_at: String, elapsed_ms: u64, completed_at: String) -> Self {
        Self {
            schema: SPEED_EXPERIMENT_SCHEMA_V1,
            producer: Producer::LINKTOP,
            subject: "speed",
            completed_at,
            acquisition: Acquisition {
                policy: ProbePolicy::Active,
                lifetime: "bounded_experiment",
                started_at: Some(started_at),
                elapsed_ms: Some(elapsed_ms),
            },
            evidence,
        }
    }
}

pub fn print_json(document: &impl Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(document)?);
    Ok(())
}

pub fn print_jsonl(document: &impl Serialize) -> Result<()> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer(&mut stdout, document)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::LatencyMetrics;
    use crate::model::{
        Address, EvidenceCoverage, NetworkConfiguration, PathStatus, ProbeKind, ProbeResult,
        ProcessTraffic, SnapshotProbe, SnapshotReport, WifiTelemetry, WorkloadSnapshot,
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
            underlay: None,
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

    #[test]
    fn readiness_document_keeps_unmeasured_purposes_explicitly_untested() {
        let report = SnapshotReport::from_results(
            test_link(),
            Some(test_counters()),
            test_peers(),
            vec![
                (ProbeKind::Gateway, test_probe_result("gateway", 8.0)),
                (ProbeKind::Dns, test_probe_result("dns", 12.0)),
                (ProbeKind::Https, test_probe_result("https", 35.0)),
                (ProbeKind::PublicIp, test_probe_result("public ip", 40.0)),
            ],
        );
        let document = readiness_document(&report, &AcquisitionWindow::start());

        assert_eq!(document.schema, READINESS_SCHEMA_V0);
        assert_eq!(document.path_status, PathStatus::Ok);
        assert_eq!(document.assessments.len(), 4);
        assert_eq!(document.assessments[0].status, ReadinessStatusV0::Ready);
        assert_eq!(
            document.assessments[0].purpose,
            ReadinessPurposeV0::InteractiveUse
        );
        for assessment in &document.assessments[1..] {
            assert_eq!(assessment.status, ReadinessStatusV0::NotTested);
            assert!(assessment.evidence.is_empty());
            assert!(!assessment.reasons.is_empty());
        }
    }

    #[test]
    fn readiness_document_degrades_interactive_use_on_failed_path_probe() {
        let report = SnapshotReport::from_results(
            test_link(),
            Some(test_counters()),
            test_peers(),
            vec![
                (ProbeKind::Gateway, test_probe_result("gateway", 8.0)),
                (ProbeKind::Dns, ProbeResult::failed("dns failed")),
                (ProbeKind::Https, test_probe_result("https", 35.0)),
                (ProbeKind::PublicIp, test_probe_result("public ip", 40.0)),
            ],
        );
        let document = readiness_document(&report, &AcquisitionWindow::start());

        assert_eq!(document.assessments[0].status, ReadinessStatusV0::Degraded);
        assert_eq!(
            document.assessments[0].reasons,
            vec!["one or more path measurements failed"]
        );
    }

    #[test]
    fn readiness_document_does_not_treat_unavailable_path_evidence_as_ready() {
        let report = SnapshotReport::from_results(
            test_link(),
            Some(test_counters()),
            test_peers(),
            vec![
                (ProbeKind::Gateway, test_probe_result("gateway", 8.0)),
                (ProbeKind::Dns, ProbeResult::unavailable("dns unavailable")),
                (ProbeKind::Https, test_probe_result("https", 35.0)),
                (ProbeKind::PublicIp, test_probe_result("public ip", 40.0)),
            ],
        );
        let document = readiness_document(&report, &AcquisitionWindow::start());

        assert_eq!(
            document.assessments[0].status,
            ReadinessStatusV0::Insufficient
        );
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
            "2026-07-26T19:59:59Z".into(),
            1_250,
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
        assert_eq!(value["acquisition"]["started_at"], "2026-07-26T19:59:59Z");
        assert_eq!(value["acquisition"]["elapsed_ms"], 1_250);
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
            "2026-07-26T19:59:59Z".into(),
            100,
            "2026-07-26T20:00:00Z".into(),
        );
        let value = serde_json::to_value(document).unwrap();

        assert_eq!(
            value["evidence"]["path_context"]["default_gateway"],
            "192.0.2.1"
        );
        assert_eq!(
            value["evidence"]["path_context"]["link_evidence"]["link_type"],
            "wifi"
        );
        assert_eq!(
            value["evidence"]["path_context"]["link_evidence"]["network_name"]["visibility"],
            "observed"
        );
        assert_eq!(
            value["evidence"]["path_context"]["link_evidence"]["network_name"]["value"],
            "lab"
        );
        assert_eq!(
            value["evidence"]["path_context"]["link_evidence"]["association_id"],
            "lab-wifi"
        );
        assert_eq!(
            value["evidence"]["path_context"]["link_evidence"]["associated_bssid"]["value"],
            "00:11:22:33:44:55"
        );
        assert_eq!(
            value["evidence"]["path_context"]["link_evidence"]["default_path_prefixes"][0],
            "192.0.2.0/24"
        );
        assert_eq!(
            value["evidence"]["path_context"]["link_evidence"]["effective_resolvers"][0],
            "192.0.2.53"
        );
        assert_eq!(value["evidence"]["peers"][0]["is_default_gateway"], true);
    }

    #[test]
    fn json_projects_effective_vpn_route_and_physical_underlay_separately() {
        let mut link = test_link();
        link.interface = Some("utun4".into());
        link.link_type = Some("vpn".into());
        link.gateway = None;
        link.addresses[0].interface = "utun4".into();
        link.addresses[0].address = "100.64.0.2".into();
        link.underlay = Some(PathUnderlay {
            interface: "en0".into(),
            link_type: "wifi".into(),
            gateway: Some("192.0.2.1".into()),
        });
        let peers = test_peers();

        let link_value = serde_json::to_value(LinkEvidence {
            link: &link,
            interface_counters: Some(&test_counters()),
        })
        .unwrap();
        assert_eq!(link_value["link"]["interface"], "utun4");
        assert_eq!(link_value["link"]["link_type"], "vpn");
        assert_eq!(link_value["link"]["underlay"]["interface"], "en0");
        assert_eq!(link_value["link"]["underlay"]["link_type"], "wifi");
        assert_eq!(link_value["interface_counters"]["interface"], "en0");

        let peer_value = serde_json::to_value(PeerEvidence::new(&link, &peers)).unwrap();
        assert_eq!(peer_value["path_context"]["default_interface"], "utun4");
        assert_eq!(peer_value["path_context"]["underlay"]["interface"], "en0");
        assert_eq!(
            peer_value["path_context"]["link_evidence"]["default_path_prefixes"],
            serde_json::json!([])
        );
        assert_eq!(peer_value["peers"][0]["is_default_gateway"], true);
    }

    #[test]
    fn peer_path_identifiers_preserve_restricted_visibility() {
        let mut link = test_link();
        link.ssid = None;
        link.ssid_restricted = true;
        let configuration = link.network_configuration.as_mut().unwrap();
        configuration.associated_bssid = None;
        configuration.bssid_restricted = true;
        let snapshot = test_peers();
        let value = serde_json::to_value(PeerEvidence::new(&link, &snapshot)).unwrap();

        assert_eq!(
            value["path_context"]["link_evidence"]["network_name"]["visibility"],
            "restricted"
        );
        assert!(value["path_context"]["link_evidence"]["network_name"]["value"].is_null());
        assert_eq!(
            value["path_context"]["link_evidence"]["associated_bssid"]["visibility"],
            "restricted"
        );
        assert!(value["path_context"]["link_evidence"]["associated_bssid"]["value"].is_null());

        let empty = LinkSnapshot::empty();
        let value = serde_json::to_value(PeerEvidence::new(&empty, &snapshot)).unwrap();
        assert!(value["path_context"].get("link_evidence").is_none());
    }

    #[test]
    fn speed_experiment_uses_a_distinct_versioned_active_contract() {
        let document = SpeedExperimentDocument::at(
            serde_json::json!({"duration_s": 10}),
            "2026-07-26T20:00:00Z".into(),
            10_250,
            "2026-07-26T20:00:10Z".into(),
        );
        let value = serde_json::to_value(document).unwrap();

        assert_eq!(value["schema"], SPEED_EXPERIMENT_SCHEMA_V1);
        assert_eq!(value["producer"]["name"], "linktop");
        assert_eq!(value["subject"], "speed");
        assert_eq!(value["completed_at"], "2026-07-26T20:00:10Z");
        assert_eq!(value["acquisition"]["policy"], "active");
        assert_eq!(value["acquisition"]["lifetime"], "bounded_experiment");
        assert_eq!(value["acquisition"]["started_at"], "2026-07-26T20:00:00Z");
        assert_eq!(value["acquisition"]["elapsed_ms"], 10_250);
        assert_eq!(value["evidence"]["duration_s"], 10);
    }

    #[test]
    fn production_constructors_measure_the_monotonic_acquisition_window() {
        let window = AcquisitionWindow {
            started_at: "2026-07-26T20:00:00Z".into(),
            started: Instant::now()
                .checked_sub(std::time::Duration::from_millis(10))
                .unwrap(),
        };
        let observation = ObservationDocument::new(
            ObservationSubject::Snapshot,
            passive_summary(EvidenceCoverage::Unavailable),
            serde_json::json!({"fixture": true}),
            &window,
        );
        let observation = serde_json::to_value(observation).unwrap();
        assert_eq!(
            observation["acquisition"]["started_at"],
            "2026-07-26T20:00:00Z"
        );
        assert!(observation["acquisition"]["elapsed_ms"].as_u64().unwrap() >= 10);

        let experiment =
            SpeedExperimentDocument::new(serde_json::json!({"fixture": true}), &window);
        let experiment = serde_json::to_value(experiment).unwrap();
        assert_eq!(
            experiment["acquisition"]["started_at"],
            "2026-07-26T20:00:00Z"
        );
        assert!(experiment["acquisition"]["elapsed_ms"].as_u64().unwrap() >= 10);
    }

    #[test]
    fn live_jsonl_records_are_self_contained_sequenced_and_bounded_by_contract() {
        let mut app = crate::model::App::new();
        assert!(app.apply(crate::model::MonitorUpdate::Link {
            generation: 1,
            snapshot: test_link(),
        }));
        let mut bounded =
            LiveObservationStream::start(ProbePolicy::Passive, Some(Duration::from_secs(1)));
        let checkpoint = bounded
            .observe(LiveTrigger::Link, crate::model::MonitorMode::Overview, &app)
            .expect("first accepted projection emits a checkpoint");
        let value = serde_json::to_value(&checkpoint).unwrap();
        assert_eq!(value["schema"], LIVE_OBSERVATION_SCHEMA_V1);
        assert_eq!(value["line"], "checkpoint");
        assert_eq!(value["sequence"], 1);
        assert_eq!(value["subject"], "overview");
        assert_eq!(value["acquisition"]["policy"], "passive");
        assert_eq!(value["acquisition"]["lifetime"], "bounded_dwell");
        assert!(value["acquisition"]["started_at"].is_string());
        assert!(value["acquisition"]["elapsed_ms"].is_number());
        assert_eq!(value["generation"], 1);
        assert_eq!(value["assessment"]["path_status"], "untested");
        assert!(value["progress"].is_array());
        assert_eq!(value["evidence"]["path"]["interface"], "en0");
        assert_eq!(value["trigger"], "link");

        let final_summary = bounded
            .final_summary(crate::model::MonitorMode::Overview, &app)
            .expect("bounded dwell has a terminal summary");
        assert_eq!(final_summary.line, LiveLineKind::FinalSummary);
        assert_eq!(final_summary.sequence, 2);
        assert!(final_summary.trigger.is_none());
        assert!(
            final_summary
                .progress
                .iter()
                .all(|progress| progress.state != crate::model::EvidenceProgressState::Collecting)
        );
        let final_value = serde_json::to_value(&final_summary).unwrap();
        assert!(
            final_value["progress"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|progress| { progress["limitations"].as_array().into_iter().flatten() })
                .any(|limitation| {
                    limitation["code"] == "bounded_acquisition_ended_before_availability"
                })
        );

        let mut unbounded = LiveObservationStream::start(ProbePolicy::Passive, None);
        assert!(
            unbounded
                .final_summary(crate::model::MonitorMode::Overview, &app)
                .is_none()
        );
    }

    #[test]
    fn live_stream_suppresses_nonmaterial_updates_until_checkpoint_or_transition() {
        let mut app = crate::model::App::new();
        let mut stream = LiveObservationStream::start(ProbePolicy::Passive, None);
        let subject = crate::model::MonitorMode::Overview;
        let first = stream
            .observe_at(
                LiveTrigger::Notice,
                subject,
                app.projection(subject),
                "2026-07-26T20:00:00.000Z".into(),
                Duration::ZERO,
            )
            .expect("first projection is a checkpoint");
        assert_eq!(first.line, LiveLineKind::Checkpoint);

        let counters = |received_bytes, transmitted_bytes| InterfaceCounters {
            interface: "en0".into(),
            received_bytes,
            transmitted_bytes,
            received_packets: received_bytes / 100,
            transmitted_packets: transmitted_bytes / 100,
            receive_errors: 0,
            transmit_errors: 0,
            drops: 0,
        };
        for (index, counters) in [
            counters(1_000, 2_000),
            counters(2_000, 4_000),
            counters(3_000, 6_000),
        ]
        .into_iter()
        .enumerate()
        {
            std::thread::sleep(Duration::from_millis(1));
            assert!(app.apply(crate::model::MonitorUpdate::Traffic {
                generation: 0,
                counters: Some(counters),
            }));
            let observed = stream.observe_at(
                LiveTrigger::Traffic,
                subject,
                app.projection(subject),
                format!("2026-07-26T20:00:0{}.000Z", index + 1),
                Duration::from_secs((index + 1) as u64),
            );
            if index < 2 {
                assert!(observed.is_some(), "progress state transition emits");
            } else {
                assert!(
                    observed.is_none(),
                    "rate-only high-frequency update is suppressed"
                );
            }
        }

        let periodic = stream
            .observe_at(
                LiveTrigger::Traffic,
                subject,
                app.projection(subject),
                "2026-07-26T20:00:07.000Z".into(),
                Duration::from_secs(7),
            )
            .expect("five-second checkpoint interval emits current full state");
        assert_eq!(periodic.line, LiveLineKind::Checkpoint);

        assert!(app.apply(crate::model::MonitorUpdate::Link {
            generation: 1,
            snapshot: test_link(),
        }));
        let transition = stream
            .observe_at(
                LiveTrigger::Link,
                subject,
                app.projection(subject),
                "2026-07-26T20:00:08.000Z".into(),
                Duration::from_secs(8),
            )
            .expect("generation change is material");
        assert_eq!(transition.line, LiveLineKind::Transition);
        assert_eq!(transition.sequence, 5);
    }

    #[test]
    fn transition_record_joins_the_completed_window_to_the_path_change() {
        let mut app = crate::model::App::new();
        let mut previous = test_link();
        previous.ssid = Some("field-kit".into());
        assert!(app.apply(crate::model::MonitorUpdate::Link {
            generation: 1,
            snapshot: previous,
        }));
        let subject = crate::model::MonitorMode::Overview;
        let mut stream = LiveObservationStream::start(ProbePolicy::Passive, None);
        assert!(
            stream
                .observe_at(
                    LiveTrigger::Link,
                    subject,
                    app.projection(subject),
                    "2026-07-26T20:00:00.000Z".into(),
                    Duration::ZERO,
                )
                .is_some()
        );

        assert!(app.apply(crate::model::MonitorUpdate::Link {
            generation: 2,
            snapshot: test_link(),
        }));
        let transition = stream
            .observe_at(
                LiveTrigger::Link,
                subject,
                app.projection(subject),
                "2026-07-26T20:00:01.000Z".into(),
                Duration::from_secs(1),
            )
            .expect("path generation change emits");
        assert_eq!(transition.line, LiveLineKind::Transition);
        let completed = transition
            .evidence
            .completed_path_window
            .as_ref()
            .expect("transition carries its completed window");
        let change = transition
            .evidence
            .last_path_change
            .as_ref()
            .expect("transition carries path-change evidence");
        assert_eq!(completed.generation, 1);
        assert_eq!(
            completed.completed_by.next_generation,
            transition.generation
        );
        assert_eq!(completed.completed_by.observed_at_ms, change.observed_at_ms);
        assert_eq!(completed.completed_by.changed_dimensions, change.dimensions);
        assert_eq!(completed.completed_by.previous, change.previous);
        assert_eq!(completed.completed_by.current, change.current);
    }

    #[test]
    fn same_health_probe_measurement_change_emits_immediately() {
        let mut app = crate::model::App::with_probe_policy(ProbePolicy::Active);
        let mut stream = LiveObservationStream::start(ProbePolicy::Active, None);
        let subject = crate::model::MonitorMode::Overview;
        assert!(
            stream
                .observe_at(
                    LiveTrigger::Notice,
                    subject,
                    app.projection(subject),
                    "2026-07-26T20:00:00.000Z".into(),
                    Duration::ZERO,
                )
                .is_some()
        );

        for (index, latency_ms) in [10.0, 12.0].into_iter().enumerate() {
            assert!(app.apply(crate::model::MonitorUpdate::ProbeFinished {
                generation: 0,
                kind: ProbeKind::Dns,
                result: crate::model::ProbeResult {
                    health: Health::Ok,
                    detail: "resolved".into(),
                    latency_ms: Some(latency_ms),
                    metrics: None,
                },
            }));
            assert!(
                stream
                    .observe_at(
                        LiveTrigger::ProbeFinished,
                        subject,
                        app.projection(subject),
                        format!("2026-07-26T20:00:0{}.000Z", index + 1),
                        Duration::from_secs((index + 1) as u64),
                    )
                    .is_some(),
                "same-health probe measurement {index} must be material"
            );
        }
    }

    #[test]
    fn live_v1_bounded_final_matches_an_exact_readable_golden() {
        let mut app = crate::model::App::new();
        let current = test_link();
        let mut previous = current.clone();
        previous.ssid = Some("field-kit".into());
        previous
            .network_configuration
            .as_mut()
            .unwrap()
            .connection_id = Some("field-kit-wifi".into());
        assert!(app.apply(crate::model::MonitorUpdate::Link {
            generation: 1,
            snapshot: previous.clone(),
        }));
        assert!(app.apply(crate::model::MonitorUpdate::Traffic {
            generation: 1,
            counters: Some(test_counters()),
        }));
        assert!(app.apply(crate::model::MonitorUpdate::Wifi {
            generation: 1,
            ssid: None,
            telemetry: previous.wifi.clone(),
        }));
        assert!(app.apply(crate::model::MonitorUpdate::Workload {
            generation: 1,
            snapshot: WorkloadSnapshot {
                health: Health::Ok,
                detail: "sampled process window".into(),
                source: Some("nettop".into()),
                interval: Duration::from_secs(1),
                processes: vec![ProcessTraffic {
                    process: "browser".into(),
                    processes: 2,
                    received_bytes_per_second: 8_192,
                    transmitted_bytes_per_second: 4_096,
                }],
            },
        }));
        assert!(app.apply(crate::model::MonitorUpdate::Peers {
            generation: 1,
            snapshot: test_peers(),
        }));
        assert!(app.apply(crate::model::MonitorUpdate::Link {
            generation: 2,
            snapshot: current,
        }));
        let mut projection = app.final_projection(crate::model::MonitorMode::Overview);
        for progress in &mut projection.progress {
            if progress.observed_span_ms.is_some() {
                progress.observed_span_ms = Some(0);
            }
            if progress.source_age_ms.is_some() {
                progress.source_age_ms = Some(0);
            }
        }
        projection.evidence.dwell.observed_span_ms = 0;
        projection
            .evidence
            .last_path_change
            .as_mut()
            .expect("transition has path-change evidence")
            .observed_at_ms = 0;
        let completed = projection
            .evidence
            .completed_path_window
            .as_mut()
            .expect("transition retains the completed generation");
        completed.observed_span_ms = 0;
        completed.completed_by.observed_at_ms = 0;

        let mut stream =
            LiveObservationStream::start(ProbePolicy::Passive, Some(Duration::from_secs(1)));
        stream.started_at = "2026-07-26T20:00:00Z".into();
        stream.sequence = 1;
        let document = stream.document_at(
            LiveLineKind::FinalSummary,
            None,
            crate::model::MonitorMode::Overview,
            projection,
            "2026-07-26T20:00:01.000Z".into(),
            Duration::from_secs(1),
        );
        assert_golden(
            &document,
            include_str!("output/fixtures/v1/live-final.json"),
        );
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
            "2026-07-26T19:59:59Z".into(),
            125,
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
            "2026-07-26T19:59:45Z".into(),
            15_000,
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
            "2026-07-26T19:59:59Z".into(),
            50,
            "2026-07-26T20:00:00Z".into(),
        );
        assert_golden(&link_document, include_str!("output/fixtures/v1/link.json"));

        let peer_document = ObservationDocument::at(
            ObservationSubject::Peers,
            passive_summary(EvidenceCoverage::Complete),
            PeerEvidence::new(&link, &peers),
            "2026-07-26T19:59:59Z".into(),
            75,
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
        let speed_document = SpeedExperimentDocument::at(
            &speed_report,
            "2026-07-26T20:00:00Z".into(),
            10_250,
            "2026-07-26T20:00:10Z".into(),
        );
        assert_golden(
            &speed_document,
            include_str!("output/fixtures/v1/speed.json"),
        );
    }
}
