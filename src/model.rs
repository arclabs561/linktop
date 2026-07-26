use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::metrics::LatencyMetrics;

pub const MAX_GATEWAY_SAMPLES: usize = 90;
pub const GATEWAY_ASSESSMENT_WINDOW: usize = 20;
pub const MIN_GATEWAY_ASSESSMENT_SAMPLES: usize = 5;
pub const MAX_EVENTS: usize = 64;
pub const MAX_COMPLETED_PATH_DWELLS: usize = 8;
pub const MAX_PATH_PROBE_EVIDENCE_AGE: Duration = Duration::from_secs(75);
pub const MAX_PUBLIC_EGRESS_EVIDENCE_AGE: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Health {
    Queued,
    Running,
    Ok,
    Degraded,
    Failed,
    Unavailable,
}

impl Health {
    pub fn label(self) -> &'static str {
        match self {
            Self::Queued => "QUEUED",
            Self::Running => "RUNNING",
            Self::Ok => "OK",
            Self::Degraded => "DEGRADED",
            Self::Failed => "FAILED",
            Self::Unavailable => "N/A",
        }
    }

    pub fn is_problem(self) -> bool {
        matches!(self, Self::Degraded | Self::Failed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCoverage {
    Collecting,
    Complete,
    Partial,
    Unavailable,
}

impl EvidenceCoverage {
    pub fn label(self) -> &'static str {
        match self {
            Self::Collecting => "COLLECTING",
            Self::Complete => "COMPLETE",
            Self::Partial => "PARTIAL",
            Self::Unavailable => "NONE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind {
    Gateway,
    Dns,
    Https,
    PublicIp,
}

impl ProbeKind {
    pub const ALL: [Self; 4] = [Self::Gateway, Self::Dns, Self::Https, Self::PublicIp];
    pub const PATH: [Self; 3] = [Self::Gateway, Self::Dns, Self::Https];

    pub fn label(self) -> &'static str {
        match self {
            Self::Gateway => "next-hop RTT",
            Self::Dns => "DNS lookup",
            Self::Https => "HTTPS target",
            Self::PublicIp => "public egress",
        }
    }

    pub const fn degraded_after_ms(self) -> Option<f64> {
        match self {
            Self::Gateway => None,
            Self::Dns => Some(500.0),
            Self::Https => Some(1_000.0),
            Self::PublicIp => None,
        }
    }

    pub const fn affects_path_health(self) -> bool {
        matches!(self, Self::Gateway | Self::Dns | Self::Https)
    }
}

impl fmt::Display for ProbeKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Address {
    pub interface: String,
    pub address: String,
    pub family: u8,
    pub is_default: bool,
    pub is_temporary: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinkSnapshot {
    pub host: String,
    pub interface: Option<String>,
    pub link_type: Option<String>,
    pub ssid: Option<String>,
    pub ssid_restricted: bool,
    pub wifi: Option<WifiTelemetry>,
    pub gateway: Option<String>,
    pub public_ip: Option<String>,
    pub resolvers: Vec<String>,
    pub addresses: Vec<Address>,
    pub network_configuration: Option<Box<NetworkConfiguration>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InterfaceCounters {
    pub interface: String,
    pub received_bytes: u64,
    pub transmitted_bytes: u64,
    pub received_packets: u64,
    pub transmitted_packets: u64,
    pub receive_errors: u64,
    pub transmit_errors: u64,
    pub drops: u64,
}

#[derive(Debug, Clone)]
pub struct InterfaceRate {
    pub received_bits_per_second: f64,
    pub transmitted_bits_per_second: f64,
    pub received_packets_per_second: f64,
    pub transmitted_packets_per_second: f64,
    pub error_delta: u64,
    pub drop_delta: u64,
}

#[derive(Debug, Clone, Default)]
pub struct InterfaceDwell {
    pub samples: u64,
    pub valid_intervals: u64,
    pub received_bytes_delta: u64,
    pub transmitted_bytes_delta: u64,
    pub received_packets_delta: u64,
    pub transmitted_packets_delta: u64,
    pub current_rate: Option<InterfaceRate>,
    pub peak_received_bits_per_second: Option<f64>,
    pub peak_transmitted_bits_per_second: Option<f64>,
    pub error_delta: u64,
    pub drop_delta: u64,
    pub counter_resets: u64,
}

#[derive(Debug, Clone, Default)]
pub struct WifiDwell {
    pub samples: u64,
    pub latest_signal_dbm: Option<f64>,
    pub worst_signal_dbm: Option<f64>,
    pub latest_signal_percent: Option<f64>,
    pub worst_signal_percent: Option<f64>,
    pub latest_channel: Option<u32>,
    pub channel_changes: u64,
}

#[derive(Debug, Clone, Default)]
pub struct WorkloadDwell {
    pub sampled_windows: u64,
    pub observed: Duration,
    pub latest_window_top: Option<ProcessTraffic>,
    pub peak_window_top: Option<ProcessTraffic>,
}

#[derive(Debug, Clone, Default)]
pub struct PathDwell {
    pub interface: InterfaceDwell,
    pub wifi: WifiDwell,
    pub workload: WorkloadDwell,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DwellPathIdentity {
    pub host: String,
    pub interface: Option<String>,
    pub link_type: Option<String>,
    pub ssid: Option<String>,
    pub ssid_restricted: bool,
    pub connection_id: Option<String>,
    pub gateway: Option<String>,
    pub resolvers: Vec<String>,
    pub address_boundaries: Vec<(String, String)>,
}

impl DwellPathIdentity {
    pub fn from_link(link: &LinkSnapshot) -> Self {
        let fingerprint = link.path_fingerprint();
        Self {
            host: link.host.clone(),
            interface: fingerprint.interface,
            link_type: fingerprint.link_type,
            ssid: fingerprint.ssid,
            ssid_restricted: fingerprint.ssid_restricted,
            connection_id: fingerprint.connection_id,
            gateway: fingerprint.gateway,
            resolvers: fingerprint.resolvers,
            address_boundaries: fingerprint.addresses,
        }
    }

    pub fn operator_label(&self) -> String {
        let interface = self.interface.as_deref().unwrap_or("no default interface");
        let link_type = self.link_type.as_deref().unwrap_or("unknown link");
        let network = self
            .ssid
            .as_deref()
            .map(str::to_owned)
            .or_else(|| {
                self.ssid_restricted
                    .then(|| "SSID hidden by platform".into())
            })
            .unwrap_or_else(|| "network identity unavailable".into());
        let gateway = self.gateway.as_deref().unwrap_or("no gateway");
        format!(
            "{} → {interface} [{link_type} / {network}] → {gateway}",
            self.host
        )
    }
}

#[derive(Debug, Clone)]
pub struct CompletedPathDwell {
    pub generation: u64,
    pub identity: DwellPathIdentity,
    pub observed: Duration,
    pub dwell: PathDwell,
    pub peers: PeerDwellSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetworkConfiguration {
    pub connection_id: Option<String>,
    pub associated_bssid: Option<String>,
    pub bssid_restricted: bool,
    pub method: Option<String>,
    pub state: Option<String>,
    pub server: Option<String>,
    pub subnet_mask: Option<String>,
    pub lease_seconds: Option<u64>,
    pub lease_started_at: Option<String>,
    pub lease_expires_at: Option<String>,
    pub router_arp_verified: Option<bool>,
    pub security: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessTraffic {
    pub process: String,
    pub processes: usize,
    pub received_bytes_per_second: u64,
    pub transmitted_bytes_per_second: u64,
}

#[derive(Debug, Clone)]
pub struct WorkloadSnapshot {
    pub health: Health,
    pub detail: String,
    pub source: Option<String>,
    pub interval: Duration,
    pub processes: Vec<ProcessTraffic>,
}

impl WorkloadSnapshot {
    pub fn pending() -> Self {
        Self {
            health: Health::Queued,
            detail: "waiting for per-process traffic accounting".into(),
            source: None,
            interval: Duration::from_secs(1),
            processes: Vec::new(),
        }
    }
}

impl PathDwell {
    fn observe_interface(
        &mut self,
        counters: Option<&InterfaceCounters>,
        interval: Option<&InterfaceInterval>,
        counter_reset: bool,
    ) {
        let interface = &mut self.interface;
        interface.current_rate = interval.map(|interval| interval.rate.clone());
        if counters.is_none() {
            return;
        }
        interface.samples = interface.samples.saturating_add(1);
        if counter_reset {
            interface.counter_resets = interface.counter_resets.saturating_add(1);
        }
        let Some(interval) = interval else {
            return;
        };
        interface.valid_intervals = interface.valid_intervals.saturating_add(1);
        interface.received_bytes_delta = interface
            .received_bytes_delta
            .saturating_add(interval.received_bytes);
        interface.transmitted_bytes_delta = interface
            .transmitted_bytes_delta
            .saturating_add(interval.transmitted_bytes);
        interface.received_packets_delta = interface
            .received_packets_delta
            .saturating_add(interval.received_packets);
        interface.transmitted_packets_delta = interface
            .transmitted_packets_delta
            .saturating_add(interval.transmitted_packets);
        interface.error_delta = interface
            .error_delta
            .saturating_add(interval.rate.error_delta);
        interface.drop_delta = interface
            .drop_delta
            .saturating_add(interval.rate.drop_delta);
        interface.peak_received_bits_per_second = Some(
            interface
                .peak_received_bits_per_second
                .unwrap_or_default()
                .max(interval.rate.received_bits_per_second),
        );
        interface.peak_transmitted_bits_per_second = Some(
            interface
                .peak_transmitted_bits_per_second
                .unwrap_or_default()
                .max(interval.rate.transmitted_bits_per_second),
        );
    }

    fn observe_wifi(&mut self, telemetry: &WifiTelemetry) {
        let wifi = &mut self.wifi;
        wifi.samples = wifi.samples.saturating_add(1);
        if let Some(signal) = telemetry.signal_dbm {
            wifi.latest_signal_dbm = Some(signal);
            wifi.worst_signal_dbm =
                Some(wifi.worst_signal_dbm.map_or(signal, |old| old.min(signal)));
        }
        if let Some(signal) = telemetry.signal_percent {
            wifi.latest_signal_percent = Some(signal);
            wifi.worst_signal_percent = Some(
                wifi.worst_signal_percent
                    .map_or(signal, |old| old.min(signal)),
            );
        }
        if let Some(channel) = telemetry.channel {
            if wifi
                .latest_channel
                .is_some_and(|previous| previous != channel)
            {
                wifi.channel_changes = wifi.channel_changes.saturating_add(1);
            }
            wifi.latest_channel = Some(channel);
        }
    }

    fn observe_workload(&mut self, snapshot: &WorkloadSnapshot) {
        if snapshot.health != Health::Ok {
            return;
        }
        let workload = &mut self.workload;
        workload.sampled_windows = workload.sampled_windows.saturating_add(1);
        workload.observed = workload.observed.saturating_add(snapshot.interval);
        workload.latest_window_top = snapshot.processes.first().cloned();
        if let Some(top) = snapshot.processes.first()
            && workload
                .peak_window_top
                .as_ref()
                .is_none_or(|peak| process_rate(top) > process_rate(peak))
        {
            workload.peak_window_top = Some(top.clone());
        }
    }
}

fn process_rate(process: &ProcessTraffic) -> u64 {
    process
        .received_bytes_per_second
        .saturating_add(process.transmitted_bytes_per_second)
}

#[derive(Debug, Clone)]
pub struct PathChange {
    pub elapsed: Duration,
    pub dimensions: Vec<&'static str>,
    pub previous: String,
    pub current: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryContext {
    pub kind: HistoryContextKind,
    pub summary: String,
    pub compact_summary: String,
    pub context_anchor: String,
    pub place_authority: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryContextKind {
    Configured,
    Loaded,
    FirstObservation,
    Recurring,
    Compatible,
    Changed,
    Returned,
    Unavailable,
    AppendFailed,
}

impl HistoryContextKind {
    pub fn is_limited(self) -> bool {
        matches!(self, Self::Unavailable | Self::AppendFailed)
    }
}

impl LinkSnapshot {
    pub fn empty() -> Self {
        Self {
            host: "discovering".into(),
            interface: None,
            link_type: None,
            ssid: None,
            ssid_restricted: false,
            wifi: None,
            gateway: None,
            public_ip: None,
            resolvers: Vec::new(),
            addresses: Vec::new(),
            network_configuration: None,
        }
    }

    fn requires_radio_evidence(&self) -> bool {
        self.link_type
            .as_deref()
            .is_some_and(|kind| kind.eq_ignore_ascii_case("wifi"))
    }

    pub(crate) fn path_fingerprint(&self) -> PathFingerprint {
        let mut resolvers = self.resolvers.clone();
        resolvers.sort();
        resolvers.dedup();
        let mut addresses: Vec<_> = self
            .addresses
            .iter()
            .filter(|address| address.is_default)
            .filter_map(|address| {
                path_address_identity(&address.address)
                    .map(|identity| (address.interface.clone(), identity))
            })
            .collect();
        addresses.sort();
        addresses.dedup();
        PathFingerprint {
            interface: self.interface.clone(),
            link_type: self.link_type.clone(),
            ssid: self.ssid.clone(),
            ssid_restricted: self.ssid_restricted,
            connection_id: self
                .network_configuration
                .as_ref()
                .and_then(|configuration| configuration.connection_id.clone()),
            gateway: self.gateway.clone(),
            resolvers,
            addresses,
        }
    }

    fn path_label(&self) -> String {
        let interface = self.interface.as_deref().unwrap_or("no default interface");
        let ssid = self
            .ssid
            .as_deref()
            .map(|value| format!(" / {value}"))
            .or_else(|| {
                self.ssid_restricted
                    .then(|| " / SSID hidden by macOS".into())
            })
            .unwrap_or_default();
        let gateway = self.gateway.as_deref().unwrap_or("no gateway");
        format!("{interface}{ssid} via {gateway}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PathFingerprint {
    interface: Option<String>,
    link_type: Option<String>,
    ssid: Option<String>,
    ssid_restricted: bool,
    connection_id: Option<String>,
    gateway: Option<String>,
    resolvers: Vec<String>,
    addresses: Vec<(String, String)>,
}

impl PathFingerprint {
    fn changed_dimensions(&self, current: &Self) -> Vec<&'static str> {
        let mut changed = Vec::new();
        if self.interface != current.interface {
            changed.push("interface");
        }
        if self.link_type != current.link_type {
            changed.push("link type");
        }
        if self.ssid != current.ssid || self.ssid_restricted != current.ssid_restricted {
            changed.push("SSID");
        }
        if self.connection_id != current.connection_id {
            changed.push("Wi-Fi association");
        }
        if self.gateway != current.gateway {
            changed.push("gateway");
        }
        if self.resolvers != current.resolvers {
            changed.push("resolvers");
        }
        if self.addresses != current.addresses {
            changed.push("address prefix");
        }
        changed
    }
}

fn path_address_identity(value: &str) -> Option<String> {
    match value.parse::<IpAddr>().ok()? {
        IpAddr::V4(address) => Some(address.to_string()),
        IpAddr::V6(address) if address.is_unicast_link_local() => None,
        IpAddr::V6(address) => {
            let segments = address.segments();
            Some(format!(
                "{:x}:{:x}:{:x}:{:x}::/64",
                segments[0], segments[1], segments[2], segments[3]
            ))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WifiTelemetry {
    pub signal_dbm: Option<f64>,
    pub noise_dbm: Option<f64>,
    pub signal_percent: Option<f64>,
    pub channel: Option<u32>,
    pub channel_width_mhz: Option<u32>,
    pub frequency_mhz: Option<u32>,
    pub band: Option<String>,
    pub phy: Option<String>,
    pub tx_rate_mbps: Option<f64>,
    pub rx_rate_mbps: Option<f64>,
    pub mcs: Option<u32>,
}

impl WifiTelemetry {
    pub fn is_empty(&self) -> bool {
        self.signal_dbm.is_none()
            && self.noise_dbm.is_none()
            && self.signal_percent.is_none()
            && self.channel.is_none()
            && self.channel_width_mhz.is_none()
            && self.frequency_mhz.is_none()
            && self.band.is_none()
            && self.phy.is_none()
            && self.tx_rate_mbps.is_none()
            && self.rx_rate_mbps.is_none()
            && self.mcs.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Peer {
    pub address: String,
    pub mac: Option<String>,
    pub interface: Option<String>,
    pub state: Option<String>,
    pub binding_conflict: bool,
    pub mac_scope: Option<MacScope>,
    pub registrant: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PeerDwell {
    pub first_observed: Duration,
    pub last_observed: Duration,
    pub observations: u64,
    pub previous_state: Option<String>,
    pub state_changes: u64,
    pub binding_changes: u64,
    pub cache_disappearances: u64,
    pub cache_returns: u64,
    pub currently_cached: bool,
    pub latest: Peer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerDwellSummary {
    pub current: usize,
    pub observed: usize,
    pub changed: usize,
    pub disappeared: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PeerKey {
    interface: Option<String>,
    address: String,
}

impl PeerKey {
    fn from_peer(peer: &Peer) -> Self {
        Self {
            interface: peer.interface.clone(),
            address: peer.address.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MacScope {
    Universal,
    Local,
}

impl MacScope {
    pub fn label(self) -> &'static str {
        match self {
            Self::Universal => "universal",
            Self::Local => "local/private",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PeerSnapshot {
    pub health: Health,
    pub detail: String,
    pub sources: Vec<String>,
    pub failed_sources: Vec<String>,
    pub oui_source: Option<String>,
    pub peers: Vec<Peer>,
}

impl PeerSnapshot {
    pub fn pending() -> Self {
        Self {
            health: Health::Queued,
            detail: "waiting for neighbor cache".into(),
            sources: Vec::new(),
            failed_sources: Vec::new(),
            oui_source: None,
            peers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeResult {
    pub health: Health,
    pub detail: String,
    pub latency_ms: Option<f64>,
    pub metrics: Option<LatencyMetrics>,
}

impl ProbeResult {
    pub fn unavailable(detail: impl Into<String>) -> Self {
        Self {
            health: Health::Unavailable,
            detail: detail.into(),
            latency_ms: None,
            metrics: None,
        }
    }

    pub fn failed(detail: impl Into<String>) -> Self {
        Self {
            health: Health::Failed,
            detail: detail.into(),
            latency_ms: None,
            metrics: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProbeView {
    pub kind: ProbeKind,
    pub health: Health,
    pub detail: String,
    pub latency_ms: Option<f64>,
    pub metrics: Option<LatencyMetrics>,
    pub updated_at: Option<Instant>,
}

impl ProbeView {
    fn queued(kind: ProbeKind) -> Self {
        Self {
            kind,
            health: Health::Queued,
            detail: "waiting for first sample".into(),
            latency_ms: None,
            metrics: None,
            updated_at: None,
        }
    }

    fn disabled(kind: ProbeKind) -> Self {
        Self {
            kind,
            health: Health::Unavailable,
            detail: "active check disabled".into(),
            latency_ms: None,
            metrics: None,
            updated_at: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Event {
    pub elapsed: Duration,
    pub message: String,
    pub health: Health,
    pub kind: EventKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Session,
    Path,
    Probe,
    Policy,
    Peer,
    Notice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SituationKind {
    Paused,
    PathTransition,
    GatewayFailure,
    InterfaceLoss,
    PassiveObservation,
    UnlocalizedFailure,
    DnsFailure,
    HttpsFailure,
    GatewayLoss,
    GatewayVariation,
    SlowDns,
    SlowHttps,
    StalePathEvidence,
    Collecting,
    WarmingBaseline,
    EvidenceGap,
    Ready,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Situation {
    pub health: Health,
    pub kind: SituationKind,
}

#[derive(Debug, Clone)]
pub enum MonitorUpdate {
    Link {
        generation: u64,
        snapshot: LinkSnapshot,
    },
    PathSettling {
        generation: u64,
    },
    Wifi {
        generation: u64,
        ssid: Option<String>,
        telemetry: Option<WifiTelemetry>,
    },
    Peers {
        generation: u64,
        snapshot: PeerSnapshot,
    },
    Traffic {
        generation: u64,
        counters: Option<InterfaceCounters>,
    },
    Workload {
        generation: u64,
        snapshot: WorkloadSnapshot,
    },
    ProbeStarted {
        generation: u64,
        kind: ProbeKind,
    },
    ProbeFinished {
        generation: u64,
        kind: ProbeKind,
        result: ProbeResult,
    },
    Notice(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorMode {
    Overview,
    Link,
    Peers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DwellCollectorScope {
    pub label: &'static str,
    pub interface: bool,
    pub wifi: bool,
    pub workload: bool,
    pub peers: bool,
}

impl MonitorMode {
    pub const fn dwell_collector_scope(self) -> DwellCollectorScope {
        match self {
            Self::Overview => DwellCollectorScope {
                label: "overview",
                interface: true,
                wifi: true,
                workload: true,
                peers: true,
            },
            Self::Link => DwellCollectorScope {
                label: "link",
                interface: true,
                wifi: true,
                workload: false,
                peers: false,
            },
            Self::Peers => DwellCollectorScope {
                label: "peers",
                interface: false,
                wifi: false,
                workload: false,
                peers: true,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbePolicy {
    Passive,
    Active,
}

impl ProbePolicy {
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum MonitorControl {
    Refresh,
    SetProbePolicy(ProbePolicy),
    Pause(bool),
    Stop,
}

#[derive(Debug)]
pub struct App {
    pub started_at: Instant,
    pub link: LinkSnapshot,
    pub probes: Vec<ProbeView>,
    pub gateway_samples: VecDeque<u64>,
    gateway_outcomes: VecDeque<Option<u64>>,
    pub gateway_attempts: usize,
    pub gateway_metrics: Option<LatencyMetrics>,
    pub peers: PeerSnapshot,
    pub interface_counters: Option<InterfaceCounters>,
    pub interface_rate: Option<InterfaceRate>,
    interface_counters_at: Option<Instant>,
    pub workload: WorkloadSnapshot,
    pub events: VecDeque<Event>,
    pub paused: bool,
    pub cycles: u64,
    pub path_generation: u64,
    pub path_observed_since: Duration,
    pub path_dwell: PathDwell,
    pub completed_path_dwells: VecDeque<CompletedPathDwell>,
    pub last_path_change: Option<PathChange>,
    pub history_context: Option<HistoryContext>,
    pub wifi_observation_settled: bool,
    pub path_transition_pending: bool,
    probe_policy: ProbePolicy,
    peer_dwell: BTreeMap<PeerKey, PeerDwell>,
    peer_baseline_seen: bool,
}

impl App {
    #[cfg(test)]
    pub fn new() -> Self {
        Self::with_probe_policy(ProbePolicy::Passive)
    }

    pub fn with_probe_policy(probe_policy: ProbePolicy) -> Self {
        let started_at = Instant::now();
        let mut app = Self {
            started_at,
            link: LinkSnapshot::empty(),
            probes: ProbeKind::ALL
                .into_iter()
                .map(|kind| {
                    if probe_policy.is_active() {
                        ProbeView::queued(kind)
                    } else {
                        ProbeView::disabled(kind)
                    }
                })
                .collect(),
            gateway_samples: VecDeque::with_capacity(MAX_GATEWAY_SAMPLES),
            gateway_outcomes: VecDeque::with_capacity(MAX_GATEWAY_SAMPLES),
            gateway_attempts: 0,
            gateway_metrics: None,
            peers: PeerSnapshot::pending(),
            interface_counters: None,
            interface_rate: None,
            interface_counters_at: None,
            workload: WorkloadSnapshot::pending(),
            events: VecDeque::with_capacity(MAX_EVENTS),
            paused: false,
            cycles: 0,
            path_generation: 0,
            path_observed_since: Duration::ZERO,
            path_dwell: PathDwell::default(),
            completed_path_dwells: VecDeque::with_capacity(MAX_COMPLETED_PATH_DWELLS),
            last_path_change: None,
            history_context: None,
            wifi_observation_settled: false,
            path_transition_pending: false,
            probe_policy,
            peer_dwell: BTreeMap::new(),
            peer_baseline_seen: false,
        };
        app.push_event(EventKind::Session, Health::Running, "instrument started");
        app
    }

    pub fn apply(&mut self, update: MonitorUpdate) {
        match update {
            MonitorUpdate::Link {
                generation,
                snapshot: mut link,
            } => {
                if generation < self.path_generation {
                    return;
                }
                if generation == self.path_generation {
                    if link.ssid_restricted
                        && self.link.ssid.is_some()
                        && !self.link.ssid_restricted
                    {
                        link.ssid.clone_from(&self.link.ssid);
                        link.ssid_restricted = false;
                    }
                    link.public_ip = self.link.public_ip.clone();
                    link.wifi = self.link.wifi.clone();
                    self.link = link;
                    self.path_transition_pending = false;
                    return;
                }

                let initial = self.path_generation == 0;
                let previous_fingerprint = self.link.path_fingerprint();
                let current_fingerprint = link.path_fingerprint();
                let previous = self.link.path_label();
                let observed_at = self.uptime();
                if !initial {
                    let peers = self.peer_dwell_summary();
                    let dwell = std::mem::take(&mut self.path_dwell);
                    if self.completed_path_dwells.len() == MAX_COMPLETED_PATH_DWELLS {
                        self.completed_path_dwells.pop_front();
                    }
                    self.completed_path_dwells.push_back(CompletedPathDwell {
                        generation: self.path_generation,
                        identity: DwellPathIdentity::from_link(&self.link),
                        observed: observed_at.saturating_sub(self.path_observed_since),
                        dwell,
                        peers,
                    });
                }
                self.path_generation = generation;
                self.path_transition_pending = false;
                self.link = link;
                self.gateway_samples.clear();
                self.gateway_outcomes.clear();
                self.gateway_attempts = 0;
                self.gateway_metrics = None;
                self.interface_counters = None;
                self.interface_counters_at = None;
                self.interface_rate = None;
                self.workload = WorkloadSnapshot::pending();
                self.path_dwell = PathDwell::default();
                self.peers = PeerSnapshot::pending();
                self.wifi_observation_settled = false;
                self.peer_dwell.clear();
                self.peer_baseline_seen = false;
                for probe in &mut self.probes {
                    *probe = if self.probe_policy.is_active() {
                        ProbeView::queued(probe.kind)
                    } else {
                        ProbeView::disabled(probe.kind)
                    };
                }
                let current = self.link.path_label();
                self.path_observed_since = observed_at;
                if !initial {
                    self.last_path_change = Some(PathChange {
                        elapsed: observed_at,
                        dimensions: previous_fingerprint.changed_dimensions(&current_fingerprint),
                        previous: previous.clone(),
                        current: current.clone(),
                    });
                }
                self.push_event(
                    EventKind::Path,
                    Health::Running,
                    if initial {
                        format!("path: {current}")
                    } else {
                        let dimensions = previous_fingerprint
                            .changed_dimensions(&current_fingerprint)
                            .join(", ");
                        format!("path changed ({dimensions}): {previous} → {current}")
                    },
                );
            }
            MonitorUpdate::PathSettling { generation } => {
                if generation == self.path_generation && !self.path_transition_pending {
                    self.path_transition_pending = true;
                    self.push_event(
                        EventKind::Path,
                        Health::Running,
                        "default route is settling; retaining the last confirmed path",
                    );
                }
            }
            MonitorUpdate::Wifi {
                generation,
                ssid,
                telemetry,
            } => {
                if generation == self.path_generation {
                    self.wifi_observation_settled = true;
                    if let Some(telemetry) = &telemetry {
                        self.path_dwell.observe_wifi(telemetry);
                    }
                    if let Some(ssid) = ssid
                        && (self.link.ssid.as_deref() != Some(ssid.as_str())
                            || self.link.ssid_restricted)
                    {
                        self.link.ssid = Some(ssid);
                        self.link.ssid_restricted = false;
                        let current = self.link.path_label();
                        if let Some(change) = self.last_path_change.as_mut()
                            && change.elapsed == self.path_observed_since
                        {
                            change.current = current.clone();
                        }
                        self.push_event(
                            EventKind::Path,
                            Health::Ok,
                            format!("Wi-Fi network identity resolved: {current}"),
                        );
                    }
                    self.link.wifi = telemetry;
                }
            }
            MonitorUpdate::Peers {
                generation,
                snapshot,
            } => {
                if generation != self.path_generation {
                    return;
                }
                self.apply_peer_snapshot(snapshot);
            }
            MonitorUpdate::Traffic {
                generation,
                counters,
            } => {
                if generation != self.path_generation {
                    return;
                }
                let now = Instant::now();
                let prior = self.interface_counters.as_ref();
                let interval = prior
                    .zip(self.interface_counters_at)
                    .zip(counters.as_ref())
                    .and_then(|((before, observed_at), after)| {
                        interface_interval(before, after, now.duration_since(observed_at))
                    });
                let counter_reset = prior
                    .zip(counters.as_ref())
                    .is_some_and(|(before, after)| counters_replaced_or_reset(before, after));
                self.path_dwell.observe_interface(
                    counters.as_ref(),
                    interval.as_ref(),
                    counter_reset,
                );
                self.interface_rate = interval.map(|interval| interval.rate);
                self.interface_counters = counters;
                self.interface_counters_at = self.interface_counters.as_ref().map(|_| now);
            }
            MonitorUpdate::Workload {
                generation,
                snapshot,
            } => {
                if generation == self.path_generation {
                    self.path_dwell.observe_workload(&snapshot);
                    self.workload = snapshot;
                }
            }
            MonitorUpdate::ProbeStarted { generation, kind } => {
                if generation != self.path_generation || !self.probe_policy.is_active() {
                    return;
                }
                let probe = self.probe_mut(kind);
                // Preserve the last settled result while a periodic refresh is
                // in flight. Only the initial sample needs an explicit running
                // state; otherwise a failed probe would briefly look healthy
                // on every retry and flood the event log with false recoveries.
                if probe.health == Health::Queued {
                    probe.health = Health::Running;
                    probe.detail = "probing…".into();
                }
            }
            MonitorUpdate::ProbeFinished {
                generation,
                kind,
                result,
            } => {
                if generation != self.path_generation || !self.probe_policy.is_active() {
                    return;
                }
                self.cycles += u64::from(kind == ProbeKind::Gateway);
                let previous = self.probe(kind).health;
                if kind == ProbeKind::Gateway {
                    if self.gateway_outcomes.len() == MAX_GATEWAY_SAMPLES {
                        self.gateway_outcomes.pop_front();
                    }
                    self.gateway_outcomes.push_back(
                        result
                            .latency_ms
                            .map(|latency| latency.round().max(1.0) as u64),
                    );
                    self.gateway_samples =
                        self.gateway_outcomes.iter().flatten().copied().collect();
                    self.gateway_attempts = self.gateway_outcomes.len();
                    let samples: Vec<_> = self
                        .gateway_outcomes
                        .iter()
                        .flatten()
                        .map(|sample| *sample as f64)
                        .collect();
                    self.gateway_metrics = Some(LatencyMetrics::from_samples(
                        &samples,
                        self.gateway_attempts,
                    ));
                }
                if kind == ProbeKind::PublicIp
                    && matches!(result.health, Health::Ok | Health::Degraded)
                {
                    self.link.public_ip = Some(result.detail.clone());
                }

                let health = result.health;
                let detail = result.detail.clone();
                let probe = self.probe_mut(kind);
                probe.health = health;
                probe.detail = detail.clone();
                probe.latency_ms = result.latency_ms;
                probe.metrics = result.metrics;
                probe.updated_at = Some(Instant::now());

                if previous != health && (previous != Health::Running || health.is_problem()) {
                    self.push_event(
                        EventKind::Probe,
                        health,
                        format!("{}: {}", kind.label(), detail),
                    );
                }
            }
            MonitorUpdate::Notice(message) => {
                self.push_event(EventKind::Notice, Health::Running, message)
            }
        }
    }

    pub fn set_paused(&mut self, paused: bool) {
        self.paused = paused;
        self.push_event(
            EventKind::Policy,
            Health::Running,
            if paused {
                "observation paused"
            } else {
                "observation resumed"
            },
        );
    }

    pub fn set_probe_policy(&mut self, probe_policy: ProbePolicy) {
        if self.probe_policy == probe_policy {
            return;
        }
        self.probe_policy = probe_policy;
        self.gateway_samples.clear();
        self.gateway_outcomes.clear();
        self.gateway_attempts = 0;
        self.gateway_metrics = None;
        self.link.public_ip = None;
        for probe in &mut self.probes {
            *probe = if probe_policy.is_active() {
                ProbeView::queued(probe.kind)
            } else {
                ProbeView::disabled(probe.kind)
            };
        }
        self.push_event(
            EventKind::Policy,
            Health::Running,
            if probe_policy.is_active() {
                "active path probes enabled by operator"
            } else {
                "active path probes disabled"
            },
        );
    }

    pub const fn probe_policy(&self) -> ProbePolicy {
        self.probe_policy
    }

    pub fn overall_health(&self) -> Health {
        self.situation().health
    }

    pub fn situation(&self) -> Situation {
        if self.paused {
            return Situation {
                health: Health::Unavailable,
                kind: SituationKind::Paused,
            };
        }
        if self.path_transition_pending {
            return Situation {
                health: Health::Running,
                kind: SituationKind::PathTransition,
            };
        }

        if self.probe_policy.is_active() && self.probe(ProbeKind::Gateway).health == Health::Failed
        {
            return Situation {
                health: Health::Failed,
                kind: SituationKind::GatewayFailure,
            };
        }

        if self
            .interface_rate
            .as_ref()
            .is_some_and(|rate| rate.error_delta > 0 || rate.drop_delta > 0)
        {
            return Situation {
                health: Health::Degraded,
                kind: SituationKind::InterfaceLoss,
            };
        }

        if !self.probe_policy.is_active() {
            return Situation {
                health: Health::Unavailable,
                kind: SituationKind::PassiveObservation,
            };
        }

        if matches!(
            self.probe(ProbeKind::Gateway).health,
            Health::Queued | Health::Running
        ) {
            return Situation {
                health: Health::Running,
                kind: SituationKind::Collecting,
            };
        }

        if [ProbeKind::Dns, ProbeKind::Https]
            .into_iter()
            .any(|kind| self.probe_is_stale(kind))
        {
            return Situation {
                health: Health::Unavailable,
                kind: SituationKind::StalePathEvidence,
            };
        }

        let gateway_unavailable = self.probe(ProbeKind::Gateway).health == Health::Unavailable;
        let downstream_failed = [ProbeKind::Dns, ProbeKind::Https]
            .into_iter()
            .any(|kind| self.probe(kind).health == Health::Failed);
        if gateway_unavailable && downstream_failed {
            return Situation {
                health: Health::Failed,
                kind: SituationKind::UnlocalizedFailure,
            };
        }

        if self.probe(ProbeKind::Dns).health == Health::Failed {
            return Situation {
                health: Health::Failed,
                kind: SituationKind::DnsFailure,
            };
        }
        if matches!(
            self.probe(ProbeKind::Dns).health,
            Health::Queued | Health::Running
        ) {
            return Situation {
                health: Health::Running,
                kind: SituationKind::Collecting,
            };
        }
        if self.probe(ProbeKind::Dns).health == Health::Unavailable
            && self.probe(ProbeKind::Https).health == Health::Failed
        {
            return Situation {
                health: Health::Failed,
                kind: SituationKind::UnlocalizedFailure,
            };
        }
        if self.probe(ProbeKind::Https).health == Health::Failed {
            return Situation {
                health: Health::Failed,
                kind: SituationKind::HttpsFailure,
            };
        }

        if let Some(metrics) = self
            .gateway_assessment_metrics()
            .filter(|metrics| metrics.health() == Health::Degraded)
        {
            return Situation {
                health: Health::Degraded,
                kind: if metrics.lost > 0 {
                    SituationKind::GatewayLoss
                } else {
                    SituationKind::GatewayVariation
                },
            };
        }

        if self.probe(ProbeKind::Dns).health == Health::Degraded {
            return Situation {
                health: Health::Degraded,
                kind: SituationKind::SlowDns,
            };
        }
        if self.probe(ProbeKind::Https).health == Health::Degraded {
            return Situation {
                health: Health::Degraded,
                kind: SituationKind::SlowHttps,
            };
        }
        if matches!(
            self.probe(ProbeKind::Https).health,
            Health::Queued | Health::Running
        ) {
            return Situation {
                health: Health::Running,
                kind: SituationKind::Collecting,
            };
        }

        let gateway = self.probe(ProbeKind::Gateway);
        if gateway.health == Health::Ok && self.gateway_attempts < MIN_GATEWAY_ASSESSMENT_SAMPLES {
            return Situation {
                health: Health::Running,
                kind: SituationKind::WarmingBaseline,
            };
        }

        if ProbeKind::PATH
            .iter()
            .all(|kind| self.probe(*kind).health == Health::Unavailable)
        {
            return Situation {
                health: Health::Unavailable,
                kind: SituationKind::EvidenceGap,
            };
        }

        if self.evidence_coverage() != EvidenceCoverage::Complete {
            Situation {
                health: Health::Ok,
                kind: SituationKind::EvidenceGap,
            }
        } else {
            Situation {
                health: Health::Ok,
                kind: SituationKind::Ready,
            }
        }
    }

    pub fn evidence_coverage(&self) -> EvidenceCoverage {
        if self.path_transition_pending {
            return EvidenceCoverage::Collecting;
        }
        let active_probe_pending = self.probe_policy.is_active()
            && self
                .probes
                .iter()
                .any(|probe| matches!(probe.health, Health::Queued | Health::Running));
        if active_probe_pending || self.peers.health == Health::Queued {
            return EvidenceCoverage::Collecting;
        }

        let link_available = self.link.interface.is_some()
            || self.link.gateway.is_some()
            || !self.link.resolvers.is_empty()
            || !self.link.addresses.is_empty();
        let link_incomplete = self.link.interface.is_none()
            || self.link.resolvers.is_empty()
            || self.link.addresses.is_empty()
            || self.interface_counters.is_none();
        let radio_missing = self.link.requires_radio_evidence() && self.link.wifi.is_none();
        let active_evidence_unavailable = !self.probe_policy.is_active()
            || self
                .probes
                .iter()
                .all(|probe| probe.health == Health::Unavailable);
        let all_evidence_unavailable = !link_available
            && active_evidence_unavailable
            && self.peers.health == Health::Unavailable
            && self.link.wifi.is_none();
        if all_evidence_unavailable {
            return EvidenceCoverage::Unavailable;
        }
        let active_evidence_incomplete = self.probe_policy.is_active()
            && self.probes.iter().any(|probe| {
                probe.health == Health::Unavailable || self.probe_is_stale(probe.kind)
            });
        if active_evidence_incomplete
            || matches!(
                self.peers.health,
                Health::Degraded | Health::Failed | Health::Unavailable
            )
            || !self.peers.failed_sources.is_empty()
            || link_incomplete
            || radio_missing
        {
            EvidenceCoverage::Partial
        } else {
            EvidenceCoverage::Complete
        }
    }

    pub fn gateway_assessment_metrics(&self) -> Option<LatencyMetrics> {
        if self.gateway_attempts < MIN_GATEWAY_ASSESSMENT_SAMPLES {
            return None;
        }
        let outcomes: Vec<_> = self
            .gateway_outcomes
            .iter()
            .rev()
            .take(GATEWAY_ASSESSMENT_WINDOW)
            .rev()
            .copied()
            .collect();
        let samples: Vec<_> = outcomes
            .iter()
            .flatten()
            .map(|sample| *sample as f64)
            .collect();
        Some(LatencyMetrics::from_samples(&samples, outcomes.len()))
    }

    pub fn probe_age(&self, kind: ProbeKind) -> Option<Duration> {
        self.probe(kind)
            .updated_at
            .map(|observed_at| Instant::now().saturating_duration_since(observed_at))
    }

    pub fn probe_view(&self, kind: ProbeKind) -> &ProbeView {
        self.probe(kind)
    }

    fn probe_is_stale(&self, kind: ProbeKind) -> bool {
        let max_age = match kind {
            ProbeKind::Gateway => return false,
            ProbeKind::Dns | ProbeKind::Https => MAX_PATH_PROBE_EVIDENCE_AGE,
            ProbeKind::PublicIp => MAX_PUBLIC_EGRESS_EVIDENCE_AGE,
        };
        self.probe_age(kind).is_some_and(|age| age > max_age)
    }

    pub fn uptime(&self) -> Duration {
        self.started_at.elapsed()
    }

    pub fn peer_dwell(&self, peer: &Peer) -> Option<&PeerDwell> {
        self.peer_dwell.get(&PeerKey::from_peer(peer))
    }

    pub fn peer_dwell_summary(&self) -> PeerDwellSummary {
        PeerDwellSummary {
            current: self.peers.peers.len(),
            observed: self.peer_dwell.len(),
            changed: self
                .peer_dwell
                .values()
                .filter(|peer| {
                    peer.state_changes > 0 || peer.binding_changes > 0 || peer.cache_returns > 0
                })
                .count(),
            disappeared: self
                .peer_dwell
                .values()
                .filter(|peer| !peer.currently_cached && peer.cache_disappearances > 0)
                .count(),
        }
    }

    fn apply_peer_snapshot(&mut self, snapshot: PeerSnapshot) {
        let observed_at = self.uptime();
        let previous_count = self.peers.peers.len();
        let current_count = snapshot.peers.len();
        let baseline_seen = self.peer_baseline_seen;
        let complete = snapshot.failed_sources.is_empty()
            && !matches!(snapshot.health, Health::Queued | Health::Unavailable);
        let observed_keys: BTreeSet<_> = snapshot.peers.iter().map(PeerKey::from_peer).collect();
        let mut events = Vec::new();

        for peer in &snapshot.peers {
            let key = PeerKey::from_peer(peer);
            if let Some(dwell) = self.peer_dwell.get_mut(&key) {
                let was_cached = dwell.currently_cached;
                if !dwell.latest.binding_conflict
                    && !peer.binding_conflict
                    && dwell.latest.mac != peer.mac
                {
                    dwell.binding_changes += 1;
                    events.push((
                        Health::Degraded,
                        format!(
                            "neighbor binding changed: {} {} → {}",
                            peer.address,
                            dwell.latest.mac.as_deref().unwrap_or("unknown MAC"),
                            peer.mac.as_deref().unwrap_or("unknown MAC")
                        ),
                    ));
                }
                if peer.binding_conflict && !dwell.latest.binding_conflict {
                    events.push((
                        Health::Running,
                        format!(
                            "neighbor sources disagree about the binding for {}",
                            peer.address
                        ),
                    ));
                }
                if dwell.latest.state != peer.state {
                    dwell.previous_state = dwell.latest.state.clone();
                    dwell.state_changes += 1;
                    events.push((
                        Health::Running,
                        format!(
                            "neighbor state: {} {} → {}",
                            peer.address,
                            dwell.latest.state.as_deref().unwrap_or("cached"),
                            peer.state.as_deref().unwrap_or("cached")
                        ),
                    ));
                }
                if !was_cached {
                    dwell.cache_returns += 1;
                    events.push((
                        Health::Ok,
                        format!("neighbor cache returned: {}", peer.address),
                    ));
                }
                dwell.last_observed = observed_at;
                dwell.observations += 1;
                dwell.currently_cached = true;
                dwell.latest = peer.clone();
            } else {
                self.peer_dwell.insert(
                    key,
                    PeerDwell {
                        first_observed: observed_at,
                        last_observed: observed_at,
                        observations: 1,
                        previous_state: None,
                        state_changes: 0,
                        binding_changes: 0,
                        cache_disappearances: 0,
                        cache_returns: 0,
                        currently_cached: true,
                        latest: peer.clone(),
                    },
                );
                if baseline_seen {
                    events.push((
                        Health::Ok,
                        format!("neighbor cache added: {}", peer.address),
                    ));
                }
            }
        }

        if complete {
            for (key, dwell) in &mut self.peer_dwell {
                if dwell.currently_cached && !observed_keys.contains(key) {
                    dwell.currently_cached = false;
                    dwell.cache_disappearances += 1;
                    if baseline_seen {
                        events.push((
                            Health::Running,
                            format!(
                                "neighbor cache absent: {} (not proof of departure)",
                                dwell.latest.address
                            ),
                        ));
                    }
                }
            }
        }

        self.peers = snapshot;
        self.peer_baseline_seen = true;
        if previous_count != current_count {
            self.push_event(
                EventKind::Peer,
                Health::Ok,
                format!("neighbor cache: {current_count} entries"),
            );
        }
        for (health, message) in events {
            self.push_event(EventKind::Peer, health, message);
        }
    }

    fn probe(&self, kind: ProbeKind) -> &ProbeView {
        self.probes
            .iter()
            .find(|probe| probe.kind == kind)
            .expect("all probe kinds are initialized")
    }

    fn probe_mut(&mut self, kind: ProbeKind) -> &mut ProbeView {
        self.probes
            .iter_mut()
            .find(|probe| probe.kind == kind)
            .expect("all probe kinds are initialized")
    }

    fn push_event(&mut self, kind: EventKind, health: Health, message: impl Into<String>) {
        if self.events.len() == MAX_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(Event {
            elapsed: self.started_at.elapsed(),
            message: message.into(),
            health,
            kind,
        });
    }
}

#[derive(Debug, Serialize)]
pub struct SnapshotReport {
    pub link: LinkSnapshot,
    pub interface_counters: Option<InterfaceCounters>,
    pub neighbors: PeerSnapshot,
    pub probes: Vec<SnapshotProbe>,
    pub summary: SnapshotSummary,
}

#[derive(Debug, Serialize)]
pub struct SnapshotProbe {
    pub kind: ProbeKind,
    pub health: Health,
    pub detail: String,
    pub latency_ms: Option<f64>,
    pub metrics: Option<LatencyMetrics>,
}

#[derive(Debug, Serialize)]
pub struct SnapshotSummary {
    pub probe_policy: ProbePolicy,
    pub path_status: PathStatus,
    pub evidence_coverage: EvidenceCoverage,
    pub completed_probes: usize,
    pub total_probes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathStatus {
    Untested,
    Ok,
    Degraded,
    Failed,
    Unavailable,
}

impl PathStatus {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Untested => "UNTESTED",
            Self::Ok => "OK",
            Self::Degraded => "DEGRADED",
            Self::Failed => "FAILED",
            Self::Unavailable => "N/A",
        }
    }

    pub const fn is_failed(self) -> bool {
        matches!(self, Self::Failed)
    }

    pub const fn is_unavailable(self) -> bool {
        matches!(self, Self::Unavailable)
    }
}

impl SnapshotReport {
    pub fn from_results(
        link: LinkSnapshot,
        interface_counters: Option<InterfaceCounters>,
        neighbors: PeerSnapshot,
        results: Vec<(ProbeKind, ProbeResult)>,
    ) -> Self {
        let probes: Vec<_> = results
            .into_iter()
            .map(|(kind, result)| SnapshotProbe {
                kind,
                health: result.health,
                detail: result.detail,
                latency_ms: result.latency_ms,
                metrics: result.metrics,
            })
            .collect();
        let path_probes = probes
            .iter()
            .filter(|probe| probe.kind.affects_path_health())
            .collect::<Vec<_>>();
        let path_status = if path_probes
            .iter()
            .any(|probe| probe.health == Health::Failed)
        {
            PathStatus::Failed
        } else if path_probes
            .iter()
            .any(|probe| probe.health == Health::Degraded)
        {
            PathStatus::Degraded
        } else if path_probes
            .iter()
            .all(|probe| probe.health == Health::Unavailable)
        {
            PathStatus::Unavailable
        } else {
            PathStatus::Ok
        };
        let radio_missing = link.requires_radio_evidence() && link.wifi.is_none();
        let local_evidence_incomplete =
            link_evidence_incomplete(&link, interface_counters.as_ref());
        let evidence_unavailable = probes
            .iter()
            .all(|probe| probe.health == Health::Unavailable)
            && neighbors.health == Health::Unavailable
            && (!link.requires_radio_evidence() || radio_missing);
        let evidence_coverage = if evidence_unavailable {
            EvidenceCoverage::Unavailable
        } else if probes
            .iter()
            .any(|probe| probe.health == Health::Unavailable)
            || matches!(
                neighbors.health,
                Health::Degraded | Health::Failed | Health::Unavailable
            )
            || !neighbors.failed_sources.is_empty()
            || radio_missing
            || local_evidence_incomplete
        {
            EvidenceCoverage::Partial
        } else {
            EvidenceCoverage::Complete
        };
        Self {
            summary: SnapshotSummary {
                probe_policy: ProbePolicy::Active,
                path_status,
                evidence_coverage,
                completed_probes: probes.len(),
                total_probes: ProbeKind::ALL.len(),
            },
            link,
            interface_counters,
            neighbors,
            probes,
        }
    }

    pub fn from_passive(
        link: LinkSnapshot,
        interface_counters: Option<InterfaceCounters>,
        neighbors: PeerSnapshot,
    ) -> Self {
        let link_available = link.interface.is_some()
            || link.gateway.is_some()
            || !link.resolvers.is_empty()
            || !link.addresses.is_empty();
        let radio_missing = link.requires_radio_evidence() && link.wifi.is_none();
        let local_evidence_incomplete =
            link_evidence_incomplete(&link, interface_counters.as_ref());
        let evidence_coverage =
            if !link_available && neighbors.health == Health::Unavailable && link.wifi.is_none() {
                EvidenceCoverage::Unavailable
            } else if link.interface.is_none()
                || local_evidence_incomplete
                || matches!(
                    neighbors.health,
                    Health::Degraded | Health::Failed | Health::Unavailable
                )
                || !neighbors.failed_sources.is_empty()
                || radio_missing
            {
                EvidenceCoverage::Partial
            } else {
                EvidenceCoverage::Complete
            };
        Self {
            summary: SnapshotSummary {
                probe_policy: ProbePolicy::Passive,
                path_status: PathStatus::Untested,
                evidence_coverage,
                completed_probes: 0,
                total_probes: 0,
            },
            link,
            interface_counters,
            neighbors,
            probes: Vec::new(),
        }
    }
}

fn link_evidence_incomplete(
    link: &LinkSnapshot,
    interface_counters: Option<&InterfaceCounters>,
) -> bool {
    link.interface.is_none()
        || link.resolvers.is_empty()
        || link.addresses.is_empty()
        || interface_counters.is_none()
}

#[derive(Debug, Clone)]
struct InterfaceInterval {
    rate: InterfaceRate,
    received_bytes: u64,
    transmitted_bytes: u64,
    received_packets: u64,
    transmitted_packets: u64,
}

fn interface_interval(
    before: &InterfaceCounters,
    after: &InterfaceCounters,
    elapsed: Duration,
) -> Option<InterfaceInterval> {
    if before.interface != after.interface || elapsed.is_zero() {
        return None;
    }
    let seconds = elapsed.as_secs_f64();
    let received_bytes = after.received_bytes.checked_sub(before.received_bytes)?;
    let transmitted_bytes = after
        .transmitted_bytes
        .checked_sub(before.transmitted_bytes)?;
    let received_packets = after
        .received_packets
        .checked_sub(before.received_packets)?;
    let transmitted_packets = after
        .transmitted_packets
        .checked_sub(before.transmitted_packets)?;
    let receive_errors = after.receive_errors.checked_sub(before.receive_errors)?;
    let transmit_errors = after.transmit_errors.checked_sub(before.transmit_errors)?;
    Some(InterfaceInterval {
        rate: InterfaceRate {
            received_bits_per_second: received_bytes as f64 * 8.0 / seconds,
            transmitted_bits_per_second: transmitted_bytes as f64 * 8.0 / seconds,
            received_packets_per_second: received_packets as f64 / seconds,
            transmitted_packets_per_second: transmitted_packets as f64 / seconds,
            error_delta: receive_errors.checked_add(transmit_errors)?,
            drop_delta: after.drops.checked_sub(before.drops)?,
        },
        received_bytes,
        transmitted_bytes,
        received_packets,
        transmitted_packets,
    })
}

fn counters_replaced_or_reset(before: &InterfaceCounters, after: &InterfaceCounters) -> bool {
    before.interface != after.interface
        || after.received_bytes < before.received_bytes
        || after.transmitted_bytes < before.transmitted_bytes
        || after.received_packets < before.received_packets
        || after.transmitted_packets < before.transmitted_packets
        || after.receive_errors < before.receive_errors
        || after.transmit_errors < before.transmit_errors
        || after.drops < before.drops
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passive_policy_is_default_and_rejects_late_probe_results() {
        let mut app = App::new();
        assert_eq!(app.probe_policy(), ProbePolicy::Passive);
        assert_eq!(app.situation().kind, SituationKind::PassiveObservation);
        assert!(
            app.probes
                .iter()
                .all(|probe| probe.detail == "active check disabled")
        );

        finish_probe(&mut app, ProbeKind::Gateway, Health::Ok, Some(4.0));
        assert!(app.gateway_samples.is_empty());
        assert_eq!(app.cycles, 0);
        assert_eq!(app.situation().kind, SituationKind::PassiveObservation);
    }

    #[test]
    fn operator_can_enable_and_disable_active_path_probes() {
        let mut app = App::new();
        app.set_probe_policy(ProbePolicy::Active);
        assert_eq!(app.probe_policy(), ProbePolicy::Active);
        assert!(
            app.probes
                .iter()
                .all(|probe| probe.health == Health::Queued)
        );
        assert_eq!(app.situation().kind, SituationKind::Collecting);

        finish_probe(&mut app, ProbeKind::Gateway, Health::Ok, Some(4.0));
        assert_eq!(app.gateway_samples.back(), Some(&4));

        app.set_probe_policy(ProbePolicy::Passive);
        assert!(app.gateway_samples.is_empty());
        assert!(app.link.public_ip.is_none());
        assert_eq!(app.situation().kind, SituationKind::PassiveObservation);
    }

    #[test]
    fn gateway_samples_are_bounded() {
        let mut app = App::with_probe_policy(ProbePolicy::Active);
        for latency in 1..=MAX_GATEWAY_SAMPLES + 5 {
            app.apply(MonitorUpdate::ProbeFinished {
                generation: 0,
                kind: ProbeKind::Gateway,
                result: ProbeResult {
                    health: Health::Ok,
                    detail: "reply".into(),
                    latency_ms: Some(latency as f64),
                    metrics: None,
                },
            });
        }
        assert_eq!(app.gateway_samples.len(), MAX_GATEWAY_SAMPLES);
        assert_eq!(app.gateway_samples.front(), Some(&6));
    }

    #[test]
    fn failed_probe_controls_overall_health() {
        let mut app = App::with_probe_policy(ProbePolicy::Active);
        for kind in ProbeKind::ALL {
            app.apply(MonitorUpdate::ProbeFinished {
                generation: 0,
                kind,
                result: ProbeResult {
                    health: if kind == ProbeKind::Https {
                        Health::Failed
                    } else {
                        Health::Ok
                    },
                    detail: "sample".into(),
                    latency_ms: Some(12.0),
                    metrics: None,
                },
            });
        }
        assert_eq!(app.overall_health(), Health::Failed);
    }

    #[test]
    fn supporting_public_identity_does_not_control_path_health() {
        let mut app = App::with_probe_policy(ProbePolicy::Active);
        for _ in 0..MIN_GATEWAY_ASSESSMENT_SAMPLES {
            finish_probe(&mut app, ProbeKind::Gateway, Health::Ok, Some(4.0));
        }
        finish_probe(&mut app, ProbeKind::Dns, Health::Ok, Some(12.0));
        finish_probe(&mut app, ProbeKind::Https, Health::Ok, Some(80.0));
        finish_probe(&mut app, ProbeKind::PublicIp, Health::Unavailable, None);

        assert_eq!(
            app.situation(),
            Situation {
                health: Health::Ok,
                kind: SituationKind::EvidenceGap,
            }
        );
        assert_eq!(app.evidence_coverage(), EvidenceCoverage::Collecting);
    }

    #[test]
    fn gateway_distribution_warms_before_it_controls_health() {
        let mut app = App::with_probe_policy(ProbePolicy::Active);
        for _ in 0..MIN_GATEWAY_ASSESSMENT_SAMPLES - 1 {
            finish_probe(&mut app, ProbeKind::Gateway, Health::Ok, Some(4.0));
        }
        finish_probe(&mut app, ProbeKind::Dns, Health::Ok, Some(12.0));
        finish_probe(&mut app, ProbeKind::Https, Health::Ok, Some(80.0));

        assert_eq!(
            app.situation(),
            Situation {
                health: Health::Running,
                kind: SituationKind::WarmingBaseline,
            }
        );

        finish_probe(&mut app, ProbeKind::Gateway, Health::Ok, Some(4.0));
        assert_eq!(app.overall_health(), Health::Ok);
    }

    #[test]
    fn diagnosis_waits_for_an_earlier_dependency_before_blame() {
        let mut app = App::with_probe_policy(ProbePolicy::Active);
        finish_probe(&mut app, ProbeKind::Dns, Health::Failed, None);
        assert_eq!(app.situation().kind, SituationKind::Collecting);

        finish_probe(&mut app, ProbeKind::Gateway, Health::Ok, Some(4.0));
        assert_eq!(app.situation().kind, SituationKind::DnsFailure);
    }

    #[test]
    fn unavailable_dependency_prevents_false_downstream_localization() {
        let mut gateway_unknown = App::with_probe_policy(ProbePolicy::Active);
        finish_probe(
            &mut gateway_unknown,
            ProbeKind::Gateway,
            Health::Unavailable,
            None,
        );
        finish_probe(&mut gateway_unknown, ProbeKind::Dns, Health::Failed, None);
        assert_eq!(
            gateway_unknown.situation(),
            Situation {
                health: Health::Failed,
                kind: SituationKind::UnlocalizedFailure,
            }
        );

        let mut dns_unknown = App::with_probe_policy(ProbePolicy::Active);
        finish_probe(&mut dns_unknown, ProbeKind::Gateway, Health::Ok, Some(4.0));
        finish_probe(&mut dns_unknown, ProbeKind::Dns, Health::Unavailable, None);
        finish_probe(&mut dns_unknown, ProbeKind::Https, Health::Failed, None);
        assert_eq!(
            dns_unknown.situation().kind,
            SituationKind::UnlocalizedFailure
        );
    }

    #[test]
    fn icmp_silence_does_not_override_successful_downstream_path() {
        let mut app = App::with_probe_policy(ProbePolicy::Active);
        finish_probe(&mut app, ProbeKind::Gateway, Health::Unavailable, None);
        finish_probe(&mut app, ProbeKind::Dns, Health::Ok, Some(12.0));
        finish_probe(&mut app, ProbeKind::Https, Health::Ok, Some(80.0));
        finish_probe(&mut app, ProbeKind::PublicIp, Health::Unavailable, None);

        assert_eq!(
            app.situation(),
            Situation {
                health: Health::Ok,
                kind: SituationKind::EvidenceGap,
            }
        );
    }

    #[test]
    fn aged_internet_probes_stop_supporting_a_current_verdict() {
        let mut app = App::with_probe_policy(ProbePolicy::Active);
        let mut link = test_link("en0", "house", "192.168.1.1");
        link.link_type = Some("ethernet".into());
        link.ssid = None;
        app.link = link;
        app.interface_counters = Some(InterfaceCounters {
            interface: "en0".into(),
            received_bytes: 1,
            transmitted_bytes: 2,
            received_packets: 3,
            transmitted_packets: 4,
            receive_errors: 0,
            transmit_errors: 0,
            drops: 0,
        });
        app.peers = PeerSnapshot {
            health: Health::Ok,
            detail: "complete native cache".into(),
            sources: vec!["arp -an".into(), "ndp -an".into()],
            failed_sources: Vec::new(),
            oui_source: None,
            peers: Vec::new(),
        };
        for _ in 0..MIN_GATEWAY_ASSESSMENT_SAMPLES {
            finish_probe(&mut app, ProbeKind::Gateway, Health::Ok, Some(4.0));
        }
        finish_probe(&mut app, ProbeKind::Dns, Health::Ok, Some(12.0));
        finish_probe(&mut app, ProbeKind::Https, Health::Ok, Some(80.0));
        finish_probe(&mut app, ProbeKind::PublicIp, Health::Ok, Some(90.0));
        app.probe_mut(ProbeKind::Dns).updated_at =
            Some(Instant::now() - MAX_PATH_PROBE_EVIDENCE_AGE - Duration::from_secs(1));

        assert_eq!(
            app.situation(),
            Situation {
                health: Health::Unavailable,
                kind: SituationKind::StalePathEvidence,
            }
        );
        assert_eq!(app.evidence_coverage(), EvidenceCoverage::Partial);
    }

    #[test]
    fn failed_path_stage_outranks_degraded_upstream_distribution() {
        let mut app = App::with_probe_policy(ProbePolicy::Active);
        for latency_ms in [4.0, 40.0, 4.0, 40.0, 4.0] {
            finish_probe(&mut app, ProbeKind::Gateway, Health::Ok, Some(latency_ms));
        }
        finish_probe(&mut app, ProbeKind::Dns, Health::Failed, None);
        assert_eq!(app.situation().kind, SituationKind::DnsFailure);

        finish_probe(&mut app, ProbeKind::Dns, Health::Degraded, Some(700.0));
        finish_probe(&mut app, ProbeKind::Https, Health::Failed, None);
        assert_eq!(app.situation().kind, SituationKind::HttpsFailure);
    }

    #[test]
    fn interface_rate_uses_deltas_and_rejects_counter_reset() {
        let before = InterfaceCounters {
            interface: "en0".into(),
            received_bytes: 1_000,
            transmitted_bytes: 2_000,
            received_packets: 10,
            transmitted_packets: 20,
            receive_errors: 1,
            transmit_errors: 2,
            drops: 3,
        };
        let after = InterfaceCounters {
            interface: "en0".into(),
            received_bytes: 2_000,
            transmitted_bytes: 4_000,
            received_packets: 30,
            transmitted_packets: 60,
            receive_errors: 2,
            transmit_errors: 4,
            drops: 5,
        };
        let rate = interface_interval(&before, &after, Duration::from_secs(2))
            .unwrap()
            .rate;
        assert_eq!(rate.received_bits_per_second, 4_000.0);
        assert_eq!(rate.transmitted_bits_per_second, 8_000.0);
        assert_eq!(rate.error_delta, 3);
        assert_eq!(rate.drop_delta, 2);

        assert!(interface_interval(&after, &before, Duration::from_secs(2)).is_none());
    }

    #[test]
    fn path_dwell_accumulates_valid_interface_radio_and_workload_windows() {
        let mut app = App::new();
        app.apply(MonitorUpdate::Link {
            generation: 1,
            snapshot: test_link("en0", "house", "192.168.1.1"),
        });
        app.apply(MonitorUpdate::Traffic {
            generation: 1,
            counters: Some(test_counters("en0", 1_000, 2_000, 10, 20, 1, 2, 3)),
        });
        app.interface_counters_at = Some(Instant::now() - Duration::from_secs(2));
        app.apply(MonitorUpdate::Traffic {
            generation: 1,
            counters: Some(test_counters("en0", 2_000, 4_000, 30, 60, 2, 4, 5)),
        });
        for (signal, channel) in [(-55.0, 36), (-72.0, 44)] {
            app.apply(MonitorUpdate::Wifi {
                generation: 1,
                ssid: None,
                telemetry: Some(WifiTelemetry {
                    signal_dbm: Some(signal),
                    noise_dbm: Some(-90.0),
                    signal_percent: None,
                    channel: Some(channel),
                    channel_width_mhz: Some(80),
                    frequency_mhz: None,
                    band: Some("5 GHz".into()),
                    phy: Some("802.11ax".into()),
                    tx_rate_mbps: Some(600.0),
                    rx_rate_mbps: None,
                    mcs: None,
                }),
            });
        }
        for (process, received, transmitted) in [("codex", 4_096, 2_048), ("browser", 8_192, 4_096)]
        {
            app.apply(MonitorUpdate::Workload {
                generation: 1,
                snapshot: WorkloadSnapshot {
                    health: Health::Ok,
                    detail: "sampled process window".into(),
                    source: Some("nettop".into()),
                    interval: Duration::from_secs(1),
                    processes: vec![ProcessTraffic {
                        process: process.into(),
                        processes: 1,
                        received_bytes_per_second: received,
                        transmitted_bytes_per_second: transmitted,
                    }],
                },
            });
        }

        let interface = &app.path_dwell.interface;
        assert_eq!(interface.samples, 2);
        assert_eq!(interface.valid_intervals, 1);
        assert_eq!(interface.received_bytes_delta, 1_000);
        assert_eq!(interface.transmitted_bytes_delta, 2_000);
        assert_eq!(interface.received_packets_delta, 20);
        assert_eq!(interface.transmitted_packets_delta, 40);
        assert_eq!(interface.error_delta, 3);
        assert_eq!(interface.drop_delta, 2);
        assert!(interface.current_rate.is_some());
        assert!(interface.peak_received_bits_per_second.is_some());
        assert!(interface.peak_transmitted_bits_per_second.is_some());

        let wifi = &app.path_dwell.wifi;
        assert_eq!(wifi.samples, 2);
        assert_eq!(wifi.latest_signal_dbm, Some(-72.0));
        assert_eq!(wifi.worst_signal_dbm, Some(-72.0));
        assert_eq!(wifi.latest_channel, Some(44));
        assert_eq!(wifi.channel_changes, 1);

        let workload = &app.path_dwell.workload;
        assert_eq!(workload.sampled_windows, 2);
        assert_eq!(workload.observed, Duration::from_secs(2));
        assert_eq!(
            workload
                .latest_window_top
                .as_ref()
                .map(|top| top.process.as_str()),
            Some("browser")
        );
        assert_eq!(
            workload
                .peak_window_top
                .as_ref()
                .map(|top| top.process.as_str()),
            Some("browser")
        );
    }

    #[test]
    fn confirmed_path_generation_resets_all_dwell_evidence() {
        let mut app = App::new();
        app.apply(MonitorUpdate::Link {
            generation: 1,
            snapshot: test_link("en0", "house", "192.168.1.1"),
        });
        app.apply(MonitorUpdate::Traffic {
            generation: 1,
            counters: Some(test_counters("en0", 1, 2, 3, 4, 0, 0, 0)),
        });
        app.apply(MonitorUpdate::Wifi {
            generation: 1,
            ssid: None,
            telemetry: Some(WifiTelemetry {
                signal_dbm: Some(-60.0),
                noise_dbm: None,
                signal_percent: None,
                channel: Some(36),
                channel_width_mhz: None,
                frequency_mhz: None,
                band: None,
                phy: None,
                tx_rate_mbps: None,
                rx_rate_mbps: None,
                mcs: None,
            }),
        });
        app.apply(MonitorUpdate::Workload {
            generation: 1,
            snapshot: WorkloadSnapshot {
                health: Health::Ok,
                detail: "empty sampled window".into(),
                source: Some("nettop".into()),
                interval: Duration::from_secs(1),
                processes: Vec::new(),
            },
        });

        app.apply(MonitorUpdate::Link {
            generation: 2,
            snapshot: test_link("en0", "hotspot", "172.20.10.1"),
        });

        assert_eq!(app.path_dwell.interface.samples, 0);
        assert_eq!(app.path_dwell.wifi.samples, 0);
        assert_eq!(app.path_dwell.workload.sampled_windows, 0);
        assert_eq!(app.path_dwell.workload.observed, Duration::ZERO);
    }

    #[test]
    fn path_switch_retains_typed_completed_generation_dwell() {
        let mut app = App::new();
        app.apply(MonitorUpdate::Link {
            generation: 1,
            snapshot: test_link("en0", "house", "192.168.1.1"),
        });
        app.apply(MonitorUpdate::Traffic {
            generation: 1,
            counters: Some(test_counters("en0", 1, 2, 3, 4, 0, 0, 0)),
        });
        app.apply(MonitorUpdate::Wifi {
            generation: 1,
            ssid: None,
            telemetry: Some(WifiTelemetry {
                signal_dbm: Some(-61.0),
                noise_dbm: None,
                signal_percent: None,
                channel: Some(36),
                channel_width_mhz: None,
                frequency_mhz: None,
                band: None,
                phy: None,
                tx_rate_mbps: None,
                rx_rate_mbps: None,
                mcs: None,
            }),
        });
        app.apply(MonitorUpdate::Workload {
            generation: 1,
            snapshot: WorkloadSnapshot {
                health: Health::Ok,
                detail: "sampled".into(),
                source: Some("nettop".into()),
                interval: Duration::from_secs(1),
                processes: Vec::new(),
            },
        });
        app.apply(MonitorUpdate::Peers {
            generation: 1,
            snapshot: test_peers(Some("02:00:00:00:00:01"), Some("STALE")),
        });

        app.apply(MonitorUpdate::Link {
            generation: 2,
            snapshot: test_link("en0", "hotspot", "172.20.10.1"),
        });

        assert_eq!(app.completed_path_dwells.len(), 1);
        let completed = app.completed_path_dwells.front().unwrap();
        assert_eq!(completed.generation, 1);
        assert_eq!(completed.identity.host, "workstation");
        assert_eq!(completed.identity.interface.as_deref(), Some("en0"));
        assert_eq!(completed.identity.ssid.as_deref(), Some("house"));
        assert_eq!(completed.identity.gateway.as_deref(), Some("192.168.1.1"));
        assert_eq!(completed.dwell.interface.samples, 1);
        assert_eq!(completed.dwell.wifi.samples, 1);
        assert_eq!(completed.dwell.workload.sampled_windows, 1);
        assert_eq!(completed.peers.current, 1);
        assert_eq!(app.path_generation, 2);
        assert_eq!(app.link.ssid.as_deref(), Some("hotspot"));
        assert_eq!(app.path_dwell.interface.samples, 0);
    }

    #[test]
    fn completed_generation_dwell_ledger_evicts_oldest_at_its_clear_cap() {
        let mut app = App::new();
        for generation in 1..=(MAX_COMPLETED_PATH_DWELLS as u64 + 2) {
            app.apply(MonitorUpdate::Link {
                generation,
                snapshot: test_link(
                    "en0",
                    &format!("network-{generation}"),
                    &format!("192.0.2.{generation}"),
                ),
            });
        }

        assert_eq!(app.completed_path_dwells.len(), MAX_COMPLETED_PATH_DWELLS);
        assert_eq!(
            app.completed_path_dwells
                .front()
                .map(|record| record.generation),
            Some(2)
        );
        assert_eq!(
            app.completed_path_dwells
                .back()
                .map(|record| record.generation),
            Some(MAX_COMPLETED_PATH_DWELLS as u64 + 1)
        );
        assert_eq!(app.path_generation, MAX_COMPLETED_PATH_DWELLS as u64 + 2);
    }

    #[test]
    fn counter_wrap_and_interface_replacement_start_new_baselines_without_fake_deltas() {
        let mut app = App::new();
        app.apply(MonitorUpdate::Traffic {
            generation: 0,
            counters: Some(test_counters("en0", 1_000, 2_000, 30, 40, 2, 3, 4)),
        });
        app.interface_counters_at = Some(Instant::now() - Duration::from_secs(1));
        app.apply(MonitorUpdate::Traffic {
            generation: 0,
            counters: Some(test_counters("en0", 10, 20, 3, 4, 0, 0, 0)),
        });
        app.interface_counters_at = Some(Instant::now() - Duration::from_secs(1));
        app.apply(MonitorUpdate::Traffic {
            generation: 0,
            counters: Some(test_counters("en9", 50_000, 60_000, 300, 400, 0, 0, 0)),
        });

        let dwell = &app.path_dwell.interface;
        assert_eq!(dwell.samples, 3);
        assert_eq!(dwell.valid_intervals, 0);
        assert_eq!(dwell.received_bytes_delta, 0);
        assert_eq!(dwell.transmitted_bytes_delta, 0);
        assert_eq!(dwell.received_packets_delta, 0);
        assert_eq!(dwell.transmitted_packets_delta, 0);
        assert_eq!(dwell.error_delta, 0);
        assert_eq!(dwell.drop_delta, 0);
        assert_eq!(dwell.counter_resets, 2);
        assert!(dwell.current_rate.is_none());
    }

    #[test]
    fn workload_dwell_counts_only_successful_sparse_observation_windows() {
        let mut app = App::new();
        app.apply(MonitorUpdate::Workload {
            generation: 0,
            snapshot: WorkloadSnapshot {
                health: Health::Ok,
                detail: "sampled".into(),
                source: Some("nettop".into()),
                interval: Duration::from_secs(1),
                processes: vec![ProcessTraffic {
                    process: "codex".into(),
                    processes: 2,
                    received_bytes_per_second: 4_096,
                    transmitted_bytes_per_second: 2_048,
                }],
            },
        });
        app.apply(MonitorUpdate::Workload {
            generation: 0,
            snapshot: WorkloadSnapshot {
                health: Health::Unavailable,
                detail: "collector timed out".into(),
                source: None,
                interval: Duration::from_secs(1),
                processes: Vec::new(),
            },
        });
        app.apply(MonitorUpdate::Workload {
            generation: 0,
            snapshot: WorkloadSnapshot {
                health: Health::Ok,
                detail: "no attributed bytes in sampled window".into(),
                source: Some("nettop".into()),
                interval: Duration::from_secs(2),
                processes: Vec::new(),
            },
        });

        let dwell = &app.path_dwell.workload;
        assert_eq!(dwell.sampled_windows, 2);
        assert_eq!(dwell.observed, Duration::from_secs(3));
        assert!(dwell.latest_window_top.is_none());
        assert_eq!(
            dwell
                .peak_window_top
                .as_ref()
                .map(|top| top.process.as_str()),
            Some("codex")
        );
    }

    #[test]
    fn rolling_gateway_metrics_count_failed_attempts() {
        let mut app = App::with_probe_policy(ProbePolicy::Active);
        for latency in [Some(10.0), None, Some(12.0)] {
            app.apply(MonitorUpdate::ProbeFinished {
                generation: 0,
                kind: ProbeKind::Gateway,
                result: ProbeResult {
                    health: latency.map_or(Health::Failed, |_| Health::Ok),
                    detail: "sample".into(),
                    latency_ms: latency,
                    metrics: None,
                },
            });
        }
        let metrics = app.gateway_metrics.unwrap();
        assert_eq!(metrics.sent, 3);
        assert_eq!(metrics.received, 2);
        assert_eq!(metrics.lost, 1);
        assert_eq!(metrics.loss_rate, Some(1.0 / 3.0));
    }

    #[test]
    fn gateway_health_uses_the_recent_assessment_window() {
        let mut app = App::with_probe_policy(ProbePolicy::Active);
        finish_probe(&mut app, ProbeKind::Gateway, Health::Failed, None);
        for _ in 0..GATEWAY_ASSESSMENT_WINDOW {
            finish_probe(&mut app, ProbeKind::Gateway, Health::Ok, Some(4.0));
        }

        let metrics = app.gateway_assessment_metrics().unwrap();
        assert_eq!(metrics.sent, GATEWAY_ASSESSMENT_WINDOW);
        assert_eq!(metrics.lost, 0);
        assert_eq!(metrics.health(), Health::Ok);
        assert_eq!(app.gateway_metrics.as_ref().unwrap().lost, 1);
    }

    #[test]
    fn path_transition_resets_path_scoped_state_and_names_both_networks() {
        let mut app = App::new();
        app.apply(MonitorUpdate::Link {
            generation: 1,
            snapshot: test_link("en0", "house", "192.168.1.1"),
        });
        app.apply(MonitorUpdate::ProbeFinished {
            generation: 1,
            kind: ProbeKind::Gateway,
            result: ProbeResult {
                health: Health::Ok,
                detail: "192.168.1.1".into(),
                latency_ms: Some(4.0),
                metrics: None,
            },
        });
        app.apply(MonitorUpdate::ProbeFinished {
            generation: 1,
            kind: ProbeKind::PublicIp,
            result: ProbeResult {
                health: Health::Ok,
                detail: "203.0.113.8".into(),
                latency_ms: Some(10.0),
                metrics: None,
            },
        });

        app.apply(MonitorUpdate::Link {
            generation: 2,
            snapshot: test_link("en0", "phone-hotspot", "172.20.10.1"),
        });

        assert_eq!(app.path_generation, 2);
        assert!(app.gateway_samples.is_empty());
        assert!(app.link.public_ip.is_none());
        assert!(app.link.wifi.is_none());
        assert!(app.interface_counters.is_none());
        assert_eq!(app.peers.health, Health::Queued);
        assert!(app.events.back().unwrap().message.contains("house"));
        assert!(app.events.back().unwrap().message.contains("phone-hotspot"));
        let change = app.last_path_change.as_ref().unwrap();
        assert!(change.dimensions.contains(&"SSID"));
        assert!(change.dimensions.contains(&"gateway"));
        assert!(change.previous.contains("house"));
        assert!(change.current.contains("phone-hotspot"));
    }

    #[test]
    fn stale_workload_sample_cannot_cross_a_path_generation() {
        let mut app = App::new();
        app.apply(MonitorUpdate::Link {
            generation: 1,
            snapshot: test_link("en0", "house", "192.168.1.1"),
        });
        app.apply(MonitorUpdate::Link {
            generation: 2,
            snapshot: test_link("en0", "phone-hotspot", "172.20.10.1"),
        });
        app.apply(MonitorUpdate::Workload {
            generation: 1,
            snapshot: WorkloadSnapshot {
                health: Health::Ok,
                detail: "one process".into(),
                source: Some("nettop".into()),
                interval: Duration::from_secs(1),
                processes: vec![ProcessTraffic {
                    process: "stale-process".into(),
                    processes: 1,
                    received_bytes_per_second: 100,
                    transmitted_bytes_per_second: 200,
                }],
            },
        });

        assert!(app.workload.processes.is_empty());
        assert_eq!(app.workload.health, Health::Queued);
    }

    #[test]
    fn route_settling_retains_the_confirmed_generation_until_link_recovers() {
        let mut app = App::new();
        let link = test_link("en0", "house", "192.168.1.1");
        app.apply(MonitorUpdate::Link {
            generation: 1,
            snapshot: link.clone(),
        });
        app.apply(MonitorUpdate::PathSettling { generation: 1 });
        app.apply(MonitorUpdate::PathSettling { generation: 1 });

        assert!(app.path_transition_pending);
        assert_eq!(app.path_generation, 1);
        assert_eq!(app.overall_health(), Health::Running);
        assert!(
            app.events
                .back()
                .unwrap()
                .message
                .contains("retaining the last confirmed path")
        );
        assert_eq!(
            app.events
                .iter()
                .filter(|event| event.message.contains("retaining the last confirmed path"))
                .count(),
            1
        );

        app.apply(MonitorUpdate::Link {
            generation: 1,
            snapshot: link,
        });
        assert!(!app.path_transition_pending);
    }

    #[test]
    fn stale_result_cannot_cross_a_path_generation() {
        let mut app = App::new();
        app.apply(MonitorUpdate::Link {
            generation: 1,
            snapshot: test_link("en0", "house", "192.168.1.1"),
        });
        app.apply(MonitorUpdate::Link {
            generation: 2,
            snapshot: test_link("en0", "phone-hotspot", "172.20.10.1"),
        });
        app.apply(MonitorUpdate::ProbeFinished {
            generation: 1,
            kind: ProbeKind::PublicIp,
            result: ProbeResult {
                health: Health::Ok,
                detail: "198.51.100.9".into(),
                latency_ms: Some(12.0),
                metrics: None,
            },
        });
        app.apply(MonitorUpdate::Wifi {
            generation: 1,
            ssid: Some("stale-network".into()),
            telemetry: Some(WifiTelemetry {
                signal_dbm: Some(-30.0),
                noise_dbm: None,
                signal_percent: None,
                channel: Some(11),
                channel_width_mhz: None,
                frequency_mhz: None,
                band: None,
                phy: None,
                tx_rate_mbps: None,
                rx_rate_mbps: None,
                mcs: None,
            }),
        });

        assert!(app.link.public_ip.is_none());
        assert!(app.link.wifi.is_none());
        assert_eq!(app.cycles, 0);
    }

    #[test]
    fn platform_wifi_evidence_can_resolve_an_os_hidden_ssid() {
        let mut app = App::new();
        let mut link = test_link("en0", "placeholder", "192.168.1.1");
        link.ssid = None;
        link.ssid_restricted = true;
        app.apply(MonitorUpdate::Link {
            generation: 1,
            snapshot: link.clone(),
        });
        app.apply(MonitorUpdate::Wifi {
            generation: 1,
            ssid: Some("house-wifi".into()),
            telemetry: None,
        });

        assert_eq!(app.link.ssid.as_deref(), Some("house-wifi"));
        assert!(!app.link.ssid_restricted);
        assert!(
            app.events
                .back()
                .unwrap()
                .message
                .contains("network identity resolved")
        );

        app.apply(MonitorUpdate::Link {
            generation: 1,
            snapshot: link,
        });
        assert_eq!(app.link.ssid.as_deref(), Some("house-wifi"));
        assert!(!app.link.ssid_restricted);
    }

    #[test]
    fn temporary_address_rotation_does_not_change_path_identity() {
        let before = test_link("en0", "house", "192.168.1.1");
        let mut after = before.clone();
        after.addresses.push(Address {
            interface: "en0".into(),
            address: "2001:db8:abcd:1::1234".into(),
            family: 6,
            is_default: true,
            is_temporary: true,
        });
        let mut rotated = after.clone();
        rotated.addresses.last_mut().unwrap().address = "2001:db8:abcd:1::9876".into();
        rotated.addresses.last_mut().unwrap().is_temporary = false;
        assert_eq!(after.path_fingerprint(), rotated.path_fingerprint());

        rotated.addresses.last_mut().unwrap().address = "2001:db8:abcd:2::9876".into();
        assert_ne!(after.path_fingerprint(), rotated.path_fingerprint());
    }

    #[test]
    fn wifi_association_change_is_path_identity_when_ssid_is_hidden() {
        let mut before = test_link("en0", "placeholder", "192.168.1.1");
        before.ssid = None;
        before.ssid_restricted = true;
        before.network_configuration = Some(Box::new(NetworkConfiguration {
            connection_id: Some("101".into()),
            associated_bssid: None,
            bssid_restricted: true,
            method: Some("DHCP".into()),
            state: Some("BOUND".into()),
            server: Some("192.168.1.1".into()),
            subnet_mask: Some("255.255.255.0".into()),
            lease_seconds: Some(43_200),
            lease_started_at: None,
            lease_expires_at: None,
            router_arp_verified: Some(true),
            security: Some("WPA2_PSK".into()),
        }));
        let mut after = before.clone();
        after.network_configuration.as_mut().unwrap().connection_id = Some("102".into());

        let before = before.path_fingerprint();
        let after = after.path_fingerprint();
        assert_ne!(before, after);
        assert_eq!(before.changed_dimensions(&after), vec!["Wi-Fi association"]);
    }

    #[test]
    fn transition_event_names_nonvisual_fingerprint_changes() {
        for (expected, change) in [
            ("link type", "link"),
            ("resolvers", "resolver"),
            ("address prefix", "address"),
        ] {
            let before = test_link("en0", "house", "192.168.1.1");
            let mut after = before.clone();
            match change {
                "link" => after.link_type = Some("ethernet".into()),
                "resolver" => after.resolvers = vec!["9.9.9.9".into()],
                "address" => after.addresses[0].address = "198.51.100.2".into(),
                _ => unreachable!(),
            }
            let mut app = App::new();
            app.apply(MonitorUpdate::Link {
                generation: 1,
                snapshot: before,
            });
            app.apply(MonitorUpdate::Link {
                generation: 2,
                snapshot: after,
            });
            assert!(
                app.events.back().unwrap().message.contains(expected),
                "transition event should identify {expected}: {}",
                app.events.back().unwrap().message
            );
        }
    }

    #[test]
    fn partial_neighbor_evidence_degrades_snapshot_summary() {
        let neighbors = PeerSnapshot {
            health: Health::Degraded,
            detail: "one native cache source failed".into(),
            sources: vec!["arp -an".into()],
            failed_sources: vec!["ndp -an".into()],
            oui_source: None,
            peers: Vec::new(),
        };
        let results = ProbeKind::ALL
            .into_iter()
            .map(|kind| {
                (
                    kind,
                    ProbeResult {
                        health: Health::Ok,
                        detail: "complete".into(),
                        latency_ms: Some(1.0),
                        metrics: None,
                    },
                )
            })
            .collect();
        let report = SnapshotReport::from_results(
            test_link("en0", "house", "192.168.1.1"),
            None,
            neighbors,
            results,
        );
        assert_eq!(report.summary.path_status, PathStatus::Ok);
        assert_eq!(report.summary.evidence_coverage, EvidenceCoverage::Partial);
    }

    #[test]
    fn passive_snapshot_reports_untested_instead_of_unavailable_path() {
        let report = SnapshotReport::from_passive(
            test_link("en0", "house", "192.168.1.1"),
            None,
            PeerSnapshot {
                health: Health::Ok,
                detail: "native neighbor cache read".into(),
                sources: vec!["arp -an".into(), "ndp -an".into()],
                failed_sources: Vec::new(),
                oui_source: None,
                peers: Vec::new(),
            },
        );

        assert_eq!(report.summary.probe_policy, ProbePolicy::Passive);
        assert_eq!(report.summary.path_status, PathStatus::Untested);
        assert!(report.probes.is_empty());
    }

    #[test]
    fn passive_complete_requires_every_expected_host_local_source() {
        let mut link = test_link("en0", "house", "192.168.1.1");
        link.link_type = Some("ethernet".into());
        link.ssid = None;
        let counters = InterfaceCounters {
            interface: "en0".into(),
            received_bytes: 1,
            transmitted_bytes: 2,
            received_packets: 3,
            transmitted_packets: 4,
            receive_errors: 0,
            transmit_errors: 0,
            drops: 0,
        };
        let neighbors = PeerSnapshot {
            health: Health::Ok,
            detail: "complete native cache".into(),
            sources: vec!["arp -an".into(), "ndp -an".into()],
            failed_sources: Vec::new(),
            oui_source: None,
            peers: Vec::new(),
        };

        let complete =
            SnapshotReport::from_passive(link.clone(), Some(counters.clone()), neighbors.clone());
        assert_eq!(
            complete.summary.evidence_coverage,
            EvidenceCoverage::Complete
        );

        let mut without_resolvers = link.clone();
        without_resolvers.resolvers.clear();
        let missing_resolvers = SnapshotReport::from_passive(
            without_resolvers,
            Some(counters.clone()),
            neighbors.clone(),
        );
        assert_eq!(
            missing_resolvers.summary.evidence_coverage,
            EvidenceCoverage::Partial
        );

        let mut without_addresses = link.clone();
        without_addresses.addresses.clear();
        let missing_addresses =
            SnapshotReport::from_passive(without_addresses, Some(counters), neighbors.clone());
        assert_eq!(
            missing_addresses.summary.evidence_coverage,
            EvidenceCoverage::Partial
        );

        let missing_counters = SnapshotReport::from_passive(link, None, neighbors);
        assert_eq!(
            missing_counters.summary.evidence_coverage,
            EvidenceCoverage::Partial
        );
    }

    #[test]
    fn missing_wifi_radio_evidence_makes_snapshot_coverage_partial() {
        let results = ProbeKind::ALL
            .into_iter()
            .map(|kind| {
                (
                    kind,
                    ProbeResult {
                        health: Health::Ok,
                        detail: "complete".into(),
                        latency_ms: Some(1.0),
                        metrics: None,
                    },
                )
            })
            .collect();
        let report = SnapshotReport::from_results(
            test_link("en0", "house", "192.168.1.1"),
            None,
            PeerSnapshot {
                health: Health::Ok,
                detail: "complete native cache".into(),
                sources: vec!["arp -an".into(), "ndp -an".into()],
                failed_sources: Vec::new(),
                oui_source: None,
                peers: Vec::new(),
            },
            results,
        );

        assert_eq!(report.summary.path_status, PathStatus::Ok);
        assert_eq!(report.summary.evidence_coverage, EvidenceCoverage::Partial);
    }

    #[test]
    fn peer_dwell_records_state_and_binding_changes_at_constant_count() {
        let mut app = App::new();
        app.apply(MonitorUpdate::Link {
            generation: 1,
            snapshot: test_link("en0", "house", "192.168.1.1"),
        });
        app.apply(MonitorUpdate::Peers {
            generation: 1,
            snapshot: test_peers(Some("02:00:00:00:00:01"), Some("STALE")),
        });
        app.apply(MonitorUpdate::Peers {
            generation: 1,
            snapshot: test_peers(Some("02:00:00:00:00:02"), Some("REACHABLE")),
        });

        let peer = &app.peers.peers[0];
        let dwell = app.peer_dwell(peer).unwrap();
        assert_eq!(dwell.observations, 2);
        assert_eq!(dwell.binding_changes, 1);
        assert_eq!(dwell.state_changes, 1);
        assert_eq!(dwell.previous_state.as_deref(), Some("STALE"));
        assert_eq!(
            app.peer_dwell_summary(),
            PeerDwellSummary {
                current: 1,
                observed: 1,
                changed: 1,
                disappeared: 0,
            }
        );
        assert!(
            app.events
                .iter()
                .any(|event| event.message.contains("binding changed"))
        );
        assert!(
            app.events
                .iter()
                .any(|event| event.message.contains("STALE → REACHABLE"))
        );
    }

    #[test]
    fn same_snapshot_binding_conflict_is_not_temporal_churn() {
        let mut app = App::new();
        app.apply(MonitorUpdate::Peers {
            generation: 0,
            snapshot: test_peers(Some("02:00:00:00:00:01"), Some("STALE")),
        });
        let mut conflicted = test_peers(None, Some("STALE"));
        conflicted.health = Health::Degraded;
        conflicted.peers[0].binding_conflict = true;
        app.apply(MonitorUpdate::Peers {
            generation: 0,
            snapshot: conflicted,
        });

        let peer = &app.peers.peers[0];
        let dwell = app.peer_dwell(peer).unwrap();
        assert_eq!(dwell.binding_changes, 0);
        assert!(
            app.events
                .iter()
                .any(|event| event.message.contains("sources disagree"))
        );
        assert!(
            app.events
                .iter()
                .all(|event| !event.message.contains("binding changed"))
        );
    }

    #[test]
    fn partial_peer_sources_do_not_invent_cache_disappearance() {
        let mut app = App::new();
        app.apply(MonitorUpdate::Peers {
            generation: 0,
            snapshot: test_peers(Some("02:00:00:00:00:01"), Some("STALE")),
        });
        app.apply(MonitorUpdate::Peers {
            generation: 0,
            snapshot: PeerSnapshot {
                health: Health::Degraded,
                detail: "IPv6 cache unavailable".into(),
                sources: vec!["arp -an".into()],
                failed_sources: vec!["ndp -an".into()],
                oui_source: None,
                peers: Vec::new(),
            },
        });
        assert_eq!(app.peer_dwell_summary().disappeared, 0);

        app.apply(MonitorUpdate::Peers {
            generation: 0,
            snapshot: PeerSnapshot {
                health: Health::Ok,
                detail: "empty complete cache".into(),
                sources: vec!["arp -an".into(), "ndp -an".into()],
                failed_sources: Vec::new(),
                oui_source: None,
                peers: Vec::new(),
            },
        });
        assert_eq!(app.peer_dwell_summary().disappeared, 1);
        assert!(
            app.events
                .iter()
                .any(|event| event.message.contains("not proof of departure"))
        );
    }

    fn test_link(interface: &str, ssid: &str, gateway: &str) -> LinkSnapshot {
        LinkSnapshot {
            host: "workstation".into(),
            interface: Some(interface.into()),
            link_type: Some("wifi".into()),
            ssid: Some(ssid.into()),
            ssid_restricted: false,
            wifi: None,
            gateway: Some(gateway.into()),
            public_ip: None,
            resolvers: vec![gateway.into()],
            addresses: vec![Address {
                interface: interface.into(),
                address: "192.0.2.2".into(),
                family: 4,
                is_default: true,
                is_temporary: false,
            }],
            network_configuration: None,
        }
    }

    fn test_peers(mac: Option<&str>, state: Option<&str>) -> PeerSnapshot {
        PeerSnapshot {
            health: Health::Ok,
            detail: "1 cached peer".into(),
            sources: vec!["arp -an".into(), "ndp -an".into()],
            failed_sources: Vec::new(),
            oui_source: None,
            peers: vec![Peer {
                address: "192.168.1.42".into(),
                mac: mac.map(str::to_owned),
                interface: Some("en0".into()),
                state: state.map(str::to_owned),
                binding_conflict: false,
                mac_scope: Some(MacScope::Local),
                registrant: None,
            }],
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn test_counters(
        interface: &str,
        received_bytes: u64,
        transmitted_bytes: u64,
        received_packets: u64,
        transmitted_packets: u64,
        receive_errors: u64,
        transmit_errors: u64,
        drops: u64,
    ) -> InterfaceCounters {
        InterfaceCounters {
            interface: interface.into(),
            received_bytes,
            transmitted_bytes,
            received_packets,
            transmitted_packets,
            receive_errors,
            transmit_errors,
            drops,
        }
    }

    fn finish_probe(app: &mut App, kind: ProbeKind, health: Health, latency_ms: Option<f64>) {
        app.apply(MonitorUpdate::ProbeFinished {
            generation: app.path_generation,
            kind,
            result: ProbeResult {
                health,
                detail: "test evidence".into(),
                latency_ms,
                metrics: None,
            },
        });
    }
}
