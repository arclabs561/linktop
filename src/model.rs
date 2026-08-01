use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use serde::Serialize;
use sha2::{Digest, Sha256};

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub underlay: Option<PathUnderlay>,
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
pub struct PathUnderlay {
    pub interface: String,
    pub link_type: String,
    pub gateway: Option<String>,
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

#[derive(Debug, Clone, PartialEq, Serialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DwellPathIdentity {
    pub host: String,
    pub interface: Option<String>,
    pub link_type: Option<String>,
    pub underlay: Option<PathUnderlay>,
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
            underlay: fingerprint.underlay,
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
        if let Some(underlay) = &self.underlay {
            let underlay_gateway = underlay.gateway.as_deref().unwrap_or("no gateway");
            format!(
                "{} → {interface} [{link_type}] over {} [{} / {network}] → {underlay_gateway}",
                self.host, underlay.interface, underlay.link_type
            )
        } else {
            format!(
                "{} → {interface} [{link_type} / {network}] → {gateway}",
                self.host
            )
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompletedPathDwell {
    pub generation: u64,
    pub identity: DwellPathIdentity,
    pub observed: Duration,
    pub completed_by: PathChange,
    pub next_generation: u64,
    pub dwell: PathDwell,
    pub peers: PeerDwellSummary,
    pub radio_applicable: bool,
    pub wifi_observation_settled: bool,
    pub workload_latest_health: Health,
    pub workload_latest_detail: String,
    pub workload_latest_source: Option<String>,
    pub peer_snapshot_observations: u64,
    pub peer_latest_health: Health,
    pub peer_latest_detail: String,
    pub peer_latest_path_filter: PeerPathFilter,
    pub peer_sources: Vec<String>,
    pub peer_failed_sources: Vec<String>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

fn traffic_shape_candidate_from_dwell(
    dwell: &InterfaceDwell,
    observed_span_ms: u64,
) -> Option<TrafficShapeCandidateV0> {
    if dwell.valid_intervals == 0 {
        return None;
    }
    let direction = match (dwell.received_bytes_delta, dwell.transmitted_bytes_delta) {
        (0, 0) => TrafficShapeDirectionV0::NoObservedTraffic,
        (received, transmitted)
            if transmitted == 0 || received >= transmitted.saturating_mul(3) =>
        {
            TrafficShapeDirectionV0::ReceiveDominant
        }
        (received, transmitted) if received == 0 || transmitted >= received.saturating_mul(3) => {
            TrafficShapeDirectionV0::TransmitDominant
        }
        _ => TrafficShapeDirectionV0::Bidirectional,
    };
    let mean_rate =
        |bytes| (observed_span_ms > 0).then(|| bytes as f64 * 8_000.0 / observed_span_ms as f64);
    let mean_packet_bytes = |bytes, packets| (packets > 0).then(|| bytes as f64 / packets as f64);
    Some(TrafficShapeCandidateV0 {
        schema: TRAFFIC_SHAPE_CANDIDATE_SCHEMA_V0,
        observed_span_ms,
        valid_intervals: dwell.valid_intervals,
        direction,
        received_bytes_delta: dwell.received_bytes_delta,
        transmitted_bytes_delta: dwell.transmitted_bytes_delta,
        received_packets_delta: dwell.received_packets_delta,
        transmitted_packets_delta: dwell.transmitted_packets_delta,
        mean_received_bits_per_second: mean_rate(dwell.received_bytes_delta),
        mean_transmitted_bits_per_second: mean_rate(dwell.transmitted_bytes_delta),
        peak_received_bits_per_second: dwell.peak_received_bits_per_second,
        peak_transmitted_bits_per_second: dwell.peak_transmitted_bits_per_second,
        mean_received_packet_bytes: mean_packet_bytes(
            dwell.received_bytes_delta,
            dwell.received_packets_delta,
        ),
        mean_transmitted_packet_bytes: mean_packet_bytes(
            dwell.transmitted_bytes_delta,
            dwell.transmitted_packets_delta,
        ),
        caveats: vec![
            "aggregate kernel interface counters",
            "not endpoint, protocol, application, person, place, or intent evidence",
        ],
    })
}

#[derive(Debug, Clone)]
pub struct PathChange {
    pub elapsed: Duration,
    pub dimensions: Vec<&'static str>,
    pub previous: String,
    pub current: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HistoryContext {
    pub kind: HistoryContextKind,
    pub summary: String,
    pub compact_summary: String,
    pub context_anchor: String,
    pub place_authority: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
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
            underlay: None,
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

    pub(crate) fn requires_radio_evidence(&self) -> bool {
        self.observation_link_type()
            .is_some_and(|kind| kind.eq_ignore_ascii_case("wifi"))
    }

    fn requires_underlay_evidence(&self) -> bool {
        self.link_type
            .as_deref()
            .is_some_and(|kind| kind.eq_ignore_ascii_case("vpn"))
    }

    pub(crate) fn observation_interface(&self) -> Option<&str> {
        self.underlay
            .as_ref()
            .map(|underlay| underlay.interface.as_str())
            .or(self.interface.as_deref())
    }

    pub(crate) fn observation_gateway(&self) -> Option<&str> {
        self.underlay
            .as_ref()
            .and_then(|underlay| underlay.gateway.as_deref())
            .or(self.gateway.as_deref())
    }

    pub(crate) fn observation_link_type(&self) -> Option<&str> {
        self.underlay
            .as_ref()
            .map(|underlay| underlay.link_type.as_str())
            .or(self.link_type.as_deref())
    }

    pub(crate) fn operator_path(&self) -> String {
        let interface = self.interface.as_deref().unwrap_or("unknown interface");
        let link_type = self.link_type.as_deref().unwrap_or("unknown link");
        let network = self
            .ssid
            .as_deref()
            .map(|value| format!(" / {value}"))
            .or_else(|| {
                self.ssid_restricted
                    .then(|| " / SSID hidden by macOS".into())
            })
            .unwrap_or_default();
        if let Some(underlay) = &self.underlay {
            let gateway = underlay.gateway.as_deref().unwrap_or("unknown gateway");
            format!(
                "{} ──▶ {interface} [{link_type}] over {} [{}{}] ──▶ {gateway}",
                self.host, underlay.interface, underlay.link_type, network
            )
        } else {
            let gateway = self.gateway.as_deref().unwrap_or("unknown gateway");
            format!(
                "{} ──▶ {interface} [{link_type}{network}] ──▶ {gateway}",
                self.host
            )
        }
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
            underlay: self.underlay.clone(),
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

    pub(crate) fn default_path_prefixes(&self) -> Vec<String> {
        self.addresses
            .iter()
            .filter(|address| address.is_default)
            .filter_map(|address| match address.address.parse::<IpAddr>().ok()? {
                IpAddr::V4(_) if self.underlay.is_some() => None,
                IpAddr::V4(value) => self
                    .network_configuration
                    .as_deref()
                    .and_then(|configuration| configuration.subnet_mask.as_deref())
                    .and_then(|mask| ipv4_prefix(value, mask)),
                IpAddr::V6(value) if value.is_unicast_link_local() => None,
                IpAddr::V6(value) => {
                    let segments = value.segments();
                    Some(format!(
                        "{:x}:{:x}:{:x}:{:x}::/64",
                        segments[0], segments[1], segments[2], segments[3]
                    ))
                }
            })
            .collect()
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
        if let Some(underlay) = &self.underlay {
            let gateway = underlay.gateway.as_deref().unwrap_or("no gateway");
            format!(
                "{interface} [{}] over {} [{}{}] via {gateway}",
                self.link_type.as_deref().unwrap_or("unknown link"),
                underlay.interface,
                underlay.link_type,
                ssid
            )
        } else {
            let gateway = self.gateway.as_deref().unwrap_or("no gateway");
            format!("{interface}{ssid} via {gateway}")
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PathFingerprint {
    interface: Option<String>,
    link_type: Option<String>,
    underlay: Option<PathUnderlay>,
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
        if self.underlay.as_ref().map(|value| &value.interface)
            != current.underlay.as_ref().map(|value| &value.interface)
        {
            changed.push("underlay interface");
        }
        if self.underlay.as_ref().map(|value| &value.link_type)
            != current.underlay.as_ref().map(|value| &value.link_type)
        {
            changed.push("underlay link type");
        }
        if self
            .underlay
            .as_ref()
            .and_then(|value| value.gateway.as_ref())
            != current
                .underlay
                .as_ref()
                .and_then(|value| value.gateway.as_ref())
        {
            changed.push("underlay gateway");
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

fn path_fingerprint_candidate_from_identity(
    identity: &DwellPathIdentity,
) -> Option<PathFingerprintCandidateV0> {
    let mut fields = Vec::new();
    let mut add = |name: &'static str, value: &str| fields.push((name, value.to_owned()));

    if let Some(interface) = identity.interface.as_deref() {
        add("interface", interface);
    }
    if let Some(link_type) = identity.link_type.as_deref() {
        add("link_type", link_type);
    }
    if let Some(underlay) = identity.underlay.as_ref() {
        add("underlay_interface", &underlay.interface);
        add("underlay_link_type", &underlay.link_type);
        if let Some(gateway) = underlay.gateway.as_deref() {
            add("underlay_gateway", gateway);
        }
    }
    if let Some(ssid) = identity.ssid.as_deref() {
        add("ssid", ssid);
    } else if identity.ssid_restricted {
        add("ssid_restricted", "true");
    }
    if let Some(connection_id) = identity.connection_id.as_deref() {
        add("connection_id", connection_id);
    }
    if let Some(gateway) = identity.gateway.as_deref() {
        add("gateway", gateway);
    }
    let mut resolvers = identity.resolvers.clone();
    resolvers.sort();
    resolvers.dedup();
    for resolver in &resolvers {
        add("resolver", resolver);
    }
    let mut address_boundaries = identity.address_boundaries.clone();
    address_boundaries.sort();
    address_boundaries.dedup();
    for (interface, address) in &address_boundaries {
        add("address_interface", interface);
        add("address_boundary", address);
    }
    if fields.is_empty() {
        return None;
    }

    let mut digest = Sha256::new();
    for (name, value) in &fields {
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(name.as_bytes());
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    let digest = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();

    Some(PathFingerprintCandidateV0 {
        schema: PATH_FINGERPRINT_CANDIDATE_SCHEMA_V0,
        observer: identity.host.clone(),
        digest,
        basis: fields.into_iter().map(|(name, _)| name).collect(),
        caveats: vec![
            "comparison digest over observed host-path dimensions",
            "not endpoint, protocol, device, person, place, or intent identity",
            "missing dimensions are omitted and values remain observer-scoped",
        ],
    })
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

fn ipv4_prefix(address: Ipv4Addr, mask: &str) -> Option<String> {
    let mask = u32::from(mask.parse::<Ipv4Addr>().ok()?);
    let inverted = !mask;
    if inverted & inverted.wrapping_add(1) != 0 {
        return None;
    }
    let prefix = mask.count_ones();
    let network = Ipv4Addr::from(u32::from(address) & mask);
    Some(format!("{network}/{prefix}"))
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
    pub last_state_change: Option<Duration>,
    pub binding_changes: u64,
    pub last_binding_change: Option<Duration>,
    pub cache_disappearances: u64,
    pub cache_returns: u64,
    pub last_cache_return: Option<Duration>,
    pub currently_cached: bool,
    pub latest: Peer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PeerDwellSummary {
    pub current: usize,
    pub observed: usize,
    pub changed: usize,
    pub disappeared: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct PeerKey {
    pub interface: Option<String>,
    pub address: String,
}

impl PeerKey {
    pub(crate) fn from_peer(peer: &Peer) -> Self {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerPathFilter {
    Pending,
    Applied,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeerSnapshot {
    pub health: Health,
    pub detail: String,
    pub path_filter: PeerPathFilter,
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
            path_filter: PeerPathFilter::Pending,
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
    pub updated_at: Option<Duration>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
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
    EvidenceGap,
    Ready,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
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
pub enum EvidenceProgressState {
    Collecting,
    Available,
    Insufficient,
    Stale,
    Unavailable,
    Unsupported,
    NotCollected,
}

impl EvidenceProgressState {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Available => "available",
            Self::Insufficient => "insufficient",
            Self::Stale => "stale",
            Self::Unavailable => "unavailable",
            Self::Unsupported => "unsupported",
            Self::NotCollected => "not collected",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceBasis {
    Observed,
    Derived,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EvidenceScope {
    CurrentSample {
        generation: u64,
        subject: String,
    },
    CurrentPathGeneration {
        generation: u64,
        subject: String,
    },
    AssessmentWindow {
        generation: u64,
        subject: String,
        maximum_observations: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClaim {
    PathContext,
    InterfaceTotals,
    InterfaceRate,
    RadioLink,
    NeighborCache,
    WorkloadAttribution,
    GatewayRtt,
    GatewayVariation,
    DnsReachability,
    HttpsReachability,
    PublicEgress,
}

impl EvidenceClaim {
    pub const fn label(self) -> &'static str {
        match self {
            Self::PathContext => "path context",
            Self::InterfaceTotals => "interface totals",
            Self::InterfaceRate => "interface rate",
            Self::RadioLink => "radio link",
            Self::NeighborCache => "neighbor cache",
            Self::WorkloadAttribution => "workload attribution",
            Self::GatewayRtt => "next-hop RTT",
            Self::GatewayVariation => "next-hop variation",
            Self::DnsReachability => "DNS reachability",
            Self::HttpsReachability => "HTTPS reachability",
            Self::PublicEgress => "public egress",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceProgress {
    pub claim: EvidenceClaim,
    pub state: EvidenceProgressState,
    pub basis: EvidenceBasis,
    pub scope: EvidenceScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observations: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub successful_observations: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_observations: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_intervals: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_span_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_age_ms: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<EvidenceLimitation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum EvidenceLimitation {
    RouteSettlingLastConfirmed,
    CumulativeCountersNoAttribution,
    MinimumCompatibleCounterObservations { required: u64 },
    CounterResetsExcluded { count: u64 },
    PlatformRadioTelemetryUnavailable,
    NativeSourcesUnavailable { sources: Vec<String> },
    CacheNotLivenessIdentityActivityOrTraffic,
    SampledHostAccountingNoEndpointProtocolPeerPersonOrIntent,
    OlderThanAssessmentFreshnessWindow,
    PublicEgressNotReachabilityDependency,
    MinimumCurrentGenerationAttempts { required: u64 },
    MinimumSuccessfulRttObservations { required: u64 },
    BoundedAcquisitionEndedBeforeAvailability,
}

impl EvidenceProgress {
    fn new(
        claim: EvidenceClaim,
        state: EvidenceProgressState,
        basis: EvidenceBasis,
        scope: EvidenceScope,
    ) -> Self {
        Self {
            claim,
            state,
            basis,
            scope,
            observations: None,
            successful_observations: None,
            required_observations: None,
            valid_intervals: None,
            observed_span_ms: None,
            source_age_ms: None,
            limitations: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LiveAssessment {
    pub situation: Situation,
    pub path_status: PathStatus,
    pub evidence_coverage: EvidenceCoverage,
}

#[derive(Debug, Clone, Serialize)]
pub struct LiveProbeEvidence {
    pub kind: ProbeKind,
    pub health: Health,
    pub detail: String,
    pub latency_ms: Option<f64>,
    pub metrics: Option<LatencyMetrics>,
    pub age_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LiveGatewayAssessmentEvidence {
    pub attempts: u64,
    pub successful_attempts: u64,
    pub required_attempts: u64,
    pub maximum_attempts: u64,
    pub metrics: Option<LatencyMetrics>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LiveWorkloadEvidence {
    pub health: Health,
    pub detail: String,
    pub source: Option<String>,
    pub interval_ms: u64,
    pub processes: Vec<ProcessTraffic>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LivePathDwellEvidence {
    pub observed_span_ms: u64,
    pub interface_samples: u64,
    pub interface_valid_intervals: u64,
    pub wifi_samples: u64,
    pub workload_windows: u64,
    pub workload_observed_ms: u64,
    pub neighbors: PeerDwellSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct LivePathChangeEvidence {
    pub observed_at_ms: u64,
    pub dimensions: Vec<&'static str>,
    pub previous: String,
    pub current: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletedPathWindowSupportState {
    Available,
    Partial,
    Unavailable,
    Unsupported,
    NotCollected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletedPathWindowSource {
    KernelInterfaceCounters,
    PlatformRadioTelemetry,
    SampledHostProcessAccounting,
    NativeNeighborCache,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum CompletedPathWindowSupportLimitation {
    CollectorOutsideSubjectScope,
    NoObservationCompletedBeforeTransition,
    CumulativeCountersNoAttribution,
    NoCompatibleCounterInterval,
    PlatformRadioTelemetryUnavailable,
    SampledHostAccountingNoEndpointProtocolPeerPersonOrIntent,
    CacheNotLivenessIdentityActivityOrTraffic,
    NativeSourcesFailed { sources: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum CompletedPathWindowLimitation {
    ProcessLocalCappedRetention { maximum_windows: u64 },
    ImmutableAfterPathTransition,
    NotCurrentPathEvidence,
    NotPersisted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompletedPathWindowCollectorScope {
    pub subject: MonitorMode,
    pub interface_counters: bool,
    pub radio_link: bool,
    pub workload_accounting: bool,
    pub neighbor_cache: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompletedPathWindowTransition {
    pub reason: &'static str,
    pub observed_at_ms: u64,
    pub next_generation: u64,
    pub changed_dimensions: Vec<&'static str>,
    pub previous: String,
    pub current: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CompletedInterfaceWindow {
    pub state: CompletedPathWindowSupportState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<CompletedPathWindowSource>,
    pub samples: u64,
    pub valid_intervals: u64,
    pub counter_resets: u64,
    pub received_bytes_delta: u64,
    pub transmitted_bytes_delta: u64,
    pub received_packets_delta: u64,
    pub transmitted_packets_delta: u64,
    pub current_rate: Option<InterfaceRate>,
    pub peak_received_bits_per_second: Option<f64>,
    pub peak_transmitted_bits_per_second: Option<f64>,
    pub error_delta: u64,
    pub drop_delta: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<CompletedPathWindowSupportLimitation>,
}

pub const TRAFFIC_SHAPE_CANDIDATE_SCHEMA_V0: &str = "linktop.traffic_shape_candidate.v0";
pub const PATH_FINGERPRINT_CANDIDATE_SCHEMA_V0: &str = "linktop.path_fingerprint_candidate.v0";

/// A deterministic comparison candidate for completed host-path episodes.
///
/// The digest is useful for grouping repeated observed path shapes. It is not
/// a device, person, place, endpoint, protocol, application, or intent
/// identity, and omitted dimensions are not evidence that they matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PathFingerprintCandidateV0 {
    pub schema: &'static str,
    pub observer: String,
    pub digest: String,
    pub basis: Vec<&'static str>,
    pub caveats: Vec<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficShapeDirectionV0 {
    NoObservedTraffic,
    ReceiveDominant,
    TransmitDominant,
    Bidirectional,
}

/// Aggregate counter features that may help compare path episodes.
///
/// This is a candidate traffic shape only. It does not identify an endpoint,
/// protocol, application, person, place, or intent.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TrafficShapeCandidateV0 {
    pub schema: &'static str,
    pub observed_span_ms: u64,
    pub valid_intervals: u64,
    pub direction: TrafficShapeDirectionV0,
    pub received_bytes_delta: u64,
    pub transmitted_bytes_delta: u64,
    pub received_packets_delta: u64,
    pub transmitted_packets_delta: u64,
    pub mean_received_bits_per_second: Option<f64>,
    pub mean_transmitted_bits_per_second: Option<f64>,
    pub peak_received_bits_per_second: Option<f64>,
    pub peak_transmitted_bits_per_second: Option<f64>,
    pub mean_received_packet_bytes: Option<f64>,
    pub mean_transmitted_packet_bytes: Option<f64>,
    pub caveats: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CompletedRadioWindow {
    pub state: CompletedPathWindowSupportState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<CompletedPathWindowSource>,
    pub applicable: bool,
    pub observation_completed: bool,
    pub samples: u64,
    pub latest_signal_dbm: Option<f64>,
    pub worst_signal_dbm: Option<f64>,
    pub latest_signal_percent: Option<f64>,
    pub worst_signal_percent: Option<f64>,
    pub latest_channel: Option<u32>,
    pub channel_changes: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<CompletedPathWindowSupportLimitation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompletedWorkloadWindow {
    pub state: CompletedPathWindowSupportState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<CompletedPathWindowSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_snapshot_health: Option<Health>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_snapshot_detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_snapshot_source: Option<String>,
    pub sampled_windows: u64,
    pub observed_span_ms: u64,
    pub latest_window_top: Option<ProcessTraffic>,
    pub peak_window_top: Option<ProcessTraffic>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<CompletedPathWindowSupportLimitation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompletedNeighborWindow {
    pub state: CompletedPathWindowSupportState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<CompletedPathWindowSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_snapshot_health: Option<Health>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_snapshot_detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_snapshot_path_filter: Option<PeerPathFilter>,
    pub snapshot_observations: u64,
    pub sources: Vec<String>,
    pub failed_sources: Vec<String>,
    pub dwell: PeerDwellSummary,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<CompletedPathWindowSupportLimitation>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CompletedPathWindow {
    pub generation: u64,
    pub path_identity: DwellPathIdentity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint_candidate: Option<PathFingerprintCandidateV0>,
    pub observed_span_ms: u64,
    pub completed_by: CompletedPathWindowTransition,
    pub collector_scope: CompletedPathWindowCollectorScope,
    pub interface: CompletedInterfaceWindow,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traffic_shape_candidate: Option<TrafficShapeCandidateV0>,
    pub radio: CompletedRadioWindow,
    pub workload: CompletedWorkloadWindow,
    pub neighbors: CompletedNeighborWindow,
    pub retained_completed_windows: u64,
    pub limitations: Vec<CompletedPathWindowLimitation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LiveEvidence {
    pub path: LinkSnapshot,
    pub interface_counters: Option<InterfaceCounters>,
    pub interface_rate: Option<InterfaceRate>,
    pub probes: Vec<LiveProbeEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_assessment: Option<LiveGatewayAssessmentEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub neighbors: Option<PeerSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workload: Option<LiveWorkloadEvidence>,
    pub dwell: LivePathDwellEvidence,
    pub last_path_change: Option<LivePathChangeEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_path_window: Option<CompletedPathWindow>,
    pub history_context: Option<HistoryContext>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppProjection {
    pub generation: u64,
    pub assessment: LiveAssessment,
    pub progress: Vec<EvidenceProgress>,
    pub evidence: LiveEvidence,
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
    pub gateway_history_metrics: Option<LatencyMetrics>,
    pub peers: PeerSnapshot,
    pub interface_counters: Option<InterfaceCounters>,
    pub interface_rate: Option<InterfaceRate>,
    interface_counters_at: Option<Duration>,
    interface_counters_first_observed_at: Option<Duration>,
    interface_counters_last_observed_at: Option<Duration>,
    pub workload: WorkloadSnapshot,
    workload_observed_at: Option<Duration>,
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
    wifi_observed_at: Option<Duration>,
    wifi_first_sample_at: Option<Duration>,
    wifi_last_sample_at: Option<Duration>,
    pub path_transition_pending: bool,
    probe_policy: ProbePolicy,
    peer_dwell: BTreeMap<PeerKey, PeerDwell>,
    peer_baseline_seen: bool,
    peer_snapshot_observations: u64,
    peer_snapshot_first_observed_at: Option<Duration>,
    peer_snapshot_last_observed_at: Option<Duration>,
    peer_window_sources: BTreeSet<String>,
    peer_window_failed_sources: BTreeSet<String>,
    last_reduced_at: Duration,
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
            gateway_history_metrics: None,
            peers: PeerSnapshot::pending(),
            interface_counters: None,
            interface_rate: None,
            interface_counters_at: None,
            interface_counters_first_observed_at: None,
            interface_counters_last_observed_at: None,
            workload: WorkloadSnapshot::pending(),
            workload_observed_at: None,
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
            wifi_observed_at: None,
            wifi_first_sample_at: None,
            wifi_last_sample_at: None,
            path_transition_pending: false,
            probe_policy,
            peer_dwell: BTreeMap::new(),
            peer_baseline_seen: false,
            peer_snapshot_observations: 0,
            peer_snapshot_first_observed_at: None,
            peer_snapshot_last_observed_at: None,
            peer_window_sources: BTreeSet::new(),
            peer_window_failed_sources: BTreeSet::new(),
            last_reduced_at: Duration::ZERO,
        };
        app.push_event_at(
            EventKind::Session,
            Health::Running,
            "instrument started",
            Duration::ZERO,
        );
        app
    }

    pub fn apply(&mut self, update: MonitorUpdate) -> bool {
        let observed_at = self.uptime();
        self.apply_at(update, observed_at)
    }

    /// Reduce one admitted update at its session-relative receipt time.
    ///
    /// Replay callers supply logical schedule time; live callers use [`Self::apply`].
    pub(crate) fn apply_at(&mut self, update: MonitorUpdate, observed_at: Duration) -> bool {
        if !self.accepts_update(&update) {
            return false;
        }
        if observed_at < self.last_reduced_at {
            return false;
        }
        self.last_reduced_at = observed_at;
        match update {
            MonitorUpdate::Link {
                generation,
                snapshot: mut link,
            } => {
                if generation < self.path_generation {
                    return false;
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
                    return true;
                }

                let initial = self.path_generation == 0;
                let previous_fingerprint = self.link.path_fingerprint();
                let current_fingerprint = link.path_fingerprint();
                let previous = self.link.path_label();
                let current = link.path_label();
                let path_change = (!initial).then(|| PathChange {
                    elapsed: observed_at,
                    dimensions: previous_fingerprint.changed_dimensions(&current_fingerprint),
                    previous: previous.clone(),
                    current: current.clone(),
                });
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
                        completed_by: path_change
                            .as_ref()
                            .expect("non-initial path has a transition")
                            .clone(),
                        next_generation: generation,
                        dwell,
                        peers,
                        radio_applicable: self.link.observation_link_type() == Some("wifi"),
                        wifi_observation_settled: self.wifi_observation_settled,
                        workload_latest_health: self.workload.health,
                        workload_latest_detail: self.workload.detail.clone(),
                        workload_latest_source: self.workload.source.clone(),
                        peer_snapshot_observations: self.peer_snapshot_observations,
                        peer_latest_health: self.peers.health,
                        peer_latest_detail: self.peers.detail.clone(),
                        peer_latest_path_filter: self.peers.path_filter,
                        peer_sources: self.peer_window_sources.iter().cloned().collect(),
                        peer_failed_sources: self
                            .peer_window_failed_sources
                            .iter()
                            .cloned()
                            .collect(),
                    });
                }
                self.path_generation = generation;
                self.path_transition_pending = false;
                self.link = link;
                self.gateway_samples.clear();
                self.gateway_outcomes.clear();
                self.gateway_attempts = 0;
                self.gateway_history_metrics = None;
                self.interface_counters = None;
                self.interface_counters_at = None;
                self.interface_counters_first_observed_at = None;
                self.interface_counters_last_observed_at = None;
                self.interface_rate = None;
                self.workload = WorkloadSnapshot::pending();
                self.workload_observed_at = None;
                self.path_dwell = PathDwell::default();
                self.peers = PeerSnapshot::pending();
                self.wifi_observation_settled = false;
                self.wifi_observed_at = None;
                self.wifi_first_sample_at = None;
                self.wifi_last_sample_at = None;
                self.peer_dwell.clear();
                self.peer_baseline_seen = false;
                self.peer_snapshot_observations = 0;
                self.peer_snapshot_first_observed_at = None;
                self.peer_snapshot_last_observed_at = None;
                self.peer_window_sources.clear();
                self.peer_window_failed_sources.clear();
                for probe in &mut self.probes {
                    *probe = if self.probe_policy.is_active() {
                        ProbeView::queued(probe.kind)
                    } else {
                        ProbeView::disabled(probe.kind)
                    };
                }
                self.path_observed_since = observed_at;
                self.last_path_change = path_change.clone();
                self.push_event_at(
                    EventKind::Path,
                    Health::Running,
                    if initial {
                        format!("path: {current}")
                    } else {
                        let dimensions = path_change
                            .as_ref()
                            .expect("non-initial path has a transition")
                            .dimensions
                            .join(", ");
                        format!("path changed ({dimensions}): {previous} → {current}")
                    },
                    observed_at,
                );
            }
            MonitorUpdate::PathSettling { generation } => {
                if generation == self.path_generation && !self.path_transition_pending {
                    self.path_transition_pending = true;
                    self.push_event_at(
                        EventKind::Path,
                        Health::Running,
                        "default route is settling; retaining the last confirmed path",
                        observed_at,
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
                    self.wifi_observed_at = Some(observed_at);
                    if let Some(telemetry) = &telemetry {
                        self.path_dwell.observe_wifi(telemetry);
                        self.wifi_first_sample_at.get_or_insert(observed_at);
                        self.wifi_last_sample_at = Some(observed_at);
                    }
                    if let Some(ssid) = ssid
                        && (self.link.ssid.as_deref() != Some(ssid.as_str())
                            || self.link.ssid_restricted)
                    {
                        self.link.ssid = Some(ssid);
                        self.link.ssid_restricted = false;
                        let current = self.link.path_label();
                        self.push_event_at(
                            EventKind::Path,
                            Health::Ok,
                            format!("Wi-Fi network identity resolved: {current}"),
                            observed_at,
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
                    return false;
                }
                self.peer_snapshot_observations = self.peer_snapshot_observations.saturating_add(1);
                self.peer_snapshot_first_observed_at
                    .get_or_insert(observed_at);
                self.peer_snapshot_last_observed_at = Some(observed_at);
                self.peer_window_sources
                    .extend(snapshot.sources.iter().cloned());
                self.peer_window_failed_sources
                    .extend(snapshot.failed_sources.iter().cloned());
                self.apply_peer_snapshot(snapshot, observed_at);
            }
            MonitorUpdate::Traffic {
                generation,
                counters,
            } => {
                if generation != self.path_generation {
                    return false;
                }
                let prior = self.interface_counters.as_ref();
                let interval = prior
                    .zip(self.interface_counters_at)
                    .zip(counters.as_ref())
                    .and_then(|((before, prior_observed_at), after)| {
                        observed_at
                            .checked_sub(prior_observed_at)
                            .and_then(|elapsed| interface_interval(before, after, elapsed))
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
                self.interface_counters_at = self.interface_counters.as_ref().map(|_| observed_at);
                if self.interface_counters.is_some() {
                    self.interface_counters_first_observed_at
                        .get_or_insert(observed_at);
                    self.interface_counters_last_observed_at = Some(observed_at);
                }
            }
            MonitorUpdate::Workload {
                generation,
                snapshot,
            } => {
                if generation == self.path_generation {
                    self.path_dwell.observe_workload(&snapshot);
                    self.workload = snapshot;
                    self.workload_observed_at = Some(observed_at);
                }
            }
            MonitorUpdate::ProbeStarted { generation, kind } => {
                if generation != self.path_generation || !self.probe_policy.is_active() {
                    return false;
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
                    return false;
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
                    self.gateway_history_metrics = Some(LatencyMetrics::from_samples(
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
                probe.updated_at = Some(observed_at);

                if previous != health && (previous != Health::Running || health.is_problem()) {
                    self.push_event_at(
                        EventKind::Probe,
                        health,
                        format!("{}: {}", kind.label(), detail),
                        observed_at,
                    );
                }
            }
            MonitorUpdate::Notice(message) => {
                self.push_event_at(EventKind::Notice, Health::Running, message, observed_at)
            }
        }
        true
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
        self.gateway_history_metrics = None;
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

        if !self.probe_policy.is_active()
            && self.path_generation == 0
            && self.link.interface.is_none()
        {
            return Situation {
                health: Health::Running,
                kind: SituationKind::Collecting,
            };
        }

        if !self.probe_policy.is_active() && self.link.interface.is_none() {
            return Situation {
                health: Health::Unavailable,
                kind: SituationKind::EvidenceGap,
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

        let link_available = self.link.interface.is_some();
        let link_incomplete = self.link.interface.is_none()
            || self.link.resolvers.is_empty()
            || self.link.addresses.is_empty()
            || (self.link.requires_underlay_evidence() && self.link.underlay.is_none())
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

    pub(crate) fn latest_completed_path_window(
        &self,
        mode: MonitorMode,
    ) -> Option<CompletedPathWindow> {
        let completed = self.completed_path_dwells.back()?;
        let scope = mode.dwell_collector_scope();

        let source = |collected: bool, value| collected.then_some(value);

        let interface = &completed.dwell.interface;
        let mut interface_limitations = Vec::new();
        if !scope.interface {
            interface_limitations
                .push(CompletedPathWindowSupportLimitation::CollectorOutsideSubjectScope);
        } else {
            interface_limitations
                .push(CompletedPathWindowSupportLimitation::CumulativeCountersNoAttribution);
            if interface.samples == 0 {
                interface_limitations.push(
                    CompletedPathWindowSupportLimitation::NoObservationCompletedBeforeTransition,
                );
            }
            if interface.valid_intervals == 0 {
                interface_limitations
                    .push(CompletedPathWindowSupportLimitation::NoCompatibleCounterInterval);
            }
        }

        let wifi = &completed.dwell.wifi;
        let mut radio_limitations = Vec::new();
        if !scope.wifi {
            radio_limitations
                .push(CompletedPathWindowSupportLimitation::CollectorOutsideSubjectScope);
        } else if completed.radio_applicable && wifi.samples == 0 {
            radio_limitations.push(if completed.wifi_observation_settled {
                CompletedPathWindowSupportLimitation::PlatformRadioTelemetryUnavailable
            } else {
                CompletedPathWindowSupportLimitation::NoObservationCompletedBeforeTransition
            });
        }

        let workload = &completed.dwell.workload;
        let mut workload_limitations = Vec::new();
        if !scope.workload {
            workload_limitations
                .push(CompletedPathWindowSupportLimitation::CollectorOutsideSubjectScope);
        } else {
            workload_limitations.push(
                CompletedPathWindowSupportLimitation::SampledHostAccountingNoEndpointProtocolPeerPersonOrIntent,
            );
            if workload.sampled_windows == 0 {
                workload_limitations.push(
                    CompletedPathWindowSupportLimitation::NoObservationCompletedBeforeTransition,
                );
            }
        }

        let mut neighbor_limitations = Vec::new();
        if !scope.peers {
            neighbor_limitations
                .push(CompletedPathWindowSupportLimitation::CollectorOutsideSubjectScope);
        } else {
            neighbor_limitations.push(
                CompletedPathWindowSupportLimitation::CacheNotLivenessIdentityActivityOrTraffic,
            );
            if completed.peer_snapshot_observations == 0 {
                neighbor_limitations.push(
                    CompletedPathWindowSupportLimitation::NoObservationCompletedBeforeTransition,
                );
            }
            if !completed.peer_failed_sources.is_empty() {
                neighbor_limitations.push(
                    CompletedPathWindowSupportLimitation::NativeSourcesFailed {
                        sources: completed.peer_failed_sources.clone(),
                    },
                );
            }
        }

        let workload_state = if !scope.workload {
            CompletedPathWindowSupportState::NotCollected
        } else if workload.sampled_windows == 0 {
            CompletedPathWindowSupportState::Unavailable
        } else if completed.workload_latest_health == Health::Ok {
            CompletedPathWindowSupportState::Available
        } else {
            CompletedPathWindowSupportState::Partial
        };
        let neighbor_state = if !scope.peers {
            CompletedPathWindowSupportState::NotCollected
        } else if completed.peer_snapshot_observations == 0 || completed.peer_sources.is_empty() {
            CompletedPathWindowSupportState::Unavailable
        } else if !completed.peer_failed_sources.is_empty() {
            CompletedPathWindowSupportState::Partial
        } else {
            match completed.peer_latest_health {
                Health::Ok => CompletedPathWindowSupportState::Available,
                Health::Unavailable
                | Health::Failed
                | Health::Queued
                | Health::Degraded
                | Health::Running => CompletedPathWindowSupportState::Partial,
            }
        };
        let traffic_shape_candidate = scope
            .interface
            .then(|| traffic_shape_candidate_from_dwell(interface, duration_ms(completed.observed)))
            .flatten();

        Some(CompletedPathWindow {
            generation: completed.generation,
            path_identity: completed.identity.clone(),
            fingerprint_candidate: path_fingerprint_candidate_from_identity(&completed.identity),
            observed_span_ms: duration_ms(completed.observed),
            completed_by: CompletedPathWindowTransition {
                reason: "path_transition",
                observed_at_ms: duration_ms(completed.completed_by.elapsed),
                next_generation: completed.next_generation,
                changed_dimensions: completed.completed_by.dimensions.clone(),
                previous: completed.completed_by.previous.clone(),
                current: completed.completed_by.current.clone(),
            },
            collector_scope: CompletedPathWindowCollectorScope {
                subject: mode,
                interface_counters: scope.interface,
                radio_link: scope.wifi,
                workload_accounting: scope.workload,
                neighbor_cache: scope.peers,
            },
            interface: CompletedInterfaceWindow {
                state: if !scope.interface {
                    CompletedPathWindowSupportState::NotCollected
                } else if interface.samples == 0 {
                    CompletedPathWindowSupportState::Unavailable
                } else if interface.valid_intervals == 0 {
                    CompletedPathWindowSupportState::Partial
                } else {
                    CompletedPathWindowSupportState::Available
                },
                source: source(
                    scope.interface,
                    CompletedPathWindowSource::KernelInterfaceCounters,
                ),
                samples: if scope.interface {
                    interface.samples
                } else {
                    0
                },
                valid_intervals: if scope.interface {
                    interface.valid_intervals
                } else {
                    0
                },
                counter_resets: if scope.interface {
                    interface.counter_resets
                } else {
                    0
                },
                received_bytes_delta: if scope.interface {
                    interface.received_bytes_delta
                } else {
                    0
                },
                transmitted_bytes_delta: if scope.interface {
                    interface.transmitted_bytes_delta
                } else {
                    0
                },
                received_packets_delta: if scope.interface {
                    interface.received_packets_delta
                } else {
                    0
                },
                transmitted_packets_delta: if scope.interface {
                    interface.transmitted_packets_delta
                } else {
                    0
                },
                current_rate: scope
                    .interface
                    .then(|| interface.current_rate.clone())
                    .flatten(),
                peak_received_bits_per_second: scope
                    .interface
                    .then_some(interface.peak_received_bits_per_second)
                    .flatten(),
                peak_transmitted_bits_per_second: scope
                    .interface
                    .then_some(interface.peak_transmitted_bits_per_second)
                    .flatten(),
                error_delta: if scope.interface {
                    interface.error_delta
                } else {
                    0
                },
                drop_delta: if scope.interface {
                    interface.drop_delta
                } else {
                    0
                },
                limitations: interface_limitations,
            },
            traffic_shape_candidate,
            radio: CompletedRadioWindow {
                state: if !scope.wifi {
                    CompletedPathWindowSupportState::NotCollected
                } else if !completed.radio_applicable {
                    CompletedPathWindowSupportState::Unsupported
                } else if wifi.samples > 0 {
                    CompletedPathWindowSupportState::Available
                } else {
                    CompletedPathWindowSupportState::Unavailable
                },
                source: source(
                    scope.wifi && completed.radio_applicable,
                    CompletedPathWindowSource::PlatformRadioTelemetry,
                ),
                applicable: completed.radio_applicable,
                observation_completed: scope.wifi
                    && completed.radio_applicable
                    && completed.wifi_observation_settled,
                samples: if scope.wifi { wifi.samples } else { 0 },
                latest_signal_dbm: scope.wifi.then_some(wifi.latest_signal_dbm).flatten(),
                worst_signal_dbm: scope.wifi.then_some(wifi.worst_signal_dbm).flatten(),
                latest_signal_percent: scope.wifi.then_some(wifi.latest_signal_percent).flatten(),
                worst_signal_percent: scope.wifi.then_some(wifi.worst_signal_percent).flatten(),
                latest_channel: scope.wifi.then_some(wifi.latest_channel).flatten(),
                channel_changes: if scope.wifi { wifi.channel_changes } else { 0 },
                limitations: radio_limitations,
            },
            workload: CompletedWorkloadWindow {
                state: workload_state,
                source: source(
                    scope.workload,
                    CompletedPathWindowSource::SampledHostProcessAccounting,
                ),
                latest_snapshot_health: scope.workload.then_some(completed.workload_latest_health),
                latest_snapshot_detail: scope
                    .workload
                    .then(|| completed.workload_latest_detail.clone()),
                latest_snapshot_source: scope
                    .workload
                    .then(|| completed.workload_latest_source.clone())
                    .flatten(),
                sampled_windows: if scope.workload {
                    workload.sampled_windows
                } else {
                    0
                },
                observed_span_ms: if scope.workload {
                    duration_ms(workload.observed)
                } else {
                    0
                },
                latest_window_top: scope
                    .workload
                    .then(|| workload.latest_window_top.clone())
                    .flatten(),
                peak_window_top: scope
                    .workload
                    .then(|| workload.peak_window_top.clone())
                    .flatten(),
                limitations: workload_limitations,
            },
            neighbors: CompletedNeighborWindow {
                state: neighbor_state,
                source: source(scope.peers, CompletedPathWindowSource::NativeNeighborCache),
                latest_snapshot_health: scope.peers.then_some(completed.peer_latest_health),
                latest_snapshot_detail: scope.peers.then(|| completed.peer_latest_detail.clone()),
                latest_snapshot_path_filter: scope
                    .peers
                    .then_some(completed.peer_latest_path_filter),
                snapshot_observations: if scope.peers {
                    completed.peer_snapshot_observations
                } else {
                    0
                },
                sources: if scope.peers {
                    completed.peer_sources.clone()
                } else {
                    Vec::new()
                },
                failed_sources: if scope.peers {
                    completed.peer_failed_sources.clone()
                } else {
                    Vec::new()
                },
                dwell: if scope.peers {
                    completed.peers
                } else {
                    PeerDwellSummary {
                        current: 0,
                        observed: 0,
                        changed: 0,
                        disappeared: 0,
                    }
                },
                limitations: neighbor_limitations,
            },
            retained_completed_windows: self.completed_path_dwells.len() as u64,
            limitations: vec![
                CompletedPathWindowLimitation::ProcessLocalCappedRetention {
                    maximum_windows: MAX_COMPLETED_PATH_DWELLS as u64,
                },
                CompletedPathWindowLimitation::ImmutableAfterPathTransition,
                CompletedPathWindowLimitation::NotCurrentPathEvidence,
                CompletedPathWindowLimitation::NotPersisted,
            ],
        })
    }

    pub fn projection(&self, mode: MonitorMode) -> AppProjection {
        let situation = self.situation();
        let progress = self.evidence_progress(mode);
        let path_status = if !self.probe_policy.is_active() {
            PathStatus::Untested
        } else {
            match situation.health {
                Health::Ok => PathStatus::Ok,
                Health::Degraded => PathStatus::Degraded,
                Health::Failed => PathStatus::Failed,
                Health::Queued | Health::Running | Health::Unavailable => PathStatus::Unavailable,
            }
        };
        let observed_span = self.uptime().saturating_sub(self.path_observed_since);
        let gateway_outcomes = self.gateway_assessment_outcomes();
        let gateway_successes = gateway_outcomes.iter().flatten().count() as u64;
        AppProjection {
            generation: self.path_generation,
            assessment: LiveAssessment {
                situation,
                path_status,
                evidence_coverage: self.evidence_coverage_for(mode, &progress),
            },
            progress,
            evidence: LiveEvidence {
                path: self.link.clone(),
                interface_counters: self.interface_counters.clone(),
                interface_rate: self.interface_rate.clone(),
                probes: if mode == MonitorMode::Overview {
                    self.probes
                        .iter()
                        .map(|probe| LiveProbeEvidence {
                            kind: probe.kind,
                            health: probe.health,
                            detail: probe.detail.clone(),
                            latency_ms: probe.latency_ms,
                            metrics: probe.metrics.clone(),
                            age_ms: self.probe_age(probe.kind).map(duration_ms),
                        })
                        .collect()
                } else {
                    Vec::new()
                },
                gateway_assessment: (mode == MonitorMode::Overview).then(|| {
                    LiveGatewayAssessmentEvidence {
                        attempts: gateway_outcomes.len() as u64,
                        successful_attempts: gateway_successes,
                        required_attempts: MIN_GATEWAY_ASSESSMENT_SAMPLES as u64,
                        maximum_attempts: GATEWAY_ASSESSMENT_WINDOW as u64,
                        metrics: self.gateway_assessment_metrics(),
                    }
                }),
                neighbors: mode
                    .dwell_collector_scope()
                    .peers
                    .then(|| self.peers.clone()),
                workload: mode
                    .dwell_collector_scope()
                    .workload
                    .then(|| LiveWorkloadEvidence {
                        health: self.workload.health,
                        detail: self.workload.detail.clone(),
                        source: self.workload.source.clone(),
                        interval_ms: duration_ms(self.workload.interval),
                        processes: self.workload.processes.clone(),
                    }),
                dwell: LivePathDwellEvidence {
                    observed_span_ms: duration_ms(observed_span),
                    interface_samples: self.path_dwell.interface.samples,
                    interface_valid_intervals: self.path_dwell.interface.valid_intervals,
                    wifi_samples: self.path_dwell.wifi.samples,
                    workload_windows: self.path_dwell.workload.sampled_windows,
                    workload_observed_ms: duration_ms(self.path_dwell.workload.observed),
                    neighbors: self.peer_dwell_summary(),
                },
                last_path_change: self.last_path_change.as_ref().map(|change| {
                    LivePathChangeEvidence {
                        observed_at_ms: duration_ms(change.elapsed),
                        dimensions: change.dimensions.clone(),
                        previous: change.previous.clone(),
                        current: change.current.clone(),
                    }
                }),
                completed_path_window: self.latest_completed_path_window(mode),
                history_context: self.history_context.clone(),
            },
        }
    }

    pub fn final_projection(&self, mode: MonitorMode) -> AppProjection {
        let mut projection = self.projection(mode);
        for progress in &mut projection.progress {
            if progress.state != EvidenceProgressState::Collecting {
                continue;
            }
            progress.state = if progress.observations.unwrap_or_default() > 0 {
                EvidenceProgressState::Insufficient
            } else {
                EvidenceProgressState::Unavailable
            };
            progress
                .limitations
                .push(EvidenceLimitation::BoundedAcquisitionEndedBeforeAvailability);
        }
        if projection.assessment.evidence_coverage == EvidenceCoverage::Collecting {
            projection.assessment.evidence_coverage = if projection
                .progress
                .iter()
                .any(|progress| progress.state == EvidenceProgressState::Available)
            {
                EvidenceCoverage::Partial
            } else {
                EvidenceCoverage::Unavailable
            };
        }
        if projection.assessment.situation.kind == SituationKind::Collecting {
            projection.assessment.situation = Situation {
                health: Health::Unavailable,
                kind: SituationKind::EvidenceGap,
            };
            projection.assessment.path_status = PathStatus::Unavailable;
        }
        projection
    }

    fn evidence_coverage_for(
        &self,
        mode: MonitorMode,
        progress: &[EvidenceProgress],
    ) -> EvidenceCoverage {
        if mode == MonitorMode::Overview {
            return self.evidence_coverage();
        }

        let relevant = progress.iter().filter(|item| {
            !matches!(
                item.state,
                EvidenceProgressState::NotCollected | EvidenceProgressState::Unsupported
            )
        });
        let states = relevant.map(|item| item.state).collect::<Vec<_>>();
        if states.contains(&EvidenceProgressState::Collecting) {
            return EvidenceCoverage::Collecting;
        }
        if states.iter().all(|state| {
            matches!(
                state,
                EvidenceProgressState::Unavailable | EvidenceProgressState::Stale
            )
        }) {
            return EvidenceCoverage::Unavailable;
        }
        if states
            .iter()
            .any(|state| *state != EvidenceProgressState::Available)
        {
            EvidenceCoverage::Partial
        } else {
            EvidenceCoverage::Complete
        }
    }

    pub fn evidence_progress(&self, mode: MonitorMode) -> Vec<EvidenceProgress> {
        let scope = mode.dwell_collector_scope();
        let generation = self.path_generation;
        let interface = self.link.observation_interface().unwrap_or("unavailable");
        let uptime = self.uptime();
        let path_span = duration_ms(uptime.saturating_sub(self.path_observed_since));
        let mut progress = Vec::with_capacity(11);

        let path_available = self.link.interface.is_some();
        let mut path = EvidenceProgress::new(
            EvidenceClaim::PathContext,
            if self.path_transition_pending || !path_available {
                EvidenceProgressState::Collecting
            } else {
                EvidenceProgressState::Available
            },
            EvidenceBasis::Observed,
            EvidenceScope::CurrentPathGeneration {
                generation,
                subject: "effective default route and corroborated physical underlay".into(),
            },
        );
        path.observations = path_available.then_some(1);
        path.observed_span_ms = path_available.then_some(path_span);
        if self.path_transition_pending {
            path.limitations
                .push(EvidenceLimitation::RouteSettlingLastConfirmed);
        }
        progress.push(path);

        let mut totals = EvidenceProgress::new(
            EvidenceClaim::InterfaceTotals,
            collector_state(
                scope.interface,
                self.interface_counters.is_some(),
                EvidenceProgressState::Collecting,
            ),
            EvidenceBasis::Observed,
            EvidenceScope::CurrentSample {
                generation,
                subject: format!("interface {interface} cumulative counters"),
            },
        );
        if scope.interface && self.interface_counters.is_some() {
            totals.observations = Some(self.path_dwell.interface.samples.max(1));
            totals.observed_span_ms = observation_span_ms(
                self.interface_counters_first_observed_at,
                self.interface_counters_last_observed_at,
            );
            totals.source_age_ms = self
                .interface_counters_last_observed_at
                .map(|observed_at| duration_ms(uptime.saturating_sub(observed_at)));
            totals
                .limitations
                .push(EvidenceLimitation::CumulativeCountersNoAttribution);
        }
        progress.push(totals);

        let mut rate = EvidenceProgress::new(
            EvidenceClaim::InterfaceRate,
            if !scope.interface {
                EvidenceProgressState::NotCollected
            } else if self.interface_rate.is_some() {
                EvidenceProgressState::Available
            } else if self.interface_counters.is_some() {
                EvidenceProgressState::Insufficient
            } else {
                EvidenceProgressState::Collecting
            },
            EvidenceBasis::Derived,
            EvidenceScope::CurrentPathGeneration {
                generation,
                subject: format!("compatible counter deltas for interface {interface}"),
            },
        );
        if scope.interface {
            rate.observations = Some(self.path_dwell.interface.samples);
            rate.required_observations = Some(2);
            rate.valid_intervals = Some(self.path_dwell.interface.valid_intervals);
            rate.observed_span_ms = observation_span_ms(
                self.interface_counters_first_observed_at,
                self.interface_counters_last_observed_at,
            );
            rate.source_age_ms = self
                .interface_counters_last_observed_at
                .map(|observed_at| duration_ms(uptime.saturating_sub(observed_at)));
            if rate.state == EvidenceProgressState::Insufficient {
                rate.limitations
                    .push(EvidenceLimitation::MinimumCompatibleCounterObservations { required: 2 });
            }
            if self.path_dwell.interface.counter_resets > 0 {
                rate.limitations
                    .push(EvidenceLimitation::CounterResetsExcluded {
                        count: self.path_dwell.interface.counter_resets,
                    });
            }
        }
        progress.push(rate);

        let mut radio = EvidenceProgress::new(
            EvidenceClaim::RadioLink,
            if !scope.wifi {
                EvidenceProgressState::NotCollected
            } else if self.link.observation_link_type().is_none() {
                EvidenceProgressState::Collecting
            } else if !self.link.requires_radio_evidence() {
                EvidenceProgressState::Unsupported
            } else if self.link.wifi.is_some() {
                EvidenceProgressState::Available
            } else if self.wifi_observation_settled {
                EvidenceProgressState::Unavailable
            } else {
                EvidenceProgressState::Collecting
            },
            EvidenceBasis::Observed,
            EvidenceScope::CurrentPathGeneration {
                generation,
                subject: format!("associated interface {interface} radio link"),
            },
        );
        if scope.wifi {
            radio.observations = Some(
                self.path_dwell
                    .wifi
                    .samples
                    .max(u64::from(self.link.wifi.is_some())),
            );
            radio.observed_span_ms =
                observation_span_ms(self.wifi_first_sample_at, self.wifi_last_sample_at);
            radio.source_age_ms = self
                .wifi_observed_at
                .map(|observed_at| duration_ms(uptime.saturating_sub(observed_at)));
            if radio.state == EvidenceProgressState::Unavailable {
                radio
                    .limitations
                    .push(EvidenceLimitation::PlatformRadioTelemetryUnavailable);
            }
        }
        progress.push(radio);

        let mut neighbors = EvidenceProgress::new(
            EvidenceClaim::NeighborCache,
            if !scope.peers {
                EvidenceProgressState::NotCollected
            } else {
                match self.peers.health {
                    Health::Queued | Health::Running => EvidenceProgressState::Collecting,
                    Health::Unavailable | Health::Failed => EvidenceProgressState::Unavailable,
                    Health::Ok | Health::Degraded => EvidenceProgressState::Available,
                }
            },
            EvidenceBasis::Observed,
            EvidenceScope::CurrentPathGeneration {
                generation,
                subject: format!(
                    "native cache rows filtered to interface {interface} and current path prefixes"
                ),
            },
        );
        if scope.peers {
            neighbors.observations = self
                .peer_baseline_seen
                .then_some(self.peer_snapshot_observations);
            neighbors.observed_span_ms = observation_span_ms(
                self.peer_snapshot_first_observed_at,
                self.peer_snapshot_last_observed_at,
            );
            neighbors.source_age_ms = self
                .peer_snapshot_last_observed_at
                .map(|observed_at| duration_ms(uptime.saturating_sub(observed_at)));
            if !self.peers.failed_sources.is_empty() {
                neighbors
                    .limitations
                    .push(EvidenceLimitation::NativeSourcesUnavailable {
                        sources: self.peers.failed_sources.clone(),
                    });
            }
            neighbors
                .limitations
                .push(EvidenceLimitation::CacheNotLivenessIdentityActivityOrTraffic);
        }
        progress.push(neighbors);

        let mut workload = EvidenceProgress::new(
            EvidenceClaim::WorkloadAttribution,
            if !scope.workload {
                EvidenceProgressState::NotCollected
            } else {
                match self.workload.health {
                    Health::Queued | Health::Running => EvidenceProgressState::Collecting,
                    Health::Unavailable | Health::Failed => EvidenceProgressState::Unavailable,
                    Health::Ok | Health::Degraded => EvidenceProgressState::Available,
                }
            },
            EvidenceBasis::Observed,
            EvidenceScope::CurrentPathGeneration {
                generation,
                subject: "sampled host process-accounting windows on external interfaces".into(),
            },
        );
        if scope.workload {
            workload.observations = Some(self.path_dwell.workload.sampled_windows);
            workload.observed_span_ms = Some(duration_ms(self.path_dwell.workload.observed));
            workload.source_age_ms = self
                .workload_observed_at
                .map(|observed_at| duration_ms(uptime.saturating_sub(observed_at)));
            workload.limitations.push(
                EvidenceLimitation::SampledHostAccountingNoEndpointProtocolPeerPersonOrIntent,
            );
        }
        progress.push(workload);

        for (claim, kind) in [
            (EvidenceClaim::GatewayRtt, ProbeKind::Gateway),
            (EvidenceClaim::DnsReachability, ProbeKind::Dns),
            (EvidenceClaim::HttpsReachability, ProbeKind::Https),
            (EvidenceClaim::PublicEgress, ProbeKind::PublicIp),
        ] {
            let probe = self.probe(kind);
            let mut item = EvidenceProgress::new(
                claim,
                if !self.probe_policy.is_active() {
                    EvidenceProgressState::NotCollected
                } else if self.probe_is_stale(kind) {
                    EvidenceProgressState::Stale
                } else {
                    match probe.health {
                        Health::Queued | Health::Running => EvidenceProgressState::Collecting,
                        Health::Unavailable => EvidenceProgressState::Unavailable,
                        Health::Ok | Health::Degraded | Health::Failed => {
                            EvidenceProgressState::Available
                        }
                    }
                },
                EvidenceBasis::Observed,
                probe_scope(generation, kind, self.link.observation_gateway()),
            );
            if self.probe_policy.is_active() {
                item.observations = probe.updated_at.map(|_| 1);
                item.source_age_ms = self.probe_age(kind).map(duration_ms);
                if self.probe_is_stale(kind) {
                    item.limitations
                        .push(EvidenceLimitation::OlderThanAssessmentFreshnessWindow);
                }
                if kind == ProbeKind::PublicIp {
                    item.limitations
                        .push(EvidenceLimitation::PublicEgressNotReachabilityDependency);
                }
            }
            progress.push(item);
        }

        let gateway_outcomes = self.gateway_assessment_outcomes();
        let gateway_attempts = gateway_outcomes.len();
        let gateway_successes = gateway_outcomes.iter().flatten().count();
        let mut variation = EvidenceProgress::new(
            EvidenceClaim::GatewayVariation,
            if !self.probe_policy.is_active() {
                EvidenceProgressState::NotCollected
            } else if gateway_attempts == 0 {
                EvidenceProgressState::Collecting
            } else if gateway_attempts < MIN_GATEWAY_ASSESSMENT_SAMPLES {
                EvidenceProgressState::Insufficient
            } else {
                EvidenceProgressState::Available
            },
            EvidenceBasis::Derived,
            EvidenceScope::AssessmentWindow {
                generation,
                subject: "next-hop RTT variation".into(),
                maximum_observations: GATEWAY_ASSESSMENT_WINDOW as u64,
            },
        );
        if self.probe_policy.is_active() {
            variation.observations = Some(gateway_attempts as u64);
            variation.required_observations = Some(MIN_GATEWAY_ASSESSMENT_SAMPLES as u64);
            if variation.state == EvidenceProgressState::Insufficient {
                variation
                    .limitations
                    .push(EvidenceLimitation::MinimumCurrentGenerationAttempts {
                        required: MIN_GATEWAY_ASSESSMENT_SAMPLES as u64,
                    });
            }
            variation.successful_observations = Some(gateway_successes as u64);
            if gateway_attempts >= MIN_GATEWAY_ASSESSMENT_SAMPLES && gateway_successes < 2 {
                variation.state = EvidenceProgressState::Insufficient;
                variation
                    .limitations
                    .push(EvidenceLimitation::MinimumSuccessfulRttObservations { required: 2 });
            }
        }
        progress.push(variation);

        progress
    }

    pub fn progress_for(&self, mode: MonitorMode, claim: EvidenceClaim) -> EvidenceProgress {
        self.evidence_progress(mode)
            .into_iter()
            .find(|progress| progress.claim == claim)
            .expect("every live projection contains every progress claim")
    }

    pub fn accepts_update(&self, update: &MonitorUpdate) -> bool {
        match update {
            MonitorUpdate::Link { generation, .. } => *generation >= self.path_generation,
            MonitorUpdate::PathSettling { generation }
            | MonitorUpdate::Wifi { generation, .. }
            | MonitorUpdate::Peers { generation, .. }
            | MonitorUpdate::Traffic { generation, .. }
            | MonitorUpdate::Workload { generation, .. } => *generation == self.path_generation,
            MonitorUpdate::ProbeStarted { generation, .. }
            | MonitorUpdate::ProbeFinished { generation, .. } => {
                *generation == self.path_generation && self.probe_policy.is_active()
            }
            MonitorUpdate::Notice(_) => true,
        }
    }

    pub fn gateway_assessment_metrics(&self) -> Option<LatencyMetrics> {
        let outcomes = self.gateway_assessment_outcomes();
        if outcomes.len() < MIN_GATEWAY_ASSESSMENT_SAMPLES {
            return None;
        }
        let samples: Vec<_> = outcomes
            .iter()
            .flatten()
            .map(|sample| *sample as f64)
            .collect();
        Some(LatencyMetrics::from_samples(&samples, outcomes.len()))
    }

    /// Return the outcome of the most recent next-hop probe attempt.
    ///
    /// The outer `Option` distinguishes no attempt from an attempt, while the
    /// inner `Option` distinguishes a reply from a timeout or other no-reply
    /// outcome. `gateway_samples` intentionally retains successful replies for
    /// charting, so it cannot answer this operator-facing "latest attempt"
    /// question on its own.
    pub fn latest_gateway_outcome(&self) -> Option<Option<u64>> {
        self.gateway_outcomes.back().copied()
    }

    fn gateway_assessment_outcomes(&self) -> Vec<Option<u64>> {
        self.gateway_outcomes
            .iter()
            .rev()
            .take(GATEWAY_ASSESSMENT_WINDOW)
            .rev()
            .copied()
            .collect()
    }

    pub fn probe_age(&self, kind: ProbeKind) -> Option<Duration> {
        self.probe(kind)
            .updated_at
            .map(|observed_at| self.uptime().saturating_sub(observed_at))
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

    fn apply_peer_snapshot(&mut self, snapshot: PeerSnapshot, observed_at: Duration) {
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
                    dwell.last_binding_change = Some(observed_at);
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
                    dwell.last_state_change = Some(observed_at);
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
                    dwell.last_cache_return = Some(observed_at);
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
                        last_state_change: None,
                        binding_changes: 0,
                        last_binding_change: None,
                        cache_disappearances: 0,
                        cache_returns: 0,
                        last_cache_return: None,
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
            self.push_event_at(
                EventKind::Peer,
                Health::Ok,
                format!("neighbor cache: {current_count} entries"),
                observed_at,
            );
        }
        for (health, message) in events {
            self.push_event_at(EventKind::Peer, health, message, observed_at);
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
        let observed_at = self.uptime();
        self.push_event_at(kind, health, message, observed_at);
    }

    fn push_event_at(
        &mut self,
        kind: EventKind,
        health: Health,
        message: impl Into<String>,
        observed_at: Duration,
    ) {
        if self.events.len() == MAX_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(Event {
            elapsed: observed_at,
            message: message.into(),
            health,
            kind,
        });
    }
}

fn collector_state(
    collected: bool,
    available: bool,
    pending: EvidenceProgressState,
) -> EvidenceProgressState {
    if !collected {
        EvidenceProgressState::NotCollected
    } else if available {
        EvidenceProgressState::Available
    } else {
        pending
    }
}

fn probe_scope(generation: u64, kind: ProbeKind, gateway: Option<&str>) -> EvidenceScope {
    let subject = match kind {
        ProbeKind::Gateway => format!("configured next hop {}", gateway.unwrap_or("unavailable")),
        ProbeKind::Dns => "configured resolver path resolving example.com".into(),
        ProbeKind::Https => "HTTPS GET to example.com".into(),
        ProbeKind::PublicIp => "bounded public-egress address provider lookup".into(),
    };
    EvidenceScope::CurrentSample {
        generation,
        subject,
    }
}

fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

fn observation_span_ms(first: Option<Duration>, last: Option<Duration>) -> Option<u64> {
    first
        .zip(last)
        .map(|(first, last)| duration_ms(last.saturating_sub(first)))
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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
        let link_coverage = passive_link_coverage(&link, interface_counters.as_ref());
        let neighbor_coverage = passive_peer_coverage(&neighbors);
        let evidence_coverage = if link_coverage == EvidenceCoverage::Unavailable
            && neighbor_coverage == EvidenceCoverage::Unavailable
        {
            EvidenceCoverage::Unavailable
        } else if link_coverage != EvidenceCoverage::Complete
            || neighbor_coverage != EvidenceCoverage::Complete
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

pub(crate) fn passive_link_summary(
    link: &LinkSnapshot,
    interface_counters: Option<&InterfaceCounters>,
) -> SnapshotSummary {
    SnapshotSummary {
        probe_policy: ProbePolicy::Passive,
        path_status: PathStatus::Untested,
        evidence_coverage: passive_link_coverage(link, interface_counters),
        completed_probes: 0,
        total_probes: 0,
    }
}

pub(crate) fn passive_peer_summary(neighbors: &PeerSnapshot) -> SnapshotSummary {
    SnapshotSummary {
        probe_policy: ProbePolicy::Passive,
        path_status: PathStatus::Untested,
        evidence_coverage: passive_peer_coverage(neighbors),
        completed_probes: 0,
        total_probes: 0,
    }
}

fn passive_link_coverage(
    link: &LinkSnapshot,
    interface_counters: Option<&InterfaceCounters>,
) -> EvidenceCoverage {
    let link_available = link.interface.is_some();
    if !link_available && link.wifi.is_none() {
        return EvidenceCoverage::Unavailable;
    }
    if link_evidence_incomplete(link, interface_counters)
        || (link.requires_radio_evidence() && link.wifi.is_none())
    {
        EvidenceCoverage::Partial
    } else {
        EvidenceCoverage::Complete
    }
}

fn passive_peer_coverage(neighbors: &PeerSnapshot) -> EvidenceCoverage {
    if matches!(neighbors.health, Health::Queued | Health::Running) {
        EvidenceCoverage::Collecting
    } else if neighbors.health == Health::Unavailable {
        EvidenceCoverage::Unavailable
    } else if matches!(neighbors.health, Health::Degraded | Health::Failed)
        || !neighbors.failed_sources.is_empty()
        || neighbors.path_filter == PeerPathFilter::Unavailable
    {
        EvidenceCoverage::Partial
    } else if neighbors.path_filter == PeerPathFilter::Pending {
        EvidenceCoverage::Collecting
    } else {
        EvidenceCoverage::Complete
    }
}

fn link_evidence_incomplete(
    link: &LinkSnapshot,
    interface_counters: Option<&InterfaceCounters>,
) -> bool {
    link.interface.is_none()
        || link.resolvers.is_empty()
        || link.addresses.is_empty()
        || (link.requires_underlay_evidence() && link.underlay.is_none())
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
    use proptest::prelude::*;

    #[test]
    fn traffic_shape_candidate_is_bounded_aggregate_feature_evidence() {
        let dwell = InterfaceDwell {
            valid_intervals: 2,
            received_bytes_delta: 9_000,
            transmitted_bytes_delta: 1_000,
            received_packets_delta: 90,
            transmitted_packets_delta: 10,
            peak_received_bits_per_second: Some(100_000.0),
            peak_transmitted_bits_per_second: Some(20_000.0),
            ..InterfaceDwell::default()
        };

        let candidate = traffic_shape_candidate_from_dwell(&dwell, 1_000).unwrap();

        assert_eq!(candidate.schema, TRAFFIC_SHAPE_CANDIDATE_SCHEMA_V0);
        assert_eq!(
            candidate.direction,
            TrafficShapeDirectionV0::ReceiveDominant
        );
        assert_eq!(candidate.mean_received_bits_per_second, Some(72_000.0));
        assert_eq!(candidate.mean_transmitted_bits_per_second, Some(8_000.0));
        assert_eq!(candidate.mean_received_packet_bytes, Some(100.0));
        assert_eq!(candidate.mean_transmitted_packet_bytes, Some(100.0));
        assert!(
            candidate
                .caveats
                .iter()
                .any(|caveat| caveat.contains("not endpoint"))
        );
        assert!(traffic_shape_candidate_from_dwell(&InterfaceDwell::default(), 1_000).is_none());
    }

    #[test]
    fn path_fingerprint_candidate_is_stable_and_explainable() {
        let link = test_link("en0", "house", "192.168.1.1");
        let mut identity = DwellPathIdentity::from_link(&link);
        identity.resolvers.push("192.168.1.2".into());
        identity
            .address_boundaries
            .push(("en0".into(), "192.168.2.0/24".into()));
        let candidate = path_fingerprint_candidate_from_identity(&identity).unwrap();

        assert_eq!(candidate.schema, PATH_FINGERPRINT_CANDIDATE_SCHEMA_V0);
        assert_eq!(candidate.observer, "workstation");
        assert_eq!(candidate.digest.len(), 64);
        assert!(candidate.basis.contains(&"interface"));
        assert!(candidate.basis.contains(&"ssid"));
        assert!(candidate.basis.contains(&"address_boundary"));
        assert!(
            candidate
                .caveats
                .iter()
                .any(|caveat| caveat.contains("not endpoint"))
        );

        let mut reordered = identity.clone();
        reordered.resolvers.reverse();
        reordered.address_boundaries.reverse();
        assert_eq!(
            path_fingerprint_candidate_from_identity(&reordered)
                .unwrap()
                .digest,
            candidate.digest
        );

        let mut changed = identity;
        changed.gateway = Some("192.168.1.254".into());
        assert_ne!(
            path_fingerprint_candidate_from_identity(&changed)
                .unwrap()
                .digest,
            candidate.digest
        );
    }

    #[test]
    fn path_fingerprint_candidate_abstains_without_path_dimensions() {
        let identity = DwellPathIdentity {
            host: "test-host".into(),
            interface: None,
            link_type: None,
            underlay: None,
            ssid: None,
            ssid_restricted: false,
            connection_id: None,
            gateway: None,
            resolvers: Vec::new(),
            address_boundaries: Vec::new(),
        };

        assert!(path_fingerprint_candidate_from_identity(&identity).is_none());
    }

    #[test]
    fn path_fingerprint_candidate_covers_each_field_branch_exactly() {
        let restricted = DwellPathIdentity {
            host: "test-host".into(),
            interface: None,
            link_type: None,
            underlay: None,
            ssid: None,
            ssid_restricted: true,
            connection_id: None,
            gateway: None,
            resolvers: Vec::new(),
            address_boundaries: Vec::new(),
        };
        let restricted_candidate = path_fingerprint_candidate_from_identity(&restricted).unwrap();
        assert_eq!(restricted_candidate.basis, vec!["ssid_restricted"]);

        let underlay = DwellPathIdentity {
            underlay: Some(PathUnderlay {
                interface: "en0".into(),
                link_type: "wifi".into(),
                gateway: Some("192.0.2.1".into()),
            }),
            ssid_restricted: false,
            ..restricted.clone()
        };
        let underlay_candidate = path_fingerprint_candidate_from_identity(&underlay).unwrap();
        assert_eq!(
            underlay_candidate.basis,
            vec![
                "underlay_interface",
                "underlay_link_type",
                "underlay_gateway"
            ]
        );

        let address_and_resolver = DwellPathIdentity {
            resolvers: vec!["192.0.2.53".into(), "192.0.2.53".into()],
            address_boundaries: vec![
                ("en0".into(), "192.0.2.0/24".into()),
                ("en0".into(), "192.0.2.0/24".into()),
            ],
            ssid_restricted: false,
            ..restricted
        };
        let address_candidate =
            path_fingerprint_candidate_from_identity(&address_and_resolver).unwrap();
        assert_eq!(
            address_candidate.basis,
            vec!["resolver", "address_interface", "address_boundary"]
        );
    }

    proptest! {
        #[test]
        fn path_fingerprint_candidate_is_order_stable_and_value_scoped(
            host_suffix in "[a-z0-9]{1,8}",
            interface in prop::option::of("[a-z0-9]{1,8}"),
            link_type in prop::option::of("[a-z0-9]{1,8}"),
            ssid in prop::option::of("[a-z0-9]{1,8}"),
            connection_id in prop::option::of("[a-z0-9]{1,8}"),
            gateway in prop::option::of("[a-z0-9]{1,8}"),
            resolvers in prop::collection::vec("[a-z0-9]{1,8}", 0..5),
            address_boundaries in prop::collection::vec(
                ("[a-z0-9]{1,8}", "[a-z0-9]{1,8}"),
                0..5,
            ),
            ssid_restricted in any::<bool>(),
        ) {
            let identity = DwellPathIdentity {
                host: format!("observer-{host_suffix}"),
                interface: interface.map(|value| format!("value-{value}")),
                link_type: link_type.map(|value| format!("value-{value}")),
                underlay: None,
                ssid: ssid.map(|value| format!("value-{value}")),
                ssid_restricted,
                connection_id: connection_id.map(|value| format!("value-{value}")),
                gateway: gateway.map(|value| format!("value-{value}")),
                resolvers: resolvers
                    .into_iter()
                    .map(|value| format!("value-{value}"))
                    .collect(),
                address_boundaries: address_boundaries
                    .into_iter()
                    .map(|(interface, address)| {
                        (format!("value-{interface}"), format!("value-{address}"))
                    })
                    .collect(),
            };

            let Some(candidate) = path_fingerprint_candidate_from_identity(&identity) else {
                prop_assert!(identity.interface.is_none());
                prop_assert!(identity.link_type.is_none());
                prop_assert!(identity.ssid.is_none());
                prop_assert!(!identity.ssid_restricted);
                prop_assert!(identity.connection_id.is_none());
                prop_assert!(identity.gateway.is_none());
                prop_assert!(identity.resolvers.is_empty());
                prop_assert!(identity.address_boundaries.is_empty());
                return Ok(());
            };

            prop_assert_eq!(&candidate.observer, &identity.host);
            prop_assert_eq!(candidate.digest.len(), 64);
            prop_assert!(candidate.digest.chars().all(|value| value.is_ascii_hexdigit()));

            let mut reordered = identity.clone();
            reordered.resolvers.reverse();
            reordered.address_boundaries.reverse();
            let reordered_candidate =
                path_fingerprint_candidate_from_identity(&reordered).unwrap();
            prop_assert_eq!(&candidate.digest, &reordered_candidate.digest);
            prop_assert_eq!(&candidate.basis, &reordered_candidate.basis);

            let encoded = serde_json::to_string(&candidate).unwrap();
            for value in identity
                .interface
                .iter()
                .chain(identity.link_type.iter())
                .chain(identity.ssid.iter())
                .chain(identity.connection_id.iter())
                .chain(identity.gateway.iter())
                .chain(identity.resolvers.iter())
            {
                prop_assert!(!encoded.contains(value));
            }
            for (interface, address) in &identity.address_boundaries {
                prop_assert!(!encoded.contains(interface));
                prop_assert!(!encoded.contains(address));
            }
        }
    }

    #[test]
    fn traffic_shape_direction_matrix_preserves_ambiguity_and_thresholds() {
        let cases = [
            (0, 0, TrafficShapeDirectionV0::NoObservedTraffic),
            (300, 0, TrafficShapeDirectionV0::ReceiveDominant),
            (0, 300, TrafficShapeDirectionV0::TransmitDominant),
            (300, 100, TrafficShapeDirectionV0::ReceiveDominant),
            (100, 300, TrafficShapeDirectionV0::TransmitDominant),
            (301, 100, TrafficShapeDirectionV0::ReceiveDominant),
            (100, 301, TrafficShapeDirectionV0::TransmitDominant),
            (200, 100, TrafficShapeDirectionV0::Bidirectional),
            (100, 200, TrafficShapeDirectionV0::Bidirectional),
        ];

        for (received, transmitted, expected) in cases {
            let dwell = InterfaceDwell {
                valid_intervals: 1,
                received_bytes_delta: received,
                transmitted_bytes_delta: transmitted,
                ..InterfaceDwell::default()
            };
            let candidate = traffic_shape_candidate_from_dwell(&dwell, 1_000).unwrap();

            assert_eq!(candidate.direction, expected);
            assert_eq!(candidate.received_bytes_delta, received);
            assert_eq!(candidate.transmitted_bytes_delta, transmitted);
        }

        let zero_span = traffic_shape_candidate_from_dwell(
            &InterfaceDwell {
                valid_intervals: 1,
                received_bytes_delta: 1,
                transmitted_bytes_delta: 1,
                ..InterfaceDwell::default()
            },
            0,
        )
        .unwrap();
        assert!(zero_span.mean_received_bits_per_second.is_none());
        assert!(zero_span.mean_transmitted_bits_per_second.is_none());
        assert!(zero_span.mean_received_packet_bytes.is_none());
        assert!(zero_span.mean_transmitted_packet_bytes.is_none());
    }

    #[test]
    fn passive_policy_is_default_and_rejects_late_probe_results() {
        let mut app = App::new();
        assert_eq!(app.probe_policy(), ProbePolicy::Passive);
        assert_eq!(app.situation().kind, SituationKind::Collecting);
        assert!(
            app.probes
                .iter()
                .all(|probe| probe.detail == "active check disabled")
        );

        finish_probe(&mut app, ProbeKind::Gateway, Health::Ok, Some(4.0));
        assert!(app.gateway_samples.is_empty());
        assert_eq!(app.cycles, 0);
        assert_eq!(app.situation().kind, SituationKind::Collecting);
    }

    #[test]
    fn passive_situation_requires_an_observed_path_fact() {
        let mut app = App::new();
        assert_eq!(app.situation().kind, SituationKind::Collecting);

        assert!(app.apply(MonitorUpdate::Link {
            generation: 1,
            snapshot: LinkSnapshot::empty(),
        }));
        assert_eq!(app.situation().kind, SituationKind::EvidenceGap);
        assert_eq!(app.situation().health, Health::Unavailable);

        let mut link = LinkSnapshot::empty();
        link.interface = Some("en0".into());
        link.gateway = Some("192.0.2.1".into());
        assert!(app.apply(MonitorUpdate::Link {
            generation: 1,
            snapshot: link,
        }));
        assert_eq!(app.situation().kind, SituationKind::PassiveObservation);
    }

    #[test]
    fn resolver_or_address_without_a_default_route_is_not_path_context() {
        let mut app = App::new();
        app.link.resolvers.push("192.0.2.53".into());
        app.link.addresses.push(Address {
            interface: "en0".into(),
            address: "192.0.2.10".into(),
            family: 4,
            is_default: false,
            is_temporary: false,
        });

        assert_eq!(app.situation().kind, SituationKind::Collecting);
        assert_eq!(
            app.progress_for(MonitorMode::Overview, EvidenceClaim::PathContext)
                .state,
            EvidenceProgressState::Collecting
        );
    }

    #[test]
    fn focused_link_projection_ignores_collectors_outside_its_scope() {
        let mut app = App::new();
        app.link.interface = Some("en0".into());
        app.link.link_type = Some("ethernet".into());
        app.link.resolvers.push("192.0.2.53".into());
        app.link.addresses.push(Address {
            interface: "en0".into(),
            address: "192.0.2.10".into(),
            family: 4,
            is_default: true,
            is_temporary: false,
        });
        let counters = |bytes| InterfaceCounters {
            interface: "en0".into(),
            received_bytes: bytes,
            transmitted_bytes: bytes,
            received_packets: bytes / 100,
            transmitted_packets: bytes / 100,
            receive_errors: 0,
            transmit_errors: 0,
            drops: 0,
        };
        assert!(app.apply(MonitorUpdate::Traffic {
            generation: 0,
            counters: Some(counters(1_000)),
        }));
        std::thread::sleep(Duration::from_millis(1));
        assert!(app.apply(MonitorUpdate::Traffic {
            generation: 0,
            counters: Some(counters(2_000)),
        }));

        let projection = app.projection(MonitorMode::Link);
        assert_eq!(
            projection.assessment.evidence_coverage,
            EvidenceCoverage::Complete
        );
        assert!(projection.evidence.neighbors.is_none());
        assert!(projection.evidence.workload.is_none());
        assert!(projection.evidence.probes.is_empty());
        assert!(projection.evidence.gateway_assessment.is_none());
        assert_eq!(app.peers.health, Health::Queued);
        assert_eq!(app.workload.health, Health::Queued);
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
        assert_eq!(app.situation().kind, SituationKind::Collecting);
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
    fn latest_gateway_outcome_preserves_a_no_reply_attempt() {
        let mut app = App::with_probe_policy(ProbePolicy::Active);
        finish_probe(&mut app, ProbeKind::Gateway, Health::Ok, Some(4.0));
        finish_probe(&mut app, ProbeKind::Gateway, Health::Failed, None);

        assert_eq!(app.gateway_samples.back(), Some(&4));
        assert_eq!(app.latest_gateway_outcome(), Some(None));
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
    fn gateway_distribution_is_claim_specific_instead_of_gating_path_status() {
        let mut app = App::with_probe_policy(ProbePolicy::Active);
        for _ in 0..MIN_GATEWAY_ASSESSMENT_SAMPLES - 1 {
            finish_probe(&mut app, ProbeKind::Gateway, Health::Ok, Some(4.0));
        }
        finish_probe(&mut app, ProbeKind::Dns, Health::Ok, Some(12.0));
        finish_probe(&mut app, ProbeKind::Https, Health::Ok, Some(80.0));

        assert_eq!(
            app.situation(),
            Situation {
                health: Health::Ok,
                kind: SituationKind::EvidenceGap,
            }
        );
        let variation = app.progress_for(MonitorMode::Overview, EvidenceClaim::GatewayVariation);
        assert_eq!(variation.state, EvidenceProgressState::Insufficient);
        assert_eq!(variation.observations, Some(4));
        assert_eq!(variation.required_observations, Some(5));

        finish_probe(&mut app, ProbeKind::Gateway, Health::Ok, Some(4.0));
        assert_eq!(app.overall_health(), Health::Ok);
        assert_eq!(
            app.progress_for(MonitorMode::Overview, EvidenceClaim::GatewayVariation)
                .state,
            EvidenceProgressState::Available
        );
    }

    #[test]
    fn variation_progress_requires_attempts_and_an_adjacent_rtt_pair() {
        let mut all_loss = App::with_probe_policy(ProbePolicy::Active);
        for _ in 0..MIN_GATEWAY_ASSESSMENT_SAMPLES {
            finish_probe(&mut all_loss, ProbeKind::Gateway, Health::Failed, None);
        }
        let progress =
            all_loss.progress_for(MonitorMode::Overview, EvidenceClaim::GatewayVariation);
        assert_eq!(progress.state, EvidenceProgressState::Insufficient);
        assert_eq!(progress.observations, Some(5));
        assert_eq!(progress.successful_observations, Some(0));
        assert!(progress.limitations.iter().any(|limitation| matches!(
            limitation,
            EvidenceLimitation::MinimumSuccessfulRttObservations { required: 2 }
        )));

        let mut one_success = App::with_probe_policy(ProbePolicy::Active);
        finish_probe(&mut one_success, ProbeKind::Gateway, Health::Ok, Some(4.0));
        for _ in 1..MIN_GATEWAY_ASSESSMENT_SAMPLES {
            finish_probe(&mut one_success, ProbeKind::Gateway, Health::Failed, None);
        }
        let progress =
            one_success.progress_for(MonitorMode::Overview, EvidenceClaim::GatewayVariation);
        assert_eq!(progress.state, EvidenceProgressState::Insufficient);
        assert_eq!(progress.observations, Some(5));
        assert_eq!(progress.successful_observations, Some(1));
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
            path_filter: PeerPathFilter::Applied,
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
        app.started_at = Instant::now() - MAX_PATH_PROBE_EVIDENCE_AGE - Duration::from_secs(1);
        app.probe_mut(ProbeKind::Dns).updated_at = Some(Duration::ZERO);

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
        app.apply_at(
            MonitorUpdate::Link {
                generation: 1,
                snapshot: test_link("en0", "house", "192.168.1.1"),
            },
            Duration::ZERO,
        );
        app.apply_at(
            MonitorUpdate::Traffic {
                generation: 1,
                counters: Some(test_counters("en0", 1_000, 2_000, 10, 20, 1, 2, 3)),
            },
            Duration::from_secs(1),
        );
        app.apply_at(
            MonitorUpdate::Traffic {
                generation: 1,
                counters: Some(test_counters("en0", 2_000, 4_000, 30, 60, 2, 4, 5)),
            },
            Duration::from_secs(3),
        );
        for (index, (signal, channel)) in [(-55.0, 36), (-72.0, 44)].into_iter().enumerate() {
            app.apply_at(
                MonitorUpdate::Wifi {
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
                },
                Duration::from_secs(4 + index as u64),
            );
        }
        for (index, (process, received, transmitted)) in
            [("codex", 4_096, 2_048), ("browser", 8_192, 4_096)]
                .into_iter()
                .enumerate()
        {
            app.apply_at(
                MonitorUpdate::Workload {
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
                },
                Duration::from_secs(6 + index as u64),
            );
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

        let window = app
            .latest_completed_path_window(MonitorMode::Overview)
            .expect("latest transition has one completed path window");
        assert_eq!(window.generation, 1);
        assert_eq!(window.path_identity.ssid.as_deref(), Some("house"));
        assert_eq!(window.completed_by.reason, "path_transition");
        assert_eq!(window.completed_by.next_generation, 2);
        assert_eq!(window.collector_scope.subject, MonitorMode::Overview);
        assert_eq!(
            window.interface.state,
            CompletedPathWindowSupportState::Partial
        );
        assert_eq!(
            window.interface.source,
            Some(CompletedPathWindowSource::KernelInterfaceCounters)
        );
        assert_eq!(
            window.radio.state,
            CompletedPathWindowSupportState::Available
        );
        assert_eq!(
            window.workload.state,
            CompletedPathWindowSupportState::Available
        );
        assert_eq!(window.workload.latest_snapshot_health, Some(Health::Ok));
        assert_eq!(
            window.neighbors.state,
            CompletedPathWindowSupportState::Available
        );
        assert_eq!(window.neighbors.snapshot_observations, 1);
        assert_eq!(window.retained_completed_windows, 1);
        assert_eq!(
            window.limitations,
            vec![
                CompletedPathWindowLimitation::ProcessLocalCappedRetention {
                    maximum_windows: MAX_COMPLETED_PATH_DWELLS as u64,
                },
                CompletedPathWindowLimitation::ImmutableAfterPathTransition,
                CompletedPathWindowLimitation::NotCurrentPathEvidence,
                CompletedPathWindowLimitation::NotPersisted,
            ]
        );
    }

    #[test]
    fn completed_window_distinguishes_unsupported_partial_and_out_of_scope_support() {
        let mut app = App::new();
        let mut ethernet = test_link("en7", "ignored", "198.51.100.1");
        ethernet.link_type = Some("ethernet".into());
        ethernet.ssid = None;
        ethernet.network_configuration = None;
        app.apply(MonitorUpdate::Link {
            generation: 1,
            snapshot: ethernet,
        });
        app.apply(MonitorUpdate::Traffic {
            generation: 1,
            counters: Some(test_counters("en7", 1_000, 2_000, 10, 20, 0, 0, 0)),
        });
        app.apply(MonitorUpdate::Workload {
            generation: 1,
            snapshot: WorkloadSnapshot {
                health: Health::Ok,
                detail: "sampled process window".into(),
                source: Some("nettop".into()),
                interval: Duration::from_secs(1),
                processes: vec![ProcessTraffic {
                    process: "browser".into(),
                    processes: 1,
                    received_bytes_per_second: 1_000,
                    transmitted_bytes_per_second: 500,
                }],
            },
        });
        app.apply(MonitorUpdate::Peers {
            generation: 1,
            snapshot: PeerSnapshot {
                health: Health::Degraded,
                detail: "ARP available; NDP failed".into(),
                path_filter: PeerPathFilter::Applied,
                sources: vec!["arp -an".into()],
                failed_sources: vec!["ndp -an".into()],
                oui_source: None,
                peers: vec![Peer {
                    address: "198.51.100.1".into(),
                    mac: Some("02:00:00:00:00:01".into()),
                    interface: Some("en7".into()),
                    state: Some("reachable".into()),
                    binding_conflict: false,
                    mac_scope: Some(MacScope::Local),
                    registrant: None,
                }],
            },
        });
        app.apply(MonitorUpdate::Link {
            generation: 2,
            snapshot: test_link("en0", "house", "192.168.1.1"),
        });

        let overview = app
            .latest_completed_path_window(MonitorMode::Overview)
            .unwrap();
        assert_eq!(
            overview.radio.state,
            CompletedPathWindowSupportState::Unsupported
        );
        assert!(!overview.radio.applicable);
        assert!(overview.radio.source.is_none());
        assert!(
            !overview
                .radio
                .limitations
                .contains(&CompletedPathWindowSupportLimitation::PlatformRadioTelemetryUnavailable)
        );
        assert_eq!(
            overview.neighbors.state,
            CompletedPathWindowSupportState::Partial
        );
        assert_eq!(
            overview.neighbors.latest_snapshot_health,
            Some(Health::Degraded)
        );
        assert!(overview.neighbors.limitations.contains(
            &CompletedPathWindowSupportLimitation::NativeSourcesFailed {
                sources: vec!["ndp -an".into()],
            }
        ));

        let focused = app.latest_completed_path_window(MonitorMode::Link).unwrap();
        assert_eq!(
            focused.workload.state,
            CompletedPathWindowSupportState::NotCollected
        );
        assert!(focused.workload.latest_snapshot_health.is_none());
        assert_eq!(focused.workload.sampled_windows, 0);
        assert!(focused.workload.latest_window_top.is_none());
        assert_eq!(
            focused.neighbors.state,
            CompletedPathWindowSupportState::NotCollected
        );
        assert!(focused.neighbors.latest_snapshot_health.is_none());
        assert_eq!(focused.neighbors.snapshot_observations, 0);
        assert!(focused.neighbors.sources.is_empty());
        assert_eq!(focused.neighbors.dwell.observed, 0);

        let peers = app
            .latest_completed_path_window(MonitorMode::Peers)
            .unwrap();
        assert_eq!(
            peers.interface.state,
            CompletedPathWindowSupportState::NotCollected
        );
        assert_eq!(peers.interface.samples, 0);
        assert!(peers.interface.current_rate.is_none());
        assert_eq!(
            peers.workload.state,
            CompletedPathWindowSupportState::NotCollected
        );
        assert_eq!(peers.workload.sampled_windows, 0);
        assert_eq!(
            peers.neighbors.state,
            CompletedPathWindowSupportState::Partial
        );
        assert_eq!(peers.neighbors.snapshot_observations, 1);
    }

    #[test]
    fn completed_window_is_immutable_when_current_wifi_identity_resolves_later() {
        let mut app = App::new();
        app.apply(MonitorUpdate::Link {
            generation: 1,
            snapshot: test_link("en0", "house", "192.168.1.1"),
        });
        app.apply(MonitorUpdate::Link {
            generation: 2,
            snapshot: test_link("en0", "hotspot", "172.20.10.1"),
        });
        let completed = app
            .latest_completed_path_window(MonitorMode::Overview)
            .expect("path transition has a completed window");

        app.apply(MonitorUpdate::Wifi {
            generation: 2,
            ssid: Some("resolved hotspot".into()),
            telemetry: None,
        });

        assert_eq!(app.link.ssid.as_deref(), Some("resolved hotspot"));
        let latest_change = app
            .last_path_change
            .as_ref()
            .expect("latest transition remains available");
        assert_eq!(latest_change.current, completed.completed_by.current);
        assert_eq!(
            app.latest_completed_path_window(MonitorMode::Overview),
            Some(completed)
        );
    }

    #[test]
    fn completed_window_marks_an_all_source_neighbor_failure_unavailable() {
        let mut app = App::new();
        app.apply(MonitorUpdate::Link {
            generation: 1,
            snapshot: test_link("en0", "house", "192.168.1.1"),
        });
        app.apply(MonitorUpdate::Peers {
            generation: 1,
            snapshot: PeerSnapshot {
                health: Health::Unavailable,
                detail: "no neighbor-cache source completed".into(),
                path_filter: PeerPathFilter::Applied,
                sources: Vec::new(),
                failed_sources: vec!["arp -an".into(), "ndp -an".into()],
                oui_source: None,
                peers: Vec::new(),
            },
        });
        app.apply(MonitorUpdate::Link {
            generation: 2,
            snapshot: test_link("en0", "hotspot", "172.20.10.1"),
        });

        let completed = app
            .latest_completed_path_window(MonitorMode::Overview)
            .expect("path transition has a completed window");
        assert_eq!(
            completed.neighbors.state,
            CompletedPathWindowSupportState::Unavailable
        );
        assert_eq!(
            completed.neighbors.latest_snapshot_health,
            Some(Health::Unavailable)
        );
        assert_eq!(completed.neighbors.snapshot_observations, 1);
        assert!(completed.neighbors.sources.is_empty());
        assert!(completed.neighbors.limitations.contains(
            &CompletedPathWindowSupportLimitation::NativeSourcesFailed {
                sources: vec!["arp -an".into(), "ndp -an".into()],
            }
        ));
    }

    #[test]
    fn completed_window_unions_neighbor_provenance_across_partial_snapshots() {
        let mut app = App::new();
        app.apply(MonitorUpdate::Link {
            generation: 1,
            snapshot: test_link("en0", "house", "192.168.1.1"),
        });
        for (source, failed_source, address) in [
            ("arp -an", "ndp -an", "192.168.1.2"),
            ("ndp -an", "arp -an", "2001:db8::2"),
        ] {
            app.apply(MonitorUpdate::Peers {
                generation: 1,
                snapshot: PeerSnapshot {
                    health: Health::Degraded,
                    detail: format!("{source} completed; {failed_source} failed"),
                    path_filter: PeerPathFilter::Applied,
                    sources: vec![source.into()],
                    failed_sources: vec![failed_source.into()],
                    oui_source: None,
                    peers: vec![Peer {
                        address: address.into(),
                        mac: None,
                        interface: Some("en0".into()),
                        state: Some("cached".into()),
                        binding_conflict: false,
                        mac_scope: None,
                        registrant: None,
                    }],
                },
            });
        }
        app.apply(MonitorUpdate::Link {
            generation: 2,
            snapshot: test_link("en0", "hotspot", "172.20.10.1"),
        });

        let completed = app
            .latest_completed_path_window(MonitorMode::Overview)
            .expect("path transition has a completed window");
        assert_eq!(
            completed.neighbors.state,
            CompletedPathWindowSupportState::Partial
        );
        assert_eq!(
            completed.neighbors.sources,
            vec!["arp -an".to_string(), "ndp -an".to_string()]
        );
        assert_eq!(
            completed.neighbors.failed_sources,
            vec!["arp -an".to_string(), "ndp -an".to_string()]
        );
        assert_eq!(completed.neighbors.snapshot_observations, 2);
        assert_eq!(completed.neighbors.dwell.observed, 2);
        assert_eq!(
            completed.neighbors.latest_snapshot_detail.as_deref(),
            Some("ndp -an completed; arp -an failed")
        );
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
    fn progress_exposes_totals_on_first_counter_sample_and_rates_on_second() {
        let mut app = App::new();
        app.apply_at(
            MonitorUpdate::Traffic {
                generation: 0,
                counters: Some(test_counters("en0", 1_000, 2_000, 30, 40, 2, 3, 4)),
            },
            Duration::ZERO,
        );

        let totals = app.progress_for(MonitorMode::Overview, EvidenceClaim::InterfaceTotals);
        let rate = app.progress_for(MonitorMode::Overview, EvidenceClaim::InterfaceRate);
        assert_eq!(totals.state, EvidenceProgressState::Available);
        assert_eq!(totals.observations, Some(1));
        assert_eq!(rate.state, EvidenceProgressState::Insufficient);
        assert_eq!(rate.observations, Some(1));
        assert_eq!(rate.required_observations, Some(2));
        assert_eq!(rate.valid_intervals, Some(0));

        app.apply_at(
            MonitorUpdate::Traffic {
                generation: 0,
                counters: Some(test_counters("en0", 2_000, 4_000, 60, 80, 2, 3, 4)),
            },
            Duration::from_secs(1),
        );
        let rate = app.progress_for(MonitorMode::Overview, EvidenceClaim::InterfaceRate);
        assert_eq!(rate.state, EvidenceProgressState::Available);
        assert_eq!(rate.observations, Some(2));
        assert_eq!(rate.valid_intervals, Some(1));
        assert!(app.interface_rate.is_some());
    }

    #[test]
    fn progress_order_and_collector_scope_are_stable() {
        let app = App::new();
        let overview = app.evidence_progress(MonitorMode::Overview);
        assert_eq!(
            overview
                .iter()
                .map(|progress| progress.claim)
                .collect::<Vec<_>>(),
            vec![
                EvidenceClaim::PathContext,
                EvidenceClaim::InterfaceTotals,
                EvidenceClaim::InterfaceRate,
                EvidenceClaim::RadioLink,
                EvidenceClaim::NeighborCache,
                EvidenceClaim::WorkloadAttribution,
                EvidenceClaim::GatewayRtt,
                EvidenceClaim::DnsReachability,
                EvidenceClaim::HttpsReachability,
                EvidenceClaim::PublicEgress,
                EvidenceClaim::GatewayVariation,
            ]
        );
        assert_eq!(
            app.progress_for(MonitorMode::Peers, EvidenceClaim::InterfaceTotals)
                .state,
            EvidenceProgressState::NotCollected
        );
        assert_eq!(
            app.progress_for(MonitorMode::Peers, EvidenceClaim::NeighborCache)
                .state,
            EvidenceProgressState::Collecting
        );
        assert_eq!(
            app.progress_for(MonitorMode::Link, EvidenceClaim::WorkloadAttribution)
                .state,
            EvidenceProgressState::NotCollected
        );
    }

    #[test]
    fn empty_neighbor_cache_observations_count_collector_snapshots_not_rows() {
        let mut app = App::new();
        let empty = PeerSnapshot {
            health: Health::Ok,
            detail: "0 cached peers; no liveness scan".into(),
            path_filter: PeerPathFilter::Applied,
            sources: vec!["arp -an".into()],
            failed_sources: Vec::new(),
            oui_source: None,
            peers: Vec::new(),
        };
        app.apply(MonitorUpdate::Peers {
            generation: 0,
            snapshot: empty.clone(),
        });
        let first = app.progress_for(MonitorMode::Overview, EvidenceClaim::NeighborCache);
        assert_eq!(first.state, EvidenceProgressState::Available);
        assert_eq!(first.observations, Some(1));

        app.apply(MonitorUpdate::Peers {
            generation: 0,
            snapshot: empty,
        });
        assert_eq!(
            app.progress_for(MonitorMode::Overview, EvidenceClaim::NeighborCache)
                .observations,
            Some(2)
        );
    }

    #[test]
    fn stale_generation_updates_are_rejected_before_projection() {
        let mut app = App::new();
        assert!(app.apply(MonitorUpdate::Link {
            generation: 1,
            snapshot: test_link("en0", "house", "192.168.1.1"),
        }));
        assert!(!app.apply(MonitorUpdate::Traffic {
            generation: 0,
            counters: Some(test_counters("en0", 1_000, 2_000, 30, 40, 2, 3, 4)),
        }));
        assert_eq!(
            app.progress_for(MonitorMode::Overview, EvidenceClaim::InterfaceTotals)
                .state,
            EvidenceProgressState::Collecting
        );
    }

    #[test]
    fn explicit_reducer_time_controls_path_dwell_and_rejects_reordering() {
        let mut app = App::new();
        assert!(app.apply_at(
            MonitorUpdate::Link {
                generation: 1,
                snapshot: test_link("en0", "house", "192.168.1.1"),
            },
            Duration::from_secs(2),
        ));
        assert!(app.apply_at(
            MonitorUpdate::Link {
                generation: 2,
                snapshot: test_link("en0", "field", "192.168.2.1"),
            },
            Duration::from_secs(9),
        ));

        let completed = app
            .completed_path_dwells
            .back()
            .expect("path transition retains its completed dwell");
        assert_eq!(completed.observed, Duration::from_secs(7));
        assert_eq!(completed.completed_by.elapsed, Duration::from_secs(9));
        assert_eq!(
            app.events.back().map(|event| event.elapsed),
            Some(Duration::from_secs(9))
        );

        let events = app.events.len();
        assert!(!app.apply_at(
            MonitorUpdate::Notice("reordered receipt".into()),
            Duration::from_secs(8),
        ));
        assert_eq!(app.events.len(), events);
        assert_eq!(app.last_reduced_at, Duration::from_secs(9));
    }

    #[test]
    fn delayed_stale_generation_does_not_advance_the_reducer_clock() {
        let mut app = App::new();
        assert!(app.apply_at(
            MonitorUpdate::Link {
                generation: 1,
                snapshot: test_link("en0", "house", "192.168.1.1"),
            },
            Duration::from_secs(1),
        ));
        assert!(app.apply_at(
            MonitorUpdate::Link {
                generation: 2,
                snapshot: test_link("en0", "field", "192.168.2.1"),
            },
            Duration::from_secs(10),
        ));
        assert!(!app.apply_at(
            MonitorUpdate::Traffic {
                generation: 1,
                counters: Some(test_counters("en0", 1, 2, 3, 4, 0, 0, 0)),
            },
            Duration::from_secs(30),
        ));
        assert_eq!(app.last_reduced_at, Duration::from_secs(10));
        assert!(app.apply_at(
            MonitorUpdate::Traffic {
                generation: 2,
                counters: Some(test_counters("en0", 10, 20, 30, 40, 0, 0, 0)),
            },
            Duration::from_secs(11),
        ));
        assert_eq!(app.last_reduced_at, Duration::from_secs(11));
        assert_eq!(
            app.interface_counters
                .as_ref()
                .map(|counters| counters.received_bytes),
            Some(10)
        );
    }

    #[test]
    fn counter_wrap_and_interface_replacement_start_new_baselines_without_fake_deltas() {
        let mut app = App::new();
        app.apply_at(
            MonitorUpdate::Traffic {
                generation: 0,
                counters: Some(test_counters("en0", 1_000, 2_000, 30, 40, 2, 3, 4)),
            },
            Duration::ZERO,
        );
        app.apply_at(
            MonitorUpdate::Traffic {
                generation: 0,
                counters: Some(test_counters("en0", 10, 20, 3, 4, 0, 0, 0)),
            },
            Duration::from_secs(1),
        );
        app.apply_at(
            MonitorUpdate::Traffic {
                generation: 0,
                counters: Some(test_counters("en9", 50_000, 60_000, 300, 400, 0, 0, 0)),
            },
            Duration::from_secs(2),
        );

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
    fn rolling_gateway_history_metrics_count_failed_attempts() {
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
        let metrics = app.gateway_history_metrics.unwrap();
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
        assert_eq!(app.gateway_history_metrics.as_ref().unwrap().lost, 1);
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
    fn vpn_path_transition_keeps_overlay_and_changes_wifi_underlay_generation() {
        let vpn_link = |ssid: &str, gateway: &str, connection_id: &str| {
            let mut link = test_link("utun4", ssid, gateway);
            link.link_type = Some("vpn".into());
            link.gateway = None;
            link.underlay = Some(PathUnderlay {
                interface: "en0".into(),
                link_type: "wifi".into(),
                gateway: Some(gateway.into()),
            });
            link.network_configuration = Some(Box::new(NetworkConfiguration {
                connection_id: Some(connection_id.into()),
                associated_bssid: None,
                bssid_restricted: true,
                method: Some("DHCP".into()),
                state: Some("BOUND".into()),
                server: Some(gateway.into()),
                subnet_mask: Some("255.255.255.0".into()),
                lease_seconds: None,
                lease_started_at: None,
                lease_expires_at: None,
                router_arp_verified: Some(true),
                security: Some("WPA3_SAE".into()),
            }));
            link
        };
        let house = vpn_link("house", "192.168.1.1", "109");
        assert_eq!(house.observation_interface(), Some("en0"));
        assert_eq!(house.observation_link_type(), Some("wifi"));
        assert_eq!(house.observation_gateway(), Some("192.168.1.1"));
        assert!(house.requires_radio_evidence());

        let mut app = App::new();
        app.apply(MonitorUpdate::Link {
            generation: 1,
            snapshot: house,
        });
        app.apply(MonitorUpdate::Link {
            generation: 2,
            snapshot: vpn_link("phone-hotspot", "172.20.10.1", "110"),
        });

        let change = app.last_path_change.as_ref().unwrap();
        assert_eq!(app.link.interface.as_deref(), Some("utun4"));
        assert_eq!(
            app.link
                .underlay
                .as_ref()
                .map(|underlay| underlay.interface.as_str()),
            Some("en0")
        );
        assert!(change.dimensions.contains(&"SSID"));
        assert!(change.dimensions.contains(&"Wi-Fi association"));
        assert!(change.dimensions.contains(&"underlay gateway"));
        assert!(change.current.contains("utun4 [vpn] over en0 [wifi"));
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
            path_filter: PeerPathFilter::Applied,
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
                path_filter: PeerPathFilter::Applied,
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
    fn focused_peer_coverage_requires_a_bounded_active_path_filter() {
        let mut neighbors = test_peers(None, Some("reachable"));
        assert_eq!(
            passive_peer_summary(&neighbors).evidence_coverage,
            EvidenceCoverage::Complete
        );

        neighbors.path_filter = PeerPathFilter::Unavailable;
        assert_eq!(
            passive_peer_summary(&neighbors).evidence_coverage,
            EvidenceCoverage::Partial
        );
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
            path_filter: PeerPathFilter::Applied,
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
                path_filter: PeerPathFilter::Applied,
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
    fn vpn_without_a_corroborated_underlay_is_partial_evidence() {
        let mut link = test_link("utun4", "unknown", "192.0.2.1");
        link.link_type = Some("vpn".into());
        link.gateway = None;
        link.underlay = None;
        let counters = InterfaceCounters {
            interface: "utun4".into(),
            received_bytes: 1,
            transmitted_bytes: 2,
            received_packets: 3,
            transmitted_packets: 4,
            receive_errors: 0,
            transmit_errors: 0,
            drops: 0,
        };

        assert_eq!(
            passive_link_summary(&link, Some(&counters)).evidence_coverage,
            EvidenceCoverage::Partial
        );
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
        assert!(dwell.last_binding_change.is_some());
        assert!(dwell.last_state_change.is_some());
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
                path_filter: PeerPathFilter::Applied,
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
                path_filter: PeerPathFilter::Applied,
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

    #[test]
    fn peer_dwell_records_when_a_binding_returns_to_the_cache() {
        let mut app = App::new();
        let peer = test_peers(Some("02:00:00:00:00:01"), Some("STALE"));
        app.apply(MonitorUpdate::Peers {
            generation: 0,
            snapshot: peer.clone(),
        });
        app.apply(MonitorUpdate::Peers {
            generation: 0,
            snapshot: PeerSnapshot {
                health: Health::Ok,
                detail: "empty complete cache".into(),
                path_filter: PeerPathFilter::Applied,
                sources: vec!["arp -an".into(), "ndp -an".into()],
                failed_sources: Vec::new(),
                oui_source: None,
                peers: Vec::new(),
            },
        });
        app.apply(MonitorUpdate::Peers {
            generation: 0,
            snapshot: peer,
        });

        let dwell = app.peer_dwell(&app.peers.peers[0]).unwrap();
        assert_eq!(dwell.cache_returns, 1);
        assert!(dwell.last_cache_return.is_some());
    }

    fn test_link(interface: &str, ssid: &str, gateway: &str) -> LinkSnapshot {
        LinkSnapshot {
            host: "workstation".into(),
            interface: Some(interface.into()),
            link_type: Some("wifi".into()),
            underlay: None,
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
            path_filter: PeerPathFilter::Applied,
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
