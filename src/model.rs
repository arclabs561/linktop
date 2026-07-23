use std::collections::VecDeque;
use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::metrics::LatencyMetrics;

pub const MAX_GATEWAY_SAMPLES: usize = 90;
pub const MAX_EVENTS: usize = 64;

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

    pub fn label(self) -> &'static str {
        match self {
            Self::Gateway => "gateway RTT",
            Self::Dns => "DNS resolve",
            Self::Https => "HTTPS edge",
            Self::PublicIp => "public edge",
        }
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
            ssid: self.ssid.clone(),
            ssid_restricted: self.ssid_restricted,
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
    pub mac_scope: Option<MacScope>,
    pub registrant: Option<String>,
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
}

#[derive(Debug, Clone)]
pub struct Event {
    pub elapsed: Duration,
    pub message: String,
    pub health: Health,
}

#[derive(Debug, Clone)]
pub enum MonitorUpdate {
    Link {
        generation: u64,
        snapshot: LinkSnapshot,
    },
    Wifi {
        generation: u64,
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

#[derive(Debug, Clone, Copy)]
pub enum MonitorControl {
    Refresh,
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
    pub events: VecDeque<Event>,
    pub paused: bool,
    pub cycles: u64,
    pub path_generation: u64,
}

impl App {
    pub fn new() -> Self {
        let started_at = Instant::now();
        let mut app = Self {
            started_at,
            link: LinkSnapshot::empty(),
            probes: ProbeKind::ALL.into_iter().map(ProbeView::queued).collect(),
            gateway_samples: VecDeque::with_capacity(MAX_GATEWAY_SAMPLES),
            gateway_outcomes: VecDeque::with_capacity(MAX_GATEWAY_SAMPLES),
            gateway_attempts: 0,
            gateway_metrics: None,
            peers: PeerSnapshot::pending(),
            interface_counters: None,
            interface_rate: None,
            interface_counters_at: None,
            events: VecDeque::with_capacity(MAX_EVENTS),
            paused: false,
            cycles: 0,
            path_generation: 0,
        };
        app.push_event(Health::Running, "instrument started");
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
                    link.public_ip = self.link.public_ip.clone();
                    link.wifi = self.link.wifi.clone();
                    self.link = link;
                    return;
                }

                let initial = self.path_generation == 0;
                let previous_fingerprint = self.link.path_fingerprint();
                let current_fingerprint = link.path_fingerprint();
                let previous = self.link.path_label();
                self.path_generation = generation;
                self.link = link;
                self.gateway_samples.clear();
                self.gateway_outcomes.clear();
                self.gateway_attempts = 0;
                self.gateway_metrics = None;
                self.interface_counters = None;
                self.interface_counters_at = None;
                self.interface_rate = None;
                self.peers = PeerSnapshot::pending();
                for probe in &mut self.probes {
                    *probe = ProbeView::queued(probe.kind);
                }
                let current = self.link.path_label();
                self.push_event(
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
            MonitorUpdate::Wifi {
                generation,
                telemetry,
            } => {
                if generation == self.path_generation {
                    self.link.wifi = telemetry;
                }
            }
            MonitorUpdate::Peers {
                generation,
                snapshot: peers,
            } => {
                if generation != self.path_generation {
                    return;
                }
                let previous = self.peers.peers.len();
                let current = peers.peers.len();
                self.peers = peers;
                if previous != current {
                    self.push_event(Health::Ok, format!("neighbor cache: {current} peer(s)"));
                }
            }
            MonitorUpdate::Traffic {
                generation,
                counters,
            } => {
                if generation != self.path_generation {
                    return;
                }
                let now = Instant::now();
                self.interface_rate = self
                    .interface_counters
                    .as_ref()
                    .zip(self.interface_counters_at)
                    .zip(counters.as_ref())
                    .and_then(|((before, observed_at), after)| {
                        interface_rate(before, after, now.duration_since(observed_at))
                    });
                self.interface_counters = counters;
                self.interface_counters_at = Some(now);
            }
            MonitorUpdate::ProbeStarted { generation, kind } => {
                if generation != self.path_generation {
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
                if generation != self.path_generation {
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
                    self.push_event(health, format!("{}: {}", kind.label(), detail));
                }
            }
            MonitorUpdate::Notice(message) => self.push_event(Health::Running, message),
        }
    }

    pub fn set_paused(&mut self, paused: bool) {
        self.paused = paused;
        self.push_event(
            Health::Running,
            if paused {
                "probes paused"
            } else {
                "probes resumed"
            },
        );
    }

    pub fn overall_health(&self) -> Health {
        if self.paused {
            return Health::Unavailable;
        }
        if self
            .probes
            .iter()
            .any(|probe| probe.health == Health::Failed)
        {
            Health::Failed
        } else if self
            .probes
            .iter()
            .any(|probe| probe.health == Health::Degraded)
            || self
                .gateway_metrics
                .as_ref()
                .is_some_and(|metrics| metrics.health() == Health::Degraded)
        {
            Health::Degraded
        } else if self
            .probes
            .iter()
            .any(|probe| matches!(probe.health, Health::Queued | Health::Running))
        {
            Health::Running
        } else if self
            .probes
            .iter()
            .all(|probe| probe.health == Health::Unavailable)
        {
            Health::Unavailable
        } else {
            Health::Ok
        }
    }

    pub fn uptime(&self) -> Duration {
        self.started_at.elapsed()
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

    fn push_event(&mut self, health: Health, message: impl Into<String>) {
        if self.events.len() == MAX_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(Event {
            elapsed: self.started_at.elapsed(),
            message: message.into(),
            health,
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
    pub health: Health,
    pub completed: usize,
    pub total: usize,
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
        let health = if probes.iter().any(|probe| probe.health == Health::Failed) {
            Health::Failed
        } else if probes.iter().any(|probe| probe.health == Health::Degraded)
            || neighbors.health == Health::Degraded
        {
            Health::Degraded
        } else if probes
            .iter()
            .all(|probe| probe.health == Health::Unavailable)
        {
            Health::Unavailable
        } else {
            Health::Ok
        };
        Self {
            summary: SnapshotSummary {
                health,
                completed: probes.len(),
                total: ProbeKind::ALL.len(),
            },
            link,
            interface_counters,
            neighbors,
            probes,
        }
    }
}

fn interface_rate(
    before: &InterfaceCounters,
    after: &InterfaceCounters,
    elapsed: Duration,
) -> Option<InterfaceRate> {
    if before.interface != after.interface || elapsed.is_zero() {
        return None;
    }
    let seconds = elapsed.as_secs_f64();
    Some(InterfaceRate {
        received_bits_per_second: after.received_bytes.checked_sub(before.received_bytes)? as f64
            * 8.0
            / seconds,
        transmitted_bits_per_second: after
            .transmitted_bytes
            .checked_sub(before.transmitted_bytes)? as f64
            * 8.0
            / seconds,
        received_packets_per_second: after
            .received_packets
            .checked_sub(before.received_packets)? as f64
            / seconds,
        transmitted_packets_per_second: after
            .transmitted_packets
            .checked_sub(before.transmitted_packets)?
            as f64
            / seconds,
        error_delta: after.receive_errors.checked_sub(before.receive_errors)?
            + after.transmit_errors.checked_sub(before.transmit_errors)?,
        drop_delta: after.drops.checked_sub(before.drops)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_samples_are_bounded() {
        let mut app = App::new();
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
        let mut app = App::new();
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
        let rate = interface_rate(&before, &after, Duration::from_secs(2)).unwrap();
        assert_eq!(rate.received_bits_per_second, 4_000.0);
        assert_eq!(rate.transmitted_bits_per_second, 8_000.0);
        assert_eq!(rate.error_delta, 3);
        assert_eq!(rate.drop_delta, 2);

        assert!(interface_rate(&after, &before, Duration::from_secs(2)).is_none());
    }

    #[test]
    fn rolling_gateway_metrics_count_failed_attempts() {
        let mut app = App::new();
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
        assert_eq!(report.summary.health, Health::Degraded);
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
        }
    }
}
