use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::net::{IpAddr, ToSocketAddrs};
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use if_addrs::get_if_addrs;
use serde_json::Value;

use crate::metrics::LatencyMetrics;
use crate::model::{
    Address, Health, InterfaceCounters, LinkSnapshot, MonitorControl, MonitorMode, MonitorUpdate,
    NetworkConfiguration, PathUnderlay, ProbeKind, ProbePolicy, ProbeResult, ProcessTraffic,
    SnapshotReport, WifiTelemetry, WorkloadSnapshot,
};
use crate::{peers, process};

const HTTPS_TARGET: &str = "https://example.com/";
const DNS_TARGET: &str = "example.com:443";
const DNS_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const SNAPSHOT_GATEWAY_ATTEMPTS: usize = 10;
const FULL_LINK_REFRESH_INTERVAL: Duration = Duration::from_secs(10);
const PATH_TRANSITION_GRACE: Duration = Duration::from_secs(3);
const ACTIVE_PATH_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
const WORKLOAD_REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const WORKLOAD_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
const PUBLIC_ENDPOINTS: [&str; 3] = [
    "https://api.ipify.org",
    "https://icanhazip.com",
    "https://wtfismyip.com/text",
];
static DNS_RESOLUTION_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Default)]
struct WifiObservation {
    ssid: Option<String>,
    telemetry: Option<WifiTelemetry>,
}

pub fn start_monitor(
    interval: Duration,
    mode: MonitorMode,
    probe_policy: ProbePolicy,
) -> (
    Receiver<MonitorUpdate>,
    Sender<MonitorControl>,
    thread::JoinHandle<()>,
) {
    let (update_tx, update_rx) = mpsc::channel();
    let (control_tx, control_rx) = mpsc::channel();
    let handle =
        thread::spawn(move || monitor_loop(interval, mode, probe_policy, update_tx, control_rx));
    (update_rx, control_tx, handle)
}

fn monitor_loop(
    interval: Duration,
    mode: MonitorMode,
    mut probe_policy: ProbePolicy,
    update_tx: Sender<MonitorUpdate>,
    control_rx: Receiver<MonitorControl>,
) {
    let mut paused = false;
    let mut stopped = false;
    let mut internet_refresh_pending = [probe_policy.is_active(); 3];
    let mut internet_last_started = [None; 3];
    let mut workload_refresh_pending = true;
    let mut workload_last_started = None;
    let mut peers_refresh_pending = true;
    let mut wifi_refresh_pending = true;
    let mut full_link_refresh_pending = true;
    let mut full_link_refreshed_at = None;
    let mut current_link = None;
    let mut tick = 0_u64;
    let mut gateway = None;
    let mut path_generation = 0_u64;
    let mut path_fingerprint = None;
    let mut incomplete_route_since = None;
    let mut incomplete_underlay_since = None;
    let probe_in_flight = Arc::new(std::array::from_fn::<_, 4, _>(|_| AtomicBool::new(false)));
    let probe_epoch = Arc::new(AtomicU64::new(0));
    let traffic_in_flight = Arc::new(AtomicBool::new(false));
    let workload_in_flight = Arc::new(AtomicBool::new(false));
    let peers_in_flight = Arc::new(AtomicBool::new(false));
    let wifi_in_flight = Arc::new(AtomicBool::new(false));
    let sleep_step = Duration::from_millis(100);
    let steps_per_tick = (interval.as_millis() / sleep_step.as_millis()).max(1) as usize;

    while !stopped {
        while let Ok(control) = control_rx.try_recv() {
            match control {
                MonitorControl::Refresh => {
                    internet_refresh_pending.fill(probe_policy.is_active());
                    workload_refresh_pending = true;
                    peers_refresh_pending = true;
                    wifi_refresh_pending = true;
                    full_link_refresh_pending = true;
                }
                MonitorControl::SetProbePolicy(policy) => {
                    if probe_policy != policy {
                        probe_policy = policy;
                        probe_epoch.fetch_add(1, Ordering::AcqRel);
                        internet_refresh_pending.fill(policy.is_active());
                        internet_last_started.fill(None);
                    }
                }
                MonitorControl::Pause(value) => paused = value,
                MonitorControl::Stop => stopped = true,
            }
        }
        if stopped {
            break;
        }

        if !paused {
            let now = Instant::now();
            let periodic_full_refresh = full_link_refreshed_at.is_none_or(|last| {
                now.saturating_duration_since(last) >= FULL_LINK_REFRESH_INTERVAL
            });
            let full_refresh_due =
                full_link_refresh_pending || periodic_full_refresh || current_link.is_none();
            let mut link = if full_refresh_due {
                full_link_refresh_pending = false;
                full_link_refreshed_at = Some(now);
                collect_link()
            } else {
                collect_light_link(
                    current_link
                        .as_ref()
                        .expect("monitor link exists after its first full refresh"),
                )
            };
            if current_link
                .as_ref()
                .is_some_and(|previous| previous.path_fingerprint() != link.path_fingerprint())
                && !full_refresh_due
            {
                link = collect_link();
                full_link_refreshed_at = Some(now);
            }
            let path_settling = should_hold_incomplete_route(
                current_link.as_ref(),
                &link,
                &mut incomplete_route_since,
                now,
            );
            if path_settling {
                link = current_link
                    .clone()
                    .expect("route settling requires a previous confirmed path");
            }
            if path_settling {
                incomplete_underlay_since = None;
            } else if should_hold_incomplete_underlay(
                current_link.as_ref(),
                &link,
                &mut incomplete_underlay_since,
                now,
            ) {
                let previous = current_link
                    .as_ref()
                    .expect("underlay settling requires a previous confirmed path");
                link.underlay.clone_from(&previous.underlay);
                link.ssid.clone_from(&previous.ssid);
                link.ssid_restricted = previous.ssid_restricted;
                link.network_configuration
                    .clone_from(&previous.network_configuration);
            }
            current_link = Some(link.clone());
            let fingerprint = link.path_fingerprint();
            if path_fingerprint.as_ref() != Some(&fingerprint) {
                path_generation = path_generation.wrapping_add(1).max(1);
                path_fingerprint = Some(fingerprint);
                internet_refresh_pending.fill(probe_policy.is_active());
                internet_last_started.fill(None);
                workload_refresh_pending = true;
                workload_last_started = None;
                peers_refresh_pending = true;
                wifi_refresh_pending = true;
            }
            gateway.clone_from(&link.gateway);
            let interface = link.observation_interface().map(str::to_string);
            if path_settling {
                let _ = update_tx.send(MonitorUpdate::PathSettling {
                    generation: path_generation,
                });
            } else {
                let _ = update_tx.send(MonitorUpdate::Link {
                    generation: path_generation,
                    snapshot: link.clone(),
                });
            }

            match (mode, path_settling) {
                (MonitorMode::Overview, false) => {
                    if permits_active_probes(mode, probe_policy) {
                        spawn_probe(
                            ProbeKind::Gateway,
                            gateway.clone(),
                            update_tx.clone(),
                            1,
                            path_generation,
                            probe_in_flight.clone(),
                            probe_epoch.clone(),
                        );
                    }
                    spawn_traffic(
                        interface.clone(),
                        update_tx.clone(),
                        path_generation,
                        traffic_in_flight.clone(),
                    );
                }
                (MonitorMode::Link, false) => {
                    spawn_traffic(
                        interface.clone(),
                        update_tx.clone(),
                        path_generation,
                        traffic_in_flight.clone(),
                    );
                }
                (MonitorMode::Peers, false)
                | (MonitorMode::Overview | MonitorMode::Link | MonitorMode::Peers, true) => {}
            }

            let workload_due = workload_last_started.is_none_or(|last| {
                now.saturating_duration_since(last) >= WORKLOAD_REFRESH_INTERVAL
            });
            if mode == MonitorMode::Overview
                && !path_settling
                && (workload_refresh_pending || workload_due)
                && spawn_workload(
                    update_tx.clone(),
                    path_generation,
                    workload_in_flight.clone(),
                )
            {
                workload_refresh_pending = false;
                workload_last_started = Some(now);
            }

            // Internet probes are bounded startup, transition, manual, or
            // disclosed low-cadence diagnostics rather than traffic coupled
            // to the gateway sample rate.
            if permits_active_probes(mode, probe_policy) && !path_settling {
                let internet_kinds = [ProbeKind::Dns, ProbeKind::Https, ProbeKind::PublicIp];
                for (index, kind) in internet_kinds.into_iter().enumerate() {
                    if periodic_internet_probe_due(kind, internet_last_started[index], now) {
                        internet_refresh_pending[index] = true;
                    }
                    let pending = &mut internet_refresh_pending[index];
                    if *pending
                        && spawn_probe(
                            kind,
                            gateway.clone(),
                            update_tx.clone(),
                            1,
                            path_generation,
                            probe_in_flight.clone(),
                            probe_epoch.clone(),
                        )
                    {
                        *pending = false;
                        internet_last_started[index] = Some(now);
                    }
                }
            }

            if !path_settling && tick.is_multiple_of(15) && mode == MonitorMode::Overview {
                peers_refresh_pending = true;
                wifi_refresh_pending = true;
            }
            if !path_settling && tick.is_multiple_of(3) && mode == MonitorMode::Link {
                wifi_refresh_pending = true;
            }
            if !path_settling && mode == MonitorMode::Peers {
                peers_refresh_pending = true;
            }
            if !path_settling {
                match mode {
                    MonitorMode::Overview => {
                        if peers_refresh_pending
                            && spawn_peers(
                                link.clone(),
                                update_tx.clone(),
                                path_generation,
                                peers_in_flight.clone(),
                            )
                        {
                            peers_refresh_pending = false;
                        }
                        if wifi_refresh_pending
                            && spawn_wifi(
                                interface.clone(),
                                update_tx.clone(),
                                path_generation,
                                wifi_in_flight.clone(),
                            )
                        {
                            wifi_refresh_pending = false;
                        }
                    }
                    MonitorMode::Link => {
                        if wifi_refresh_pending
                            && spawn_wifi(
                                interface.clone(),
                                update_tx.clone(),
                                path_generation,
                                wifi_in_flight.clone(),
                            )
                        {
                            wifi_refresh_pending = false;
                        }
                    }
                    MonitorMode::Peers => {
                        if peers_refresh_pending
                            && spawn_peers(
                                link.clone(),
                                update_tx.clone(),
                                path_generation,
                                peers_in_flight.clone(),
                            )
                        {
                            peers_refresh_pending = false;
                        }
                    }
                }
            }
            tick = tick.wrapping_add(1);
        }

        for _ in 0..steps_per_tick {
            match control_rx.recv_timeout(sleep_step) {
                Ok(MonitorControl::Refresh) => {
                    internet_refresh_pending.fill(probe_policy.is_active());
                    workload_refresh_pending = true;
                    peers_refresh_pending = true;
                    wifi_refresh_pending = true;
                    full_link_refresh_pending = true;
                    break;
                }
                Ok(MonitorControl::SetProbePolicy(policy)) => {
                    if probe_policy != policy {
                        probe_policy = policy;
                        probe_epoch.fetch_add(1, Ordering::AcqRel);
                        internet_refresh_pending.fill(policy.is_active());
                        internet_last_started.fill(None);
                    }
                    break;
                }
                Ok(MonitorControl::Pause(value)) => {
                    paused = value;
                    break;
                }
                Ok(MonitorControl::Stop) => {
                    stopped = true;
                    break;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    stopped = true;
                    break;
                }
            }
        }
    }
}

fn permits_active_probes(mode: MonitorMode, probe_policy: ProbePolicy) -> bool {
    mode == MonitorMode::Overview && probe_policy.is_active()
}

fn periodic_internet_probe_due(
    kind: ProbeKind,
    last_started: Option<Instant>,
    now: Instant,
) -> bool {
    matches!(kind, ProbeKind::Dns | ProbeKind::Https)
        && last_started
            .is_some_and(|last| now.saturating_duration_since(last) >= ACTIVE_PATH_REFRESH_INTERVAL)
}

fn spawn_probe(
    kind: ProbeKind,
    gateway: Option<String>,
    tx: Sender<MonitorUpdate>,
    gateway_attempts: usize,
    generation: u64,
    in_flight: Arc<[AtomicBool; 4]>,
    probe_epoch: Arc<AtomicU64>,
) -> bool {
    let slot = probe_slot(kind);
    if in_flight[slot].swap(true, Ordering::AcqRel) {
        return false;
    }
    let epoch = probe_epoch.load(Ordering::Acquire);
    let _ = tx.send(MonitorUpdate::ProbeStarted { generation, kind });
    thread::spawn(move || {
        let result = run_probe(kind, gateway.as_deref(), gateway_attempts);
        if probe_epoch.load(Ordering::Acquire) == epoch {
            let _ = tx.send(MonitorUpdate::ProbeFinished {
                generation,
                kind,
                result,
            });
        }
        in_flight[slot].store(false, Ordering::Release);
    });
    true
}

fn probe_slot(kind: ProbeKind) -> usize {
    match kind {
        ProbeKind::Gateway => 0,
        ProbeKind::Dns => 1,
        ProbeKind::Https => 2,
        ProbeKind::PublicIp => 3,
    }
}

fn spawn_peers(
    link: LinkSnapshot,
    tx: Sender<MonitorUpdate>,
    generation: u64,
    in_flight: Arc<AtomicBool>,
) -> bool {
    if in_flight.swap(true, Ordering::AcqRel) {
        return false;
    }
    thread::spawn(move || {
        let _ = tx.send(MonitorUpdate::Peers {
            generation,
            snapshot: peers::collect(&link),
        });
        in_flight.store(false, Ordering::Release);
    });
    true
}

fn spawn_wifi(
    interface: Option<String>,
    tx: Sender<MonitorUpdate>,
    generation: u64,
    in_flight: Arc<AtomicBool>,
) -> bool {
    if in_flight.swap(true, Ordering::AcqRel) {
        return false;
    }
    thread::spawn(move || {
        let observation = collect_wifi(interface.as_deref());
        let _ = tx.send(MonitorUpdate::Wifi {
            generation,
            ssid: observation.ssid,
            telemetry: observation.telemetry,
        });
        in_flight.store(false, Ordering::Release);
    });
    true
}

fn spawn_traffic(
    interface: Option<String>,
    tx: Sender<MonitorUpdate>,
    generation: u64,
    in_flight: Arc<AtomicBool>,
) {
    if in_flight.swap(true, Ordering::AcqRel) {
        return;
    }
    thread::spawn(move || {
        let counters = interface.as_deref().and_then(collect_interface_counters);
        let _ = tx.send(MonitorUpdate::Traffic {
            generation,
            counters,
        });
        in_flight.store(false, Ordering::Release);
    });
}

fn spawn_workload(tx: Sender<MonitorUpdate>, generation: u64, in_flight: Arc<AtomicBool>) -> bool {
    if in_flight.swap(true, Ordering::AcqRel) {
        return false;
    }
    thread::spawn(move || {
        let _ = tx.send(MonitorUpdate::Workload {
            generation,
            snapshot: collect_workload_snapshot(),
        });
        in_flight.store(false, Ordering::Release);
    });
    true
}

pub(crate) fn collect_workload_snapshot() -> WorkloadSnapshot {
    if !cfg!(target_os = "macos") {
        return WorkloadSnapshot {
            health: Health::Unavailable,
            detail: "per-process external-interface accounting has no platform backend".into(),
            source: None,
            interval: WORKLOAD_SAMPLE_INTERVAL,
            processes: Vec::new(),
        };
    }
    let mut command = Command::new("nettop");
    command.args([
        "-P",
        "-L",
        "2",
        "-d",
        "-n",
        "-x",
        "-s",
        "1",
        "-t",
        "external",
        "-J",
        "bytes_in,bytes_out",
    ]);
    let output = match process::run_bounded(&mut command, Duration::from_secs(3)) {
        Ok(Some(output)) if output.status.success() => output,
        Ok(Some(output)) => {
            return WorkloadSnapshot {
                health: Health::Unavailable,
                detail: format!(
                    "nettop exited {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
                source: Some("nettop".into()),
                interval: WORKLOAD_SAMPLE_INTERVAL,
                processes: Vec::new(),
            };
        }
        Ok(None) => {
            return WorkloadSnapshot {
                health: Health::Unavailable,
                detail: "nettop sample deadline exceeded".into(),
                source: Some("nettop".into()),
                interval: WORKLOAD_SAMPLE_INTERVAL,
                processes: Vec::new(),
            };
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return WorkloadSnapshot {
                health: Health::Unavailable,
                detail: "nettop command not found".into(),
                source: None,
                interval: WORKLOAD_SAMPLE_INTERVAL,
                processes: Vec::new(),
            };
        }
        Err(error) => {
            return WorkloadSnapshot {
                health: Health::Unavailable,
                detail: format!("nettop failed: {error}"),
                source: Some("nettop".into()),
                interval: WORKLOAD_SAMPLE_INTERVAL,
                processes: Vec::new(),
            };
        }
    };
    let processes = parse_nettop_process_traffic(&String::from_utf8_lossy(&output.stdout));
    WorkloadSnapshot {
        health: Health::Ok,
        detail: if processes.is_empty() {
            "no per-process external-interface traffic in the latest 1s sample".into()
        } else {
            format!(
                "{} process group(s) with external-interface traffic over 1s",
                processes.len()
            )
        },
        source: Some("nettop -P -L 2 -d -n -x -s 1 -t external".into()),
        interval: WORKLOAD_SAMPLE_INTERVAL,
        processes,
    }
}

fn parse_nettop_process_traffic(output: &str) -> Vec<ProcessTraffic> {
    let mut current: BTreeMap<String, (usize, u64, u64)> = BTreeMap::new();
    let mut in_sample = false;
    for line in output.lines() {
        let line = line.trim();
        if line.starts_with(",bytes_in,bytes_out") {
            current.clear();
            in_sample = true;
            continue;
        }
        if !in_sample || line.is_empty() {
            continue;
        }
        let mut fields = line.split(',');
        let identity = fields.next().unwrap_or_default();
        let received = fields.next().and_then(|value| value.parse::<u64>().ok());
        let transmitted = fields.next().and_then(|value| value.parse::<u64>().ok());
        let (Some(received), Some(transmitted)) = (received, transmitted) else {
            continue;
        };
        if received == 0 && transmitted == 0 {
            continue;
        }
        let process = identity
            .rsplit_once('.')
            .filter(|(_, suffix)| suffix.chars().all(|character| character.is_ascii_digit()))
            .map_or(identity, |(process, _)| process)
            .to_string();
        if process.is_empty() {
            continue;
        }
        let entry = current.entry(process).or_insert((0, 0, 0));
        entry.0 += 1;
        entry.1 = entry.1.saturating_add(received);
        entry.2 = entry.2.saturating_add(transmitted);
    }
    let mut processes: Vec<_> = current
        .into_iter()
        .map(
            |(process, (processes, received_bytes_per_second, transmitted_bytes_per_second))| {
                ProcessTraffic {
                    process,
                    processes,
                    received_bytes_per_second,
                    transmitted_bytes_per_second,
                }
            },
        )
        .collect();
    processes.sort_by(|left, right| {
        let left_total = left
            .received_bytes_per_second
            .saturating_add(left.transmitted_bytes_per_second);
        let right_total = right
            .received_bytes_per_second
            .saturating_add(right.transmitted_bytes_per_second);
        right_total
            .cmp(&left_total)
            .then_with(|| left.process.cmp(&right.process))
    });
    processes
}

pub fn collect_snapshot(timeout: Duration) -> SnapshotReport {
    let mut link = collect_link();
    let wifi_interface = link.observation_interface().map(str::to_string);
    let wifi = thread::spawn(move || collect_wifi(wifi_interface.as_deref()));
    let neighbor_link = link.clone();
    let neighbors = thread::spawn(move || peers::collect(&neighbor_link));
    let gateway = link.gateway.clone();
    let (tx, rx) = mpsc::channel();
    for kind in ProbeKind::ALL {
        let tx = tx.clone();
        let gateway = gateway.clone();
        thread::spawn(move || {
            let attempts = if kind == ProbeKind::Gateway {
                SNAPSHOT_GATEWAY_ATTEMPTS
            } else {
                1
            };
            let _ = tx.send((kind, run_probe(kind, gateway.as_deref(), attempts)));
        });
    }
    drop(tx);

    let deadline = Instant::now() + timeout;
    let mut results = Vec::with_capacity(ProbeKind::ALL.len());
    while results.len() < ProbeKind::ALL.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match rx.recv_timeout(remaining) {
            Ok(result) => results.push(result),
            Err(_) => break,
        }
    }

    for kind in ProbeKind::ALL {
        if !results.iter().any(|(completed, _)| *completed == kind) {
            results.push((
                kind,
                if kind.affects_path_health() {
                    ProbeResult::failed("snapshot deadline exceeded")
                } else {
                    ProbeResult::unavailable("snapshot deadline exceeded")
                },
            ));
        }
    }
    results.sort_by_key(|(kind, _)| ProbeKind::ALL.iter().position(|item| item == kind));
    if let Some((_, result)) = results
        .iter()
        .find(|(kind, result)| *kind == ProbeKind::PublicIp && result.health == Health::Ok)
    {
        link.public_ip = Some(result.detail.clone());
    }
    apply_wifi_observation(&mut link, wifi.join().unwrap_or_default());
    let neighbors = neighbors
        .join()
        .unwrap_or_else(|_| crate::model::PeerSnapshot {
            health: Health::Unavailable,
            detail: "neighbor-cache worker panicked".into(),
            path_filter: crate::model::PeerPathFilter::Unavailable,
            sources: Vec::new(),
            failed_sources: Vec::new(),
            oui_source: None,
            peers: Vec::new(),
        });
    let interface_counters = link
        .observation_interface()
        .and_then(collect_interface_counters);
    SnapshotReport::from_results(link, interface_counters, neighbors, results)
}

pub fn collect_passive_snapshot() -> SnapshotReport {
    let mut link = collect_link();
    let wifi_interface = link.observation_interface().map(str::to_string);
    let wifi = thread::spawn(move || collect_wifi(wifi_interface.as_deref()));
    let neighbor_link = link.clone();
    let neighbors = thread::spawn(move || peers::collect(&neighbor_link));
    let interface_counters = link
        .observation_interface()
        .and_then(collect_interface_counters);
    apply_wifi_observation(&mut link, wifi.join().unwrap_or_default());
    let neighbors = neighbors
        .join()
        .unwrap_or_else(|_| crate::model::PeerSnapshot {
            health: Health::Unavailable,
            detail: "neighbor-cache worker panicked".into(),
            path_filter: crate::model::PeerPathFilter::Unavailable,
            sources: Vec::new(),
            failed_sources: Vec::new(),
            oui_source: None,
            peers: Vec::new(),
        });
    SnapshotReport::from_passive(link, interface_counters, neighbors)
}

pub(crate) fn collect_interface_counters(interface: &str) -> Option<InterfaceCounters> {
    if interface.is_empty() || interface.contains('/') || interface.contains("..") {
        return None;
    }
    if cfg!(target_os = "macos") {
        command_output("netstat", &["-ibdn"])
            .and_then(|output| parse_macos_interface_counters(&output, interface))
    } else if cfg!(target_os = "linux") {
        let base = std::path::Path::new("/sys/class/net")
            .join(interface)
            .join("statistics");
        let read = |name: &str| {
            fs::read_to_string(base.join(name))
                .ok()?
                .trim()
                .parse::<u64>()
                .ok()
        };
        Some(InterfaceCounters {
            interface: interface.into(),
            received_bytes: read("rx_bytes")?,
            transmitted_bytes: read("tx_bytes")?,
            received_packets: read("rx_packets")?,
            transmitted_packets: read("tx_packets")?,
            receive_errors: read("rx_errors")?,
            transmit_errors: read("tx_errors")?,
            drops: read("rx_dropped")?.saturating_add(read("tx_dropped")?),
        })
    } else {
        None
    }
}

fn parse_macos_interface_counters(output: &str, interface: &str) -> Option<InterfaceCounters> {
    output.lines().find_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.first().copied() != Some(interface)
            || !fields
                .get(2)
                .is_some_and(|field| field.starts_with("<Link#"))
        {
            return None;
        }
        Some(InterfaceCounters {
            interface: interface.into(),
            received_packets: fields.get(4)?.parse().ok()?,
            receive_errors: fields.get(5)?.parse().ok()?,
            received_bytes: fields.get(6)?.parse().ok()?,
            transmitted_packets: fields.get(7)?.parse().ok()?,
            transmit_errors: fields.get(8)?.parse().ok()?,
            transmitted_bytes: fields.get(9)?.parse().ok()?,
            drops: fields.get(11)?.parse().ok()?,
        })
    })
}

pub fn collect_link() -> LinkSnapshot {
    let route = default_route();
    let interface = route.as_ref().and_then(|value| value.0.clone());
    let gateway = route.and_then(|value| value.1);
    let underlay = physical_underlay(interface.as_deref(), None);
    let observation_interface = underlay
        .as_ref()
        .map(|value| value.interface.as_str())
        .or(interface.as_deref());
    let addresses = local_addresses(interface.as_deref());
    let (ssid, ssid_restricted, network_configuration) =
        network_configuration(observation_interface);
    LinkSnapshot {
        host: short_hostname(),
        link_type: interface.as_deref().map(link_type),
        underlay,
        ssid,
        ssid_restricted,
        wifi: None,
        interface,
        gateway,
        public_ip: None,
        resolvers: resolver_servers(),
        addresses,
        network_configuration,
    }
}

fn collect_light_link(previous: &LinkSnapshot) -> LinkSnapshot {
    let route = default_route();
    let interface = route.as_ref().and_then(|value| value.0.clone());
    let gateway = route.and_then(|value| value.1);
    let underlay = physical_underlay(interface.as_deref(), previous.underlay.as_ref());
    let observation_interface = underlay
        .as_ref()
        .map(|value| value.interface.as_str())
        .or(interface.as_deref());
    let addresses = local_addresses(interface.as_deref());
    let (ssid, ssid_restricted, network_configuration) =
        network_configuration(observation_interface);
    let mut link = previous.clone();
    link.link_type = interface.as_deref().map(link_type);
    link.underlay = underlay;
    link.interface = interface;
    link.ssid = ssid;
    link.ssid_restricted = ssid_restricted;
    link.gateway = gateway;
    link.addresses = addresses;
    link.network_configuration = network_configuration;
    link.public_ip = None;
    link.wifi = None;
    link
}

fn should_hold_incomplete_route(
    previous: Option<&LinkSnapshot>,
    candidate: &LinkSnapshot,
    incomplete_since: &mut Option<Instant>,
    observed_at: Instant,
) -> bool {
    let route_became_incomplete =
        previous.is_some_and(|link| link.interface.is_some()) && candidate.interface.is_none();
    if !route_became_incomplete {
        *incomplete_since = None;
        return false;
    }
    let first_incomplete = *incomplete_since.get_or_insert(observed_at);
    observed_at.saturating_duration_since(first_incomplete) < PATH_TRANSITION_GRACE
}

fn should_hold_incomplete_underlay(
    previous: Option<&LinkSnapshot>,
    candidate: &LinkSnapshot,
    incomplete_since: &mut Option<Instant>,
    observed_at: Instant,
) -> bool {
    let underlay_became_incomplete = previous.is_some_and(|link| {
        link.interface == candidate.interface
            && link.underlay.is_some()
            && candidate.underlay.is_none()
    });
    if !underlay_became_incomplete {
        *incomplete_since = None;
        return false;
    }
    let first_incomplete = *incomplete_since.get_or_insert(observed_at);
    observed_at.saturating_duration_since(first_incomplete) < PATH_TRANSITION_GRACE
}

pub fn collect_link_snapshot() -> LinkSnapshot {
    let mut link = collect_link();
    let observation = collect_wifi(link.observation_interface());
    apply_wifi_observation(&mut link, observation);
    link
}

fn apply_wifi_observation(link: &mut LinkSnapshot, observation: WifiObservation) {
    if let Some(ssid) = observation.ssid {
        link.ssid = Some(ssid);
        link.ssid_restricted = false;
    }
    link.wifi = observation.telemetry;
}

fn run_probe(kind: ProbeKind, gateway: Option<&str>, gateway_attempts: usize) -> ProbeResult {
    match kind {
        ProbeKind::Gateway => probe_gateway(gateway, gateway_attempts),
        ProbeKind::Dns => probe_dns(),
        ProbeKind::Https => probe_https(),
        ProbeKind::PublicIp => probe_public_ip(),
    }
}

pub(crate) fn probe_gateway(gateway: Option<&str>, attempts: usize) -> ProbeResult {
    let Some(gateway) = gateway else {
        return ProbeResult::unavailable("default gateway not found");
    };
    let attempts = attempts.max(1);
    let mut command = Command::new("ping");
    if cfg!(target_os = "windows") {
        command.args(["-n", &attempts.to_string(), "-w", "1000", gateway]);
    } else if cfg!(target_os = "macos") {
        command.args(["-n", "-c", &attempts.to_string(), "-W", "1000", gateway]);
    } else {
        command.args(["-n", "-c", &attempts.to_string(), "-W", "1", gateway]);
    }
    let timeout = Duration::from_secs(attempts as u64 + 3);
    let output = match process::run_bounded(&mut command, timeout) {
        Ok(Some(output)) => output,
        Ok(None) => return ProbeResult::failed(format!("{gateway}: ping deadline exceeded")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return ProbeResult::unavailable("ping command not found");
        }
        Err(error) => return ProbeResult::failed(format!("ping failed: {error}")),
    };
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let samples = parse_ping_latencies(&combined);
    let metrics = LatencyMetrics::from_samples(&samples, attempts);
    let health = if samples.is_empty() {
        Health::Unavailable
    } else {
        metrics.health()
    };
    let loss = metrics.loss_rate.map_or_else(
        || "loss unknown".into(),
        |value| format!("{:.0}% loss", value * 100.0),
    );
    ProbeResult {
        health,
        detail: if samples.is_empty() {
            format!("{gateway}: no ICMP echo replies; filtering or reachability unknown")
        } else if attempts == 1 {
            format!("{gateway}, reply, {loss}")
        } else {
            format!("{gateway}, {attempts} attempts, {loss}")
        },
        latency_ms: metrics.rtt_p50_ms,
        metrics: Some(metrics),
    }
}

fn probe_dns() -> ProbeResult {
    if DNS_RESOLUTION_IN_FLIGHT.swap(true, Ordering::AcqRel) {
        return ProbeResult::unavailable(
            "example.com: previous system-resolver lookup is still in flight",
        );
    }
    let started = Instant::now();
    let result = run_task_with_deadline(DNS_PROBE_TIMEOUT, || {
        let result = DNS_TARGET
            .to_socket_addrs()
            .map(|addresses| {
                addresses
                    .map(|address| address.ip())
                    .collect::<BTreeSet<_>>()
            })
            .map_err(|error| error.to_string());
        DNS_RESOLUTION_IN_FLIGHT.store(false, Ordering::Release);
        result
    });
    let addresses = match result {
        Some(Ok(addresses)) => addresses,
        Some(Err(error)) => return ProbeResult::failed(format!("example.com: {error}")),
        None => {
            return ProbeResult::failed(format!(
                "example.com: system-resolver deadline exceeded ({:.0}s)",
                DNS_PROBE_TIMEOUT.as_secs_f64()
            ));
        }
    };
    let latency = started.elapsed().as_secs_f64() * 1_000.0;
    ProbeResult {
        health: if latency
            >= ProbeKind::Dns
                .degraded_after_ms()
                .expect("DNS has a latency threshold")
        {
            Health::Degraded
        } else {
            Health::Ok
        },
        detail: format!("example.com → {} address(es)", addresses.len()),
        latency_ms: Some(latency),
        metrics: None,
    }
}

fn run_task_with_deadline<T, F>(timeout: Duration, task: F) -> Option<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(task());
    });
    rx.recv_timeout(timeout).ok()
}

fn probe_https() -> ProbeResult {
    let client = match http_client(Duration::from_secs(3)) {
        Ok(client) => client,
        Err(error) => return ProbeResult::failed(format!("client setup: {error}")),
    };
    let started = Instant::now();
    let response = match client.get(HTTPS_TARGET).send() {
        Ok(response) => response,
        Err(error) => return ProbeResult::failed(short_reqwest_error(&error)),
    };
    let latency = started.elapsed().as_secs_f64() * 1_000.0;
    let status = response.status();
    ProbeResult {
        health: if !status.is_success() {
            Health::Failed
        } else if latency
            >= ProbeKind::Https
                .degraded_after_ms()
                .expect("HTTPS has a latency threshold")
        {
            Health::Degraded
        } else {
            Health::Ok
        },
        detail: format!("example.com HTTP {}", status.as_u16()),
        latency_ms: Some(latency),
        metrics: None,
    }
}

fn probe_public_ip() -> ProbeResult {
    for endpoint in PUBLIC_ENDPOINTS {
        let started = Instant::now();
        if let Ok(address) = fetch_public_ip(endpoint) {
            let latency = started.elapsed().as_secs_f64() * 1_000.0;
            return ProbeResult {
                health: Health::Ok,
                detail: address.to_string(),
                latency_ms: Some(latency),
                metrics: None,
            };
        }
    }
    ProbeResult::unavailable("all public-IP endpoints failed or timed out")
}

fn fetch_public_ip(endpoint: &str) -> Result<IpAddr> {
    let response = http_client(Duration::from_secs(2))?
        .get(endpoint)
        .send()
        .with_context(|| format!("request {endpoint}"))?
        .error_for_status()
        .with_context(|| format!("response {endpoint}"))?;
    let body = response.text().context("read public address")?;
    let address = IpAddr::from_str(body.trim()).context("parse public address")?;
    anyhow::ensure!(
        is_public_address(address),
        "endpoint returned a non-public address"
    );
    Ok(address)
}

fn is_public_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_private()
                && !address.is_loopback()
                && !address.is_link_local()
                && !address.is_broadcast()
                && !address.is_documentation()
                && !address.is_unspecified()
                && !address.is_multicast()
        }
        IpAddr::V6(address) => {
            let segments = address.segments();
            let unique_local = segments[0] & 0xfe00 == 0xfc00;
            let link_local = segments[0] & 0xffc0 == 0xfe80;
            let documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
            !address.is_loopback()
                && !address.is_unspecified()
                && !address.is_multicast()
                && !unique_local
                && !link_local
                && !documentation
        }
    }
}

fn http_client(timeout: Duration) -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::limited(3))
        .user_agent("linktop/0.1")
        .build()
        .context("build HTTP client")
}

fn short_reqwest_error(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "example.com: request timed out".into()
    } else if error.is_connect() {
        "example.com: connection failed".into()
    } else {
        format!("example.com: {error}")
    }
}

pub(crate) fn default_gateway() -> Option<String> {
    default_route().and_then(|route| route.1)
}

fn short_hostname() -> String {
    command_output("hostname", &["-s"])
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "unknown-host".into())
}

fn default_route() -> Option<(Option<String>, Option<String>)> {
    if cfg!(target_os = "macos") {
        let output = command_output("route", &["-n", "get", "default"])?;
        Some(parse_macos_route(&output))
    } else if cfg!(target_os = "windows") {
        let output = command_output("route", &["print", "-4"])?;
        Some(parse_windows_route(&output))
    } else {
        let output = command_output("ip", &["route", "show", "default"])?;
        Some(parse_linux_route(&output))
    }
}

fn physical_underlay(
    effective_interface: Option<&str>,
    known_underlay: Option<&PathUnderlay>,
) -> Option<PathUnderlay> {
    let effective_interface = effective_interface?;
    if !cfg!(target_os = "macos") || !is_tunnel_interface(effective_interface) {
        return None;
    }

    let nwi = command_output("scutil", &["--nwi"])?;
    let interfaces = parse_macos_nwi_interfaces(&nwi);
    let mut hardware = BTreeMap::new();
    if let Some(known) = known_underlay
        && interfaces
            .iter()
            .find(|interface| interface.as_str() != effective_interface)
            == Some(&known.interface)
    {
        hardware.insert(known.interface.clone(), known.link_type.clone());
    }
    if hardware.is_empty() {
        let hardware_ports = command_output("networksetup", &["-listallhardwareports"])?;
        hardware = parse_macos_hardware_interfaces(&hardware_ports);
    }
    for (candidate, link_type) in macos_underlay_candidates(effective_interface, &nwi, &hardware) {
        let Some(scoped_route) =
            command_output("route", &["-n", "get", "-ifscope", &candidate, "default"])
        else {
            continue;
        };
        let (interface, gateway) = parse_macos_route(&scoped_route);
        if interface.as_deref() == Some(candidate.as_str()) {
            return Some(PathUnderlay {
                interface: candidate,
                link_type,
                gateway,
            });
        }
    }
    None
}

fn macos_underlay_candidates(
    effective_interface: &str,
    nwi: &str,
    hardware: &BTreeMap<String, String>,
) -> Vec<(String, String)> {
    parse_macos_nwi_interfaces(nwi)
        .into_iter()
        .filter(|candidate| candidate != effective_interface)
        .filter_map(|candidate| {
            hardware
                .get(&candidate)
                .cloned()
                .map(|link_type| (candidate, link_type))
        })
        .collect()
}

fn parse_macos_nwi_interfaces(output: &str) -> Vec<String> {
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix("Network interfaces:"))
        .map(|interfaces| interfaces.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default()
}

fn parse_macos_hardware_interfaces(output: &str) -> BTreeMap<String, String> {
    let mut hardware = BTreeMap::new();
    let mut hardware_port: Option<String> = None;
    for line in output.lines() {
        if let Some(value) = line.strip_prefix("Hardware Port:") {
            let label = value.trim().to_lowercase();
            hardware_port = Some(if label.contains("wi-fi") || label.contains("airport") {
                "wifi".into()
            } else if label.contains("ethernet")
                || label.contains("thunderbolt")
                || label.contains("usb")
            {
                "ethernet".into()
            } else {
                label
            });
        } else if let Some(value) = line.strip_prefix("Device:")
            && let Some(link_type) = hardware_port.take()
        {
            hardware.insert(value.trim().to_string(), link_type);
        }
    }
    hardware
}

fn parse_macos_route(output: &str) -> (Option<String>, Option<String>) {
    let mut interface = None;
    let mut gateway = None;
    for line in output.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("interface:") {
            interface = Some(value.trim().into());
        } else if let Some(value) = line.strip_prefix("gateway:") {
            gateway = Some(value.trim().into());
        }
    }
    (interface, gateway)
}

fn parse_linux_route(output: &str) -> (Option<String>, Option<String>) {
    let words: Vec<_> = output.split_whitespace().collect();
    (value_after(&words, "dev"), value_after(&words, "via"))
}

fn parse_windows_route(output: &str) -> (Option<String>, Option<String>) {
    for line in output.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() >= 4 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
            return (Some(fields[3].into()), Some(fields[2].into()));
        }
    }
    (None, None)
}

fn value_after(words: &[&str], needle: &str) -> Option<String> {
    words
        .iter()
        .position(|word| *word == needle)
        .and_then(|index| words.get(index + 1))
        .map(|value| (*value).to_string())
}

fn local_addresses(default_interface: Option<&str>) -> Vec<Address> {
    let temporary_addresses = default_interface
        .filter(|_| cfg!(target_os = "macos"))
        .map(macos_temporary_addresses)
        .unwrap_or_default();
    let mut addresses: Vec<_> = get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|item| !item.is_loopback())
        .filter(|item| {
            !matches!(
                item.name.as_str(),
                "awdl0" | "llw0" | "ap1" | "anpi0" | "anpi1"
            )
        })
        .map(|item| {
            let ip = item.ip();
            Address {
                interface: item.name.clone(),
                address: ip.to_string(),
                family: if ip.is_ipv4() { 4 } else { 6 },
                is_default: default_interface == Some(item.name.as_str()),
                is_temporary: temporary_addresses.contains(&ip.to_string()),
            }
        })
        .collect();
    addresses.sort_by_key(|address| {
        (
            !address.is_default,
            address.interface.clone(),
            address.family,
            address.address.clone(),
        )
    });
    addresses
}

fn resolver_servers() -> Vec<String> {
    if cfg!(target_os = "macos")
        && let Some(output) = command_output("scutil", &["--dns"])
    {
        let resolvers = parse_macos_resolvers(&output);
        if !resolvers.is_empty() {
            return resolvers;
        }
    }
    fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.trim().strip_prefix("nameserver "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

fn parse_macos_resolvers(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            let (key, value) = line.trim().split_once(':')?;
            key.trim()
                .starts_with("nameserver[")
                .then(|| value.trim().to_string())
        })
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn macos_temporary_addresses(interface: &str) -> BTreeSet<String> {
    parse_macos_temporary_addresses(&command_output("ifconfig", &[interface]).unwrap_or_default())
}

fn parse_macos_temporary_addresses(output: &str) -> BTreeSet<String> {
    output
        .lines()
        .filter(|line| line.contains(" temporary"))
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some("inet6"))
                .then(|| fields.next())
                .flatten()
                .and_then(|value| value.split('%').next())
                .map(str::to_string)
        })
        .collect()
}

fn network_configuration(
    interface: Option<&str>,
) -> (Option<String>, bool, Option<Box<NetworkConfiguration>>) {
    let Some(interface) = interface else {
        return (None, false, None);
    };
    if cfg!(target_os = "macos") {
        let Some(output) = command_output("ipconfig", &["getsummary", interface]) else {
            return (None, false, None);
        };
        let value = output.lines().find_map(|line| {
            let line = line.trim();
            (line.starts_with("SSID") && !line.starts_with("BSSID"))
                .then(|| {
                    line.split_once(':')
                        .map(|(_, value)| value.trim().to_string())
                })
                .flatten()
        });
        let restricted = value.as_deref() == Some("<redacted>");
        return (
            (!restricted).then_some(value).flatten(),
            restricted,
            parse_macos_network_configuration(&output).map(Box::new),
        );
    }
    let value = if cfg!(target_os = "linux") {
        command_output("iwgetid", &["-r", "-i", interface])
    } else if cfg!(target_os = "windows") {
        command_output("netsh", &["wlan", "show", "interfaces"]).and_then(|output| {
            output.lines().find_map(|line| {
                let (key, value) = line.split_once(':')?;
                (key.trim().eq_ignore_ascii_case("SSID") && !value.trim().is_empty())
                    .then(|| value.trim().to_string())
            })
        })
    } else {
        None
    };
    (value, false, None)
}

fn parse_macos_network_configuration(output: &str) -> Option<NetworkConfiguration> {
    let value = |key: &str| {
        output.lines().find_map(|line| {
            let (candidate, value) = line.trim().split_once(':')?;
            (candidate.trim() == key).then(|| value.trim().to_string())
        })
    };
    let lease_seconds = value("lease_time (uint32)").and_then(|value| {
        value
            .strip_prefix("0x")
            .and_then(|hex| u64::from_str_radix(hex, 16).ok())
            .or_else(|| value.parse().ok())
    });
    let bssid = value("BSSID");
    let bssid_restricted = bssid.as_deref() == Some("<redacted>");
    let configuration = NetworkConfiguration {
        connection_id: value("ConnectionID"),
        associated_bssid: (!bssid_restricted).then_some(bssid).flatten(),
        bssid_restricted,
        method: value("ConfigMethod"),
        state: value("State"),
        server: value("server_identifier (ip)"),
        subnet_mask: value("subnet_mask (ip)"),
        lease_seconds,
        lease_started_at: value("LeaseStartTime"),
        lease_expires_at: value("LeaseExpirationTime"),
        router_arp_verified: value("RouterARPVerified")
            .map(|value| value.eq_ignore_ascii_case("true")),
        security: value("Security"),
    };
    (configuration.method.is_some()
        || configuration.state.is_some()
        || configuration.server.is_some()
        || configuration.security.is_some())
    .then_some(configuration)
}

fn link_type(interface: &str) -> String {
    if is_tunnel_interface(interface) {
        "vpn".into()
    } else if interface.starts_with("wl") {
        "wifi".into()
    } else if interface.starts_with("tailscale") {
        "tailscale".into()
    } else if cfg!(target_os = "macos") {
        macos_link_type(interface).unwrap_or_else(|| "network".into())
    } else if interface.starts_with("en") || interface.starts_with("eth") {
        "ethernet".into()
    } else {
        "network".into()
    }
}

fn is_tunnel_interface(interface: &str) -> bool {
    interface.starts_with("utun") || interface.starts_with("tun") || interface.starts_with("wg")
}

fn macos_link_type(interface: &str) -> Option<String> {
    let output = command_output("networksetup", &["-listallhardwareports"])?;
    parse_macos_hardware_interfaces(&output)
        .get(interface)
        .cloned()
}

fn collect_wifi(interface: Option<&str>) -> WifiObservation {
    let Some(interface) = interface else {
        return WifiObservation::default();
    };
    if link_type(interface) != "wifi" {
        return WifiObservation::default();
    }
    if cfg!(target_os = "macos") {
        let mut command = Command::new("system_profiler");
        command.args(["SPAirPortDataType", "-json"]);
        let Some(output) = process::run_bounded(&mut command, Duration::from_secs(12))
            .ok()
            .flatten()
        else {
            return WifiObservation::default();
        };
        if !output.status.success() {
            return WifiObservation::default();
        }
        parse_macos_wifi(&String::from_utf8_lossy(&output.stdout), interface).unwrap_or_default()
    } else if cfg!(target_os = "windows") {
        WifiObservation {
            telemetry: command_output("netsh", &["wlan", "show", "interfaces"])
                .and_then(|output| parse_windows_wifi(&output)),
            ..WifiObservation::default()
        }
    } else {
        WifiObservation {
            telemetry: command_output("iw", &["dev", interface, "link"])
                .and_then(|output| parse_linux_wifi(&output)),
            ..WifiObservation::default()
        }
    }
}

fn parse_macos_wifi(output: &str, interface: &str) -> Option<WifiObservation> {
    let payload: Value = serde_json::from_str(output).ok()?;
    let interfaces = payload
        .get("SPAirPortDataType")?
        .as_array()?
        .iter()
        .filter_map(|adapter| adapter.get("spairport_airport_interfaces")?.as_array())
        .flatten();
    for candidate in interfaces {
        if candidate.get("_name").and_then(Value::as_str) != Some(interface) {
            continue;
        }
        let current = candidate.get("spairport_current_network_information")?;
        let signal_noise = current
            .get("spairport_signal_noise")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let signal_values = extract_numbers(signal_noise);
        let channel_text = current
            .get("spairport_network_channel")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let channel_values = extract_numbers(channel_text);
        let telemetry = WifiTelemetry {
            signal_dbm: signal_values.first().copied(),
            noise_dbm: signal_values.get(1).copied(),
            signal_percent: None,
            channel: channel_values.first().map(|value| *value as u32),
            channel_width_mhz: channel_text
                .split(|character: char| !character.is_ascii_digit())
                .filter_map(|part| part.parse().ok())
                .find(|width| matches!(width, 20 | 40 | 80 | 160 | 320)),
            frequency_mhz: None,
            band: channel_text
                .split_once('(')
                .and_then(|(_, rest)| rest.split_once(',').map(|(band, _)| band.to_string())),
            phy: current
                .get("spairport_network_phymode")
                .and_then(Value::as_str)
                .map(str::to_string),
            tx_rate_mbps: current.get("spairport_network_rate").and_then(number_value),
            rx_rate_mbps: None,
            mcs: current
                .get("spairport_network_mcs")
                .and_then(Value::as_u64)
                .map(|value| value as u32),
        };
        let ssid = current
            .get("_name")
            .and_then(Value::as_str)
            .filter(|value| *value != "<redacted>")
            .map(str::to_string);
        return (ssid.is_some() || !telemetry.is_empty()).then_some(WifiObservation {
            ssid,
            telemetry: (!telemetry.is_empty()).then_some(telemetry),
        });
    }
    None
}

fn parse_linux_wifi(output: &str) -> Option<WifiTelemetry> {
    if output.contains("Not connected") {
        return None;
    }
    let telemetry = WifiTelemetry {
        signal_dbm: line_number(output, "signal:"),
        noise_dbm: None,
        signal_percent: None,
        channel: None,
        channel_width_mhz: None,
        frequency_mhz: line_number(output, "freq:").map(|value| value as u32),
        band: None,
        phy: None,
        tx_rate_mbps: line_number(output, "tx bitrate:"),
        rx_rate_mbps: line_number(output, "rx bitrate:"),
        mcs: None,
    };
    (!telemetry.is_empty()).then_some(telemetry)
}

fn parse_windows_wifi(output: &str) -> Option<WifiTelemetry> {
    if output.to_ascii_lowercase().contains("state")
        && output.to_ascii_lowercase().contains("disconnected")
    {
        return None;
    }
    let telemetry = WifiTelemetry {
        signal_dbm: None,
        noise_dbm: None,
        signal_percent: line_number(output, "Signal"),
        channel: line_number(output, "Channel").map(|value| value as u32),
        channel_width_mhz: None,
        frequency_mhz: None,
        band: None,
        phy: line_value(output, "Radio type"),
        tx_rate_mbps: line_number(output, "Transmit rate (Mbps)"),
        rx_rate_mbps: line_number(output, "Receive rate (Mbps)"),
        mcs: None,
    };
    (!telemetry.is_empty()).then_some(telemetry)
}

fn number_value(value: &Value) -> Option<f64> {
    value.as_f64().or_else(|| {
        value
            .as_str()
            .and_then(|text| extract_numbers(text).first().copied())
    })
}

fn line_number(output: &str, label: &str) -> Option<f64> {
    line_value(output, label).and_then(|value| extract_numbers(&value).first().copied())
}

fn line_value(output: &str, label: &str) -> Option<String> {
    let label = label.trim_end_matches(':');
    output.lines().find_map(|line| {
        let (key, value) = line.trim().split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case(label)
            .then(|| value.trim().to_string())
    })
}

fn extract_numbers(value: &str) -> Vec<f64> {
    value
        .split(|character: char| {
            !character.is_ascii_digit() && character != '-' && character != '.'
        })
        .filter(|part| !part.is_empty() && *part != "-" && *part != ".")
        .filter_map(|part| part.parse().ok())
        .collect()
}

fn command_output(program: &str, arguments: &[&str]) -> Option<String> {
    let mut command = Command::new(program);
    command.args(arguments);
    let output = process::run_bounded(&mut command, Duration::from_secs(2))
        .ok()
        .flatten()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn parse_ping_latencies(output: &str) -> Vec<f64> {
    let mut samples = Vec::new();
    let mut rest = output;
    while let Some(position) = rest.find("time") {
        rest = &rest[position + 4..];
        let value = rest
            .trim_start()
            .trim_start_matches(['=', '<'])
            .trim_start();
        let number: String = value
            .chars()
            .take_while(|character| character.is_ascii_digit() || *character == '.')
            .collect();
        if let Ok(sample) = number.parse() {
            samples.push(sample);
        }
    }
    samples
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_probe_scheduler_requires_explicit_overview_policy() {
        for mode in [MonitorMode::Overview, MonitorMode::Link, MonitorMode::Peers] {
            assert!(!permits_active_probes(mode, ProbePolicy::Passive));
        }
        assert!(permits_active_probes(
            MonitorMode::Overview,
            ProbePolicy::Active
        ));
        assert!(!permits_active_probes(
            MonitorMode::Link,
            ProbePolicy::Active
        ));
        assert!(!permits_active_probes(
            MonitorMode::Peers,
            ProbePolicy::Active
        ));
    }

    #[test]
    fn task_deadline_returns_completed_work() {
        assert_eq!(
            run_task_with_deadline(Duration::from_secs(1), || 42),
            Some(42)
        );
    }

    #[test]
    fn task_deadline_releases_the_caller_when_work_stalls() {
        let started = Instant::now();
        let result = run_task_with_deadline(Duration::from_millis(5), || {
            thread::sleep(Duration::from_millis(200));
            42
        });
        assert_eq!(result, None);
        assert!(started.elapsed() < Duration::from_millis(150));
    }

    #[test]
    fn active_live_refreshes_core_path_checks_but_not_public_identity() {
        let started = Instant::now();
        let due = started + ACTIVE_PATH_REFRESH_INTERVAL;
        for kind in [ProbeKind::Dns, ProbeKind::Https] {
            assert!(!periodic_internet_probe_due(
                kind,
                Some(started),
                due - Duration::from_millis(1)
            ));
            assert!(periodic_internet_probe_due(kind, Some(started), due));
        }
        assert!(!periodic_internet_probe_due(
            ProbeKind::PublicIp,
            Some(started),
            due
        ));
    }

    #[test]
    fn parses_platform_default_routes() {
        assert_eq!(
            parse_macos_route("gateway: 192.168.1.1\ninterface: en0\n"),
            (Some("en0".into()), Some("192.168.1.1".into()))
        );
        assert_eq!(
            parse_linux_route("default via 10.0.0.1 dev wlan0 proto dhcp"),
            (Some("wlan0".into()), Some("10.0.0.1".into()))
        );
        assert_eq!(
            parse_windows_route("0.0.0.0  0.0.0.0  192.0.2.1  192.0.2.2  25"),
            (Some("192.0.2.2".into()), Some("192.0.2.1".into()))
        );
    }

    #[test]
    fn macos_underlay_candidates_require_active_nwi_and_hardware_evidence() {
        let nwi = "IPv4 network interface information\n\
                     utun4 : flags : 0x7\n\
                     en0 : flags : 0x7\n\
                   Network interfaces: utun4 en0 bridge0\n";
        let hardware = parse_macos_hardware_interfaces(
            "Hardware Port: Wi-Fi\n\
             Device: en0\n\
             Ethernet Address: 00:11:22:33:44:55\n\
             Hardware Port: Thunderbolt Bridge\n\
             Device: bridge0\n",
        );

        assert_eq!(
            macos_underlay_candidates("utun4", nwi, &hardware),
            vec![
                ("en0".into(), "wifi".into()),
                ("bridge0".into(), "ethernet".into())
            ]
        );
        assert!(
            macos_underlay_candidates("en0", nwi, &hardware)
                .iter()
                .all(|(interface, _)| interface != "en0")
        );
    }

    #[test]
    fn transient_underlay_gap_is_held_before_sustained_evidence_loss() {
        let mut previous = LinkSnapshot::empty();
        previous.interface = Some("utun4".into());
        previous.link_type = Some("vpn".into());
        previous.underlay = Some(PathUnderlay {
            interface: "en0".into(),
            link_type: "wifi".into(),
            gateway: Some("192.168.1.1".into()),
        });
        let mut candidate = previous.clone();
        candidate.underlay = None;
        let started = Instant::now();
        let mut incomplete_since = None;

        assert!(should_hold_incomplete_underlay(
            Some(&previous),
            &candidate,
            &mut incomplete_since,
            started,
        ));
        assert!(should_hold_incomplete_underlay(
            Some(&previous),
            &candidate,
            &mut incomplete_since,
            started + PATH_TRANSITION_GRACE - Duration::from_millis(1),
        ));
        assert!(!should_hold_incomplete_underlay(
            Some(&previous),
            &candidate,
            &mut incomplete_since,
            started + PATH_TRANSITION_GRACE,
        ));

        candidate.interface = Some("utun5".into());
        assert!(!should_hold_incomplete_underlay(
            Some(&previous),
            &candidate,
            &mut incomplete_since,
            started + Duration::from_secs(1),
        ));
        assert!(incomplete_since.is_none());
    }

    #[test]
    fn transient_missing_route_is_held_before_a_sustained_disconnect() {
        let mut previous = LinkSnapshot::empty();
        previous.interface = Some("en0".into());
        let candidate = LinkSnapshot::empty();
        let started = Instant::now();
        let mut incomplete_since = None;

        assert!(should_hold_incomplete_route(
            Some(&previous),
            &candidate,
            &mut incomplete_since,
            started,
        ));
        assert!(should_hold_incomplete_route(
            Some(&previous),
            &candidate,
            &mut incomplete_since,
            started + PATH_TRANSITION_GRACE - Duration::from_millis(1),
        ));
        assert!(!should_hold_incomplete_route(
            Some(&previous),
            &candidate,
            &mut incomplete_since,
            started + PATH_TRANSITION_GRACE,
        ));

        let mut settled = candidate;
        settled.interface = Some("en0".into());
        assert!(!should_hold_incomplete_route(
            Some(&previous),
            &settled,
            &mut incomplete_since,
            started + Duration::from_secs(1),
        ));
        assert!(incomplete_since.is_none());
    }

    #[test]
    fn parses_macos_interface_counters_from_the_link_row() {
        let counters = parse_macos_interface_counters(
            "Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll Drop\n\
             en0 1500 <Link#14> aa:bb:cc:dd:ee:ff 10 1 2000 20 2 3000 0 3\n\
             en0 1500 192.168.1 192.168.1.2 10 - 2000 20 - 3000 - -\n",
            "en0",
        )
        .unwrap();
        assert_eq!(counters.received_bytes, 2_000);
        assert_eq!(counters.transmitted_bytes, 3_000);
        assert_eq!(counters.drops, 3);
    }

    #[test]
    fn parses_effective_macos_resolvers_across_scoped_sections() {
        let resolvers = parse_macos_resolvers(
            "resolver #1\n  nameserver[0] : 100.100.100.100\n\
             resolver #2\n  nameserver[0] : 192.168.1.1\n\
             DNS configuration (for scoped queries)\n\
             resolver #1\n  nameserver[0] : 192.168.1.1\n",
        );
        assert_eq!(resolvers, vec!["100.100.100.100", "192.168.1.1"]);
    }

    #[test]
    fn parses_macos_dhcp_context_without_requiring_identifiers() {
        let configuration = parse_macos_network_configuration(
            "ConnectionID : 101\n\
             BSSID : 02:00:00:00:00:01\n\
             ConfigMethod : DHCP\n\
             LeaseExpirationTime : 07/25/2026 02:55:49\n\
             LeaseStartTime : 07/24/2026 14:55:49\n\
             State : BOUND\n\
             server_identifier (ip): 192.168.1.1\n\
             lease_time (uint32): 0xa8c0\n\
             subnet_mask (ip): 255.255.255.0\n\
             RouterARPVerified : TRUE\n\
             Security : WPA2_PSK\n",
        )
        .unwrap();
        assert_eq!(configuration.connection_id.as_deref(), Some("101"));
        assert_eq!(
            configuration.associated_bssid.as_deref(),
            Some("02:00:00:00:00:01")
        );
        assert!(!configuration.bssid_restricted);
        assert_eq!(configuration.method.as_deref(), Some("DHCP"));
        assert_eq!(configuration.state.as_deref(), Some("BOUND"));
        assert_eq!(configuration.server.as_deref(), Some("192.168.1.1"));
        assert_eq!(configuration.lease_seconds, Some(43_200));
        assert_eq!(
            configuration.lease_started_at.as_deref(),
            Some("07/24/2026 14:55:49")
        );
        assert_eq!(
            configuration.lease_expires_at.as_deref(),
            Some("07/25/2026 02:55:49")
        );
        assert_eq!(configuration.router_arp_verified, Some(true));
        assert_eq!(configuration.security.as_deref(), Some("WPA2_PSK"));
    }

    #[test]
    fn macos_bssid_redaction_is_a_coverage_state_not_an_identifier() {
        let configuration = parse_macos_network_configuration(
            "ConnectionID : 101\n\
             BSSID : <redacted>\n\
             ConfigMethod : DHCP\n\
             State : BOUND\n",
        )
        .unwrap();

        assert!(configuration.associated_bssid.is_none());
        assert!(configuration.bssid_restricted);
    }

    #[test]
    fn parses_latest_nettop_delta_and_aggregates_processes() {
        let processes = parse_nettop_process_traffic(
            ",bytes_in,bytes_out,\n\
             codex.10,1000,2000,\n\
             mDNSResponder.20,5000,100,\n\
             ,bytes_in,bytes_out,\n\
             codex.10,100,200,\n\
             codex.11,300,400,\n\
             mDNSResponder.20,10,0,\n",
        );
        assert_eq!(processes.len(), 2);
        assert_eq!(processes[0].process, "codex");
        assert_eq!(processes[0].processes, 2);
        assert_eq!(processes[0].received_bytes_per_second, 400);
        assert_eq!(processes[0].transmitted_bytes_per_second, 600);
        assert_eq!(processes[1].process, "mDNSResponder");
    }

    #[test]
    fn identifies_only_macos_ipv6_addresses_marked_temporary() {
        let addresses = parse_macos_temporary_addresses(
            "inet6 fe80::1%en0 prefixlen 64 secured scopeid 0xe\n\
             inet6 2001:db8::1 prefixlen 64 autoconf temporary\n\
             inet 192.0.2.2 netmask 0xffffff00\n",
        );
        assert_eq!(addresses, BTreeSet::from(["2001:db8::1".into()]));
    }

    #[test]
    fn public_address_filter_rejects_local_and_documentation_ranges() {
        assert!(is_public_address(IpAddr::from_str("8.8.8.8").unwrap()));
        assert!(is_public_address(
            IpAddr::from_str("2606:4700:4700::1111").unwrap()
        ));
        assert!(!is_public_address(IpAddr::from_str("192.168.1.1").unwrap()));
        assert!(!is_public_address(IpAddr::from_str("2001:db8::1").unwrap()));
    }

    #[test]
    fn parses_every_ping_reply() {
        assert_eq!(
            parse_ping_latencies("time=12.47 ms\ntime<1 ms\ntime=20 ms"),
            vec![12.47, 1.0, 20.0]
        );
    }

    #[test]
    fn parses_linux_wifi_without_identifiers() {
        let telemetry = parse_linux_wifi(
            "Connected to aa:bb:cc:dd:ee:ff\n\tfreq: 5180\n\tsignal: -55.00 dBm\n\ttx bitrate: 650.0 MBit/s\n",
        )
        .unwrap();
        assert_eq!(telemetry.frequency_mhz, Some(5180));
        assert_eq!(telemetry.signal_dbm, Some(-55.0));
        assert_eq!(telemetry.tx_rate_mbps, Some(650.0));
    }

    #[test]
    fn parses_windows_wifi_without_bssid_or_ssid() {
        let telemetry = parse_windows_wifi(
            "State : connected\nSignal : 80%\nChannel : 157\nReceive rate (Mbps) : 600\nTransmit rate (Mbps) : 650\nRadio type : 802.11ax\n",
        )
        .unwrap();
        assert_eq!(telemetry.signal_percent, Some(80.0));
        assert_eq!(telemetry.channel, Some(157));
        assert_eq!(telemetry.rx_rate_mbps, Some(600.0));
        assert_eq!(telemetry.phy.as_deref(), Some("802.11ax"));
    }

    #[test]
    fn parses_system_profiler_wifi() {
        let observation = parse_macos_wifi(
            r#"{
              "SPAirPortDataType": [{"spairport_airport_interfaces": [{
                "_name": "en0",
                "spairport_current_network_information": {
                  "_name": "house-wifi",
                  "spairport_network_channel": "157 (5GHz, 80MHz)",
                  "spairport_network_mcs": 7,
                  "spairport_network_phymode": "802.11ac",
                  "spairport_network_rate": 650,
                  "spairport_signal_noise": "-55 dBm / -95 dBm"
                }
              }]}]
            }"#,
            "en0",
        )
        .unwrap();
        assert_eq!(observation.ssid.as_deref(), Some("house-wifi"));
        let telemetry = observation.telemetry.unwrap();
        assert_eq!(telemetry.signal_dbm, Some(-55.0));
        assert_eq!(telemetry.noise_dbm, Some(-95.0));
        assert_eq!(telemetry.channel, Some(157));
        assert_eq!(telemetry.channel_width_mhz, Some(80));
        assert_eq!(telemetry.band.as_deref(), Some("5GHz"));
        assert_eq!(telemetry.tx_rate_mbps, Some(650.0));
    }
}
