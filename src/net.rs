use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::net::{IpAddr, ToSocketAddrs};
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use if_addrs::get_if_addrs;
use serde_json::Value;

use crate::metrics::LatencyMetrics;
use crate::model::{
    Address, Health, InterfaceCounters, LinkSnapshot, MonitorControl, MonitorMode, MonitorUpdate,
    ProbeKind, ProbeResult, SnapshotReport, WifiTelemetry,
};
use crate::{peers, process};

const HTTPS_TARGET: &str = "https://example.com/";
const DNS_TARGET: &str = "example.com:443";
const SNAPSHOT_GATEWAY_ATTEMPTS: usize = 10;
const PUBLIC_ENDPOINTS: [&str; 3] = [
    "https://api.ipify.org",
    "https://icanhazip.com",
    "https://wtfismyip.com/text",
];

pub fn start_monitor(
    interval: Duration,
    mode: MonitorMode,
) -> (
    Receiver<MonitorUpdate>,
    Sender<MonitorControl>,
    thread::JoinHandle<()>,
) {
    let (update_tx, update_rx) = mpsc::channel();
    let (control_tx, control_rx) = mpsc::channel();
    let handle = thread::spawn(move || monitor_loop(interval, mode, update_tx, control_rx));
    (update_rx, control_tx, handle)
}

fn monitor_loop(
    interval: Duration,
    mode: MonitorMode,
    update_tx: Sender<MonitorUpdate>,
    control_rx: Receiver<MonitorControl>,
) {
    let mut paused = false;
    let mut stopped = false;
    let mut internet_refresh_pending = [true; 3];
    let mut peers_refresh_pending = true;
    let mut wifi_refresh_pending = true;
    let mut tick = 0_u64;
    let mut gateway = None;
    let mut interface = None;
    let mut path_generation = 0_u64;
    let mut path_fingerprint = None;
    let probe_in_flight = Arc::new(std::array::from_fn::<_, 4, _>(|_| AtomicBool::new(false)));
    let traffic_in_flight = Arc::new(AtomicBool::new(false));
    let peers_in_flight = Arc::new(AtomicBool::new(false));
    let wifi_in_flight = Arc::new(AtomicBool::new(false));
    let sleep_step = Duration::from_millis(100);
    let steps_per_tick = (interval.as_millis() / sleep_step.as_millis()).max(1) as usize;

    while !stopped {
        while let Ok(control) = control_rx.try_recv() {
            match control {
                MonitorControl::Refresh => {
                    internet_refresh_pending.fill(true);
                    peers_refresh_pending = true;
                    wifi_refresh_pending = true;
                }
                MonitorControl::Pause(value) => paused = value,
                MonitorControl::Stop => stopped = true,
            }
        }
        if stopped {
            break;
        }

        if !paused {
            let link = collect_link();
            let fingerprint = link.path_fingerprint();
            if path_fingerprint.as_ref() != Some(&fingerprint) {
                path_generation = path_generation.wrapping_add(1).max(1);
                path_fingerprint = Some(fingerprint);
                internet_refresh_pending.fill(true);
                peers_refresh_pending = true;
                wifi_refresh_pending = true;
            }
            gateway.clone_from(&link.gateway);
            interface.clone_from(&link.interface);
            let _ = update_tx.send(MonitorUpdate::Link {
                generation: path_generation,
                snapshot: link.clone(),
            });

            match mode {
                MonitorMode::Overview => {
                    spawn_probe(
                        ProbeKind::Gateway,
                        gateway.clone(),
                        update_tx.clone(),
                        1,
                        path_generation,
                        probe_in_flight.clone(),
                    );
                    spawn_traffic(
                        interface.clone(),
                        update_tx.clone(),
                        path_generation,
                        traffic_in_flight.clone(),
                    );
                }
                MonitorMode::Link => {
                    spawn_traffic(
                        interface.clone(),
                        update_tx.clone(),
                        path_generation,
                        traffic_in_flight.clone(),
                    );
                }
                MonitorMode::Peers => {}
            }

            // Internet probes are a bounded startup, transition, or manual
            // refresh diagnostic rather than background traffic coupled to
            // the gateway sample rate.
            if mode == MonitorMode::Overview {
                for (pending, kind) in internet_refresh_pending.iter_mut().zip([
                    ProbeKind::Dns,
                    ProbeKind::Https,
                    ProbeKind::PublicIp,
                ]) {
                    if *pending
                        && spawn_probe(
                            kind,
                            gateway.clone(),
                            update_tx.clone(),
                            1,
                            path_generation,
                            probe_in_flight.clone(),
                        )
                    {
                        *pending = false;
                    }
                }
            }

            if tick.is_multiple_of(15) && mode == MonitorMode::Overview {
                peers_refresh_pending = true;
                wifi_refresh_pending = true;
            }
            if tick.is_multiple_of(3) && mode == MonitorMode::Link {
                wifi_refresh_pending = true;
            }
            if mode == MonitorMode::Peers {
                peers_refresh_pending = true;
            }
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
            tick = tick.wrapping_add(1);
        }

        for _ in 0..steps_per_tick {
            match control_rx.recv_timeout(sleep_step) {
                Ok(MonitorControl::Refresh) => {
                    internet_refresh_pending.fill(true);
                    peers_refresh_pending = true;
                    wifi_refresh_pending = true;
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

fn spawn_probe(
    kind: ProbeKind,
    gateway: Option<String>,
    tx: Sender<MonitorUpdate>,
    gateway_attempts: usize,
    generation: u64,
    in_flight: Arc<[AtomicBool; 4]>,
) -> bool {
    let slot = probe_slot(kind);
    if in_flight[slot].swap(true, Ordering::AcqRel) {
        return false;
    }
    let _ = tx.send(MonitorUpdate::ProbeStarted { generation, kind });
    thread::spawn(move || {
        let result = run_probe(kind, gateway.as_deref(), gateway_attempts);
        let _ = tx.send(MonitorUpdate::ProbeFinished {
            generation,
            kind,
            result,
        });
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
        let telemetry = collect_wifi_telemetry(interface.as_deref());
        let _ = tx.send(MonitorUpdate::Wifi {
            generation,
            telemetry,
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

pub fn collect_snapshot(timeout: Duration) -> SnapshotReport {
    let mut link = collect_link();
    let wifi_interface = link.interface.clone();
    let wifi = thread::spawn(move || collect_wifi_telemetry(wifi_interface.as_deref()));
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
            results.push((kind, ProbeResult::failed("snapshot deadline exceeded")));
        }
    }
    results.sort_by_key(|(kind, _)| ProbeKind::ALL.iter().position(|item| item == kind));
    if let Some((_, result)) = results
        .iter()
        .find(|(kind, result)| *kind == ProbeKind::PublicIp && !result.health.is_problem())
    {
        link.public_ip = Some(result.detail.clone());
    }
    link.wifi = wifi.join().unwrap_or(None);
    let neighbors = neighbors
        .join()
        .unwrap_or_else(|_| crate::model::PeerSnapshot {
            health: Health::Unavailable,
            detail: "neighbor-cache worker panicked".into(),
            sources: Vec::new(),
            failed_sources: Vec::new(),
            oui_source: None,
            peers: Vec::new(),
        });
    let interface_counters = link
        .interface
        .as_deref()
        .and_then(collect_interface_counters);
    SnapshotReport::from_results(link, interface_counters, neighbors, results)
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
    let addresses = local_addresses(interface.as_deref());
    let (ssid, ssid_restricted) = wifi_ssid(interface.as_deref());
    LinkSnapshot {
        host: short_hostname(),
        link_type: interface.as_deref().map(link_type),
        ssid,
        ssid_restricted,
        wifi: None,
        interface,
        gateway,
        public_ip: None,
        resolvers: resolver_servers(),
        addresses,
    }
}

pub fn collect_link_snapshot() -> LinkSnapshot {
    let mut link = collect_link();
    link.wifi = collect_wifi_telemetry(link.interface.as_deref());
    link
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
        Health::Failed
    } else {
        metrics.health()
    };
    let loss = metrics.loss_rate.map_or_else(
        || "loss unknown".into(),
        |value| format!("{:.0}% loss", value * 100.0),
    );
    ProbeResult {
        health,
        detail: format!("{gateway}, {attempts} attempt(s), {loss}"),
        latency_ms: metrics.rtt_p50_ms,
        metrics: Some(metrics),
    }
}

fn probe_dns() -> ProbeResult {
    let started = Instant::now();
    let addresses = match DNS_TARGET.to_socket_addrs() {
        Ok(addresses) => addresses
            .map(|address| address.ip())
            .collect::<BTreeSet<_>>(),
        Err(error) => return ProbeResult::failed(format!("example.com: {error}")),
    };
    let latency = started.elapsed().as_secs_f64() * 1_000.0;
    ProbeResult {
        health: if latency >= 500.0 {
            Health::Degraded
        } else {
            Health::Ok
        },
        detail: format!("example.com → {} address(es)", addresses.len()),
        latency_ms: Some(latency),
        metrics: None,
    }
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
        } else if latency >= 1_000.0 {
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
                health: if latency >= 1_500.0 {
                    Health::Degraded
                } else {
                    Health::Ok
                },
                detail: address.to_string(),
                latency_ms: Some(latency),
                metrics: None,
            };
        }
    }
    ProbeResult::failed("all public-IP endpoints failed or timed out")
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

fn wifi_ssid(interface: Option<&str>) -> (Option<String>, bool) {
    let Some(interface) = interface else {
        return (None, false);
    };
    let value = if cfg!(target_os = "macos") {
        command_output("ipconfig", &["getsummary", interface]).and_then(|output| {
            output.lines().find_map(|line| {
                let line = line.trim();
                (line.starts_with("SSID") && !line.starts_with("BSSID"))
                    .then(|| {
                        line.split_once(':')
                            .map(|(_, value)| value.trim().to_string())
                    })
                    .flatten()
            })
        })
    } else if cfg!(target_os = "linux") {
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
    if cfg!(target_os = "macos") && value.as_deref() == Some("<redacted>") {
        (None, true)
    } else {
        (value, false)
    }
}

fn link_type(interface: &str) -> String {
    if interface.starts_with("utun") || interface.starts_with("tun") || interface.starts_with("wg")
    {
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

fn macos_link_type(interface: &str) -> Option<String> {
    let output = command_output("networksetup", &["-listallhardwareports"])?;
    let mut hardware_port: Option<String> = None;
    for line in output.lines() {
        if let Some(value) = line.strip_prefix("Hardware Port:") {
            hardware_port = Some(value.trim().to_lowercase());
        } else if let Some(value) = line.strip_prefix("Device:") {
            if value.trim() == interface {
                let label = hardware_port.as_deref().unwrap_or("network");
                return Some(if label.contains("wi-fi") || label.contains("airport") {
                    "wifi".into()
                } else if label.contains("ethernet")
                    || label.contains("thunderbolt")
                    || label.contains("usb")
                {
                    "ethernet".into()
                } else {
                    label.into()
                });
            }
            hardware_port = None;
        }
    }
    None
}

fn collect_wifi_telemetry(interface: Option<&str>) -> Option<WifiTelemetry> {
    let interface = interface?;
    if link_type(interface) != "wifi" {
        return None;
    }
    if cfg!(target_os = "macos") {
        let mut command = Command::new("system_profiler");
        command.args(["SPAirPortDataType", "-json"]);
        let output = process::run_bounded(&mut command, Duration::from_secs(12))
            .ok()
            .flatten()?;
        output
            .status
            .success()
            .then(|| parse_macos_wifi(&String::from_utf8_lossy(&output.stdout), interface))
            .flatten()
    } else if cfg!(target_os = "windows") {
        command_output("netsh", &["wlan", "show", "interfaces"])
            .and_then(|output| parse_windows_wifi(&output))
    } else {
        command_output("iw", &["dev", interface, "link"])
            .and_then(|output| parse_linux_wifi(&output))
    }
}

fn parse_macos_wifi(output: &str, interface: &str) -> Option<WifiTelemetry> {
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
        return (!telemetry.is_empty()).then_some(telemetry);
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
        let telemetry = parse_macos_wifi(
            r#"{
              "SPAirPortDataType": [{"spairport_airport_interfaces": [{
                "_name": "en0",
                "spairport_current_network_information": {
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
        assert_eq!(telemetry.signal_dbm, Some(-55.0));
        assert_eq!(telemetry.noise_dbm, Some(-95.0));
        assert_eq!(telemetry.channel, Some(157));
        assert_eq!(telemetry.channel_width_mhz, Some(80));
        assert_eq!(telemetry.band.as_deref(), Some("5GHz"));
        assert_eq!(telemetry.tx_rate_mbps, Some(650.0));
    }
}
