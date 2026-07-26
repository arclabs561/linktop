mod capture;
mod history;
mod metrics;
mod model;
mod net;
mod oui;
mod peers;
mod plain;
mod process;
mod speed;
mod ui;

use std::ffi::OsString;
use std::io::{self, IsTerminal};
use std::path::PathBuf;
use std::sync::mpsc::TryRecvError;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use model::{Health, MonitorControl, MonitorMode, ProbePolicy};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

#[derive(Debug, Parser)]
#[command(
    name = "linktop",
    version,
    about = "Terminal instrument for the host's current network context",
    long_about = "Observe the default route, interface, radio, counters, and native neighbor cache without transmitting by default. Active next-hop, DNS, HTTPS, and public-egress probes are explicit."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Seconds between live observations and, when enabled, next-hop RTT probes.
    #[arg(long, global = true, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..=60))]
    interval: u64,

    /// Stream the live monitor as append-only text instead of opening the TUI.
    #[arg(long, global = true)]
    plain: bool,

    /// Exit a live overview, link, or peers view after this many seconds.
    #[arg(long, global = true, value_parser = clap::value_parser!(u64).range(1..=86_400))]
    dwell: Option<u64>,

    /// Enable next-hop, DNS, HTTPS, and public-egress probes in the overview.
    #[arg(long)]
    active: bool,

    /// Read, compare, and append private host-path evidence at PATH (or LINKTOP_HISTORY).
    #[arg(long, global = true, value_name = "PATH")]
    history: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print one passive host, route, radio, counter, and neighbor-cache report.
    Snapshot {
        /// Emit stable machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run one bounded active path diagnosis and exit.
    #[command(alias = "diag")]
    Probe {
        /// Emit stable machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Print interface, route, resolver, address, and radio state without internet probes.
    Link {
        /// Emit stable machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show the native neighbor cache without probing the LAN.
    Peers {
        /// Emit stable machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run an explicit bounded iperf3 TCP test with gateway latency under load.
    Speed {
        /// iperf3 server to test.
        host: String,
        /// iperf3 server port.
        #[arg(long, default_value_t = 5201)]
        port: u16,
        /// Load-test duration in seconds.
        #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..=300))]
        duration: u64,
        /// Emit stable machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run a live view headlessly and save styled screenshots at explicit elapsed times.
    #[command(alias = "capture-ui")]
    Screenshot {
        /// Live subject to render.
        #[arg(value_enum, default_value_t = CaptureView::Overview)]
        view: CaptureView,
        /// Elapsed seconds to capture; repeat the flag or separate values with commas.
        #[arg(long = "at", required = true, value_delimiter = ',', value_parser = clap::value_parser!(u64).range(1..=86_400))]
        at: Vec<u64>,
        /// Fixed terminal width in columns.
        #[arg(long, default_value_t = 140, value_parser = clap::value_parser!(u16).range(60..=300))]
        columns: u16,
        /// Fixed terminal height in rows.
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u16).range(10..=100))]
        rows: u16,
        /// Private directory for timestamped text and SVG or native ANSI/HTML frames.
        #[arg(long, default_value = "linktop-captures")]
        output_dir: PathBuf,
        /// Exercise the real Crossterm TUI in a fixed-size tmux PTY and save ANSI and HTML.
        #[arg(long)]
        native: bool,
        /// Enable active path probes in an overview capture.
        #[arg(long)]
        active: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CaptureView {
    Overview,
    Link,
    Peers,
}

impl From<CaptureView> for MonitorMode {
    fn from(view: CaptureView) -> Self {
        match view {
            CaptureView::Overview => Self::Overview,
            CaptureView::Link => Self::Link,
            CaptureView::Peers => Self::Peers,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiveOutput {
    Tui,
    Plain,
    Once,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let interval = Duration::from_secs(cli.interval);
    let dwell = cli.dwell.map(Duration::from_secs);
    let plain = cli.plain;
    let explicit_history = cli.history.clone();
    let probe_policy = if cli.active {
        ProbePolicy::Active
    } else {
        ProbePolicy::Passive
    };
    let terminal_stdin = io::stdin().is_terminal();
    let terminal_stdout = io::stdout().is_terminal();
    let live_output = choose_live_output(terminal_stdin, terminal_stdout, plain, dwell);
    let default_history = resolve_default_history(
        explicit_history.clone(),
        std::env::var_os("LINKTOP_HISTORY"),
        live_output != LiveOutput::Once,
    );
    match cli.command {
        Some(Command::Snapshot { json }) => {
            reject_live_options("snapshot", plain, dwell)?;
            reject_root_active("snapshot", cli.active)?;
            reject_history("snapshot", explicit_history.as_ref())?;
            snapshot(json)
        }
        Some(Command::Probe { json }) => {
            reject_live_options("probe", plain, dwell)?;
            reject_root_active("probe", cli.active)?;
            reject_history("probe", explicit_history.as_ref())?;
            probe(json)
        }
        Some(Command::Link { json }) => {
            reject_root_active("link", cli.active)?;
            reject_history("link", explicit_history.as_ref())?;
            if json {
                reject_live_options("link --json", plain, dwell)?;
                link(true)
            } else {
                match live_output {
                    LiveOutput::Tui => run_tui(
                        interval,
                        MonitorMode::Link,
                        dwell,
                        ProbePolicy::Passive,
                        None,
                    ),
                    LiveOutput::Plain => run_plain(
                        interval,
                        MonitorMode::Link,
                        dwell,
                        ProbePolicy::Passive,
                        None,
                    ),
                    LiveOutput::Once => link(false),
                }
            }
        }
        Some(Command::Peers { json }) => {
            reject_root_active("peers", cli.active)?;
            reject_history("peers", explicit_history.as_ref())?;
            if json {
                reject_live_options("peers --json", plain, dwell)?;
                peers(true)
            } else {
                match live_output {
                    LiveOutput::Tui => run_tui(
                        interval,
                        MonitorMode::Peers,
                        dwell,
                        ProbePolicy::Passive,
                        None,
                    ),
                    LiveOutput::Plain => run_plain(
                        interval,
                        MonitorMode::Peers,
                        dwell,
                        ProbePolicy::Passive,
                        None,
                    ),
                    LiveOutput::Once => peers(false),
                }
            }
        }
        Some(Command::Speed {
            host,
            port,
            duration,
            json,
        }) => {
            reject_live_options("speed", plain, dwell)?;
            reject_root_active("speed", cli.active)?;
            reject_history("speed", explicit_history.as_ref())?;
            speed(&host, port, Duration::from_secs(duration), json)
        }
        Some(Command::Screenshot {
            view,
            at,
            columns,
            rows,
            output_dir,
            native,
            active,
        }) => {
            reject_live_options("screenshot", plain, dwell)?;
            reject_root_active("screenshot", cli.active)?;
            let mode = view.into();
            anyhow::ensure!(
                !active || mode == MonitorMode::Overview,
                "screenshot --active is only valid for the overview"
            );
            anyhow::ensure!(
                explicit_history.is_none() || mode == MonitorMode::Overview,
                "screenshot --history is only valid for the overview"
            );
            let capture_policy = if active {
                ProbePolicy::Active
            } else {
                ProbePolicy::Passive
            };
            let size = capture::CaptureSize { columns, rows };
            if native {
                capture::run_native(
                    interval,
                    mode,
                    capture_policy,
                    &at,
                    size,
                    &output_dir,
                    explicit_history,
                )
            } else {
                capture::run(
                    interval,
                    mode,
                    capture_policy,
                    &at,
                    size,
                    &output_dir,
                    explicit_history,
                )
            }
        }
        None => match live_output {
            LiveOutput::Tui => run_tui(
                interval,
                MonitorMode::Overview,
                dwell,
                probe_policy,
                default_history,
            ),
            LiveOutput::Plain => run_plain(
                interval,
                MonitorMode::Overview,
                dwell,
                probe_policy,
                default_history,
            ),
            LiveOutput::Once if default_history.is_some() => {
                anyhow::bail!("--history requires a live terminal or --plain --dwell")
            }
            LiveOutput::Once if probe_policy.is_active() => probe(false),
            LiveOutput::Once => snapshot(false),
        },
    }
}

fn choose_live_output(
    terminal_stdin: bool,
    terminal_stdout: bool,
    plain: bool,
    dwell: Option<Duration>,
) -> LiveOutput {
    if plain {
        LiveOutput::Plain
    } else if terminal_stdin && terminal_stdout {
        LiveOutput::Tui
    } else if dwell.is_some() {
        LiveOutput::Plain
    } else {
        LiveOutput::Once
    }
}

fn reject_live_options(subject: &str, plain: bool, dwell: Option<Duration>) -> Result<()> {
    anyhow::ensure!(!plain, "--plain cannot be combined with {subject}");
    anyhow::ensure!(dwell.is_none(), "--dwell cannot be combined with {subject}");
    Ok(())
}

fn reject_root_active(subject: &str, active: bool) -> Result<()> {
    anyhow::ensure!(
        !active,
        "--active applies to the live overview; use `linktop probe` for a bounded active diagnosis (not {subject})"
    );
    Ok(())
}

fn reject_history(subject: &str, history: Option<&PathBuf>) -> Result<()> {
    anyhow::ensure!(
        history.is_none(),
        "--history applies to the live overview (not {subject})"
    );
    Ok(())
}

fn resolve_default_history(
    explicit: Option<PathBuf>,
    environment: Option<OsString>,
    use_environment: bool,
) -> Option<PathBuf> {
    explicit.or_else(|| {
        use_environment
            .then_some(environment)
            .flatten()
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    })
}

fn snapshot(json: bool) -> Result<()> {
    let report = net::collect_passive_snapshot();
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "LINKTOP  PASSIVE SNAPSHOT / PATH UNTESTED / COVERAGE {}",
            report.summary.evidence_coverage.label()
        );
        println!(
            "route    default via {} dev {}",
            report.link.gateway.as_deref().unwrap_or("unknown next hop"),
            report
                .link
                .interface
                .as_deref()
                .unwrap_or("unknown interface")
        );
        if let Some(configuration) = network_configuration_text(&report.link) {
            println!("config   {configuration}");
        }
        if let Some(wifi) = &report.link.wifi {
            println!(
                "802.11   RSSI {}  noise {}  channel {}  PHY {}  tx {}",
                human_dbm(wifi.signal_dbm.or(wifi.signal_percent)),
                human_dbm(wifi.noise_dbm),
                wifi.channel
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "?".into()),
                wifi.phy.as_deref().unwrap_or("?"),
                speed::human_rate(wifi.tx_rate_mbps.map(|value| value * 1_000_000.0))
            );
        }
        println!(
            "resolvers {}",
            if report.link.resolvers.is_empty() {
                "unavailable".into()
            } else {
                report.link.resolvers.join(", ")
            }
        );
        for address in report
            .link
            .addresses
            .iter()
            .filter(|address| address.is_default)
        {
            println!(
                "address   IPv{} {}{}",
                address.family,
                address.address,
                if address.is_temporary {
                    " (temporary)"
                } else {
                    ""
                }
            );
        }
        println!(
            "neighbors {:<9} {}",
            report.neighbors.health.label(),
            report.neighbors.detail
        );
        if let Some(counters) = &report.interface_counters {
            println!(
                "traffic   {} received / {} transmitted / {} errors / {} drops [{}]",
                human_bytes(counters.received_bytes),
                human_bytes(counters.transmitted_bytes),
                counters.receive_errors + counters.transmit_errors,
                counters.drops,
                counters.interface
            );
        }
        println!("active    off; run `linktop probe` for bounded path checks");
    }
    Ok(())
}

fn probe(json: bool) -> Result<()> {
    let report = net::collect_snapshot(Duration::from_secs(15));
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "LINKTOP  ACTIVE PATH {} / COVERAGE {}",
            report.summary.path_status.label(),
            report.summary.evidence_coverage.label()
        );
        println!(
            "route    default via {} dev {}",
            report.link.gateway.as_deref().unwrap_or("unknown next hop"),
            report
                .link
                .interface
                .as_deref()
                .unwrap_or("unknown interface")
        );
        println!(
            "egress   {}",
            report
                .link
                .public_ip
                .as_deref()
                .unwrap_or("public egress unavailable")
        );
        for probe in &report.probes {
            let latency = probe
                .latency_ms
                .map(|value| format!("{value:.0} ms"))
                .unwrap_or_else(|| "—".into());
            println!(
                "{:<9} {:<13} {:>8}  {}",
                probe.health.label(),
                probe.kind.label(),
                latency,
                probe.detail
            );
            if let Some(metrics) = &probe.metrics {
                println!(
                    "          p50 {}  p95 {}  mean|ΔRTT| {}  loss {}",
                    human_ms(metrics.rtt_p50_ms),
                    human_ms(metrics.rtt_p95_ms),
                    human_ms(metrics.mean_abs_adjacent_rtt_delta_ms),
                    metrics
                        .loss_rate
                        .map(|value| format!("{:.0}%", value * 100.0))
                        .unwrap_or_else(|| "?".into())
                );
            }
        }
        println!(
            "neighbors {:<9} {}",
            report.neighbors.health.label(),
            report.neighbors.detail
        );
        println!(
            "completed {}/{} bounded active probes",
            report.summary.completed_probes, report.summary.total_probes
        );
    }
    if report.summary.path_status.is_failed() {
        std::process::exit(1);
    }
    if report.summary.path_status.is_unavailable() {
        std::process::exit(2);
    }
    Ok(())
}

fn link(json: bool) -> Result<()> {
    let link = net::collect_link_snapshot();
    if json {
        println!("{}", serde_json::to_string_pretty(&link)?);
        return Ok(());
    }
    println!("LINKTOP  LOCAL LINK");
    println!(
        "path     {} [{}] → {}",
        link.interface.as_deref().unwrap_or("unknown interface"),
        link.link_type.as_deref().unwrap_or("unknown link"),
        link.gateway.as_deref().unwrap_or("unknown gateway")
    );
    if let Some(configuration) = network_configuration_text(&link) {
        println!("config   {configuration}");
    }
    if let Some(ssid) = &link.ssid {
        println!("ssid     {ssid}");
    } else if link.ssid_restricted {
        println!("ssid     unavailable (hidden by macOS Location Services policy)");
    }
    if let Some(wifi) = &link.wifi {
        println!(
            "radio    signal {}  noise {}  channel {}  tx {}",
            human_dbm(wifi.signal_dbm.or(wifi.signal_percent)),
            human_dbm(wifi.noise_dbm),
            wifi.channel
                .map(|value| value.to_string())
                .unwrap_or_else(|| "?".into()),
            speed::human_rate(wifi.tx_rate_mbps.map(|value| value * 1_000_000.0))
        );
    }
    if let Some(counters) = link
        .interface
        .as_deref()
        .and_then(net::collect_interface_counters)
    {
        println!(
            "traffic  {} received / {} transmitted / {} errors / {} drops",
            human_bytes(counters.received_bytes),
            human_bytes(counters.transmitted_bytes),
            counters.receive_errors + counters.transmit_errors,
            counters.drops
        );
    }
    println!("resolver {}", link.resolvers.join(", "));
    for address in &link.addresses {
        println!(
            "{} {:<8} {}{}",
            if address.is_default { ">" } else { " " },
            address.interface,
            address.address,
            if address.is_temporary {
                " (temporary)"
            } else {
                ""
            }
        );
    }
    Ok(())
}

fn peers(json: bool) -> Result<()> {
    let link = net::collect_link();
    let report = peers::collect(&link);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        let gateway = link.gateway;
        println!("LINKTOP  NEIGHBOR CACHE / PASSIVE");
        println!("{}", report.detail);
        println!(
            "evidence {}  OUI {}",
            report.sources.join(" + "),
            report
                .oui_source
                .as_deref()
                .unwrap_or("registry unavailable")
        );
        for peer in &report.peers {
            println!(
                "{:<40} {:<18} {:<10} {:<12} {:<9} {:<36} {}",
                peer.address,
                peer.mac.as_deref().unwrap_or("—"),
                peer.interface.as_deref().unwrap_or("—"),
                peer.state.as_deref().unwrap_or("—"),
                if gateway.as_deref() == Some(peer.address.as_str()) {
                    "gateway"
                } else {
                    "—"
                },
                ui::peer_state_meaning(peer.state.as_deref()),
                peer.registrant
                    .as_deref()
                    .or_else(|| peer.mac_scope.map(|scope| scope.label()))
                    .unwrap_or("—")
            );
        }
    }
    if report.health == Health::Unavailable {
        std::process::exit(2);
    }
    Ok(())
}

fn speed(host: &str, port: u16, duration: Duration, json: bool) -> Result<()> {
    let report = speed::run(host, port, duration)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    println!(
        "LINKTOP  IPERF3 {}:{} (TCP, {}s)",
        report.target, report.port, report.duration_s
    );
    println!(
        "sent     {}  retransmits {}",
        speed::human_rate(report.transfer.sent_bits_per_second),
        report
            .transfer
            .retransmits
            .map(|value| value.to_string())
            .unwrap_or_else(|| "?".into())
    );
    println!(
        "received {}",
        speed::human_rate(report.transfer.received_bits_per_second)
    );
    if let (Some(baseline), Some(loaded)) = (
        &report.gateway_latency.baseline,
        &report.gateway_latency.loaded,
    ) {
        println!(
            "gateway  baseline p95 {}  loaded p95 {}  loaded {}",
            human_ms(
                baseline
                    .metrics
                    .as_ref()
                    .and_then(|metrics| metrics.rtt_p95_ms)
            ),
            human_ms(
                loaded
                    .metrics
                    .as_ref()
                    .and_then(|metrics| metrics.rtt_p95_ms)
            ),
            loaded.health.label()
        );
    }
    Ok(())
}

fn human_ms(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:.1}ms"))
        .unwrap_or_else(|| "?".into())
}

fn network_configuration_text(link: &model::LinkSnapshot) -> Option<String> {
    let configuration = link.network_configuration.as_ref()?;
    let mut parts = Vec::new();
    if let Some(connection_id) = &configuration.connection_id {
        parts.push(format!("association {connection_id}"));
    }
    if let Some(bssid) = &configuration.associated_bssid {
        parts.push(format!("BSSID {bssid}"));
    } else if configuration.bssid_restricted {
        parts.push("BSSID hidden by macOS".into());
    }
    if let Some(method) = &configuration.method {
        parts.push(method.clone());
    }
    if let Some(state) = &configuration.state {
        parts.push(state.to_ascii_lowercase());
    }
    if let Some(server) = &configuration.server {
        parts.push(format!("server {server}"));
    }
    if let Some(mask) = &configuration.subnet_mask {
        parts.push(format!("mask {mask}"));
    }
    if let Some(seconds) = configuration.lease_seconds {
        parts.push(format!("lease {}h", seconds / 3_600));
    }
    if let (Some(start), Some(end)) = (
        configuration.lease_started_at.as_deref(),
        configuration.lease_expires_at.as_deref(),
    ) {
        parts.push(format!("{start} → {end}"));
    }
    if let Some(security) = &configuration.security {
        parts.push(security.replace('_', "-"));
    }
    if configuration.router_arp_verified == Some(true) {
        parts.push("router ARP verified".into());
    }
    (!parts.is_empty()).then(|| parts.join(" · "))
}

fn human_dbm(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:.0}"))
        .unwrap_or_else(|| "?".into())
}

fn human_bytes(bytes: u64) -> String {
    let mut value = bytes as f64;
    for unit in ["B", "KB", "MB", "GB", "TB"] {
        if value < 1_000.0 || unit == "TB" {
            return format!("{value:.1} {unit}");
        }
        value /= 1_000.0;
    }
    unreachable!()
}

fn run_tui(
    interval: Duration,
    mode: MonitorMode,
    dwell: Option<Duration>,
    probe_policy: ProbePolicy,
    history_path: Option<PathBuf>,
) -> Result<()> {
    enable_raw_mode().context("enable terminal raw mode")?;
    let _guard = TerminalGuard;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("enter alternate terminal screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("create terminal")?;

    let (updates, controls, monitor) = net::start_monitor(interval, mode, probe_policy);
    let mut app = model::App::with_probe_policy(probe_policy);
    let mut history = history_path.map(history::HistorySession::open);
    if let Some(history) = &history {
        history.attach(&mut app);
    }
    let mut active_mode = mode;
    let mut peer_offset = 0_usize;
    let can_navigate = mode == MonitorMode::Overview;
    let deadline = dwell.map(|duration| Instant::now() + duration);
    let result = (|| -> Result<()> {
        loop {
            loop {
                match updates.try_recv() {
                    Ok(update) => {
                        apply_monitor_update(&mut app, history.as_mut(), update);
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        app.apply(model::MonitorUpdate::Notice("probe worker stopped".into()));
                        break;
                    }
                }
            }
            terminal
                .draw(|frame| ui::render(frame, &app, active_mode, peer_offset, can_navigate))?;

            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                break;
            }

            if event::poll(Duration::from_millis(100))?
                && let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('r') => {
                        controls.send(MonitorControl::Refresh).ok();
                        app.apply(model::MonitorUpdate::Notice(
                            "manual refresh requested".into(),
                        ));
                    }
                    KeyCode::Char('p') => {
                        let paused = !app.paused;
                        controls.send(MonitorControl::Pause(paused)).ok();
                        app.set_paused(paused);
                    }
                    KeyCode::Char('a') if can_navigate => {
                        let policy = if app.probe_policy().is_active() {
                            ProbePolicy::Passive
                        } else {
                            ProbePolicy::Active
                        };
                        controls.send(MonitorControl::SetProbePolicy(policy)).ok();
                        app.set_probe_policy(policy);
                    }
                    KeyCode::Char('1') if can_navigate => {
                        active_mode = MonitorMode::Overview;
                    }
                    KeyCode::Char('2') if can_navigate => {
                        active_mode = MonitorMode::Link;
                    }
                    KeyCode::Char('3') if can_navigate => {
                        active_mode = MonitorMode::Peers;
                    }
                    KeyCode::Tab if can_navigate => {
                        active_mode = next_dashboard_view(active_mode);
                    }
                    KeyCode::Down | KeyCode::Char('j') if active_mode == MonitorMode::Peers => {
                        peer_offset =
                            (peer_offset + 1).min(app.peers.peers.len().saturating_sub(1));
                    }
                    KeyCode::Up | KeyCode::Char('k') if active_mode == MonitorMode::Peers => {
                        peer_offset = peer_offset.saturating_sub(1);
                    }
                    KeyCode::PageDown if active_mode == MonitorMode::Peers => {
                        peer_offset =
                            (peer_offset + 10).min(app.peers.peers.len().saturating_sub(1));
                    }
                    KeyCode::PageUp if active_mode == MonitorMode::Peers => {
                        peer_offset = peer_offset.saturating_sub(10);
                    }
                    KeyCode::Home | KeyCode::Char('g') if active_mode == MonitorMode::Peers => {
                        peer_offset = 0;
                    }
                    KeyCode::End | KeyCode::Char('G') if active_mode == MonitorMode::Peers => {
                        peer_offset = app.peers.peers.len().saturating_sub(1);
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    })();

    controls.send(MonitorControl::Stop).ok();
    monitor.join().ok();
    result
}

fn next_dashboard_view(mode: MonitorMode) -> MonitorMode {
    match mode {
        MonitorMode::Overview => MonitorMode::Link,
        MonitorMode::Link => MonitorMode::Peers,
        MonitorMode::Peers => MonitorMode::Overview,
    }
}

fn run_plain(
    interval: Duration,
    mode: MonitorMode,
    dwell: Option<Duration>,
    probe_policy: ProbePolicy,
    history_path: Option<PathBuf>,
) -> Result<()> {
    let (updates, controls, monitor) = net::start_monitor(interval, mode, probe_policy);
    let mut app = model::App::with_probe_policy(probe_policy);
    let mut history = history_path.map(history::HistorySession::open);
    if let Some(history) = &history {
        history.attach(&mut app);
        println!(
            "history  {} [{}]",
            history_status(&app).0,
            history_status(&app).1
        );
    }
    let subject = match mode {
        MonitorMode::Overview if probe_policy.is_active() => {
            "active path probes + passive host/cache observation / no LAN scan"
        }
        MonitorMode::Overview => {
            "passive host/cache observation / path reachability untested / no LAN scan"
        }
        MonitorMode::Link => "local route + radio + interface counters / no Internet probes",
        MonitorMode::Peers => "passive neighbor-cache observation / no LAN scan",
    };
    let lifetime = dwell.map_or_else(
        || "Ctrl-C to stop".into(),
        |duration| format!("exits after {}s", duration.as_secs()),
    );
    println!("LINKTOP LIVE  {subject} / {lifetime}");
    let deadline = dwell.map(|duration| Instant::now() + duration);
    loop {
        let update = if let Some(deadline) = deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match updates.recv_timeout(remaining.min(Duration::from_millis(250))) {
                Ok(update) => update,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        } else {
            match updates.recv() {
                Ok(update) => update,
                Err(_) => break,
            }
        };
        let observed = update.clone();
        let before = plain::PlainState::from(&app);
        let history_line = apply_monitor_update(&mut app, history.as_mut(), update);
        for line in plain::format_update(&observed, &before, &app) {
            println!("{line}");
        }
        if let Some(line) = history_line {
            println!("+{} history  {line}", plain::format_elapsed(app.uptime()));
        }
    }
    controls.send(MonitorControl::Stop).ok();
    monitor.join().ok();
    if dwell.is_some() {
        for line in plain::format_dwell_summary(&app, mode.dwell_collector_scope()) {
            println!("{line}");
        }
    }
    Ok(())
}

pub(crate) fn apply_monitor_update(
    app: &mut model::App,
    history: Option<&mut history::HistorySession>,
    update: model::MonitorUpdate,
) -> Option<String> {
    let observed = update.clone();
    app.apply(update);
    history.and_then(|history| history.observe_update(&observed, app))
}

fn history_status(app: &model::App) -> (&str, &str) {
    app.history_context
        .as_ref()
        .map(|context| (context.summary.as_str(), context.evidence.as_str()))
        .unwrap_or(("history disabled", "no durable retention"))
}

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn overview_is_passive_unless_active_is_explicit() {
        let passive = Cli::try_parse_from(["linktop"]).unwrap();
        assert!(!passive.active);

        let active =
            Cli::try_parse_from(["linktop", "--active", "--plain", "--dwell", "5"]).unwrap();
        assert!(active.active);
        assert!(active.plain);
        assert_eq!(active.dwell, Some(5));

        let probe = Cli::try_parse_from(["linktop", "probe", "--json"]).unwrap();
        assert!(matches!(probe.command, Some(Command::Probe { json: true })));
    }

    #[test]
    fn history_environment_is_only_a_nonempty_root_default() {
        let explicit = PathBuf::from("operator.jsonl");
        assert_eq!(
            resolve_default_history(
                Some(explicit.clone()),
                Some(OsString::from("environment.jsonl")),
                true
            ),
            Some(explicit)
        );
        assert_eq!(
            resolve_default_history(None, Some(OsString::from("environment.jsonl")), true),
            Some(PathBuf::from("environment.jsonl"))
        );
        assert_eq!(
            resolve_default_history(None, Some(OsString::new()), true),
            None
        );
        assert_eq!(
            resolve_default_history(None, Some(OsString::from("environment.jsonl")), false),
            None
        );
    }

    #[test]
    fn live_options_work_after_a_focused_subcommand() {
        let cli = Cli::try_parse_from([
            "linktop",
            "peers",
            "--plain",
            "--dwell",
            "7",
            "--interval",
            "3",
        ])
        .unwrap();
        assert!(cli.plain);
        assert_eq!(cli.dwell, Some(7));
        assert_eq!(cli.interval, 3);
        assert!(matches!(cli.command, Some(Command::Peers { json: false })));
    }

    #[test]
    fn screenshot_parses_repeated_and_delimited_frame_times() {
        let cli = Cli::try_parse_from([
            "linktop",
            "screenshot",
            "peers",
            "--at",
            "2,5",
            "--at",
            "10",
            "--columns",
            "100",
            "--rows",
            "24",
            "--native",
        ])
        .unwrap();
        let Some(Command::Screenshot {
            view,
            at,
            columns,
            rows,
            native,
            ..
        }) = cli.command
        else {
            panic!("screenshot command was not parsed");
        };
        assert_eq!(view, CaptureView::Peers);
        assert_eq!(at, vec![2, 5, 10]);
        assert_eq!((columns, rows), (100, 24));
        assert!(native);
    }

    #[test]
    fn transactional_commands_reject_live_lifetimes() {
        assert!(reject_live_options("snapshot", true, Some(Duration::from_secs(2))).is_err());
        assert!(reject_live_options("speed", false, Some(Duration::from_secs(2))).is_err());
    }

    #[test]
    fn output_policy_covers_terminal_pipe_stream_and_dwell_contracts() {
        let dwell = Some(Duration::from_secs(5));
        assert_eq!(choose_live_output(true, true, false, None), LiveOutput::Tui);
        assert_eq!(
            choose_live_output(false, true, false, None),
            LiveOutput::Once
        );
        assert_eq!(
            choose_live_output(true, false, false, None),
            LiveOutput::Once
        );
        assert_eq!(
            choose_live_output(false, false, false, None),
            LiveOutput::Once
        );
        assert_eq!(
            choose_live_output(true, true, true, None),
            LiveOutput::Plain
        );
        assert_eq!(
            choose_live_output(false, false, true, None),
            LiveOutput::Plain
        );
        assert_eq!(
            choose_live_output(true, true, false, dwell),
            LiveOutput::Tui
        );
        assert_eq!(
            choose_live_output(false, true, false, dwell),
            LiveOutput::Plain
        );
    }

    #[test]
    fn dashboard_view_cycle_is_stable() {
        assert_eq!(
            next_dashboard_view(MonitorMode::Overview),
            MonitorMode::Link
        );
        assert_eq!(next_dashboard_view(MonitorMode::Link), MonitorMode::Peers);
        assert_eq!(
            next_dashboard_view(MonitorMode::Peers),
            MonitorMode::Overview
        );
    }
}
