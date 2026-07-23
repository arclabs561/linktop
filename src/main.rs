mod metrics;
mod model;
mod net;
mod oui;
mod peers;
mod plain;
mod process;
mod speed;
mod ui;

use std::io::{self, IsTerminal};
use std::sync::mpsc::TryRecvError;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use model::{Health, MonitorControl, MonitorMode};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

#[derive(Debug, Parser)]
#[command(
    name = "linktop",
    version,
    about = "Live terminal instrument for the active network path",
    long_about = "Inspect the active interface, gateway, DNS, HTTPS reachability, public edge, and rolling gateway latency without scanning the LAN."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Seconds between gateway samples in the live monitor.
    #[arg(long, global = true, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..=60))]
    interval: u64,

    /// Stream the live monitor as append-only text instead of opening the TUI.
    #[arg(long, global = true)]
    plain: bool,

    /// Exit a live overview, link, or peers view after this many seconds.
    #[arg(long, global = true, value_parser = clap::value_parser!(u64).range(1..=86_400))]
    dwell: Option<u64>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print one bounded diagnostic report and exit.
    #[command(alias = "diag")]
    Snapshot {
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
    let terminal_stdin = io::stdin().is_terminal();
    let terminal_stdout = io::stdout().is_terminal();
    let live_output = choose_live_output(terminal_stdin, terminal_stdout, plain, dwell);
    match cli.command {
        Some(Command::Snapshot { json }) => {
            reject_live_options("snapshot", plain, dwell)?;
            snapshot(json)
        }
        Some(Command::Link { json }) => {
            if json {
                reject_live_options("link --json", plain, dwell)?;
                link(true)
            } else {
                match live_output {
                    LiveOutput::Tui => run_tui(interval, MonitorMode::Link, dwell),
                    LiveOutput::Plain => run_plain(interval, MonitorMode::Link, dwell),
                    LiveOutput::Once => link(false),
                }
            }
        }
        Some(Command::Peers { json }) => {
            if json {
                reject_live_options("peers --json", plain, dwell)?;
                peers(true)
            } else {
                match live_output {
                    LiveOutput::Tui => run_tui(interval, MonitorMode::Peers, dwell),
                    LiveOutput::Plain => run_plain(interval, MonitorMode::Peers, dwell),
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
            speed(&host, port, Duration::from_secs(duration), json)
        }
        None => match live_output {
            LiveOutput::Tui => run_tui(interval, MonitorMode::Overview, dwell),
            LiveOutput::Plain => run_plain(interval, MonitorMode::Overview, dwell),
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

fn snapshot(json: bool) -> Result<()> {
    let report = net::collect_snapshot(Duration::from_secs(15));
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("LINKTOP  {}", report.summary.health.label());
        println!(
            "path     {} → {} → {}",
            report
                .link
                .interface
                .as_deref()
                .unwrap_or("unknown interface"),
            report.link.gateway.as_deref().unwrap_or("unknown gateway"),
            report
                .link
                .public_ip
                .as_deref()
                .unwrap_or("unknown public edge")
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
                    "          p50 {}  p95 {}  jitter {}  loss {}",
                    human_ms(metrics.rtt_p50_ms),
                    human_ms(metrics.rtt_p95_ms),
                    human_ms(metrics.rtt_ipdv_abs_mean_ms),
                    metrics
                        .loss_rate
                        .map(|value| format!("{:.0}%", value * 100.0))
                        .unwrap_or_else(|| "?".into())
                );
            }
        }
        println!("neighbors {}", report.neighbors.detail);
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
        println!(
            "completed {}/{} bounded probes",
            report.summary.completed, report.summary.total
        );
    }
    if report.summary.health == Health::Failed {
        std::process::exit(1);
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
        println!("LINKTOP  PASSIVE NEIGHBORS");
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

fn run_tui(interval: Duration, mode: MonitorMode, dwell: Option<Duration>) -> Result<()> {
    enable_raw_mode().context("enable terminal raw mode")?;
    let _guard = TerminalGuard;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("enter alternate terminal screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("create terminal")?;

    let (updates, controls, monitor) = net::start_monitor(interval, mode);
    let mut app = model::App::new();
    let mut peer_offset = 0_usize;
    let deadline = dwell.map(|duration| Instant::now() + duration);
    let result = (|| -> Result<()> {
        loop {
            loop {
                match updates.try_recv() {
                    Ok(update) => app.apply(update),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        app.apply(model::MonitorUpdate::Notice("probe worker stopped".into()));
                        break;
                    }
                }
            }
            terminal.draw(|frame| ui::render(frame, &app, mode, peer_offset))?;

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
                    KeyCode::Down | KeyCode::Char('j') if mode == MonitorMode::Peers => {
                        peer_offset =
                            (peer_offset + 1).min(app.peers.peers.len().saturating_sub(1));
                    }
                    KeyCode::Up | KeyCode::Char('k') if mode == MonitorMode::Peers => {
                        peer_offset = peer_offset.saturating_sub(1);
                    }
                    KeyCode::PageDown if mode == MonitorMode::Peers => {
                        peer_offset =
                            (peer_offset + 10).min(app.peers.peers.len().saturating_sub(1));
                    }
                    KeyCode::PageUp if mode == MonitorMode::Peers => {
                        peer_offset = peer_offset.saturating_sub(10);
                    }
                    KeyCode::Home | KeyCode::Char('g') if mode == MonitorMode::Peers => {
                        peer_offset = 0;
                    }
                    KeyCode::End | KeyCode::Char('G') if mode == MonitorMode::Peers => {
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

fn run_plain(interval: Duration, mode: MonitorMode, dwell: Option<Duration>) -> Result<()> {
    let (updates, controls, monitor) = net::start_monitor(interval, mode);
    let mut app = model::App::new();
    let subject = match mode {
        MonitorMode::Overview => "active path probes + passive neighbors / no LAN scan",
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
        app.apply(update);
        for line in plain::format_update(&observed, &before, &app) {
            println!("{line}");
        }
    }
    controls.send(MonitorControl::Stop).ok();
    monitor.join().ok();
    Ok(())
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
}
