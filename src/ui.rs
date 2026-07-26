use std::collections::BTreeSet;
use std::time::Duration;

use chrono::NaiveDateTime;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::prelude::{Color, Frame, Line, Modifier, Span, Style};
use ratatui::widgets::{Block, Borders, Paragraph, Sparkline, Wrap};

use crate::model::{App, EventKind, Health, MonitorMode, Peer, ProbeKind, SituationKind};

const INK: Color = Color::Rgb(192, 202, 214);
const MUTED: Color = Color::Rgb(95, 109, 126);
const GRID: Color = Color::Rgb(48, 61, 74);
const ACCENT: Color = Color::Rgb(37, 203, 216);
const OK: Color = Color::Rgb(100, 211, 134);
const WARN: Color = Color::Rgb(242, 190, 70);
const FAIL: Color = Color::Rgb(244, 91, 105);

pub fn render(
    frame: &mut Frame<'_>,
    app: &App,
    mode: MonitorMode,
    peer_offset: usize,
    can_navigate: bool,
) {
    let area = frame.area();
    match mode {
        MonitorMode::Link => {
            render_link_focus(frame, area, app, can_navigate);
        }
        MonitorMode::Peers => {
            render_peers_focus(frame, area, app, peer_offset, can_navigate);
        }
        MonitorMode::Overview => render_overview(frame, area, app, can_navigate),
    }
}

fn render_overview(frame: &mut Frame<'_>, area: Rect, app: &App, can_navigate: bool) {
    if area.width < 76 || area.height < 22 {
        render_overview_compact(frame, area, app, can_navigate);
        return;
    }
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(6),
            Constraint::Length(5),
            Constraint::Min(8),
            Constraint::Length(1),
        ])
        .split(area);

    render_header(frame, vertical[0], app, MonitorMode::Overview);
    render_diagnosis(frame, vertical[1], app);
    render_path(frame, vertical[2], app);

    if area.width < 120 || area.height < 25 {
        render_overview_evidence(frame, vertical[3], app);
        render_footer(frame, vertical[4], app, MonitorMode::Overview, can_navigate);
        return;
    }

    let main = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(vertical[3]);
    if !app.probe_policy().is_active() {
        render_overview_evidence(frame, main[0], app);
        if area.height < 28 {
            render_events(frame, main[1], app);
            render_footer(frame, vertical[4], app, MonitorMode::Overview, can_navigate);
            return;
        }
        let dwell_height = if main[1].height >= 14 {
            11
        } else {
            main[1].height.saturating_sub(2).max(1)
        };
        let context = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(dwell_height), Constraint::Min(2)])
            .split(main[1]);
        render_path_dwell(frame, context[0], app);
        render_events(frame, context[1], app);
        render_footer(frame, vertical[4], app, MonitorMode::Overview, can_navigate);
        return;
    }
    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(56), Constraint::Percentage(44)])
        .split(main[0]);
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(6), Constraint::Min(4)])
        .split(main[1]);

    render_latency(frame, left[0], app);
    render_events(frame, left[1], app);
    render_probes(frame, right[0], app);
    if area.height >= 28 {
        render_active_path_dwell(frame, right[1], app);
    } else {
        render_scope(frame, right[1], app);
    }
    render_footer(frame, vertical[4], app, MonitorMode::Overview, can_navigate);
}

fn render_overview_evidence(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let mut lines = Vec::new();
    if app.probe_policy().is_active() {
        lines.push(gateway_summary_line(app, area.width));
        lines.extend(app.probes.iter().map(|probe| {
            let latency = probe
                .latency_ms
                .map(|value| format!("{value:>5.0} ms"))
                .unwrap_or_else(|| "      —".into());
            Line::from(vec![
                Span::styled(
                    format!("{:<10} ", probe.health.label()),
                    Style::default()
                        .fg(health_color(probe.health))
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{:<13}", probe.kind.label()),
                    Style::default().fg(INK),
                ),
                Span::styled(latency, Style::default().fg(MUTED)),
                Span::styled(
                    format!(
                        "  {:>7}",
                        app.probe_age(probe.kind)
                            .map(freshness)
                            .unwrap_or_else(|| "pending".into())
                    ),
                    Style::default().fg(MUTED),
                ),
                Span::styled(format!("  {}", probe.detail), Style::default().fg(MUTED)),
            ])
        }));
    } else {
        lines.push(Line::from(vec![
            Span::styled("policy     ", Style::default().fg(MUTED)),
            Span::styled(
                "passive host-local · no active probes · [a] enables bounded path diagnosis",
                Style::default().fg(INK),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("interface  ", Style::default().fg(MUTED)),
            Span::styled(
                app.interface_rate.as_ref().map_or_else(
                    || "rate baseline pending".into(),
                    |rate| {
                        format!(
                            "rx {} · tx {} · errors +{} · drops +{}",
                            crate::speed::human_rate(Some(rate.received_bits_per_second)),
                            crate::speed::human_rate(Some(rate.transmitted_bits_per_second)),
                            rate.error_delta,
                            rate.drop_delta
                        )
                    },
                ),
                Style::default().fg(INK),
            ),
        ]));
        lines.push(workload_evidence_line(app));
        lines.push(Line::from(vec![
            Span::styled("resolvers  ", Style::default().fg(MUTED)),
            Span::styled(
                if app.link.resolvers.is_empty() {
                    "unavailable".into()
                } else {
                    app.link.resolvers.join(", ")
                },
                Style::default().fg(INK),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("neighbors  ", Style::default().fg(MUTED)),
            Span::styled(
                format!(
                    "{} cache entries · {}",
                    app.peers.peers.len(),
                    if app.peers.sources.is_empty() {
                        "source pending".into()
                    } else {
                        app.peers.sources.join(" + ")
                    }
                ),
                Style::default().fg(INK),
            ),
        ]));
    }
    if app.probe_policy().is_active() {
        lines.push(workload_evidence_line(app));
    }
    lines.push(Line::from(vec![
        Span::styled("scope     ", Style::default().fg(MUTED)),
        Span::styled(
            format!(
                "{} addresses · {} · {}",
                app.link.addresses.len(),
                peer_session_summary(app),
                if app.peers.sources.is_empty() {
                    "neighbor-cache source pending".into()
                } else {
                    app.peers.sources.join("+")
                }
            ),
            Style::default().fg(INK),
        ),
    ]));
    let content_rows = usize::from(area.height.saturating_sub(2));
    if let Some(history) = &app.history_context {
        if content_rows >= lines.len() + 2 {
            lines.extend([
                Line::from(vec![
                    Span::styled("anchor     ", Style::default().fg(MUTED)),
                    Span::styled(history.context_anchor.clone(), Style::default().fg(INK)),
                ]),
                Line::from(vec![
                    Span::styled("place      ", Style::default().fg(MUTED)),
                    Span::styled(history.place_authority.clone(), Style::default().fg(INK)),
                ]),
            ]);
        }
    }
    lines.truncate(content_rows);
    frame.render_widget(
        Paragraph::new(lines).block(instrument_block(" EVIDENCE LEDGER ")),
        area,
    );
}

fn render_header(frame: &mut Frame<'_>, area: Rect, app: &App, mode: MonitorMode) {
    let narrow = area.width < 90;
    let (subject, health, measure) = match mode {
        MonitorMode::Overview => (
            if narrow {
                "OVERVIEW"
            } else if app.probe_policy().is_active() {
                "PATH DIAGNOSIS / ACTIVE"
            } else {
                "NETWORK CONTEXT"
            },
            app.overall_health(),
            if !app.probe_policy().is_active() {
                if narrow {
                    format!("GEN {}", app.path_generation)
                } else {
                    format!("PATH GEN {}", app.path_generation)
                }
            } else if narrow {
                format!("N {}", app.cycles)
            } else {
                format!("RTT PROBES {}", app.cycles)
            },
        ),
        MonitorMode::Link => (
            if narrow {
                "LOCAL LINK"
            } else {
                "LOCAL LINK / PASSIVE OBSERVATION"
            },
            if app.link.interface.is_some() {
                Health::Ok
            } else {
                Health::Running
            },
            if narrow {
                format!("GEN {}", app.path_generation)
            } else {
                format!("PATH GEN {}", app.path_generation)
            },
        ),
        MonitorMode::Peers => (
            if narrow {
                "NEIGHBORS"
            } else {
                "NEIGHBOR CACHE / PASSIVE OBSERVATION"
            },
            app.peers.health,
            if narrow {
                format!(
                    "{}/{}",
                    app.peers.peers.len(),
                    app.peer_dwell_summary().observed.max(app.peers.peers.len())
                )
            } else {
                format!(
                    "CACHED {} / OBSERVED {}",
                    app.peers.peers.len(),
                    app.peer_dwell_summary().observed.max(app.peers.peers.len())
                )
            },
        ),
    };
    let status = match mode {
        MonitorMode::Overview if !app.probe_policy().is_active() => "PASSIVE",
        MonitorMode::Link if app.link.interface.is_some() => "OBSERVED",
        MonitorMode::Link => "DISCOVERING",
        MonitorMode::Overview | MonitorMode::Peers => health.label(),
    };
    let title = Line::from(vec![
        Span::styled(
            " LINKTOP ",
            Style::default()
                .fg(Color::Black)
                .bg(ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!("  {subject}"), Style::default().fg(INK)),
        Span::raw("  "),
        Span::styled(
            status,
            Style::default()
                .fg(health_color(health))
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("   UP {}   {} ", format_duration(app.uptime()), measure),
            Style::default().fg(MUTED),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(title)
            .block(instrument_block(" LIVE STATUS "))
            .alignment(Alignment::Left),
        area,
    );
}

pub(crate) struct OverviewDiagnosis {
    pub health: Health,
    pub summary: String,
    pub context: String,
    pub compact_context: String,
    pub context_is_salient: bool,
    pub coverage: String,
    pub action: &'static str,
}

pub(crate) fn overview_diagnosis(app: &App) -> OverviewDiagnosis {
    let situation = app.situation();
    let health = situation.health;
    let summary = match situation.kind {
        SituationKind::Paused => "current values are retained, not live".into(),
        SituationKind::PathTransition => {
            "switching networks; retaining the last confirmed path".into()
        }
        SituationKind::GatewayFailure => failed_probe_summary(app, ProbeKind::Gateway),
        SituationKind::InterfaceLoss => {
            let rate = app
                .interface_rate
                .as_ref()
                .expect("interface loss situation has a rate sample");
            format!(
                "local interface counters increased: +{} error(s), +{} drop(s)",
                rate.error_delta, rate.drop_delta
            )
        }
        SituationKind::PassiveObservation => {
            let interface = app
                .link
                .interface
                .as_deref()
                .unwrap_or("an unknown interface");
            let gateway = app.link.gateway.as_deref().unwrap_or("an unknown gateway");
            format!(
                "observing local path via {interface} and {gateway}; Internet reachability is not tested"
            )
        }
        SituationKind::UnlocalizedFailure => {
            "a downstream path check failed, but earlier dependency evidence is unavailable".into()
        }
        SituationKind::DnsFailure => failed_probe_summary(app, ProbeKind::Dns),
        SituationKind::HttpsFailure => failed_probe_summary(app, ProbeKind::Https),
        SituationKind::GatewayLoss => {
            let metrics = app
                .gateway_assessment_metrics()
                .expect("gateway loss situation has assessment metrics");
            format!(
                "gateway loss {:.0}% over {} recent attempts",
                metrics.loss_rate.unwrap_or_default() * 100.0,
                metrics.sent
            )
        }
        SituationKind::GatewayVariation => {
            let metrics = app
                .gateway_assessment_metrics()
                .expect("gateway variation situation has assessment metrics");
            format!(
                "next-hop RTT spread: p50 {}, p95 {}, mean |ΔRTT| {} over {} probes",
                human_ms(metrics.rtt_p50_ms),
                human_ms(metrics.rtt_p95_ms),
                human_ms(metrics.mean_abs_adjacent_rtt_delta_ms),
                metrics.sent
            )
        }
        SituationKind::SlowDns => slow_probe_summary(app, ProbeKind::Dns),
        SituationKind::SlowHttps => slow_probe_summary(app, ProbeKind::Https),
        SituationKind::StalePathEvidence => {
            "DNS or HTTPS evidence is older than 75s; end-to-end status is stale".into()
        }
        SituationKind::Collecting => {
            let pending = ProbeKind::PATH
                .iter()
                .filter(|kind| {
                    matches!(
                        app.probe_view(**kind).health,
                        Health::Queued | Health::Running
                    )
                })
                .map(|kind| kind.label())
                .collect::<Vec<_>>()
                .join(", ");
            format!("collecting path evidence: {pending}")
        }
        SituationKind::WarmingBaseline => format!(
            "warming next-hop RTT baseline {}/{}; core path checks settled",
            app.gateway_attempts,
            crate::model::MIN_GATEWAY_ASSESSMENT_SAMPLES
        ),
        SituationKind::EvidenceGap if health == Health::Unavailable => {
            "path evidence is unavailable from this host".into()
        }
        SituationKind::EvidenceGap => {
            "tested path responded; supporting evidence is incomplete".into()
        }
        SituationKind::Ready => {
            "gateway, DNS, and HTTPS responded; no current path issue observed".into()
        }
    };

    let settled = ProbeKind::PATH
        .iter()
        .map(|kind| app.probe_view(*kind))
        .filter(|probe| !matches!(probe.health, Health::Queued | Health::Running))
        .count();
    let public_evidence = if !app.probe_policy().is_active() {
        "public egress untested".into()
    } else {
        let probe = app.probe_view(ProbeKind::PublicIp);
        match probe.health {
            Health::Queued | Health::Running => "public egress pending".into(),
            Health::Ok => format!(
                "public egress {}",
                app.probe_age(ProbeKind::PublicIp)
                    .map(freshness)
                    .unwrap_or_else(|| "age unknown".into())
            ),
            _ => "public egress unavailable".into(),
        }
    };
    let peer_summary = app.peer_dwell_summary();
    let peer_evidence = if app.peers.health == Health::Queued {
        "neighbor cache pending".into()
    } else {
        let mut summary = format!(
            "cache {}/{}",
            peer_summary.current,
            peer_summary.observed.max(peer_summary.current)
        );
        if peer_summary.changed > 0 {
            summary.push_str(&format!(" Δ{}", peer_summary.changed));
        }
        if !app.peers.failed_sources.is_empty() || app.peers.sources.is_empty() {
            summary.push_str(" partial");
        }
        summary
    };
    let radio_evidence = if app.link.wifi.is_some() {
        "radio observed"
    } else if app
        .link
        .link_type
        .as_deref()
        .is_some_and(|kind| kind.eq_ignore_ascii_case("wifi"))
    {
        "radio unavailable"
    } else {
        "radio n/a"
    };
    let mut coverage = if app.probe_policy().is_active() {
        format!(
            "coverage {} · core {settled}/{} · {public_evidence} · {peer_evidence} · {radio_evidence}",
            app.evidence_coverage().label(),
            ProbeKind::PATH.len()
        )
    } else {
        format!(
            "passive coverage {} · route {} · {peer_evidence} · {radio_evidence} · probes off",
            app.evidence_coverage().label(),
            if app.link.interface.is_some() {
                "observed"
            } else {
                "unavailable"
            }
        )
    };
    if let Some(history) = &app.history_context {
        coverage.push_str(" · history cited");
        if history.kind.is_limited() {
            coverage.push_str("/limited");
        }
    }
    let action = match situation.kind {
        SituationKind::Paused => "next: p resumes observation",
        SituationKind::PathTransition => "next: allow the default route to settle",
        SituationKind::GatewayFailure => "next: [2] inspect the local link and gateway; r retries",
        SituationKind::InterfaceLoss => {
            "next: [2] compare radio and traffic with the counter increase"
        }
        SituationKind::PassiveObservation => {
            "next: a enables next-hop, DNS, HTTPS, and public-egress probes"
        }
        SituationKind::UnlocalizedFailure => {
            "next: restore the missing gateway or DNS evidence before assigning a cause"
        }
        SituationKind::DnsFailure | SituationKind::SlowDns => {
            "next: inspect the configured resolver; r retries the bounded lookup"
        }
        SituationKind::HttpsFailure | SituationKind::SlowHttps => {
            "next: gateway and DNS passed; r retries the upstream HTTPS check"
        }
        SituationKind::StalePathEvidence => "next: r refreshes the bounded DNS and HTTPS probes",
        SituationKind::GatewayLoss | SituationKind::GatewayVariation => {
            "next: [2] compare radio and traffic against the gateway episode"
        }
        SituationKind::Collecting | SituationKind::WarmingBaseline => {
            "next: allow the initial path evidence to settle"
        }
        SituationKind::EvidenceGap if health == Health::Unavailable => {
            "next: [2] inspect which local path evidence is unavailable"
        }
        SituationKind::EvidenceGap => {
            "next: the path is usable; r retries missing supporting evidence"
        }
        SituationKind::Ready => {
            "next: no action; [2] link and [3] neighbor cache show supporting evidence"
        }
    };
    let (context, compact_context, context_is_salient) = salient_context(app);
    OverviewDiagnosis {
        health,
        summary,
        context,
        compact_context,
        context_is_salient,
        coverage,
        action,
    }
}

pub(crate) fn overview_status_label(app: &App) -> &'static str {
    if app.situation().kind == SituationKind::PassiveObservation {
        "UNTESTED"
    } else {
        app.situation().health.label()
    }
}

fn salient_context(app: &App) -> (String, String, bool) {
    if app.path_transition_pending {
        let message = "change   default route settling; last confirmed path retained".to_string();
        return (message.clone(), message, true);
    }
    let path_change = app.last_path_change.as_ref().map(|change| {
        (
            change.elapsed,
            format!(
                "{}: {} → {}",
                change.dimensions.join(", "),
                change.previous,
                change.current
            ),
        )
    });
    let event_change = app
        .events
        .iter()
        .rev()
        .find(|event| match event.kind {
            EventKind::Peer => !event.message.starts_with("neighbor cache:"),
            EventKind::Policy | EventKind::Notice => true,
            EventKind::Session | EventKind::Path | EventKind::Probe => false,
        })
        .map(|event| (event.elapsed, event.message.clone()));
    if let Some((elapsed, message)) = [path_change, event_change]
        .into_iter()
        .flatten()
        .max_by_key(|(elapsed, _)| *elapsed)
    {
        let message = format!("change   +{} {message}", format_duration(elapsed));
        return (message.clone(), message, true);
    }
    if app.path_generation == 0 {
        let message = "context  waiting for the first confirmed default route".to_string();
        (message.clone(), message, false)
    } else if let Some(history) = &app.history_context {
        (
            format!("history  {}", history.summary),
            format!("history  {}", history.compact_summary),
            true,
        )
    } else {
        let message = format!(
            "context  generation {} observed for {}; no transition seen this session",
            app.path_generation,
            format_duration(app.uptime().saturating_sub(app.path_observed_since))
        );
        (message.clone(), message, false)
    }
}

fn workload_evidence_line(app: &App) -> Line<'static> {
    Line::from(vec![
        Span::styled("workload   ", Style::default().fg(MUTED)),
        Span::styled(workload_summary(app), Style::default().fg(INK)),
    ])
}

fn workload_summary(app: &App) -> String {
    let Some(process) = app.workload.processes.first() else {
        return match app.workload.health {
            Health::Queued | Health::Running => "per-process traffic sampling…".into(),
            Health::Ok => "no external-interface process traffic in the latest 1s sample".into(),
            Health::Degraded | Health::Failed | Health::Unavailable => {
                format!("per-process traffic unavailable: {}", app.workload.detail)
            }
        };
    };
    format!(
        "top process {}{} · rx {} · tx {} / {}s",
        process.process,
        if process.processes > 1 {
            format!("×{}", process.processes)
        } else {
            String::new()
        },
        crate::speed::human_rate(Some(process.received_bytes_per_second as f64 * 8.0)),
        crate::speed::human_rate(Some(process.transmitted_bytes_per_second as f64 * 8.0)),
        app.workload.interval.as_secs()
    )
}

fn compact_workload_summary(app: &App) -> String {
    let Some(process) = app.workload.processes.first() else {
        return match app.workload.health {
            Health::Queued | Health::Running => "process attribution sampling…".into(),
            Health::Ok => "proc no external-interface traffic / 1s".into(),
            Health::Degraded | Health::Failed | Health::Unavailable => {
                "process attribution unavailable".into()
            }
        };
    };
    format!(
        "proc {}{} · rx {} · tx {} / {}s",
        process.process,
        if process.processes > 1 {
            format!("×{}", process.processes)
        } else {
            String::new()
        },
        crate::speed::human_rate(Some(process.received_bytes_per_second as f64 * 8.0)),
        crate::speed::human_rate(Some(process.transmitted_bytes_per_second as f64 * 8.0)),
        app.workload.interval.as_secs()
    )
}

fn network_configuration_summary(app: &App) -> String {
    let mut parts = Vec::new();
    if let Some(configuration) = &app.link.network_configuration {
        if let Some(method) = &configuration.method {
            let prefix = configuration
                .subnet_mask
                .as_deref()
                .and_then(ipv4_mask_prefix)
                .map(|prefix| format!(" /{prefix}"))
                .unwrap_or_default();
            parts.push(format!("{method}{prefix}"));
        }
        if let Some(connection_id) = &configuration.connection_id {
            parts.push(format!("association {connection_id}"));
        }
        if let Some(bssid) = &configuration.associated_bssid {
            parts.push(format!("BSSID {bssid}"));
        } else if configuration.bssid_restricted {
            parts.push("BSSID hidden by macOS".into());
        }
        if let (Some(start), Some(end)) = (
            configuration.lease_started_at.as_deref(),
            configuration.lease_expires_at.as_deref(),
        ) {
            parts.push(format!("lease {}", lease_window(start, end)));
        } else if let Some(seconds) = configuration.lease_seconds {
            parts.push(format!("lease {}h", seconds / 3_600));
        }
        if let Some(security) = &configuration.security {
            parts.push(security.replace('_', "-"));
        }
    }
    let has_v4 = app
        .link
        .addresses
        .iter()
        .any(|address| address.is_default && address.family == 4);
    let has_v6 = app
        .link
        .addresses
        .iter()
        .any(|address| address.is_default && address.family == 6);
    parts.push(
        match (has_v4, has_v6) {
            (true, true) => "dual-stack",
            (true, false) => "IPv4 only",
            (false, true) => "IPv6 only",
            (false, false) => "address family pending",
        }
        .into(),
    );
    let default_interface = app.link.interface.as_deref();
    let overlays: BTreeSet<_> = app
        .link
        .addresses
        .iter()
        .filter(|address| !address.is_default)
        .filter(|address| Some(address.interface.as_str()) != default_interface)
        .map(|address| address.interface.as_str())
        .collect();
    if !overlays.is_empty() {
        parts.push(format!(
            "overlay {}",
            overlays.into_iter().collect::<Vec<_>>().join("+")
        ));
    }
    parts.join(" · ")
}

fn compact_network_configuration_summary(app: &App) -> String {
    network_configuration_summary(app)
        .replace("DHCP /", "DHCP/")
        .replace("association ", "assoc ")
        .replace("dual-stack", "v4+v6")
        .replace("IPv4 only", "v4")
        .replace("IPv6 only", "v6")
        .replace("overlay ", "")
}

fn short_clock(value: &str) -> String {
    value
        .split_whitespace()
        .next_back()
        .map(|time| time.split(':').take(2).collect::<Vec<_>>().join(":"))
        .unwrap_or_else(|| value.to_string())
}

fn lease_window(start: &str, end: &str) -> String {
    const MACOS_DHCP_TIMESTAMP: &str = "%m/%d/%Y %H:%M:%S";

    let parsed = NaiveDateTime::parse_from_str(start, MACOS_DHCP_TIMESTAMP)
        .ok()
        .zip(NaiveDateTime::parse_from_str(end, MACOS_DHCP_TIMESTAMP).ok());
    let Some((start_at, end_at)) = parsed else {
        return format!("{}→{}", short_clock(start), short_clock(end));
    };

    let start_clock = start_at.format("%H:%M");
    let end_clock = end_at.format("%H:%M");
    let day_delta = end_at
        .date()
        .signed_duration_since(start_at.date())
        .num_days();
    match day_delta {
        0 => format!("{start_clock}→{end_clock}"),
        1..=9 => format!("{start_clock}→+{day_delta}d {end_clock}"),
        _ => format!(
            "{}→{}",
            start_at.format("%m/%d %H:%M"),
            end_at.format("%m/%d %H:%M")
        ),
    }
}

fn ipv4_mask_prefix(mask: &str) -> Option<u32> {
    let octets: Vec<u8> = mask
        .split('.')
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    if octets.len() != 4 {
        return None;
    }
    let bits = u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]);
    let prefix = bits.count_ones();
    let expected = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (bits == expected).then_some(prefix)
}

fn failed_probe_summary(app: &App, kind: ProbeKind) -> String {
    let probe = app.probe_view(kind);
    match probe.latency_ms {
        Some(latency) => format!(
            "{} failed after {latency:.0} ms — {}",
            kind.label(),
            probe.detail
        ),
        None => format!("{} failed — {}", kind.label(), probe.detail),
    }
}

fn slow_probe_summary(app: &App, kind: ProbeKind) -> String {
    let probe = app.probe_view(kind);
    match (probe.latency_ms, kind.degraded_after_ms()) {
        (Some(latency), Some(threshold)) => format!(
            "{} took {latency:.0} ms; degraded at {threshold:.0} ms",
            kind.label()
        ),
        _ => format!("{} degraded — {}", kind.label(), probe.detail),
    }
}

fn render_diagnosis(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let diagnosis = overview_diagnosis(app);
    let context = if area.width < 120 {
        &diagnosis.compact_context
    } else {
        &diagnosis.context
    };
    let lines = vec![
        Line::from(vec![
            Span::styled(
                format!(" {:<10}", overview_status_label(app)),
                Style::default()
                    .fg(health_color(diagnosis.health))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(diagnosis.summary, Style::default().fg(INK)),
        ]),
        Line::from(Span::styled(
            format!(
                " {}",
                fit(context, usize::from(area.width.saturating_sub(3)))
            ),
            Style::default().fg(INK),
        )),
        Line::from(Span::styled(
            format!(" {}", diagnosis.coverage),
            Style::default().fg(MUTED),
        )),
        Line::from(Span::styled(
            format!(" {}", diagnosis.action),
            Style::default().fg(ACCENT),
        )),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(instrument_block(" DIAGNOSIS ")),
        area,
    );
}

fn render_path(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let interface = app.link.interface.as_deref().unwrap_or("discovering");
    let link = app.link.link_type.as_deref().unwrap_or("link");
    let ssid = app
        .link
        .ssid
        .as_deref()
        .map(|value| format!(" / {value}"))
        .or_else(|| {
            app.link
                .ssid_restricted
                .then(|| " / SSID hidden by macOS".into())
        })
        .unwrap_or_default();
    let ssid = if area.width < 70 { String::new() } else { ssid };
    let gateway = app.link.gateway.as_deref().unwrap_or("discovering");
    let path = Line::from(vec![
        Span::styled(format!(" {} ", app.link.host), Style::default().fg(INK)),
        Span::styled("──▶", Style::default().fg(GRID)),
        Span::styled(
            format!(" {interface} [{link}{ssid}] "),
            Style::default().fg(ACCENT),
        ),
        Span::styled("──▶", Style::default().fg(GRID)),
        Span::styled(format!(" {gateway} "), Style::default().fg(INK)),
    ]);
    let network_context = network_configuration_summary(app);
    let radio = app.link.wifi.as_ref().map(|wifi| {
        let signal = wifi
            .signal_dbm
            .map(|value| format!("{value:.0} dBm"))
            .or_else(|| wifi.signal_percent.map(|value| format!("{value:.0}%")))
            .unwrap_or_else(|| "signal ?".into());
        let channel = wifi
            .channel
            .map(|value| format!("ch {value}"))
            .or_else(|| wifi.frequency_mhz.map(|value| format!("{value} MHz")))
            .unwrap_or_else(|| "channel ?".into());
        let rate = wifi
            .tx_rate_mbps
            .map(|value| format!("tx {value:.0} Mb/s"))
            .unwrap_or_else(|| "tx ?".into());
        format!("RSSI {signal} · {channel} · {rate}")
    });
    let traffic = app.interface_rate.as_ref().map(|rate| {
        let mut summary = format!(
            "if rx {} · tx {}",
            crate::speed::human_rate(Some(rate.received_bits_per_second)),
            crate::speed::human_rate(Some(rate.transmitted_bits_per_second)),
        );
        if rate.error_delta > 0 {
            summary.push_str(&format!(" · err +{}", rate.error_delta));
        }
        if rate.drop_delta > 0 {
            summary.push_str(&format!(" · drop +{}", rate.drop_delta));
        }
        summary
    });
    let mut telemetry_parts = vec![
        radio.unwrap_or_else(|| "RSSI/channel not observed".into()),
        traffic.unwrap_or_else(|| "interface counters sampling…".into()),
    ];
    if area.width >= 120 {
        telemetry_parts.push(compact_workload_summary(app));
    }
    let telemetry = fit(
        &format!(" {}", telemetry_parts.join("   ")),
        usize::from(area.width.saturating_sub(2)),
    );
    let network_context = fit(
        &format!(" {network_context}"),
        usize::from(area.width.saturating_sub(2)),
    );
    frame.render_widget(
        Paragraph::new(vec![
            path,
            Line::from(Span::styled(network_context, Style::default().fg(MUTED))),
            Line::from(Span::styled(telemetry, Style::default().fg(MUTED))),
        ])
        .block(instrument_block(&format!(
            " LOCAL PATH / GENERATION {} ",
            app.path_generation
        ))),
        area,
    );
}

fn render_latency(frame: &mut Frame<'_>, area: Rect, app: &App) {
    if !app.probe_policy().is_active() {
        let route = format!(
            "{} → {}",
            app.link
                .interface
                .as_deref()
                .unwrap_or("interface unavailable"),
            app.link
                .gateway
                .as_deref()
                .unwrap_or("next hop unavailable")
        );
        let radio = app.link.wifi.as_ref().map_or_else(
            || "telemetry unavailable".into(),
            |wifi| {
                format!(
                    "RSSI {} / noise {} / ch {} / PHY {} / tx {}",
                    human_dbm(wifi.signal_dbm.or(wifi.signal_percent)),
                    human_dbm(wifi.noise_dbm),
                    wifi.channel
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "?".into()),
                    wifi.phy.as_deref().unwrap_or("?"),
                    crate::speed::human_rate(wifi.tx_rate_mbps.map(|value| value * 1_000_000.0))
                )
            },
        );
        let traffic = app.interface_rate.as_ref().map_or_else(
            || "rate baseline pending".into(),
            |rate| {
                format!(
                    "rx {} / tx {} / errors +{} / drops +{}",
                    crate::speed::human_rate(Some(rate.received_bits_per_second)),
                    crate::speed::human_rate(Some(rate.transmitted_bits_per_second)),
                    rate.error_delta,
                    rate.drop_delta
                )
            },
        );
        let resolvers = if app.link.resolvers.is_empty() {
            "unavailable".into()
        } else {
            app.link.resolvers.join(", ")
        };
        let neighbor_source = if app.peers.sources.is_empty() {
            "pending".into()
        } else {
            app.peers.sources.join(" + ")
        };
        let lines = vec![
            Line::from(vec![
                Span::styled(" route     ", Style::default().fg(MUTED)),
                Span::styled(route, Style::default().fg(INK)),
            ]),
            Line::from(vec![
                Span::styled(" 802.11    ", Style::default().fg(MUTED)),
                Span::styled(radio, Style::default().fg(INK)),
            ]),
            Line::from(vec![
                Span::styled(" interface ", Style::default().fg(MUTED)),
                Span::styled(traffic, Style::default().fg(INK)),
            ]),
            Line::from(vec![
                Span::styled(" resolvers ", Style::default().fg(MUTED)),
                Span::styled(resolvers, Style::default().fg(INK)),
            ]),
            Line::from(vec![
                Span::styled(" neighbors ", Style::default().fg(MUTED)),
                Span::styled(
                    format!(
                        "{} cache entries / {neighbor_source}",
                        app.peers.peers.len()
                    ),
                    Style::default().fg(INK),
                ),
            ]),
            Line::from(Span::styled(
                " active probes off · [a] enables bounded path diagnosis",
                Style::default().fg(ACCENT),
            )),
        ];
        frame.render_widget(
            Paragraph::new(lines)
                .block(instrument_block(" PASSIVE OBSERVATIONS "))
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    }
    let samples: Vec<u64> = app.gateway_samples.iter().copied().collect();
    let latest = samples.last().copied();
    let max = samples.iter().copied().max().unwrap_or(1).max(10);
    let distribution = app.gateway_metrics.as_ref().map(|metrics| {
        format!(
            "p50 {} / p95 {} / mean|ΔRTT| {} / loss {}",
            human_ms(metrics.rtt_p50_ms),
            human_ms(metrics.rtt_p95_ms),
            human_ms(metrics.mean_abs_adjacent_rtt_delta_ms),
            metrics
                .loss_rate
                .map(|value| format!("{:.0}%", value * 100.0))
                .unwrap_or_else(|| "?".into())
        )
    });
    let title = match (latest, distribution) {
        (Some(value), Some(distribution)) => format!(
            " NEXT-HOP RTT / latest {value}ms / {distribution} / n {}/{} ",
            app.gateway_attempts,
            crate::model::MAX_GATEWAY_SAMPLES
        ),
        (Some(value), None) => format!(
            " NEXT-HOP RTT / latest {value}ms / n {}/{} ",
            app.gateway_attempts,
            crate::model::MAX_GATEWAY_SAMPLES
        ),
        (None, _) => " NEXT-HOP RTT / waiting for probes ".into(),
    };
    frame.render_widget(
        Sparkline::default()
            .block(instrument_block(&title))
            .data(&samples)
            .max(max)
            .style(Style::default().fg(ACCENT)),
        area,
    );
}

fn render_probes(frame: &mut Frame<'_>, area: Rect, app: &App) {
    if !app.probe_policy().is_active() {
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(vec![
                    Span::styled(" next hop ", Style::default().fg(MUTED)),
                    Span::styled("ICMP echo · every interval", Style::default().fg(INK)),
                ]),
                Line::from(vec![
                    Span::styled(" target   ", Style::default().fg(MUTED)),
                    Span::styled(
                        "DNS + HTTPS example.com · every 60s",
                        Style::default().fg(INK),
                    ),
                ]),
                Line::from(vec![
                    Span::styled(" egress   ", Style::default().fg(MUTED)),
                    Span::styled(
                        "HTTPS address lookup · enable/path/r",
                        Style::default().fg(INK),
                    ),
                ]),
                Line::from(Span::styled(
                    " [a] start active path diagnosis",
                    Style::default().fg(ACCENT),
                )),
            ])
            .block(instrument_block(" ACTIVE PROBES / OFF ")),
            area,
        );
        return;
    }
    let detail_width = usize::from(area.width.saturating_sub(2)).saturating_sub(45);
    let lines: Vec<Line<'_>> = app
        .probes
        .iter()
        .map(|probe| {
            let latency = probe
                .latency_ms
                .map(|value| format!("{value:>6.0} ms"))
                .unwrap_or_else(|| "       —".into());
            Line::from(vec![
                Span::styled(
                    format!(" {:<10}", probe.health.label()),
                    Style::default()
                        .fg(health_color(probe.health))
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(" {:<13}", probe.kind.label()),
                    Style::default().fg(INK),
                ),
                Span::styled(latency, Style::default().fg(MUTED)),
                Span::styled(
                    format!(
                        "  {:>7}",
                        app.probe_age(probe.kind)
                            .map(freshness)
                            .unwrap_or_else(|| "pending".into())
                    ),
                    Style::default().fg(MUTED),
                ),
                Span::styled(
                    format!("  {}", fit(&probe.detail, detail_width)),
                    Style::default().fg(MUTED),
                ),
            ])
        })
        .collect();
    frame.render_widget(
        Paragraph::new(lines).block(instrument_block(" ACTIVE PROBES ")),
        area,
    );
}

fn render_events(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let available = area.height.saturating_sub(2) as usize;
    let lines: Vec<Line<'_>> = app
        .events
        .iter()
        .rev()
        .take(available)
        .rev()
        .map(|event| {
            Line::from(vec![
                Span::styled(
                    format!(" +{} ", format_duration(event.elapsed)),
                    Style::default().fg(MUTED),
                ),
                Span::styled("▌ ", Style::default().fg(health_color(event.health))),
                Span::styled(event.message.as_str(), Style::default().fg(INK)),
            ])
        })
        .collect();
    frame.render_widget(
        Paragraph::new(lines)
            .block(instrument_block(" SESSION EVENTS "))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_path_dwell(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let dwell = &app.path_dwell;
    let interface = &dwell.interface;
    let radio = &dwell.wifi;
    let workload = &dwell.workload;
    let peers = app.peer_dwell_summary();
    let value_width = usize::from(area.width.saturating_sub(14));
    let current_rate = interface.current_rate.as_ref().map_or_else(
        || "unavailable".into(),
        |rate| {
            format!(
                "rx {} / tx {}",
                crate::speed::human_rate(Some(rate.received_bits_per_second)),
                crate::speed::human_rate(Some(rate.transmitted_bits_per_second))
            )
        },
    );
    let peak_rate = match (
        interface.peak_received_bits_per_second,
        interface.peak_transmitted_bits_per_second,
    ) {
        (Some(received), Some(transmitted)) => format!(
            "rx {} / tx {}",
            crate::speed::human_rate(Some(received)),
            crate::speed::human_rate(Some(transmitted))
        ),
        _ => "unavailable".into(),
    };
    let radio_signal = match (
        radio.latest_signal_dbm,
        radio.worst_signal_dbm,
        radio.latest_signal_percent,
        radio.worst_signal_percent,
    ) {
        (Some(latest), Some(worst), _, _) => {
            format!("RSSI latest {latest:.0}, worst {worst:.0} dBm")
        }
        (_, _, Some(latest), Some(worst)) => {
            format!("signal latest {latest:.0}%, worst {worst:.0}%")
        }
        _ => "signal unavailable".into(),
    };
    let process_windows = dwell_process_windows(workload);
    let lines = vec![
        dwell_line(
            "window",
            format!(
                "generation {} / {} / bounded in-memory evidence",
                app.path_generation,
                format_duration(app.uptime().saturating_sub(app.path_observed_since))
            ),
            value_width,
        ),
        dwell_line(
            "interface",
            format!(
                "n={} valid={} reset={} errors=+{} drops=+{}",
                interface.samples,
                interface.valid_intervals,
                interface.counter_resets,
                interface.error_delta,
                interface.drop_delta
            ),
            value_width,
        ),
        dwell_line(
            "deltas",
            format!(
                "bytes rx={} tx={} / packets rx={} tx={}",
                human_bytes(interface.received_bytes_delta),
                human_bytes(interface.transmitted_bytes_delta),
                interface.received_packets_delta,
                interface.transmitted_packets_delta
            ),
            value_width,
        ),
        dwell_line("latest rate", current_rate, value_width),
        dwell_line("peak rate", peak_rate, value_width),
        dwell_line(
            "radio",
            format!(
                "n={} / ch {} Δ{} / {radio_signal}",
                radio.samples,
                radio
                    .latest_channel
                    .map(|channel| channel.to_string())
                    .unwrap_or_else(|| "unavailable".into()),
                radio.channel_changes
            ),
            value_width,
        ),
        dwell_line(
            "neighbors",
            format!(
                "cached={} observed={} changed={} absent={} ≠ liveness",
                peers.current, peers.observed, peers.changed, peers.disappeared
            ),
            value_width,
        ),
        dwell_line(
            "workload",
            format!(
                "n={} span={}; sampled windows ≠ session traffic",
                workload.sampled_windows,
                format_duration(workload.observed)
            ),
            value_width,
        ),
        dwell_line("processes", process_windows, value_width),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(instrument_block(" SINCE PATH CHANGE ")),
        area,
    );
}

fn render_active_path_dwell(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let interface = &app.path_dwell.interface;
    let wifi = &app.path_dwell.wifi;
    let workload = &app.path_dwell.workload;
    let peers = app.peer_dwell_summary();
    let value_width = usize::from(area.width.saturating_sub(13));
    let rate = interface.current_rate.as_ref().map_or_else(
        || "latest unavailable".into(),
        |current| {
            format!(
                "latest rx {} tx {}",
                dwell_rate(current.received_bits_per_second),
                dwell_rate(current.transmitted_bits_per_second)
            )
        },
    );
    let peak = match (
        interface.peak_received_bits_per_second,
        interface.peak_transmitted_bits_per_second,
    ) {
        (Some(received), Some(transmitted)) => format!(
            "peak rx {} tx {}",
            dwell_rate(received),
            dwell_rate(transmitted)
        ),
        _ => "peak unavailable".into(),
    };
    let radio = match (wifi.latest_signal_dbm, wifi.worst_signal_dbm) {
        (Some(latest), Some(worst)) => format!(
            "n={} RSSI latest {latest:.0} worst {worst:.0} dBm ch {} Δ{}",
            wifi.samples,
            wifi.latest_channel
                .map(|channel| channel.to_string())
                .unwrap_or_else(|| "unavailable".into()),
            wifi.channel_changes
        ),
        _ => format!(
            "n={} signal unavailable ch {} Δ{}",
            wifi.samples,
            wifi.latest_channel
                .map(|channel| channel.to_string())
                .unwrap_or_else(|| "unavailable".into()),
            wifi.channel_changes
        ),
    };
    let lines = vec![
        dwell_line(
            "interface",
            format!(
                "n={} valid={} · {rate} · {peak}",
                interface.samples, interface.valid_intervals
            ),
            value_width,
        ),
        dwell_line(
            "deltas",
            format!(
                "rx {} tx {} · errors +{} drops +{} reset {}",
                human_bytes(interface.received_bytes_delta),
                human_bytes(interface.transmitted_bytes_delta),
                interface.error_delta,
                interface.drop_delta,
                interface.counter_resets
            ),
            value_width,
        ),
        dwell_line("radio", radio, value_width),
        dwell_line(
            "workload",
            format!(
                "n={} span={} · {}",
                workload.sampled_windows,
                format_duration(workload.observed),
                dwell_process_windows(workload)
            ),
            value_width,
        ),
        dwell_line(
            "neighbors",
            format!(
                "cached={} observed={} changed={} absent={} ≠ liveness",
                peers.current, peers.observed, peers.changed, peers.disappeared
            ),
            value_width,
        ),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(instrument_block(&format!(
            " PATH DWELL / PASSIVE SOURCES / GENERATION {} ",
            app.path_generation
        ))),
        area,
    );
}

fn dwell_process_windows(workload: &crate::model::WorkloadDwell) -> String {
    if workload.sampled_windows == 0 {
        return "not sampled; no successful workload window".into();
    }
    let latest = workload
        .latest_window_top
        .as_ref()
        .map_or_else(|| "none attributed".into(), sampled_process);
    let peak = workload
        .peak_window_top
        .as_ref()
        .map_or_else(|| "none attributed".into(), sampled_process);
    if workload.latest_window_top == workload.peak_window_top {
        format!("latest=peak {latest}")
    } else {
        format!("latest {latest} / peak {peak}")
    }
}

fn dwell_line(label: &'static str, value: String, value_width: usize) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label:<11} "), Style::default().fg(MUTED)),
        Span::styled(fit(&value, value_width), Style::default().fg(INK)),
    ])
}

fn sampled_process(process: &crate::model::ProcessTraffic) -> String {
    format!(
        "{}{} {}",
        process.process,
        if process.processes > 1 {
            format!("×{}", process.processes)
        } else {
            String::new()
        },
        dwell_rate(
            process
                .received_bytes_per_second
                .saturating_add(process.transmitted_bytes_per_second) as f64
                * 8.0
        )
    )
}

fn dwell_rate(bits_per_second: f64) -> String {
    if bits_per_second < 1_000.0 {
        format!("{bits_per_second:.0}bit/s")
    } else if bits_per_second < 1_000_000.0 {
        format!("{:.1}Kbit/s", bits_per_second / 1_000.0)
    } else if bits_per_second < 1_000_000_000.0 {
        format!("{:.1}Mbit/s", bits_per_second / 1_000_000.0)
    } else {
        format!("{:.1}Gbit/s", bits_per_second / 1_000_000_000.0)
    }
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

fn render_addresses(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let available = area.height.saturating_sub(2) as usize;
    let lines: Vec<Line<'_>> = app
        .link
        .addresses
        .iter()
        .take(available)
        .map(|address| {
            Line::from(vec![
                Span::styled(
                    address_marker(address.is_default, address.is_temporary),
                    Style::default().fg(ACCENT),
                ),
                Span::styled(
                    format!("{:<7}", address.interface),
                    Style::default().fg(MUTED),
                ),
                Span::styled(address.address.as_str(), Style::default().fg(INK)),
            ])
        })
        .collect();
    frame.render_widget(
        Paragraph::new(lines)
            .block(instrument_block(" LOCAL ADDRESSES / ▶ DEFAULT / ~ TEMP "))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_scope(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let default_addresses = app
        .link
        .addresses
        .iter()
        .filter(|address| address.is_default)
        .count();
    let source = if app.peers.sources.is_empty() {
        "source pending".into()
    } else {
        app.peers.sources.join("+")
    };
    let completeness = if app.peers.failed_sources.is_empty() {
        app.peers.health.label().to_ascii_lowercase()
    } else {
        format!("partial; missing {}", app.peers.failed_sources.join("+"))
    };
    let content_rows = usize::from(area.height.saturating_sub(2));
    let value_width = usize::from(area.width.saturating_sub(10));
    let history_lines = app.history_context.as_ref().map(|history| {
        vec![
            Line::from(vec![
                Span::styled(" history", Style::default().fg(MUTED)),
                Span::styled(
                    format!(" {}", fit(&history.compact_summary, value_width)),
                    Style::default().fg(INK),
                ),
            ]),
            Line::from(vec![
                Span::styled(" place  ", Style::default().fg(MUTED)),
                Span::styled(
                    fit(&history.place_authority, value_width),
                    Style::default().fg(INK),
                ),
            ]),
            Line::from(vec![
                Span::styled(" anchor ", Style::default().fg(MUTED)),
                Span::styled(
                    fit(&history.context_anchor, value_width),
                    Style::default().fg(INK),
                ),
            ]),
        ]
    });
    let mut lines = Vec::new();
    if history_lines.is_some() && content_rows < 6 {
        lines.extend(history_lines.into_iter().flatten());
    } else {
        lines.extend([
            Line::from(vec![
                Span::styled(" local  ", Style::default().fg(MUTED)),
                Span::styled(
                    fit(
                        &format!(
                            "{default_addresses} default / {} total address(es)",
                            app.link.addresses.len()
                        ),
                        value_width,
                    ),
                    Style::default().fg(INK),
                ),
            ]),
            Line::from(vec![
                Span::styled(" cache  ", Style::default().fg(MUTED)),
                Span::styled(
                    fit(
                        &format!(
                            "{} via {source} / {completeness}",
                            peer_session_summary(app)
                        ),
                        value_width,
                    ),
                    Style::default().fg(INK),
                ),
            ]),
            Line::from(vec![
                Span::styled(" probes ", Style::default().fg(MUTED)),
                Span::styled(
                    fit(
                        if app.probe_policy().is_active() {
                            "active · next-hop periodic · DNS/HTTPS 60s · egress on demand"
                        } else {
                            "off · next-hop/DNS/HTTPS/public egress untested"
                        },
                        value_width,
                    ),
                    Style::default().fg(INK),
                ),
            ]),
        ]);
        if content_rows >= 9 {
            lines.extend([
                Line::from(vec![
                    Span::styled(" sources", Style::default().fg(MUTED)),
                    Span::styled(
                        fit(
                            "route/DHCP · 802.11 · counters/nettop · ARP/NDP",
                            value_width,
                        ),
                        Style::default().fg(INK),
                    ),
                ]),
                Line::from(vec![
                    Span::styled(" fence  ", Style::default().fg(MUTED)),
                    Span::styled(
                        fit(
                            &format!(
                                "generation {}; stale workers rejected; route gaps held 3s",
                                app.path_generation
                            ),
                            value_width,
                        ),
                        Style::default().fg(INK),
                    ),
                ]),
            ]);
        }
        lines.extend(history_lines.into_iter().flatten());
        if lines.len() < content_rows {
            lines.push(Line::from(Span::styled(
                " [2] full link evidence   [3] neighbor details",
                Style::default().fg(ACCENT),
            )));
        }
    }
    lines.truncate(content_rows);
    frame.render_widget(
        Paragraph::new(lines)
            .block(instrument_block(" EVIDENCE / ACTIVITY BOUNDARY "))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_link_focus(frame: &mut Frame<'_>, area: Rect, app: &App, can_navigate: bool) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(1),
        ])
        .split(area);
    render_header(frame, chunks[0], app, MonitorMode::Link);

    if chunks[1].height < 15 || chunks[1].width < 82 {
        if chunks[1].height < 10 {
            frame.render_widget(
                Paragraph::new(link_shallow_lines(app, chunks[1].width))
                    .block(instrument_block(" LOCAL LINK / PASSIVE ONLY ")),
                chunks[1],
            );
            render_footer(frame, chunks[2], app, MonitorMode::Link, can_navigate);
            return;
        }
        let available = chunks[1].height.saturating_sub(2) as usize;
        let mut lines = link_shallow_lines(app, chunks[1].width);
        let address_rows = available.saturating_sub(lines.len());
        append_compact_address_lines(&mut lines, app, chunks[1].width, address_rows);
        frame.render_widget(
            Paragraph::new(lines).block(instrument_block(" LOCAL LINK / OBSERVED STATE ")),
            chunks[1],
        );
        render_footer(frame, chunks[2], app, MonitorMode::Link, can_navigate);
        return;
    }

    let body = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Length(7),
            Constraint::Min(4),
        ])
        .split(chunks[1]);
    frame.render_widget(
        Paragraph::new(link_identity_lines(app))
            .block(instrument_block(" ACTIVE LOCAL PATH "))
            .wrap(Wrap { trim: true }),
        body[0],
    );
    let evidence = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
        .split(body[1]);
    frame.render_widget(
        Paragraph::new(link_telemetry_lines(app))
            .block(instrument_block(" RADIO / INTERFACE "))
            .wrap(Wrap { trim: true }),
        evidence[0],
    );
    render_addresses(frame, evidence[1], app);
    render_events(frame, body[2], app);
    render_footer(frame, chunks[2], app, MonitorMode::Link, can_navigate);
}

fn append_compact_address_lines(
    lines: &mut Vec<Line<'static>>,
    app: &App,
    width: u16,
    available: usize,
) {
    if available == 0 {
        return;
    }
    let usable = usize::from(width.saturating_sub(2));
    lines.push(Line::from(Span::styled(
        "addresses",
        Style::default().fg(MUTED).add_modifier(Modifier::BOLD),
    )));
    let row_capacity = available.saturating_sub(1);
    if row_capacity == 0 {
        return;
    }
    if app.link.addresses.is_empty() {
        lines.push(Line::from(Span::styled(
            "  unavailable",
            Style::default().fg(MUTED),
        )));
        return;
    }
    let show_marker = app.link.addresses.len() > row_capacity;
    let address_capacity = row_capacity.saturating_sub(usize::from(show_marker));
    lines.extend(
        app.link
            .addresses
            .iter()
            .take(address_capacity)
            .map(|address| {
                let text = format!(
                    "{}{:<7}{}",
                    address_marker(address.is_default, address.is_temporary),
                    address.interface,
                    address.address
                );
                Line::from(Span::styled(fit(&text, usable), Style::default().fg(INK)))
            }),
    );
    if show_marker {
        lines.push(Line::from(Span::styled(
            format!(
                "… {} more address(es); use --json for the complete set",
                app.link.addresses.len() - address_capacity
            ),
            Style::default().fg(ACCENT),
        )));
    }
}

fn link_shallow_lines(app: &App, width: u16) -> Vec<Line<'static>> {
    let usable = usize::from(width.saturating_sub(2));
    let ssid = app
        .link
        .ssid
        .as_deref()
        .map(str::to_owned)
        .or_else(|| {
            app.link
                .ssid_restricted
                .then(|| "SSID hidden by macOS".into())
        })
        .unwrap_or_else(|| "network identity unavailable".into());
    let default_addresses: Vec<_> = app
        .link
        .addresses
        .iter()
        .filter(|address| address.is_default)
        .collect();
    let address = default_addresses
        .iter()
        .find(|address| address.family == 4)
        .or_else(|| default_addresses.first())
        .map_or_else(
            || "unavailable".into(),
            |address| {
                format!(
                    "{}{}",
                    address.address,
                    if default_addresses.len() > 1 {
                        format!(" +{}", default_addresses.len() - 1)
                    } else {
                        String::new()
                    }
                )
            },
        );
    let resolver = app.link.resolvers.first().map_or_else(
        || "unavailable".into(),
        |resolver| {
            format!(
                "{resolver}{}",
                if app.link.resolvers.len() > 1 {
                    format!(" +{}", app.link.resolvers.len() - 1)
                } else {
                    String::new()
                }
            )
        },
    );
    let radio = app.link.wifi.as_ref().map_or_else(
        || "unavailable".into(),
        |wifi| {
            format!(
                "signal {} / channel {}",
                wifi.signal_dbm
                    .or(wifi.signal_percent)
                    .map(|value| format!("{value:.0}"))
                    .unwrap_or_else(|| "?".into()),
                wifi.channel
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "?".into())
            )
        },
    );
    let traffic = app.interface_rate.as_ref().map_or_else(
        || "sampling…".into(),
        |rate| {
            format!(
                "rx {} / tx {}",
                crate::speed::human_rate(Some(rate.received_bits_per_second)),
                crate::speed::human_rate(Some(rate.transmitted_bits_per_second))
            )
        },
    );
    let counters = app.interface_counters.as_ref().map_or_else(
        || "unavailable".into(),
        |counters| {
            format!(
                "errors {} / drops {}",
                counters.receive_errors + counters.transmit_errors,
                counters.drops
            )
        },
    );
    [
        format!(
            "path      {} [{} / {}] → {}",
            app.link.interface.as_deref().unwrap_or("interface?"),
            app.link.link_type.as_deref().unwrap_or("link?"),
            ssid,
            app.link.gateway.as_deref().unwrap_or("gateway?")
        ),
        format!("config    {}", compact_network_configuration_summary(app)),
        format!("address   {address}"),
        format!("resolver  {resolver}"),
        format!("radio     {radio}"),
        format!("traffic   {traffic}"),
        format!("totals    {counters}"),
    ]
    .into_iter()
    .map(|line| Line::from(Span::styled(fit(&line, usable), Style::default().fg(INK))))
    .collect()
}

fn address_marker(is_default: bool, is_temporary: bool) -> &'static str {
    match (is_default, is_temporary) {
        (true, true) => "▶~ ",
        (true, false) => "▶  ",
        (false, true) => "~  ",
        (false, false) => "   ",
    }
}

fn link_identity_lines(app: &App) -> Vec<Line<'_>> {
    let ssid = app
        .link
        .ssid
        .as_deref()
        .map(|value| format!(" / {value}"))
        .or_else(|| {
            app.link
                .ssid_restricted
                .then(|| " / SSID hidden by macOS".into())
        })
        .unwrap_or_default();
    vec![
        Line::from(vec![
            Span::styled(format!(" {} ", app.link.host), Style::default().fg(INK)),
            Span::styled("──▶ ", Style::default().fg(GRID)),
            Span::styled(
                format!(
                    "{} [{}{}]",
                    app.link.interface.as_deref().unwrap_or("discovering"),
                    app.link.link_type.as_deref().unwrap_or("link"),
                    ssid
                ),
                Style::default().fg(ACCENT),
            ),
            Span::styled(" ──▶ ", Style::default().fg(GRID)),
            Span::styled(
                app.link.gateway.as_deref().unwrap_or("no gateway"),
                Style::default().fg(INK),
            ),
        ]),
        Line::from(vec![
            Span::styled(" resolver  ", Style::default().fg(MUTED)),
            Span::styled(
                if app.link.resolvers.is_empty() {
                    "unavailable".into()
                } else {
                    app.link.resolvers.join(", ")
                },
                Style::default().fg(INK),
            ),
        ]),
        Line::from(vec![
            Span::styled(" config    ", Style::default().fg(MUTED)),
            Span::styled(network_configuration_summary(app), Style::default().fg(INK)),
        ]),
    ]
}

fn link_telemetry_lines(app: &App) -> Vec<Line<'_>> {
    let (radio_signal, radio_rate) = app.link.wifi.as_ref().map_or_else(
        || {
            (
                "radio telemetry unavailable".into(),
                "radio rate unavailable".into(),
            )
        },
        |wifi| {
            (
                format!(
                    "signal {}  noise {}  channel {}",
                    wifi.signal_dbm
                        .or(wifi.signal_percent)
                        .map(|value| format!("{value:.0}"))
                        .unwrap_or_else(|| "?".into()),
                    wifi.noise_dbm
                        .map(|value| format!("{value:.0}"))
                        .unwrap_or_else(|| "?".into()),
                    wifi.channel
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "?".into()),
                ),
                format!(
                    "radio rate tx {}  rx {}",
                    crate::speed::human_rate(wifi.tx_rate_mbps.map(|value| value * 1_000_000.0)),
                    crate::speed::human_rate(wifi.rx_rate_mbps.map(|value| value * 1_000_000.0)),
                ),
            )
        },
    );
    let traffic = app.interface_rate.as_ref().map_or_else(
        || "traffic rate sampling…".into(),
        |rate| {
            format!(
                "rx {}  tx {}",
                crate::speed::human_rate(Some(rate.received_bits_per_second)),
                crate::speed::human_rate(Some(rate.transmitted_bits_per_second))
            )
        },
    );
    let counters = app.interface_counters.as_ref().map_or_else(
        || "counter deltas unavailable".into(),
        |counters| {
            format!(
                "counter totals: errors {}  drops {}",
                counters.receive_errors + counters.transmit_errors,
                counters.drops
            )
        },
    );
    vec![
        Line::from(Span::styled(
            format!(" {radio_signal}"),
            Style::default().fg(INK),
        )),
        Line::from(Span::styled(
            format!(" {radio_rate}"),
            Style::default().fg(MUTED),
        )),
        Line::from(Span::styled(
            format!(" {traffic}"),
            Style::default().fg(INK),
        )),
        Line::from(Span::styled(
            format!(" {counters}"),
            Style::default().fg(MUTED),
        )),
    ]
}

fn render_peers_focus(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &App,
    peer_offset: usize,
    can_navigate: bool,
) {
    if area.height < 21 {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(5),
                Constraint::Length(1),
            ])
            .split(area);
        render_header(frame, chunks[0], app, MonitorMode::Peers);
        render_peer_table(frame, chunks[1], app, peer_offset);
        render_footer(frame, chunks[2], app, MonitorMode::Peers, can_navigate);
        return;
    }
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(7),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .split(area);
    render_header(frame, chunks[0], app, MonitorMode::Peers);

    let ssid = app
        .link
        .ssid
        .as_deref()
        .map(|value| format!(" / {value}"))
        .or_else(|| {
            app.link
                .ssid_restricted
                .then(|| " / SSID hidden by macOS".into())
        })
        .unwrap_or_default();
    let sources = if app.peers.sources.is_empty() {
        "source pending".into()
    } else {
        app.peers.sources.join(" + ")
    };
    let failed_sources = if app.peers.failed_sources.is_empty() {
        String::new()
    } else {
        format!("  /  missing {}", app.peers.failed_sources.join(" + "))
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(" path      ", Style::default().fg(MUTED)),
                Span::styled(
                    format!(
                        "{} [{}{}] via {}",
                        app.link.interface.as_deref().unwrap_or("discovering"),
                        app.link.link_type.as_deref().unwrap_or("link"),
                        ssid,
                        app.link.gateway.as_deref().unwrap_or("no gateway")
                    ),
                    Style::default().fg(INK),
                ),
            ]),
            Line::from(vec![
                Span::styled(" evidence  ", Style::default().fg(MUTED)),
                Span::styled(sources, Style::default().fg(INK)),
                Span::styled(failed_sources, Style::default().fg(WARN)),
                Span::styled(
                    format!(
                        "  /  OUI {}",
                        app.peers
                            .oui_source
                            .as_deref()
                            .and_then(|source| source.rsplit('/').next())
                            .unwrap_or("unavailable")
                    ),
                    Style::default().fg(MUTED),
                ),
            ]),
            Line::from(vec![
                Span::styled(" session   ", Style::default().fg(MUTED)),
                Span::styled(peer_session_summary(app), Style::default().fg(INK)),
                Span::styled(
                    " / current path generation only",
                    Style::default().fg(MUTED),
                ),
            ]),
            Line::from(vec![
                Span::styled(" semantics ", Style::default().fg(MUTED)),
                Span::styled(
                    "cache presence is not liveness; disappearance is not departure",
                    Style::default().fg(INK),
                ),
            ]),
            Line::from(vec![
                Span::styled(" activity  ", Style::default().fg(MUTED)),
                Span::styled(
                    "unknown; native cache has no traffic or application vantage",
                    Style::default().fg(INK),
                ),
            ]),
        ])
        .block(instrument_block(" OBSERVATION CONTEXT "))
        .wrap(Wrap { trim: true }),
        chunks[1],
    );

    render_peer_table(frame, chunks[2], app, peer_offset);
    render_footer(frame, chunks[3], app, MonitorMode::Peers, can_navigate);
}

fn render_peer_table(frame: &mut Frame<'_>, area: Rect, app: &App, peer_offset: usize) {
    let peers = ordered_peers(app);
    let content_rows = area.height.saturating_sub(2) as usize;
    let capacity = peer_table_capacity(area);
    let wide = area.width >= 104;
    let tight = area.width < 76;
    let offset = peer_offset.min(peers.len().saturating_sub(capacity.max(1)));
    let end = (offset + capacity).min(peers.len());
    let mut lines = Vec::new();

    if wide && content_rows > 0 {
        let address_width = if area.width >= 138 { 39 } else { 28 };
        lines.push(Line::from(Span::styled(
            format!(
                "   {:<7} {:<address_width$} {:<17} {:<11} {:<8} {}",
                "IFACE", "ADDRESS", "MAC", "STATE", "ROLE", "ATTENTION / SESSION / ATTRIBUTION"
            ),
            Style::default().fg(MUTED).add_modifier(Modifier::BOLD),
        )));
        for peer in peers.iter().skip(offset).take(capacity) {
            lines.push(peer_wide_line(peer, app, address_width));
        }
    } else if tight {
        for peer in peers.iter().skip(offset).take(capacity) {
            lines.extend(peer_tight_lines(peer, app, area.width));
        }
    } else {
        for peer in peers.iter().skip(offset).take(capacity) {
            lines.extend(peer_narrow_lines(peer, app, area.width));
        }
    }

    if peers.is_empty() {
        lines.push(Line::from(Span::styled(
            app.peers.detail.as_str(),
            Style::default().fg(MUTED),
        )));
    }
    let range = if peers.is_empty() {
        "0 / 0".into()
    } else {
        format!("{}-{} / {}", offset + 1, end, peers.len())
    };
    frame.render_widget(
        Paragraph::new(lines).block(instrument_block(&format!(
            " PASSIVE NEIGHBORS / {range} / NO SCAN "
        ))),
        area,
    );
}

pub(crate) fn peer_page_capacity(area: Rect) -> usize {
    let table_height = if area.height < 21 {
        area.height.saturating_sub(4)
    } else {
        area.height.saturating_sub(11)
    };
    peer_table_capacity(Rect::new(area.x, area.y, area.width, table_height))
}

fn peer_table_capacity(area: Rect) -> usize {
    let content_rows = area.height.saturating_sub(2) as usize;
    let wide = area.width >= 104;
    let rows_per_peer = if wide {
        1
    } else if area.width < 76 {
        3
    } else {
        2
    };
    let header_rows = usize::from(wide && content_rows > 0);
    content_rows
        .saturating_sub(header_rows)
        .checked_div(rows_per_peer)
        .unwrap_or(0)
}

fn peer_wide_line<'a>(peer: &'a Peer, app: &App, address_width: usize) -> Line<'a> {
    let gateway = app.link.gateway.as_deref() == Some(peer.address.as_str());
    Line::from(vec![
        Span::styled(
            if gateway { " ▶ " } else { "   " },
            Style::default().fg(if gateway { ACCENT } else { MUTED }),
        ),
        Span::styled(
            format!("{:<7} ", peer.interface.as_deref().unwrap_or("?")),
            Style::default().fg(MUTED),
        ),
        Span::styled(
            format!("{:<address_width$} ", fit(&peer.address, address_width)),
            Style::default().fg(INK),
        ),
        Span::styled(
            format!("{:<17} ", peer_mac_label(peer)),
            Style::default().fg(MUTED),
        ),
        Span::styled(
            format!("{:<11} ", peer.state.as_deref().unwrap_or("cached")),
            Style::default().fg(MUTED),
        ),
        Span::styled(
            format!("{:<8} ", if gateway { "gateway" } else { "neighbor" }),
            Style::default().fg(if gateway { ACCENT } else { MUTED }),
        ),
        Span::styled(
            format!(
                "{} / {} / {}",
                peer_attention_label(app, peer),
                peer_dwell_label(app, peer),
                peer_attribution(peer)
            ),
            Style::default().fg(INK),
        ),
    ])
}

fn peer_tight_lines<'a>(peer: &'a Peer, app: &App, width: u16) -> Vec<Line<'a>> {
    let gateway = app.link.gateway.as_deref() == Some(peer.address.as_str());
    let role = if gateway { "gateway" } else { "neighbor" };
    let state = peer.state.as_deref().unwrap_or("cached");
    let attention = peer_attention_label(app, peer);
    let dwell = peer_dwell_tight_label(app, peer);
    let mac = peer_mac_label(peer);
    let fixed_width = 7 + mac.chars().count() + 3 + 3 + dwell.chars().count();
    let attribution_width = usize::from(width)
        .saturating_sub(2)
        .saturating_sub(fixed_width)
        .max(8);

    vec![
        Line::from(vec![
            Span::styled(
                if gateway { " ▶ " } else { "   " },
                Style::default().fg(if gateway { ACCENT } else { MUTED }),
            ),
            Span::styled(
                format!("{:<7}", peer.interface.as_deref().unwrap_or("?")),
                Style::default().fg(MUTED),
            ),
            Span::styled(
                format!(" {role}"),
                Style::default().fg(if gateway { ACCENT } else { MUTED }),
            ),
            Span::styled(format!(" · {state}"), Style::default().fg(MUTED)),
            Span::styled(format!(" · {attention}"), Style::default().fg(INK)),
        ]),
        Line::from(vec![
            Span::styled("   address ", Style::default().fg(MUTED)),
            Span::styled(
                fit(&peer.address, usize::from(width.saturating_sub(13)).max(1)),
                Style::default().fg(INK),
            ),
        ]),
        Line::from(vec![
            Span::styled("   mac ", Style::default().fg(MUTED)),
            Span::styled(mac, Style::default().fg(MUTED)),
            Span::styled(" · ", Style::default().fg(GRID)),
            Span::styled(
                fit(peer_attribution(peer), attribution_width),
                Style::default().fg(INK),
            ),
            Span::styled(" · ", Style::default().fg(GRID)),
            Span::styled(dwell, Style::default().fg(ACCENT)),
        ]),
    ]
}

fn peer_narrow_lines<'a>(peer: &'a Peer, app: &App, width: u16) -> Vec<Line<'a>> {
    let gateway = app.link.gateway.as_deref() == Some(peer.address.as_str());
    let state = peer.state.as_deref().unwrap_or("cached");
    let dwell = peer_dwell_compact_label(app, peer);
    let fixed_width = 11 + 17 + 2 + 2 + dwell.chars().count();
    let attribution_width = usize::from(width)
        .saturating_sub(2)
        .saturating_sub(fixed_width)
        .max(8);
    vec![
        Line::from(vec![
            Span::styled(
                if gateway { " ▶ " } else { "   " },
                Style::default().fg(if gateway { ACCENT } else { MUTED }),
            ),
            Span::styled(
                format!("{:<7} ", fit(peer.interface.as_deref().unwrap_or("?"), 7)),
                Style::default().fg(MUTED),
            ),
            Span::styled(peer.address.as_str(), Style::default().fg(INK)),
            Span::styled(
                format!("  {:<9}", if gateway { "gateway" } else { "neighbor" }),
                Style::default().fg(if gateway { ACCENT } else { MUTED }),
            ),
            Span::styled(state, Style::default().fg(MUTED)),
        ]),
        Line::from(vec![
            Span::styled(
                format!("           {}  ", peer_mac_label(peer)),
                Style::default().fg(MUTED),
            ),
            Span::styled(
                format!(
                    "{:<attribution_width$}  ",
                    fit(
                        &format!(
                            "{} / {}",
                            peer_attention_label(app, peer),
                            peer_attribution(peer)
                        ),
                        attribution_width
                    )
                ),
                Style::default().fg(INK),
            ),
            Span::styled(dwell, Style::default().fg(ACCENT)),
        ]),
    ]
}

fn peer_attribution(peer: &Peer) -> &str {
    if peer.binding_conflict {
        return "conflicting evidence";
    }
    peer.registrant
        .as_deref()
        .or_else(|| peer.mac_scope.map(|scope| scope.label()))
        .unwrap_or("unattributed")
}

fn peer_mac_label(peer: &Peer) -> &str {
    if peer.binding_conflict {
        "source conflict"
    } else {
        peer.mac.as_deref().unwrap_or("no MAC")
    }
}

fn peer_dwell_label(app: &App, peer: &Peer) -> String {
    let Some(dwell) = app.peer_dwell(peer) else {
        return "seen in current snapshot".into();
    };
    let age = app.uptime().saturating_sub(dwell.last_observed);
    let changes = dwell.state_changes
        + dwell.binding_changes
        + dwell.cache_disappearances
        + dwell.cache_returns;
    format!(
        "n={}{} / first +{} / last {}",
        dwell.observations,
        if changes == 0 {
            String::new()
        } else {
            format!(" / Δ{changes}")
        },
        format_duration(dwell.first_observed),
        compact_age(age)
    )
}

fn peer_dwell_compact_label(app: &App, peer: &Peer) -> String {
    let Some(dwell) = app.peer_dwell(peer) else {
        return "current snapshot".into();
    };
    let age = app.uptime().saturating_sub(dwell.last_observed);
    let changes = dwell.state_changes
        + dwell.binding_changes
        + dwell.cache_disappearances
        + dwell.cache_returns;
    format!(
        "n={}{} first=+{} last={}",
        dwell.observations,
        if changes == 0 {
            String::new()
        } else {
            format!(" Δ{changes}")
        },
        format_duration(dwell.first_observed),
        compact_age(age)
    )
}

fn peer_dwell_tight_label(app: &App, peer: &Peer) -> String {
    let Some(dwell) = app.peer_dwell(peer) else {
        return "current snapshot".into();
    };
    let age = app.uptime().saturating_sub(dwell.last_observed);
    let changes = dwell.state_changes
        + dwell.binding_changes
        + dwell.cache_disappearances
        + dwell.cache_returns;
    format!(
        "n={}{} last={}",
        dwell.observations,
        if changes == 0 {
            String::new()
        } else {
            format!(" Δ{changes}")
        },
        compact_age(age)
    )
}

fn compact_age(duration: Duration) -> String {
    if duration.as_secs() == 0 {
        "now".into()
    } else {
        format_age(duration)
    }
}

fn format_age(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds < 60 {
        format!("{seconds}s ago")
    } else {
        format!("{} ago", format_duration(duration))
    }
}

fn freshness(duration: Duration) -> String {
    if duration.as_secs() < 2 {
        "now".into()
    } else if duration.as_secs() < 60 {
        format!("{}s ago", duration.as_secs())
    } else {
        format_duration(duration)
    }
}

pub(crate) fn peer_state_meaning(state: Option<&str>) -> &'static str {
    match state.map(str::to_ascii_uppercase).as_deref() {
        Some("REACHABLE") => "recently confirmed by kernel",
        Some("STALE") => "cached; confirmation expired",
        Some("DELAY") => "kernel waiting before recheck",
        Some("PROBE") => "kernel revalidating neighbor",
        Some("FAILED") => "address resolution failed",
        Some("INCOMPLETE") => "address resolution in progress",
        Some("DYNAMIC") => "learned dynamically",
        _ => "cached; liveness unknown",
    }
}

fn fit(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.into();
    }
    let mut clipped: String = value.chars().take(width.saturating_sub(1)).collect();
    clipped.push('…');
    clipped
}

fn render_footer(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &App,
    mode: MonitorMode,
    can_navigate: bool,
) {
    let state = if app.paused { "PAUSED" } else { "LIVE" };
    if area.width < 100 {
        if can_navigate && area.width < 76 {
            let probes = if app.probe_policy().is_active() {
                "probes:on"
            } else {
                "probes:off"
            };
            frame.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled(" q ", Style::default().fg(Color::Black).bg(INK)),
                    Span::styled(" quit  ", Style::default().fg(MUTED)),
                    Span::styled(" a ", Style::default().fg(Color::Black).bg(INK)),
                    Span::styled(format!(" {probes}  "), Style::default().fg(MUTED)),
                    Span::styled(" 1/2/3 ", Style::default().fg(Color::Black).bg(INK)),
                    Span::styled(" views  ", Style::default().fg(MUTED)),
                    Span::styled(
                        format!("{state} "),
                        Style::default().fg(if app.paused { WARN } else { OK }),
                    ),
                ])),
                area,
            );
            return;
        }
        let mut spans = vec![
            Span::styled(" q ", Style::default().fg(Color::Black).bg(INK)),
            Span::styled(" quit  ", Style::default().fg(MUTED)),
        ];
        if mode == MonitorMode::Peers {
            spans.extend([
                Span::styled(" j/k ", Style::default().fg(Color::Black).bg(INK)),
                Span::styled(" scroll  ", Style::default().fg(MUTED)),
            ]);
        } else {
            spans.extend([
                Span::styled(" r ", Style::default().fg(Color::Black).bg(INK)),
                Span::styled(" refresh  ", Style::default().fg(MUTED)),
                Span::styled(" p ", Style::default().fg(Color::Black).bg(INK)),
                Span::styled(" pause  ", Style::default().fg(MUTED)),
            ]);
        }
        if can_navigate {
            spans.extend([
                Span::styled(" a ", Style::default().fg(Color::Black).bg(INK)),
                Span::styled(
                    if app.probe_policy().is_active() {
                        " probes:on  "
                    } else {
                        " probes:off  "
                    },
                    Style::default().fg(MUTED),
                ),
                Span::styled(" 1/2/3 ", Style::default().fg(Color::Black).bg(INK)),
                Span::styled(" views  ", Style::default().fg(MUTED)),
            ]);
        }
        spans.push(Span::styled(
            format!("{state} "),
            Style::default().fg(if app.paused { WARN } else { OK }),
        ));
        frame.render_widget(Paragraph::new(Line::from(spans)), area);
        return;
    }
    let mut spans = vec![
        Span::styled(" q ", Style::default().fg(Color::Black).bg(INK)),
        Span::styled(" quit  ", Style::default().fg(MUTED)),
        Span::styled(" r ", Style::default().fg(Color::Black).bg(INK)),
        Span::styled(" refresh  ", Style::default().fg(MUTED)),
        Span::styled(" p ", Style::default().fg(Color::Black).bg(INK)),
        Span::styled(" pause/resume  ", Style::default().fg(MUTED)),
    ];
    if mode == MonitorMode::Peers {
        spans.extend([
            Span::styled(" j/k ", Style::default().fg(Color::Black).bg(INK)),
            Span::styled(" scroll  ", Style::default().fg(MUTED)),
            Span::styled(" PgUp/PgDn ", Style::default().fg(Color::Black).bg(INK)),
            Span::styled(" page  ", Style::default().fg(MUTED)),
        ]);
    }
    if can_navigate {
        spans.extend([
            Span::styled(" a ", Style::default().fg(Color::Black).bg(INK)),
            Span::styled(
                if app.probe_policy().is_active() {
                    " probes:on  "
                } else {
                    " probes:off  "
                },
                Style::default().fg(MUTED),
            ),
            Span::styled(" 1/2/3 ", Style::default().fg(Color::Black).bg(INK)),
            Span::styled(" views  ", Style::default().fg(MUTED)),
            Span::styled(" Tab ", Style::default().fg(Color::Black).bg(INK)),
            Span::styled(" next  ", Style::default().fg(MUTED)),
        ]);
    }
    spans.push(Span::styled(
        format!("{state} "),
        Style::default().fg(if app.paused { WARN } else { OK }),
    ));
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn render_overview_compact(frame: &mut Frame<'_>, area: Rect, app: &App, can_navigate: bool) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .split(area);
    render_header(frame, chunks[0], app, MonitorMode::Overview);
    let diagnosis = overview_diagnosis(app);
    let ssid = app
        .link
        .ssid
        .as_deref()
        .map(str::to_owned)
        .or_else(|| {
            app.link
                .ssid_restricted
                .then(|| "SSID hidden by macOS".into())
        })
        .unwrap_or_default();
    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                format!("{:<10} ", overview_status_label(app)),
                Style::default()
                    .fg(health_color(diagnosis.health))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                compact_diagnosis_summary(app, &diagnosis, area.width),
                Style::default().fg(INK),
            ),
        ]),
        compact_local_path_line(app, area.width, &ssid),
    ];
    if diagnosis.context_is_salient {
        lines.push(Line::from(Span::styled(
            fit(
                &diagnosis.compact_context,
                usize::from(area.width.saturating_sub(2)),
            ),
            Style::default().fg(INK),
        )));
    } else {
        lines.push(compact_coverage_line(app, area.width));
    }
    if app.probe_policy().is_active() {
        lines.push(gateway_summary_line(app, area.width));
    } else {
        lines.push(compact_workload_line(app, area.width));
    }
    if diagnosis.context_is_salient {
        lines.push(compact_coverage_line(app, area.width));
    }
    lines.push(Line::from(vec![
        Span::styled("context   ", Style::default().fg(MUTED)),
        Span::styled(
            fit(
                &network_configuration_summary(app),
                usize::from(area.width.saturating_sub(12)),
            ),
            Style::default().fg(INK),
        ),
    ]));
    lines.push(Line::from(Span::styled(
        diagnosis.action,
        Style::default().fg(ACCENT),
    )));
    if app.probe_policy().is_active() {
        lines.extend(app.probes.iter().map(|probe| {
            let latency = probe
                .latency_ms
                .map(|value| format!("{value:>5.0} ms"))
                .unwrap_or_else(|| "      —".into());
            let age = app
                .probe_age(probe.kind)
                .map(freshness)
                .unwrap_or_else(|| "pending".into());
            Line::from(vec![
                Span::styled(
                    format!("{:<10} ", probe.health.label()),
                    Style::default().fg(health_color(probe.health)),
                ),
                Span::styled(
                    format!("{:<13}", probe.kind.label()),
                    Style::default().fg(INK),
                ),
                Span::styled(latency, Style::default().fg(MUTED)),
                Span::styled(format!("  {age:>7}"), Style::default().fg(MUTED)),
                Span::styled(format!("  {}", probe.detail), Style::default().fg(MUTED)),
            ])
        }));
    }
    lines.push(compact_telemetry_line(app));
    let available = chunks[1].height.saturating_sub(2) as usize;
    if lines.len() < available {
        let event_count = available - lines.len();
        lines.extend(app.events.iter().rev().take(event_count).map(|event| {
            Line::from(vec![
                Span::styled(
                    format!("+{} ", format_duration(event.elapsed)),
                    Style::default().fg(MUTED),
                ),
                Span::styled("▌ ", Style::default().fg(health_color(event.health))),
                Span::styled(event.message.as_str(), Style::default().fg(INK)),
            ])
        }));
    }
    frame.render_widget(
        Paragraph::new(lines).block(instrument_block(" OPERATOR SUMMARY ")),
        chunks[1],
    );
    render_footer(frame, chunks[2], app, MonitorMode::Overview, can_navigate);
}

fn compact_workload_line(app: &App, width: u16) -> Line<'static> {
    let summary = app.workload.processes.first().map_or_else(
        || workload_summary(app),
        |process| {
            let process_label = format!(
                "{}{}",
                process.process,
                if process.processes > 1 {
                    format!("×{}", process.processes)
                } else {
                    String::new()
                }
            );
            format!(
                "{} rx {} tx {} /{}s",
                fit(&process_label, 16),
                compact_rate(process.received_bytes_per_second as f64 * 8.0),
                compact_rate(process.transmitted_bytes_per_second as f64 * 8.0),
                app.workload.interval.as_secs()
            )
        },
    );
    Line::from(vec![
        Span::styled("process   ", Style::default().fg(MUTED)),
        Span::styled(
            fit(&summary, usize::from(width.saturating_sub(12))),
            Style::default().fg(INK),
        ),
    ])
}

fn compact_rate(bits_per_second: f64) -> String {
    if bits_per_second < 1_000.0 {
        format!("{bits_per_second:.0}bit/s")
    } else if bits_per_second < 1_000_000.0 {
        format!("{:.2}Kbit/s", bits_per_second / 1_000.0)
    } else if bits_per_second < 1_000_000_000.0 {
        format!("{:.2}Mbit/s", bits_per_second / 1_000_000.0)
    } else {
        format!("{:.2}Gbit/s", bits_per_second / 1_000_000_000.0)
    }
}

fn compact_diagnosis_summary(app: &App, diagnosis: &OverviewDiagnosis, width: u16) -> String {
    if width >= 76 {
        return diagnosis.summary.clone();
    }
    let summary = match app.situation().kind {
        SituationKind::PassiveObservation => {
            "default route observed; end-to-end reachability untested".into()
        }
        SituationKind::GatewayLoss => {
            let metrics = app
                .gateway_assessment_metrics()
                .expect("gateway loss situation has metrics");
            format!(
                "gateway loss {:.0}% / n{}",
                metrics.loss_rate.unwrap_or_default() * 100.0,
                metrics.sent
            )
        }
        SituationKind::GatewayVariation => {
            let metrics = app
                .gateway_assessment_metrics()
                .expect("gateway variation situation has metrics");
            format!(
                "gateway unstable: p50 {} / p95 {} / n{}",
                human_ms(metrics.rtt_p50_ms),
                human_ms(metrics.rtt_p95_ms),
                metrics.sent
            )
        }
        SituationKind::SlowDns => {
            let probe = app.probe_view(ProbeKind::Dns);
            format!("DNS slow: {} / limit 500ms", human_ms(probe.latency_ms))
        }
        SituationKind::SlowHttps => {
            let probe = app.probe_view(ProbeKind::Https);
            format!("HTTPS slow: {} / limit 1000ms", human_ms(probe.latency_ms))
        }
        SituationKind::StalePathEvidence => "core path evidence stale; r refreshes".into(),
        SituationKind::WarmingBaseline => format!(
            "warming next-hop {}/{}; core passed",
            app.gateway_attempts,
            crate::model::MIN_GATEWAY_ASSESSMENT_SAMPLES
        ),
        SituationKind::Ready => "core path checks passed".into(),
        SituationKind::EvidenceGap if diagnosis.health == Health::Ok => {
            "path works; supporting evidence partial".into()
        }
        _ => diagnosis.summary.clone(),
    };
    fit(&summary, usize::from(width.saturating_sub(13)))
}

fn compact_local_path_line<'a>(app: &'a App, width: u16, ssid: &str) -> Line<'a> {
    let interface = app.link.interface.as_deref().unwrap_or("interface?");
    let link_type = app.link.link_type.as_deref().unwrap_or("link?");
    let gateway = app.link.gateway.as_deref().unwrap_or("gateway?");
    if width < 88 {
        let network = if ssid.is_empty() {
            link_type.to_owned()
        } else if ssid == "SSID hidden by macOS" {
            format!("{link_type} / SSID hidden")
        } else {
            format!("{link_type} / {ssid}")
        };
        let summary = format!(
            "g{} {interface} [{network}] → gw {gateway}",
            app.path_generation
        );
        return Line::from(vec![
            Span::styled("path      ", Style::default().fg(MUTED)),
            Span::styled(
                fit(&summary, usize::from(width.saturating_sub(12))),
                Style::default().fg(INK),
            ),
        ]);
    }
    let network = if ssid.is_empty() {
        link_type.to_owned()
    } else {
        format!("{link_type} / {ssid}")
    };
    Line::from(vec![
        Span::styled(
            format!("local g{:<2} ", app.path_generation),
            Style::default().fg(MUTED),
        ),
        Span::styled(app.link.host.as_str(), Style::default().fg(INK)),
        Span::styled(" → ", Style::default().fg(GRID)),
        Span::styled(
            format!("{interface} [{network}]"),
            Style::default().fg(ACCENT),
        ),
        Span::styled(" → ", Style::default().fg(GRID)),
        Span::styled(gateway, Style::default().fg(INK)),
    ])
}

fn compact_coverage_line(app: &App, width: u16) -> Line<'static> {
    let peer_summary = app.peer_dwell_summary();
    let cache = if app.peers.health == Health::Queued {
        "cache pending".into()
    } else {
        format!(
            "cache {}/{}",
            peer_summary.current,
            peer_summary.observed.max(peer_summary.current)
        )
    };
    let probes = if app.probe_policy().is_active() {
        let settled = ProbeKind::PATH
            .iter()
            .map(|kind| app.probe_view(*kind))
            .filter(|probe| !matches!(probe.health, Health::Queued | Health::Running))
            .count();
        format!("core {settled}/{}", ProbeKind::PATH.len())
    } else {
        "probes off".into()
    };
    let history = app.history_context.as_ref().map(|history| {
        if history.kind.is_limited() {
            "history limited"
        } else {
            "history"
        }
    });
    let mut summary = format!(
        "coverage {} · {cache} · {probes}",
        app.evidence_coverage().label()
    );
    if let Some(history) = history {
        summary.push_str(&format!(" · {history}"));
    }
    Line::from(Span::styled(
        fit(&summary, usize::from(width.saturating_sub(2))),
        Style::default().fg(MUTED),
    ))
}

fn gateway_summary_line(app: &App, width: u16) -> Line<'_> {
    if !app.probe_policy().is_active() {
        return Line::from(vec![
            Span::styled("next hop  ", Style::default().fg(MUTED)),
            Span::styled(
                if width < 70 {
                    "RTT untested · active probes off"
                } else {
                    "reachability and RTT untested · [a] enables active probes"
                },
                Style::default().fg(INK),
            ),
        ]);
    }
    if let Some(metrics) = &app.gateway_metrics {
        if width < 70 {
            return Line::from(vec![
                Span::styled("next hop  ", Style::default().fg(MUTED)),
                Span::styled(
                    format!(
                        "p50 {}  p95 {}  mean|ΔRTT| {}  loss {}  n={}",
                        human_ms(metrics.rtt_p50_ms),
                        human_ms(metrics.rtt_p95_ms),
                        human_ms(metrics.mean_abs_adjacent_rtt_delta_ms),
                        metrics
                            .loss_rate
                            .map(|value| format!("{:.0}%", value * 100.0))
                            .unwrap_or_else(|| "?".into()),
                        metrics.sent,
                    ),
                    Style::default().fg(INK),
                ),
            ]);
        }
        Line::from(vec![
            Span::styled("next hop  ", Style::default().fg(MUTED)),
            Span::styled(
                format!(
                    "p50 {}  p95 {}  mean|ΔRTT| {}  loss {} / {} probes  trend {}",
                    human_ms(metrics.rtt_p50_ms),
                    human_ms(metrics.rtt_p95_ms),
                    human_ms(metrics.mean_abs_adjacent_rtt_delta_ms),
                    metrics
                        .loss_rate
                        .map(|value| format!("{:.0}%", value * 100.0))
                        .unwrap_or_else(|| "?".into()),
                    metrics.sent,
                    latency_trend(app)
                ),
                Style::default().fg(INK),
            ),
        ])
    } else {
        Line::from(vec![
            Span::styled("next hop  ", Style::default().fg(MUTED)),
            Span::styled("waiting for latency samples", Style::default().fg(INK)),
        ])
    }
}

fn latency_trend(app: &App) -> String {
    let samples: Vec<_> = app
        .gateway_samples
        .iter()
        .rev()
        .take(12)
        .rev()
        .copied()
        .collect();
    let Some(maximum) = samples.iter().copied().max() else {
        return "pending".into();
    };
    if samples.len() == 1 {
        return "1 sample".into();
    }
    const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    samples
        .into_iter()
        .map(|sample| {
            let level = sample.saturating_mul(7).checked_div(maximum).unwrap_or(0) as usize;
            BARS[level.min(BARS.len() - 1)]
        })
        .collect()
}

fn compact_telemetry_line(app: &App) -> Line<'_> {
    let radio = app.link.wifi.as_ref().map_or_else(
        || "radio not observed".into(),
        |wifi| {
            format!(
                "radio {} / ch {}",
                wifi.signal_dbm
                    .map(|value| format!("{value:.0} dBm"))
                    .or_else(|| wifi.signal_percent.map(|value| format!("{value:.0}%")))
                    .unwrap_or_else(|| "?".into()),
                wifi.channel
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "?".into())
            )
        },
    );
    let traffic = app.interface_rate.as_ref().map_or_else(
        || "traffic sampling…".into(),
        |rate| {
            format!(
                "rx {} / tx {}",
                crate::speed::human_rate(Some(rate.received_bits_per_second)),
                crate::speed::human_rate(Some(rate.transmitted_bits_per_second))
            )
        },
    );
    Line::from(vec![
        Span::styled("link      ", Style::default().fg(MUTED)),
        Span::styled(format!("{radio} · {traffic}"), Style::default().fg(INK)),
    ])
}

fn ordered_peers(app: &App) -> Vec<&crate::model::Peer> {
    let mut peers: Vec<_> = app.peers.peers.iter().collect();
    peers.sort_by(|left, right| {
        peer_attention_rank(app, right).cmp(&peer_attention_rank(app, left))
    });
    peers
}

fn peer_attention_rank(app: &App, peer: &Peer) -> u8 {
    if peer.binding_conflict {
        return 110;
    }
    if app.link.gateway.as_deref() == Some(peer.address.as_str()) {
        return 100;
    }
    let dwell = app.peer_dwell(peer);
    if dwell.is_some_and(|dwell| dwell.binding_changes > 0) {
        return 95;
    }
    if matches!(
        peer.state
            .as_deref()
            .map(str::to_ascii_uppercase)
            .as_deref(),
        Some("FAILED" | "INCOMPLETE")
    ) {
        return 90;
    }
    if dwell.is_some_and(|dwell| dwell.cache_returns > 0) {
        return 85;
    }
    if dwell.is_some_and(|dwell| dwell.state_changes > 0) {
        return 80;
    }
    match peer
        .state
        .as_deref()
        .map(str::to_ascii_uppercase)
        .as_deref()
    {
        Some("PROBE" | "DELAY") => 70,
        Some("REACHABLE") => 60,
        _ if dwell.is_some_and(|dwell| dwell.observations == 1) => 50,
        _ => 0,
    }
}

fn peer_attention_label(app: &App, peer: &Peer) -> &'static str {
    if peer.binding_conflict {
        return "source disagreement";
    }
    if app.link.gateway.as_deref() == Some(peer.address.as_str()) {
        return "path gateway";
    }
    let dwell = app.peer_dwell(peer);
    if dwell.is_some_and(|dwell| dwell.binding_changes > 0) {
        return "binding changed";
    }
    if matches!(
        peer.state
            .as_deref()
            .map(str::to_ascii_uppercase)
            .as_deref(),
        Some("FAILED" | "INCOMPLETE")
    ) {
        return "resolution issue";
    }
    if dwell.is_some_and(|dwell| dwell.cache_returns > 0) {
        return "cache returned";
    }
    if dwell.is_some_and(|dwell| dwell.state_changes > 0) {
        return "state changed";
    }
    match peer
        .state
        .as_deref()
        .map(str::to_ascii_uppercase)
        .as_deref()
    {
        Some("PROBE" | "DELAY") => "kernel checking",
        Some("REACHABLE") => "kernel-confirmed",
        _ if dwell.is_some_and(|dwell| dwell.observations == 1) => "first seen this session",
        _ => "cached only",
    }
}

fn peer_session_summary(app: &App) -> String {
    let summary = app.peer_dwell_summary();
    let observed = summary.observed.max(summary.current);
    let mut value = format!("{} cached / {observed} observed", summary.current);
    if summary.changed > 0 {
        value.push_str(&format!(" / {} changed", summary.changed));
    }
    if summary.disappeared > 0 {
        value.push_str(&format!(" / {} cache-absent", summary.disappeared));
    }
    value
}

fn instrument_block<'a>(title: &'a str) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(GRID))
        .title(Span::styled(title, Style::default().fg(MUTED)))
}

fn health_color(health: Health) -> Color {
    match health {
        Health::Ok => OK,
        Health::Degraded => WARN,
        Health::Failed => FAIL,
        Health::Running => ACCENT,
        Health::Queued | Health::Unavailable => MUTED,
    }
}

fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    format!("{:02}:{:02}", seconds / 60, seconds % 60)
}

fn human_ms(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:.0}ms"))
        .unwrap_or_else(|| "?".into())
}

fn human_dbm(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:.0}dBm"))
        .unwrap_or_else(|| "?".into())
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;
    use crate::model::{
        Address, HistoryContext, InterfaceCounters, LinkSnapshot, MonitorUpdate, ProbeKind,
        ProbePolicy, ProbeResult, ProcessTraffic, WifiTelemetry, WorkloadSnapshot,
    };

    #[test]
    fn dashboard_paints_structure_before_network_results_arrive() {
        let app = App::new();
        let backend = TestBackend::new(120, 32);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Overview, 0, true))
            .unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("LINKTOP"));
        assert!(rendered.contains("DIAGNOSIS"));
        assert!(rendered.contains("LOCAL PATH"));
        assert!(rendered.contains("PASSIVE"));
        assert!(rendered.contains("EVIDENCE LEDGER"));
        assert!(rendered.contains("SESSION EVENTS"));
        assert!(!rendered.contains("ACTIVE PROBES / OFF"));
        assert!(rendered.contains("reachability is not tested"));
    }

    #[test]
    fn dashboard_surfaces_path_probe_and_event_details() {
        let mut app = App::with_probe_policy(ProbePolicy::Active);
        app.apply(MonitorUpdate::Link {
            generation: 1,
            snapshot: LinkSnapshot {
                host: "workstation".into(),
                interface: Some("en0".into()),
                link_type: Some("wifi".into()),
                ssid: Some("lab-net".into()),
                ssid_restricted: false,
                wifi: None,
                gateway: Some("192.168.1.1".into()),
                public_ip: None,
                resolvers: vec!["192.168.1.1".into()],
                addresses: vec![Address {
                    interface: "en0".into(),
                    address: "192.168.1.42".into(),
                    family: 4,
                    is_default: true,
                    is_temporary: false,
                }],
                network_configuration: None,
            },
        });
        app.apply(MonitorUpdate::ProbeFinished {
            generation: 1,
            kind: ProbeKind::Gateway,
            result: ProbeResult {
                health: Health::Ok,
                detail: "192.168.1.1 replied".into(),
                latency_ms: Some(4.0),
                metrics: None,
            },
        });

        let backend = TestBackend::new(120, 32);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Overview, 0, true))
            .unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("workstation"));
        assert!(rendered.contains("en0 [wifi / lab-net]"));
        assert!(rendered.contains("192.168.1.1"));
        assert!(rendered.contains("next-hop RTT"));
        assert!(rendered.contains("4 ms"));
        assert!(rendered.contains("now"));
        assert!(rendered.contains("ACTIVE PROBES"));
        assert_eq!(app.gateway_samples.back(), Some(&4));
    }

    #[test]
    fn wide_passive_terminal_uses_evidence_and_events_without_probe_panel_sprawl() {
        let app = App::new();
        let backend = TestBackend::new(160, 26);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Overview, 0, true))
            .unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("DIAGNOSIS"));
        assert!(rendered.contains("EVIDENCE LEDGER"));
        assert!(rendered.contains("neighbor cache pending"));
        assert!(rendered.contains("SESSION EVENTS"));
        assert!(!rendered.contains("SINCE PATH CHANGE"));
        assert!(!rendered.contains("ACTIVE PROBES / OFF"));
        assert!(!rendered.contains("EVIDENCE / ACTIVITY BOUNDARY"));
        assert!(!rendered.contains("LOCAL ADDRESSES"));
    }

    #[test]
    fn shallow_link_view_keeps_operator_evidence_instead_of_wrapped_explanation() {
        let mut app = App::new();
        app.link.interface = Some("en0".into());
        app.link.link_type = Some("wifi".into());
        app.link.ssid = Some("house-wifi".into());
        app.link.gateway = Some("192.168.1.1".into());
        app.link.resolvers = vec!["192.168.1.1".into(), "1.1.1.1".into()];
        app.link.addresses = vec![Address {
            interface: "en0".into(),
            address: "192.168.1.10".into(),
            family: 4,
            is_default: true,
            is_temporary: false,
        }];
        let backend = TestBackend::new(60, 12);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Link, 0, false))
            .unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("LOCAL LINK / PASSIVE ONLY"));
        assert!(rendered.contains("en0 [wifi / house-wifi]"));
        assert!(rendered.contains("address   192.168.1.10"));
        assert!(rendered.contains("resolver  192.168.1.1 +1"));
        assert!(rendered.contains("traffic   sampling"));
        assert!(!rendered.contains("focused local evidence"));
    }

    #[test]
    fn compact_link_view_marks_addresses_that_do_not_fit() {
        let mut app = App::new();
        app.link.interface = Some("en0".into());
        app.link.link_type = Some("wifi".into());
        app.link.ssid = Some("house-wifi".into());
        app.link.gateway = Some("192.168.1.1".into());
        app.link.resolvers = vec!["192.168.1.1".into()];
        app.link.addresses = (1..=5)
            .map(|index| Address {
                interface: "en0".into(),
                address: format!("2001:db8::{index}"),
                family: 6,
                is_default: true,
                is_temporary: index == 1,
            })
            .collect();
        let backend = TestBackend::new(80, 16);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Link, 0, false))
            .unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("LOCAL LINK / OBSERVED STATE"));
        assert!(rendered.contains("OBSERVED"));
        assert!(rendered.contains("more address(es)"));
        assert!(rendered.contains("complete set"));
    }

    #[test]
    fn focused_peers_uses_the_body_for_scrollable_operator_evidence() {
        let mut app = App::new();
        app.link.host = "workstation".into();
        app.link.interface = Some("en0".into());
        app.link.link_type = Some("wifi".into());
        app.link.ssid = Some("operator-net".into());
        app.link.gateway = Some("192.168.1.1".into());
        app.peers = peer_fixture(18);
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Peers, 0, false))
            .unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("NEIGHBOR CACHE / PASSIVE OBSERVATION"));
        assert!(rendered.contains("operator-net"));
        assert!(rendered.contains("cache presence is not liveness"));
        assert!(rendered.contains("192.168.1.1"));
        assert!(rendered.contains("gateway"));
        assert!(rendered.contains("neighbor STALE"));
        assert!(!rendered.contains("neighborSTALE"));
        assert!(!rendered.contains("GATEWAY RTT"));
    }

    #[test]
    fn focused_peers_scroll_offset_changes_the_visible_window() {
        let mut app = App::new();
        app.peers = peer_fixture(24);
        let backend = TestBackend::new(120, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Peers, 12, false))
            .unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("12-24 / 24"));
        assert!(rendered.contains("192.168.1.12"));
        assert!(!rendered.contains("192.168.1.2 "));
    }

    #[test]
    fn focused_peers_names_missing_native_evidence() {
        let mut app = App::new();
        app.peers = peer_fixture(2);
        app.peers.health = Health::Degraded;
        app.peers.failed_sources = vec!["ndp -an".into()];
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Peers, 0, false))
            .unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("missing ndp -an"));
        assert!(rendered.contains("DEGRADED"));
    }

    #[test]
    fn very_shallow_peers_view_keeps_peer_rows_instead_of_context_chrome() {
        let mut app = App::new();
        app.peers = peer_fixture(12);
        let backend = TestBackend::new(80, 12);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Peers, 0, false))
            .unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("PASSIVE NEIGHBORS"));
        assert!(rendered.contains("192.168.1.1"));
        assert!(!rendered.contains("OBSERVATION CONTEXT"));
    }

    #[test]
    fn tight_peers_view_keeps_ipv6_identity_and_attention_semantics() {
        let mut app = App::new();
        app.link.gateway = Some("2001:0db8:0000:0000:0000:0000:0000:0002".into());
        let snapshot = crate::model::PeerSnapshot {
            health: Health::Ok,
            detail: "2 cached peers; no liveness scan".into(),
            sources: vec!["arp -an".into(), "ndp -an".into()],
            failed_sources: Vec::new(),
            oui_source: Some("Wireshark manuf".into()),
            peers: vec![
                Peer {
                    address: "2001:0db8:0000:0000:0000:0000:0000:0002".into(),
                    mac: Some("02:00:5e:10:00:01".into()),
                    interface: Some("en0".into()),
                    state: None,
                    binding_conflict: false,
                    mac_scope: None,
                    registrant: Some("Synthetic Labs".into()),
                },
                Peer {
                    address: "192.0.2.20".into(),
                    mac: Some("02:00:5e:10:00:02".into()),
                    interface: Some("en0".into()),
                    state: Some("REACHABLE".into()),
                    binding_conflict: false,
                    mac_scope: None,
                    registrant: Some("Example Networks".into()),
                },
            ],
        };
        app.apply(MonitorUpdate::Peers {
            generation: 0,
            snapshot: snapshot.clone(),
        });
        app.apply(MonitorUpdate::Peers {
            generation: 0,
            snapshot,
        });

        let backend = TestBackend::new(70, 14);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Peers, 0, false))
            .unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("192.0.2.20"));
        assert!(rendered.contains("REACHABLE · kernel-confirmed"));
        assert!(rendered.contains("Synthetic"));
        assert!(rendered.contains("n=2 last=now"));
        assert!(rendered.contains("1-2 / 2"));
    }

    #[test]
    fn compact_overview_summarizes_peer_evidence_without_inventory_rows() {
        let mut app = App::new();
        app.peers = peer_fixture(30);
        let backend = TestBackend::new(120, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Overview, 0, true))
            .unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("cache 30/30"));
        assert!(!rendered.contains("192.168.1.1"));
    }

    #[test]
    fn wide_passive_overview_tells_the_path_scoped_dwell_story() {
        let app = dwell_overview_fixture();
        let backend = TestBackend::new(160, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Overview, 0, true))
            .unwrap();
        let rendered = buffer_text(terminal.backend());

        assert!(rendered.contains("SINCE PATH CHANGE"));
        assert!(rendered.contains("generation 1"));
        assert!(rendered.contains("n=2 valid=1 reset=0"));
        assert!(rendered.contains("bytes rx=1.0 KB tx=2.0 KB"));
        assert!(rendered.contains("latest rate"));
        assert!(rendered.contains("peak rate"));
        assert!(rendered.contains("RSSI latest -72, worst -72 dBm"));
        assert!(rendered.contains("ch 44 Δ1"), "{rendered}");
        assert!(rendered.contains("n=2 span=00:02"));
        assert!(rendered.contains("sampled windows ≠ session traffic"));
        assert!(rendered.contains("latest codex"));
        assert!(rendered.contains("peak browser"));
        assert!(rendered.contains("≠ liveness"));
    }

    #[test]
    fn passive_dwell_panel_appears_only_when_the_boundary_layout_can_fit_it() {
        let app = dwell_overview_fixture();
        for height in [25, 26, 27] {
            let backend = TestBackend::new(120, height);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal
                .draw(|frame| render(frame, &app, MonitorMode::Overview, 0, true))
                .unwrap();
            let rendered = buffer_text(terminal.backend());
            assert!(rendered.contains("DIAGNOSIS"), "{height}\n{rendered}");
            assert!(rendered.contains("EVIDENCE LEDGER"), "{height}\n{rendered}");
            assert!(rendered.contains("SESSION EVENTS"), "{height}\n{rendered}");
            assert!(
                !rendered.contains("SINCE PATH CHANGE"),
                "{height}\n{rendered}"
            );
            assert!(!rendered.contains("latest rate"), "{height}\n{rendered}");
        }

        let backend = TestBackend::new(120, 28);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Overview, 0, true))
            .unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("SINCE PATH CHANGE"), "{rendered}");
        assert!(rendered.contains("processes"), "{rendered}");
        assert!(rendered.contains("SESSION EVENTS"), "{rendered}");
    }

    #[test]
    fn fresh_workload_dwell_is_not_presented_as_latest_equals_peak() {
        let app = App::new();
        let backend = TestBackend::new(160, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Overview, 0, true))
            .unwrap();
        let rendered = buffer_text(terminal.backend());

        assert!(rendered.contains("not sampled; no successful workload window"));
        assert!(!rendered.contains("latest=peak none"));
    }

    #[test]
    fn wide_active_overview_keeps_causal_probes_and_passive_path_dwell() {
        let mut app = dwell_overview_fixture();
        app.set_probe_policy(ProbePolicy::Active);
        app.apply(MonitorUpdate::ProbeFinished {
            generation: 1,
            kind: ProbeKind::Gateway,
            result: ProbeResult {
                health: Health::Ok,
                detail: "gateway replied".into(),
                latency_ms: Some(4.0),
                metrics: None,
            },
        });
        let backend = TestBackend::new(160, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Overview, 0, true))
            .unwrap();
        let rendered = buffer_text(terminal.backend());

        assert!(rendered.contains("NEXT-HOP RTT"), "{rendered}");
        assert!(rendered.contains("ACTIVE PROBES"), "{rendered}");
        assert!(rendered.contains("next-hop RTT"), "{rendered}");
        assert!(
            rendered.contains("PATH DWELL / PASSIVE SOURCES"),
            "{rendered}"
        );
        assert!(rendered.contains("interface"), "{rendered}");
        assert!(rendered.contains("workload"), "{rendered}");
        assert!(rendered.contains("neighbors"), "{rendered}");
    }

    #[test]
    fn active_boundary_layout_defers_dwell_until_all_compact_rows_fit() {
        let mut app = dwell_overview_fixture();
        app.set_probe_policy(ProbePolicy::Active);
        for height in [25, 26, 27] {
            let backend = TestBackend::new(120, height);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal
                .draw(|frame| render(frame, &app, MonitorMode::Overview, 0, true))
                .unwrap();
            let rendered = buffer_text(terminal.backend());
            assert!(rendered.contains("ACTIVE PROBES"), "{height}\n{rendered}");
            assert!(
                rendered.contains("EVIDENCE / ACTIVITY BOUNDARY"),
                "{height}\n{rendered}"
            );
            assert!(
                !rendered.contains("PATH DWELL / PASSIVE SOURCES"),
                "{height}\n{rendered}"
            );
        }

        let backend = TestBackend::new(120, 28);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Overview, 0, true))
            .unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("ACTIVE PROBES"), "{rendered}");
        assert!(
            rendered.contains("PATH DWELL / PASSIVE SOURCES"),
            "{rendered}"
        );
        assert!(rendered.contains("neighbors"), "{rendered}");
    }

    #[test]
    fn normal_overview_keeps_operator_priority_without_dwell_detail() {
        let app = dwell_overview_fixture();
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Overview, 0, true))
            .unwrap();
        let rendered = buffer_text(terminal.backend());

        assert!(rendered.contains("DIAGNOSIS"));
        assert!(rendered.contains("workstation ──▶ en0"));
        assert!(rendered.contains("coverage"));
        assert!(rendered.contains("next:"));
        assert!(!rendered.contains("SINCE PATH CHANGE"));
        assert!(!rendered.contains("sampled windows ≠ session traffic"));
    }

    #[test]
    fn tight_overview_keeps_diagnosis_path_coverage_and_action_without_dwell_detail() {
        let app = dwell_overview_fixture();
        let backend = TestBackend::new(70, 14);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Overview, 0, true))
            .unwrap();
        let rendered = buffer_text(terminal.backend());

        assert!(
            rendered.contains("local interface counters increased"),
            "{rendered}"
        );
        assert!(rendered.contains("path"));
        assert!(rendered.contains("en0 [wifi / house]"));
        assert!(rendered.contains("coverage"));
        assert!(rendered.contains("next:"));
        assert!(!rendered.contains("SINCE PATH CHANGE"));
        assert!(!rendered.contains("latest rate"));
    }

    #[test]
    fn ten_row_overview_keeps_network_identity_evidence_and_navigation() {
        let mut app = App::new();
        app.link.interface = Some("en0".into());
        app.link.link_type = Some("wifi".into());
        app.link.ssid = Some("house-wifi".into());
        app.link.gateway = Some("192.168.1.1".into());
        let backend = TestBackend::new(60, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Overview, 0, true))
            .unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("OVERVIEW"));
        assert!(rendered.contains("en0 [wifi / house-wifi]"));
        assert!(rendered.contains("gw 192.168.1.1"));
        assert!(rendered.contains("coverage"));
        assert!(rendered.contains("process"));
        assert!(rendered.contains("probes:off"));
        assert!(rendered.contains("1/2/3"));
        assert!(rendered.contains("LIVE"));
    }

    #[test]
    fn overview_explains_the_threshold_that_caused_degradation() {
        let mut app = App::with_probe_policy(ProbePolicy::Active);
        app.apply(MonitorUpdate::ProbeFinished {
            generation: 0,
            kind: ProbeKind::Gateway,
            result: ProbeResult {
                health: Health::Ok,
                detail: "gateway replied".into(),
                latency_ms: Some(4.0),
                metrics: None,
            },
        });
        app.apply(MonitorUpdate::ProbeFinished {
            generation: 0,
            kind: ProbeKind::Dns,
            result: ProbeResult {
                health: Health::Degraded,
                detail: "example.com → 4 address(es)".into(),
                latency_ms: Some(612.0),
                metrics: None,
            },
        });
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Overview, 0, true))
            .unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("DNS lookup took 612 ms; degraded at 500 ms"));
        assert!(rendered.contains("core 2/3"));
    }

    #[test]
    fn overview_names_a_wifi_route_settling_window() {
        let mut app = App::new();
        app.apply(MonitorUpdate::Link {
            generation: 1,
            snapshot: LinkSnapshot {
                interface: Some("en0".into()),
                gateway: Some("192.168.1.1".into()),
                ..LinkSnapshot::empty()
            },
        });
        app.apply(MonitorUpdate::PathSettling { generation: 1 });
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Overview, 0, true))
            .unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("switching networks; retaining the last confirmed path"));
        assert!(rendered.contains("allow the default route to settle"));
    }

    #[test]
    fn overview_promotes_the_last_network_transition() {
        let mut app = App::new();
        app.apply(MonitorUpdate::Link {
            generation: 1,
            snapshot: LinkSnapshot {
                host: "workstation".into(),
                interface: Some("en0".into()),
                link_type: Some("wifi".into()),
                ssid: Some("house".into()),
                gateway: Some("192.168.1.1".into()),
                resolvers: vec!["192.168.1.1".into()],
                ..LinkSnapshot::empty()
            },
        });
        app.apply(MonitorUpdate::Link {
            generation: 2,
            snapshot: LinkSnapshot {
                host: "workstation".into(),
                interface: Some("en0".into()),
                link_type: Some("wifi".into()),
                ssid: Some("phone-hotspot".into()),
                gateway: Some("172.20.10.1".into()),
                resolvers: vec!["172.20.10.1".into()],
                ..LinkSnapshot::empty()
            },
        });
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Overview, 0, true))
            .unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("change"));
        assert!(rendered.contains("SSID, gateway, resolvers"));
        assert!(rendered.contains("house"));
        assert!(rendered.contains("phone-hotspot"));
    }

    #[test]
    fn overview_promotes_prior_context_without_inventing_a_place() {
        let mut app = App::new();
        app.apply(MonitorUpdate::Link {
            generation: 1,
            snapshot: LinkSnapshot {
                host: "workstation".into(),
                interface: Some("en0".into()),
                link_type: Some("wifi".into()),
                gateway: Some("192.0.2.1".into()),
                ..LinkSnapshot::empty()
            },
        });
        app.history_context = Some(HistoryContext {
            kind: crate::model::HistoryContextKind::Recurring,
            summary: "recurring network context · 3 prior observations".into(),
            compact_summary: "recurring · 3 prior · 2m · BSSID hidden · place unknown".into(),
            context_anchor: "gateway link binding observed".into(),
            place_authority: "unknown · assertion source not configured".into(),
            evidence: "netmon host-path v0 · context anchor: gateway link binding observed · place unknown; assertion source not configured".into(),
        });
        for (width, height) in [(160, 30), (100, 24), (70, 14)] {
            let backend = TestBackend::new(width, height);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal
                .draw(|frame| render(frame, &app, MonitorMode::Overview, 0, true))
                .unwrap();
            let rendered = buffer_text(terminal.backend());
            assert!(rendered.contains("recurring"));
            if width >= 120 {
                assert!(rendered.contains("recurring network context"));
                assert!(rendered.contains("gateway link binding observed"));
                assert!(rendered.contains("assertion source not configured"));
            } else {
                assert!(rendered.contains("place unknown"));
            }
            assert!(!rendered.contains("location:"));
        }
        assert!(overview_diagnosis(&app).context_is_salient);
    }

    #[test]
    fn overview_marks_history_limitations_from_typed_state_not_prose() {
        let mut app = App::new();
        app.history_context = Some(HistoryContext {
            kind: crate::model::HistoryContextKind::Unavailable,
            summary: "archive could not be read".into(),
            compact_summary: "unavailable · live diagnosis unaffected".into(),
            context_anchor: "unavailable".into(),
            place_authority: "unknown · history unavailable".into(),
            evidence: "current diagnosis unaffected".into(),
        });

        let diagnosis = overview_diagnosis(&app);

        assert!(diagnosis.coverage.contains("history cited/limited"));
    }

    #[test]
    fn compact_passive_overview_promotes_the_busiest_process() {
        let mut app = App::new();
        app.workload = WorkloadSnapshot {
            health: Health::Ok,
            detail: "1 process group".into(),
            source: Some("nettop external-interface deltas".into()),
            interval: Duration::from_secs(1),
            processes: vec![ProcessTraffic {
                process: "codex".into(),
                processes: 2,
                received_bytes_per_second: 4_096,
                transmitted_bytes_per_second: 2_048,
            }],
        };
        let backend = TestBackend::new(60, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Overview, 0, true))
            .unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("process"));
        assert!(rendered.contains("codex×2"));
        assert!(rendered.contains("rx 32.77Kbit/s"));
        assert!(rendered.contains("/1s"));
    }

    #[test]
    fn ipv4_prefix_rejects_non_contiguous_masks() {
        assert_eq!(ipv4_mask_prefix("255.255.255.0"), Some(24));
        assert_eq!(ipv4_mask_prefix("255.255.0.0"), Some(16));
        assert_eq!(ipv4_mask_prefix("255.0.255.0"), None);
        assert_eq!(ipv4_mask_prefix("255.255.255"), None);
    }

    #[test]
    fn lease_window_preserves_day_rollover() {
        assert_eq!(
            lease_window("07/25/2026 20:04:21", "07/26/2026 20:04:21"),
            "20:04→+1d 20:04"
        );
        assert_eq!(
            lease_window("07/25/2026 20:04:21", "07/25/2026 22:04:21"),
            "20:04→22:04"
        );
    }

    #[test]
    fn overview_separates_local_hops_from_public_identity() {
        let mut app = App::with_probe_policy(ProbePolicy::Active);
        app.link.host = "workstation".into();
        app.link.interface = Some("en0".into());
        app.link.gateway = Some("192.168.1.1".into());
        app.apply(MonitorUpdate::ProbeFinished {
            generation: 0,
            kind: ProbeKind::PublicIp,
            result: ProbeResult {
                health: Health::Ok,
                detail: "203.0.113.10".into(),
                latency_ms: Some(80.0),
                metrics: None,
            },
        });
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Overview, 0, true))
            .unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("workstation ──▶ en0"));
        assert!(rendered.contains("public egress"));
        assert!(rendered.contains("203.0.113.10"));
    }

    #[test]
    fn overview_session_exposes_in_process_view_navigation() {
        let app = App::new();
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Overview, 0, true))
            .unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("1/2/3"));
        assert!(rendered.contains("Tab"));

        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Link, 0, true))
            .unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("LOCAL LINK / PASSIVE OBSERVATION"));
        assert!(rendered.contains("1/2/3"));
    }

    #[test]
    fn peers_view_surfaces_generation_scoped_dwell_evidence() {
        let mut app = App::new();
        let first = peer_fixture(1);
        app.apply(MonitorUpdate::Peers {
            generation: 0,
            snapshot: first.clone(),
        });
        let mut changed = first;
        changed.peers[0].state = Some("REACHABLE".into());
        app.apply(MonitorUpdate::Peers {
            generation: 0,
            snapshot: changed,
        });

        let backend = TestBackend::new(120, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Peers, 0, false))
            .unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("1 cached / 1 observed / 1 changed"));
        assert!(rendered.contains("n=2"));
        assert!(rendered.contains("Δ1"));
    }

    #[test]
    fn peers_rank_changed_bindings_ahead_of_stable_cache_rows() {
        let mut app = App::new();
        let first = peer_fixture(3);
        app.apply(MonitorUpdate::Peers {
            generation: 0,
            snapshot: first.clone(),
        });
        let mut changed = first;
        changed.peers[2].mac = Some("02:00:00:00:ff:ff".into());
        app.apply(MonitorUpdate::Peers {
            generation: 0,
            snapshot: changed,
        });

        let ordered = ordered_peers(&app);
        assert_eq!(ordered[0].address, "192.168.1.3");
        assert_eq!(peer_attention_label(&app, ordered[0]), "binding changed");
        assert_eq!(peer_attention_label(&app, ordered[1]), "cached only");
    }

    #[test]
    fn peers_rank_same_snapshot_source_disagreement_without_claiming_churn() {
        let mut app = App::new();
        app.peers = peer_fixture(3);
        app.peers.peers[1].mac = None;
        app.peers.peers[1].binding_conflict = true;

        let ordered = ordered_peers(&app);
        assert_eq!(ordered[0].address, "192.168.1.2");
        assert_eq!(
            peer_attention_label(&app, ordered[0]),
            "source disagreement"
        );
        assert_eq!(peer_mac_label(ordered[0]), "source conflict");
    }

    fn peer_fixture(count: usize) -> crate::model::PeerSnapshot {
        crate::model::PeerSnapshot {
            health: Health::Ok,
            detail: format!("{count} cached peer(s); no liveness scan"),
            sources: vec!["arp -an".into(), "ndp -an".into()],
            failed_sources: Vec::new(),
            oui_source: Some("Wireshark manuf".into()),
            peers: (1..=count)
                .map(|index| crate::model::Peer {
                    address: format!("192.168.1.{index}"),
                    mac: Some(format!("02:00:00:00:00:{index:02x}")),
                    interface: Some("en0".into()),
                    state: Some("STALE".into()),
                    binding_conflict: false,
                    mac_scope: Some(crate::model::MacScope::Local),
                    registrant: None,
                })
                .collect(),
        }
    }

    fn dwell_overview_fixture() -> App {
        let mut app = App::new();
        app.apply(MonitorUpdate::Link {
            generation: 1,
            snapshot: LinkSnapshot {
                host: "workstation".into(),
                interface: Some("en0".into()),
                link_type: Some("wifi".into()),
                ssid: Some("house".into()),
                gateway: Some("192.168.1.1".into()),
                resolvers: vec!["192.168.1.1".into()],
                ..LinkSnapshot::empty()
            },
        });
        let counters =
            |received_bytes, transmitted_bytes, received_packets, transmitted_packets| {
                InterfaceCounters {
                    interface: "en0".into(),
                    received_bytes,
                    transmitted_bytes,
                    received_packets,
                    transmitted_packets,
                    receive_errors: u64::from(received_bytes > 1_000),
                    transmit_errors: 0,
                    drops: u64::from(received_bytes > 1_000),
                }
            };
        app.apply(MonitorUpdate::Traffic {
            generation: 1,
            counters: Some(counters(1_000, 2_000, 10, 20)),
        });
        app.apply(MonitorUpdate::Traffic {
            generation: 1,
            counters: Some(counters(2_000, 4_000, 30, 60)),
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
        for (process, received, transmitted) in [("browser", 8_192, 4_096), ("codex", 4_096, 2_048)]
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
        let peers = peer_fixture(1);
        app.apply(MonitorUpdate::Peers {
            generation: 1,
            snapshot: peers.clone(),
        });
        app.apply(MonitorUpdate::Peers {
            generation: 1,
            snapshot: peers,
        });
        app
    }

    fn buffer_text(backend: &TestBackend) -> String {
        let buffer = backend.buffer();
        let area = buffer.area;
        let mut output = String::new();
        for y in area.y..area.y + area.height {
            for x in area.x..area.x + area.width {
                output.push_str(buffer[(x, y)].symbol());
            }
            output.push('\n');
        }
        output
    }
}
