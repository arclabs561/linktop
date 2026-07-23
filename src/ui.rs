use std::time::Duration;

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::prelude::{Color, Frame, Line, Modifier, Span, Style};
use ratatui::widgets::{Block, Borders, Paragraph, Sparkline, Wrap};

use crate::model::{App, Health, MonitorMode, Peer};

const INK: Color = Color::Rgb(192, 202, 214);
const MUTED: Color = Color::Rgb(95, 109, 126);
const GRID: Color = Color::Rgb(48, 61, 74);
const ACCENT: Color = Color::Rgb(37, 203, 216);
const OK: Color = Color::Rgb(100, 211, 134);
const WARN: Color = Color::Rgb(242, 190, 70);
const FAIL: Color = Color::Rgb(244, 91, 105);

pub fn render(frame: &mut Frame<'_>, app: &App, mode: MonitorMode, peer_offset: usize) {
    let area = frame.area();
    match mode {
        MonitorMode::Link => {
            render_link_focus(frame, area, app);
            return;
        }
        MonitorMode::Peers => {
            render_peers_focus(frame, area, app, peer_offset);
            return;
        }
        MonitorMode::Overview => {}
    }
    if area.width < 100 || area.height < 30 {
        render_compact(frame, area, app, mode);
        return;
    }

    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Min(12),
            Constraint::Length(1),
        ])
        .split(area);

    render_header(frame, vertical[0], app, mode);
    render_path(frame, vertical[1], app);

    let main = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(62), Constraint::Percentage(38)])
        .split(vertical[2]);
    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(6)])
        .split(main[0]);
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(6)])
        .split(main[1]);

    render_latency(frame, left[0], app);
    render_events(frame, left[1], app);
    render_probes(frame, right[0], app);
    let address_height = (app.link.addresses.len() as u16 + 2)
        .clamp(3, 7)
        .min(right[1].height.saturating_sub(3));
    let inventory = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(address_height), Constraint::Min(3)])
        .split(right[1]);
    render_addresses(frame, inventory[0], app);
    render_peers(frame, inventory[1], app);
    render_footer(frame, vertical[3], app, mode);
}

fn render_header(frame: &mut Frame<'_>, area: Rect, app: &App, mode: MonitorMode) {
    let (subject, health, measure) = match mode {
        MonitorMode::Overview => (
            "NETWORK PATH / ACTIVE PROBES",
            app.overall_health(),
            format!("SAMPLES {}", app.cycles),
        ),
        MonitorMode::Link => (
            "LOCAL LINK / PASSIVE OBSERVATION",
            if app.link.interface.is_some() {
                Health::Ok
            } else {
                Health::Running
            },
            format!("PATH GEN {}", app.path_generation),
        ),
        MonitorMode::Peers => (
            "NEIGHBOR CACHE / PASSIVE OBSERVATION",
            app.peers.health,
            format!("CACHED {}", app.peers.peers.len()),
        ),
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
            health.label(),
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
    let gateway = app.link.gateway.as_deref().unwrap_or("discovering");
    let public = app.link.public_ip.as_deref().unwrap_or("probing");
    let path = Line::from(vec![
        Span::styled(format!(" {} ", app.link.host), Style::default().fg(INK)),
        Span::styled("──▶", Style::default().fg(GRID)),
        Span::styled(
            format!(" {interface} [{link}{ssid}] "),
            Style::default().fg(ACCENT),
        ),
        Span::styled("──▶", Style::default().fg(GRID)),
        Span::styled(format!(" {gateway} "), Style::default().fg(INK)),
        Span::styled("──▶", Style::default().fg(GRID)),
        Span::styled(format!(" {public} "), Style::default().fg(OK)),
    ]);
    let resolver = app
        .link
        .resolvers
        .first()
        .map(|value| format!("resolver {value}"))
        .unwrap_or_else(|| "resolver unknown".into());
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
        format!("radio {signal} / {channel} / {rate}")
    });
    let traffic = app.interface_rate.as_ref().map(|rate| {
        format!(
            "traffic rx {} / tx {} / errors +{} / drops +{}",
            crate::speed::human_rate(Some(rate.received_bits_per_second)),
            crate::speed::human_rate(Some(rate.transmitted_bits_per_second)),
            rate.error_delta,
            rate.drop_delta
        )
    });
    frame.render_widget(
        Paragraph::new(vec![
            path,
            Line::from(Span::styled(
                format!(
                    "   {resolver}{}",
                    radio.map(|value| format!("   {value}")).unwrap_or_default()
                ),
                Style::default().fg(MUTED),
            )),
            Line::from(Span::styled(
                format!(
                    "   {}",
                    traffic.unwrap_or_else(|| "traffic sampling…".into())
                ),
                Style::default().fg(MUTED),
            )),
        ])
        .block(instrument_block(" ACTIVE PATH ")),
        area,
    );
}

fn render_latency(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let samples: Vec<u64> = app.gateway_samples.iter().copied().collect();
    let latest = samples.last().copied();
    let max = samples.iter().copied().max().unwrap_or(1).max(10);
    let distribution = app.gateway_metrics.as_ref().map(|metrics| {
        format!(
            "p50 {} / p95 {} / jitter {} / loss {}",
            human_ms(metrics.rtt_p50_ms),
            human_ms(metrics.rtt_p95_ms),
            human_ms(metrics.rtt_ipdv_abs_mean_ms),
            metrics
                .loss_rate
                .map(|value| format!("{:.0}%", value * 100.0))
                .unwrap_or_else(|| "?".into())
        )
    });
    let title = match (latest, distribution) {
        (Some(value), Some(distribution)) => {
            format!(" GATEWAY RTT / latest {value} ms / {distribution} / scale {max} ms ")
        }
        (Some(value), None) => format!(" GATEWAY RTT / latest {value} ms / scale {max} ms "),
        (None, _) => " GATEWAY RTT / waiting for samples ".into(),
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
    let lines: Vec<Line<'_>> = app
        .probes
        .iter()
        .map(|probe| {
            let latency = probe
                .latency_ms
                .map(|value| format!("{:>6.0} ms", value))
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
                Span::styled(format!("  {}", probe.detail), Style::default().fg(MUTED)),
            ])
        })
        .collect();
    frame.render_widget(
        Paragraph::new(lines).block(instrument_block(" PROBES ")),
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
            .block(instrument_block(" EVENT BUS "))
            .wrap(Wrap { trim: true }),
        area,
    );
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

fn render_peers(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let available = area.height.saturating_sub(2) as usize;
    let lines: Vec<Line<'_>> = if app.peers.peers.is_empty() {
        vec![Line::from(Span::styled(
            app.peers.detail.as_str(),
            Style::default().fg(MUTED),
        ))]
    } else {
        let peers: Vec<_> = ordered_peers(app).collect();
        let visible = if peers.len() > available {
            available.saturating_sub(1)
        } else {
            available
        };
        let mut lines: Vec<_> = peers
            .iter()
            .take(visible)
            .map(|peer| {
                Line::from(vec![
                    Span::styled(
                        format!(" {:<7}", peer.interface.as_deref().unwrap_or("?")),
                        Style::default().fg(MUTED),
                    ),
                    Span::styled(format!("{:<20}", peer.address), Style::default().fg(INK)),
                    Span::styled(
                        format!("{:<18}", peer.mac.as_deref().unwrap_or("—")),
                        Style::default().fg(MUTED),
                    ),
                    Span::styled(
                        peer.state.as_deref().unwrap_or("cached"),
                        Style::default().fg(MUTED),
                    ),
                    Span::styled(
                        format!(
                            "  {}{}",
                            if app.link.gateway.as_deref() == Some(peer.address.as_str()) {
                                "gateway  "
                            } else {
                                ""
                            },
                            peer.registrant
                                .as_deref()
                                .or_else(|| peer.mac_scope.map(|scope| scope.label()))
                                .unwrap_or("")
                        ),
                        Style::default().fg(MUTED),
                    ),
                ])
            })
            .collect();
        if peers.len() > visible {
            lines.push(Line::from(Span::styled(
                format!(" +{} more — open `linktop peers`", peers.len() - visible),
                Style::default().fg(WARN),
            )));
        }
        lines
    };
    frame.render_widget(
        Paragraph::new(lines)
            .block(instrument_block(" PASSIVE NEIGHBORS / NO SCAN "))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_link_focus(frame: &mut Frame<'_>, area: Rect, app: &App) {
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
        let mut lines = link_identity_lines(app);
        lines.extend(link_telemetry_lines(app));
        lines.push(Line::from(Span::styled(
            "addresses",
            Style::default().fg(MUTED).add_modifier(Modifier::BOLD),
        )));
        lines.extend(app.link.addresses.iter().map(|address| {
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
        }));
        frame.render_widget(
            Paragraph::new(lines)
                .block(instrument_block(" LOCAL LINK / OBSERVED STATE "))
                .wrap(Wrap { trim: true }),
            chunks[1],
        );
        render_footer(frame, chunks[2], app, MonitorMode::Link);
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
    render_footer(frame, chunks[2], app, MonitorMode::Link);
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
        Line::from(Span::styled(
            " full local operator evidence; no Internet probes in this view",
            Style::default().fg(MUTED),
        )),
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

fn render_peers_focus(frame: &mut Frame<'_>, area: Rect, app: &App, peer_offset: usize) {
    if area.height < 16 {
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
        render_footer(frame, chunks[2], app, MonitorMode::Peers);
        return;
    }
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(5),
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
                Span::styled(" semantics ", Style::default().fg(MUTED)),
                Span::styled(
                    "cache presence is not liveness; disappearance is not departure",
                    Style::default().fg(INK),
                ),
            ]),
        ])
        .block(instrument_block(" OBSERVATION CONTEXT "))
        .wrap(Wrap { trim: true }),
        chunks[1],
    );

    render_peer_table(frame, chunks[2], app, peer_offset);
    render_footer(frame, chunks[3], app, MonitorMode::Peers);
}

fn render_peer_table(frame: &mut Frame<'_>, area: Rect, app: &App, peer_offset: usize) {
    let peers: Vec<_> = ordered_peers(app).collect();
    let content_rows = area.height.saturating_sub(2) as usize;
    let wide = area.width >= 104;
    let rows_per_peer = if wide { 1 } else { 2 };
    let header_rows = usize::from(wide && content_rows > 0);
    let capacity = content_rows
        .saturating_sub(header_rows)
        .checked_div(rows_per_peer)
        .unwrap_or(0);
    let offset = peer_offset.min(peers.len().saturating_sub(capacity.max(1)));
    let end = (offset + capacity).min(peers.len());
    let mut lines = Vec::new();

    if wide && content_rows > 0 {
        let address_width = if area.width >= 138 { 39 } else { 28 };
        lines.push(Line::from(Span::styled(
            format!(
                "   {:<7} {:<address_width$} {:<17} {:<11} {:<8} {}",
                "IFACE", "ADDRESS", "MAC", "STATE", "ROLE", "ATTRIBUTION"
            ),
            Style::default().fg(MUTED).add_modifier(Modifier::BOLD),
        )));
        for peer in peers.iter().skip(offset).take(capacity) {
            lines.push(peer_wide_line(peer, app, address_width));
        }
    } else {
        for peer in peers.iter().skip(offset).take(capacity) {
            lines.extend(peer_narrow_lines(peer, app));
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
        Paragraph::new(lines)
            .block(instrument_block(&format!(
                " PASSIVE NEIGHBORS / {range} / NO SCAN "
            )))
            .wrap(Wrap { trim: false }),
        area,
    );
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
            format!("{:<17} ", peer.mac.as_deref().unwrap_or("—")),
            Style::default().fg(MUTED),
        ),
        Span::styled(
            format!("{:<11} ", peer.state.as_deref().unwrap_or("cached")),
            Style::default().fg(MUTED),
        ),
        Span::styled(
            format!("{:<8} ", if gateway { "gateway" } else { "peer" }),
            Style::default().fg(if gateway { ACCENT } else { MUTED }),
        ),
        Span::styled(
            format!(
                "{} / {}",
                peer_attribution(peer),
                peer_state_meaning(peer.state.as_deref())
            ),
            Style::default().fg(INK),
        ),
    ])
}

fn peer_narrow_lines<'a>(peer: &'a Peer, app: &App) -> Vec<Line<'a>> {
    let gateway = app.link.gateway.as_deref() == Some(peer.address.as_str());
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
            Span::styled(peer.address.as_str(), Style::default().fg(INK)),
            Span::styled(
                if gateway { "  gateway" } else { "  peer" },
                Style::default().fg(if gateway { ACCENT } else { MUTED }),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                format!("           {}  ", peer.mac.as_deref().unwrap_or("no MAC")),
                Style::default().fg(MUTED),
            ),
            Span::styled(
                format!("{}  ", peer.state.as_deref().unwrap_or("cached")),
                Style::default().fg(MUTED),
            ),
            Span::styled(
                format!(
                    "{} / {}",
                    peer_attribution(peer),
                    peer_state_meaning(peer.state.as_deref())
                ),
                Style::default().fg(INK),
            ),
        ]),
    ]
}

fn peer_attribution(peer: &Peer) -> &str {
    peer.registrant
        .as_deref()
        .or_else(|| peer.mac_scope.map(|scope| scope.label()))
        .unwrap_or("unattributed")
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

fn render_footer(frame: &mut Frame<'_>, area: Rect, app: &App, mode: MonitorMode) {
    let state = if app.paused { "PAUSED" } else { "LIVE" };
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
    spans.push(Span::styled(
        format!("{state} "),
        Style::default().fg(if app.paused { WARN } else { OK }),
    ));
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn render_compact(frame: &mut Frame<'_>, area: Rect, app: &App, mode: MonitorMode) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .split(area);
    render_header(frame, chunks[0], app, mode);
    let mut lines = vec![Line::from(vec![
        Span::styled(format!("{} ", app.link.host), Style::default().fg(INK)),
        Span::styled("→ ", Style::default().fg(GRID)),
        Span::styled(
            format!(
                "{} [{}{}] ",
                app.link.interface.as_deref().unwrap_or("interface?"),
                app.link.link_type.as_deref().unwrap_or("link?"),
                app.link
                    .ssid
                    .as_deref()
                    .map(|ssid| format!(" / {ssid}"))
                    .or_else(|| {
                        app.link
                            .ssid_restricted
                            .then(|| " / SSID hidden by macOS".into())
                    })
                    .unwrap_or_default()
            ),
            Style::default().fg(ACCENT),
        ),
        Span::styled("→ ", Style::default().fg(GRID)),
        Span::styled(
            app.link.gateway.as_deref().unwrap_or("gateway?"),
            Style::default().fg(INK),
        ),
        Span::styled(" → ", Style::default().fg(GRID)),
        Span::styled(
            app.link.public_ip.as_deref().unwrap_or("public?"),
            Style::default().fg(OK),
        ),
    ])];
    if let Some(wifi) = &app.link.wifi {
        lines.push(Line::from(Span::styled(
            format!(
                "radio  signal {}  channel {}  tx {}",
                wifi.signal_dbm
                    .map(|value| format!("{value:.0} dBm"))
                    .or_else(|| wifi.signal_percent.map(|value| format!("{value:.0}%")))
                    .unwrap_or_else(|| "?".into()),
                wifi.channel
                    .map(|value| value.to_string())
                    .or_else(|| wifi.frequency_mhz.map(|value| format!("{value} MHz")))
                    .unwrap_or_else(|| "?".into()),
                wifi.tx_rate_mbps
                    .map(|value| format!("{value:.0} Mb/s"))
                    .unwrap_or_else(|| "?".into())
            ),
            Style::default().fg(MUTED),
        )));
    }
    if let Some(metrics) = &app.gateway_metrics {
        lines.push(Line::from(vec![
            Span::styled("gateway  ", Style::default().fg(MUTED)),
            Span::styled(
                format!(
                    "p50 {}  p95 {}  jitter {}  loss {}",
                    human_ms(metrics.rtt_p50_ms),
                    human_ms(metrics.rtt_p95_ms),
                    human_ms(metrics.rtt_ipdv_abs_mean_ms),
                    metrics
                        .loss_rate
                        .map(|value| format!("{:.0}%", value * 100.0))
                        .unwrap_or_else(|| "?".into())
                ),
                Style::default().fg(INK),
            ),
        ]));
    }
    if let Some(rate) = &app.interface_rate {
        lines.push(Line::from(Span::styled(
            format!(
                "traffic rx {}  tx {}  errors +{}  drops +{}",
                crate::speed::human_rate(Some(rate.received_bits_per_second)),
                crate::speed::human_rate(Some(rate.transmitted_bits_per_second)),
                rate.error_delta,
                rate.drop_delta
            ),
            Style::default().fg(MUTED),
        )));
    }
    lines.extend(app.probes.iter().map(|probe| {
        Line::from(vec![
            Span::styled(
                format!("{:<10} ", probe.health.label()),
                Style::default().fg(health_color(probe.health)),
            ),
            Span::styled(probe.kind.label(), Style::default().fg(INK)),
            Span::styled(format!("  {}", probe.detail), Style::default().fg(MUTED)),
        ])
    }));
    lines.push(Line::from(vec![
        Span::styled("peers    ", Style::default().fg(MUTED)),
        Span::styled(app.peers.detail.as_str(), Style::default().fg(INK)),
    ]));
    let remaining = chunks[1]
        .height
        .saturating_sub(2)
        .saturating_sub(lines.len() as u16) as usize;
    let peers: Vec<_> = ordered_peers(app).collect();
    let visible = if peers.len() > remaining {
        remaining.saturating_sub(1)
    } else {
        remaining
    };
    lines.extend(peers.iter().take(visible).map(|peer| {
        Line::from(vec![
            Span::styled(
                format!("         {:<7}", peer.interface.as_deref().unwrap_or("?")),
                Style::default().fg(MUTED),
            ),
            Span::styled(peer.address.as_str(), Style::default().fg(INK)),
            Span::styled(
                format!("  {}", peer.mac.as_deref().unwrap_or("—")),
                Style::default().fg(MUTED),
            ),
            Span::styled(
                format!(
                    "  {}{}",
                    if app.link.gateway.as_deref() == Some(peer.address.as_str()) {
                        "gateway  "
                    } else {
                        ""
                    },
                    peer.registrant
                        .as_deref()
                        .or_else(|| peer.mac_scope.map(|scope| scope.label()))
                        .unwrap_or("")
                ),
                Style::default().fg(MUTED),
            ),
        ])
    }));
    if peers.len() > visible && remaining > 0 {
        lines.push(Line::from(Span::styled(
            format!("         +{} more — `linktop peers`", peers.len() - visible),
            Style::default().fg(WARN),
        )));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(instrument_block(" LIVE SUMMARY "))
            .wrap(Wrap { trim: false }),
        chunks[1],
    );
    render_footer(frame, chunks[2], app, mode);
}

fn ordered_peers(app: &App) -> impl Iterator<Item = &crate::model::Peer> {
    let gateway = app.link.gateway.as_deref();
    let default_interface = app.link.interface.as_deref();
    app.peers
        .peers
        .iter()
        .filter(move |peer| gateway == Some(peer.address.as_str()))
        .chain(app.peers.peers.iter().filter(move |peer| {
            gateway != Some(peer.address.as_str()) && peer.interface.as_deref() == default_interface
        }))
        .chain(app.peers.peers.iter().filter(move |peer| {
            gateway != Some(peer.address.as_str()) && peer.interface.as_deref() != default_interface
        }))
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

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;
    use crate::model::{Address, LinkSnapshot, MonitorUpdate, ProbeKind, ProbeResult};

    #[test]
    fn dashboard_paints_structure_before_network_results_arrive() {
        let app = App::new();
        let backend = TestBackend::new(120, 32);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Overview, 0))
            .unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("LINKTOP"));
        assert!(rendered.contains("ACTIVE PATH"));
        assert!(rendered.contains("RUNNING"));
        assert!(rendered.contains("waiting for samples"));
    }

    #[test]
    fn dashboard_surfaces_path_probe_and_event_details() {
        let mut app = App::new();
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
            .draw(|frame| render(frame, &app, MonitorMode::Overview, 0))
            .unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("workstation"));
        assert!(rendered.contains("en0 [wifi / lab-net]"));
        assert!(rendered.contains("192.168.1.1"));
        assert!(rendered.contains("gateway RTT"));
        assert!(rendered.contains("4 ms"));
        assert_eq!(app.gateway_samples.back(), Some(&4));
    }

    #[test]
    fn short_terminal_uses_dense_summary_instead_of_squashed_panels() {
        let app = App::new();
        let backend = TestBackend::new(160, 26);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Overview, 0))
            .unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("LIVE SUMMARY"));
        assert!(rendered.contains("peers"));
        assert!(!rendered.contains("EVENT BUS"));
        assert!(!rendered.contains("LOCAL ADDRESSES"));
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
            .draw(|frame| render(frame, &app, MonitorMode::Peers, 0))
            .unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("NEIGHBOR CACHE / PASSIVE OBSERVATION"));
        assert!(rendered.contains("operator-net"));
        assert!(rendered.contains("cache presence is not liveness"));
        assert!(rendered.contains("192.168.1.1"));
        assert!(rendered.contains("gateway"));
        assert!(!rendered.contains("GATEWAY RTT"));
    }

    #[test]
    fn focused_peers_scroll_offset_changes_the_visible_window() {
        let mut app = App::new();
        app.peers = peer_fixture(24);
        let backend = TestBackend::new(120, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Peers, 12))
            .unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("13-"));
        assert!(rendered.contains("192.168.1.13"));
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
            .draw(|frame| render(frame, &app, MonitorMode::Peers, 0))
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
            .draw(|frame| render(frame, &app, MonitorMode::Peers, 0))
            .unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("PASSIVE NEIGHBORS"));
        assert!(rendered.contains("192.168.1.1"));
        assert!(!rendered.contains("OBSERVATION CONTEXT"));
    }

    #[test]
    fn compact_overview_declares_hidden_peers() {
        let mut app = App::new();
        app.peers = peer_fixture(30);
        let backend = TestBackend::new(120, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &app, MonitorMode::Overview, 0))
            .unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("more — `linktop peers`"));
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
                    mac_scope: Some(crate::model::MacScope::Local),
                    registrant: None,
                })
                .collect(),
        }
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
