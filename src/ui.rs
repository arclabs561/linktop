use std::time::Duration;

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::prelude::{Color, Frame, Line, Modifier, Span, Style};
use ratatui::widgets::{Block, Borders, Paragraph, Sparkline, Wrap};

use crate::model::{App, Health};

const INK: Color = Color::Rgb(192, 202, 214);
const MUTED: Color = Color::Rgb(95, 109, 126);
const GRID: Color = Color::Rgb(48, 61, 74);
const ACCENT: Color = Color::Rgb(37, 203, 216);
const OK: Color = Color::Rgb(100, 211, 134);
const WARN: Color = Color::Rgb(242, 190, 70);
const FAIL: Color = Color::Rgb(244, 91, 105);

pub fn render(frame: &mut Frame<'_>, app: &App) {
    let area = frame.area();
    if area.width < 100 || area.height < 24 {
        render_compact(frame, area, app);
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

    render_header(frame, vertical[0], app);
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
    let inventory = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(right[1]);
    render_addresses(frame, inventory[0], app);
    render_peers(frame, inventory[1], app);
    render_footer(frame, vertical[3], app);
}

fn render_header(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let health = app.overall_health();
    let title = Line::from(vec![
        Span::styled(
            " LINKTOP ",
            Style::default()
                .fg(Color::Black)
                .bg(ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("  NETWORK PATH / ACTIVE PROBES", Style::default().fg(INK)),
        Span::raw("  "),
        Span::styled(
            health.label(),
            Style::default()
                .fg(health_color(health))
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(
                "   UP {}   SAMPLES {} ",
                format_duration(app.uptime()),
                app.cycles
            ),
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
                    if address.is_default { " ▶ " } else { "   " },
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
            .block(instrument_block(" LOCAL ADDRESSES "))
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
        ordered_peers(app)
            .take(available)
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
            .collect()
    };
    frame.render_widget(
        Paragraph::new(lines)
            .block(instrument_block(" PASSIVE NEIGHBORS / NO SCAN "))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_footer(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let state = if app.paused { "PAUSED" } else { "LIVE" };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" q ", Style::default().fg(Color::Black).bg(INK)),
            Span::styled(" quit  ", Style::default().fg(MUTED)),
            Span::styled(" r ", Style::default().fg(Color::Black).bg(INK)),
            Span::styled(" refresh  ", Style::default().fg(MUTED)),
            Span::styled(" p ", Style::default().fg(Color::Black).bg(INK)),
            Span::styled(" pause/resume", Style::default().fg(MUTED)),
            Span::styled(
                format!("                                    {state} "),
                Style::default().fg(if app.paused { WARN } else { OK }),
            ),
        ])),
        area,
    );
}

fn render_compact(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .split(area);
    render_header(frame, chunks[0], app);
    let mut lines = vec![Line::from(vec![
        Span::styled(format!("{} ", app.link.host), Style::default().fg(INK)),
        Span::styled("→ ", Style::default().fg(GRID)),
        Span::styled(
            format!(
                "{} [{}] ",
                app.link.interface.as_deref().unwrap_or("interface?"),
                app.link.link_type.as_deref().unwrap_or("link?")
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
    lines.extend(ordered_peers(app).take(remaining).map(|peer| {
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
    frame.render_widget(
        Paragraph::new(lines)
            .block(instrument_block(" LIVE SUMMARY "))
            .wrap(Wrap { trim: true }),
        chunks[1],
    );
    render_footer(frame, chunks[2], app);
}

fn ordered_peers(app: &App) -> impl Iterator<Item = &crate::model::Peer> {
    let gateway = app.link.gateway.as_deref();
    app.peers
        .peers
        .iter()
        .filter(move |peer| gateway == Some(peer.address.as_str()))
        .chain(
            app.peers
                .peers
                .iter()
                .filter(move |peer| gateway != Some(peer.address.as_str())),
        )
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
        terminal.draw(|frame| render(frame, &app)).unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("LINKTOP"));
        assert!(rendered.contains("ACTIVE PATH"));
        assert!(rendered.contains("RUNNING"));
        assert!(rendered.contains("waiting for samples"));
    }

    #[test]
    fn dashboard_surfaces_path_probe_and_event_details() {
        let mut app = App::new();
        app.apply(MonitorUpdate::Link(LinkSnapshot {
            host: "workstation".into(),
            interface: Some("en0".into()),
            link_type: Some("wifi".into()),
            ssid: Some("lab-net".into()),
            wifi: None,
            gateway: Some("192.168.1.1".into()),
            public_ip: None,
            resolvers: vec!["192.168.1.1".into()],
            addresses: vec![Address {
                interface: "en0".into(),
                address: "192.168.1.42".into(),
                family: 4,
                is_default: true,
            }],
        }));
        app.apply(MonitorUpdate::ProbeFinished(
            ProbeKind::Gateway,
            ProbeResult {
                health: Health::Ok,
                detail: "192.168.1.1 replied".into(),
                latency_ms: Some(4.0),
                metrics: None,
            },
        ));

        let backend = TestBackend::new(120, 32);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render(frame, &app)).unwrap();
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
        let backend = TestBackend::new(160, 18);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render(frame, &app)).unwrap();
        let rendered = buffer_text(terminal.backend());
        assert!(rendered.contains("LIVE SUMMARY"));
        assert!(rendered.contains("peers"));
        assert!(!rendered.contains("EVENT BUS"));
        assert!(!rendered.contains("LOCAL ADDRESSES"));
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
