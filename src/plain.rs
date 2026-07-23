use std::collections::BTreeMap;
use std::time::Duration;

use chrono::{Local, SecondsFormat};

use crate::model::{App, LinkSnapshot, MonitorUpdate, Peer, PeerSnapshot, ProbeKind};

#[derive(Debug, Clone)]
pub struct PlainState {
    link: LinkSnapshot,
    peers: PeerSnapshot,
}

impl From<&App> for PlainState {
    fn from(app: &App) -> Self {
        Self {
            link: app.link.clone(),
            peers: app.peers.clone(),
        }
    }
}

pub fn format_update(update: &MonitorUpdate, before: &PlainState, app: &App) -> Vec<String> {
    let elapsed = format_elapsed(app.uptime());
    match update {
        MonitorUpdate::Link { snapshot: link, .. } if path_changed(&before.link, link) => {
            path_lines(&elapsed, link)
        }
        MonitorUpdate::Wifi { telemetry: wifi, .. }
            if before.link.wifi.as_ref() != wifi.as_ref() =>
        {
            let Some(wifi) = wifi else {
                return vec![format!(
                    "+{elapsed} radio    unavailable [source: platform link tools]"
                )];
            };
            vec![format!(
                "+{elapsed} radio    signal={} noise={} channel={} tx={} [source: platform link tools]",
                human_dbm(wifi.signal_dbm.or(wifi.signal_percent)),
                human_dbm(wifi.noise_dbm),
                wifi.channel
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "?".into()),
                wifi.tx_rate_mbps
                    .map(|value| format!("{value:.0}Mb/s"))
                    .unwrap_or_else(|| "?".into())
            )]
        }
        MonitorUpdate::Peers { snapshot: peers, .. }
            if before.peers.peers != peers.peers
                || before.peers.health != peers.health
                || before.peers.failed_sources != peers.failed_sources =>
        {
            peer_change_lines(&elapsed, &before.peers, peers, app.link.gateway.as_deref())
        }
        MonitorUpdate::Traffic {
            counters: Some(counters),
            ..
        } => app
            .interface_rate
            .as_ref()
            .map(|rate| {
                vec![format!(
                    "+{elapsed} traffic  interface={} rx={} tx={} packets={:.0}/{:.0}s errors=+{} drops=+{} [source: kernel interface counters]",
                    counters.interface,
                    crate::speed::human_rate(Some(rate.received_bits_per_second)),
                    crate::speed::human_rate(Some(rate.transmitted_bits_per_second)),
                    rate.received_packets_per_second,
                    rate.transmitted_packets_per_second,
                    rate.error_delta,
                    rate.drop_delta
                )]
            })
            .unwrap_or_default(),
        MonitorUpdate::ProbeFinished { kind, result, .. } => {
            let mut measurements = result
                .latency_ms
                .map(|value| format!("rtt={value:.1}ms "))
                .unwrap_or_default();
            if *kind == ProbeKind::Gateway
                && let Some(metrics) = &app.gateway_metrics
            {
                measurements = format!(
                    "rtt={} p50={} p95={} jitter={} loss={} ",
                    human_ms(result.latency_ms),
                    human_ms(metrics.rtt_p50_ms),
                    human_ms(metrics.rtt_p95_ms),
                    human_ms(metrics.rtt_ipdv_abs_mean_ms),
                    metrics
                        .loss_rate
                        .map(|value| format!("{:.0}%", value * 100.0))
                        .unwrap_or_else(|| "?".into())
                );
            }
            vec![format!(
                "+{elapsed} {:<8} {:<13} {measurements}{}",
                result.health.label(),
                kind.label(),
                result.detail
            )]
        }
        MonitorUpdate::Notice(message) => vec![format!("+{elapsed} notice   {message}")],
        MonitorUpdate::Link { .. }
        | MonitorUpdate::Wifi { .. }
        | MonitorUpdate::Peers { .. }
        | MonitorUpdate::Traffic { counters: None, .. }
        | MonitorUpdate::ProbeStarted { .. } => Vec::new(),
    }
}

fn path_changed(before: &LinkSnapshot, after: &LinkSnapshot) -> bool {
    before.host != after.host || before.path_fingerprint() != after.path_fingerprint()
}

fn path_lines(elapsed: &str, link: &LinkSnapshot) -> Vec<String> {
    let ssid = link
        .ssid
        .as_deref()
        .map(|value| format!(" / {value}"))
        .or_else(|| {
            link.ssid_restricted
                .then(|| " / SSID hidden by macOS Location Services policy".into())
        })
        .unwrap_or_default();
    let mut lines = vec![format!(
        "+{elapsed} path     {} → {} [{}{}] → {}",
        link.host,
        link.interface.as_deref().unwrap_or("unknown interface"),
        link.link_type.as_deref().unwrap_or("unknown link"),
        ssid,
        link.gateway.as_deref().unwrap_or("unknown gateway")
    )];
    lines.push(format!(
        "+{elapsed} resolver {} [source: host resolver configuration]",
        if link.resolvers.is_empty() {
            "unavailable".into()
        } else {
            link.resolvers.join(", ")
        }
    ));
    lines.extend(
        link.addresses
            .iter()
            .filter(|address| address.is_default)
            .map(|address| {
                format!(
                    "+{elapsed} address  interface={} family=ipv{} address={} temporary={} [source: host interface state]",
                    address.interface, address.family, address.address, address.is_temporary
                )
            }),
    );
    lines
}

fn peer_change_lines(
    elapsed: &str,
    before: &PeerSnapshot,
    after: &PeerSnapshot,
    gateway: Option<&str>,
) -> Vec<String> {
    let sources = if after.sources.is_empty() {
        "source unavailable".into()
    } else {
        format!("source: {}", after.sources.join(" + "))
    };
    let mut lines = vec![format!(
        "+{elapsed} peers    {} [{sources}; cached evidence, not liveness]",
        after.detail
    )];
    let old = peer_map(&before.peers);
    let new = peer_map(&after.peers);
    if before.health == crate::model::Health::Queued {
        lines.extend(
            new.values()
                .map(|peer| format!("+{elapsed} peer =   {}", peer_label(peer, gateway))),
        );
        return lines;
    }
    for (key, peer) in &new {
        if !old.contains_key(key) {
            lines.push(format!("+{elapsed} peer +   {}", peer_label(peer, gateway)));
        }
    }
    for (key, peer) in &old {
        if !new.contains_key(key) {
            lines.push(format!(
                "+{elapsed} peer -   {} [absent from latest cache; not proof of departure]",
                peer_label(peer, gateway)
            ));
        }
    }
    lines
}

fn peer_map(peers: &[Peer]) -> BTreeMap<(String, Option<String>, Option<String>), &Peer> {
    peers
        .iter()
        .map(|peer| {
            (
                (
                    peer.address.clone(),
                    peer.mac.clone(),
                    peer.interface.clone(),
                ),
                peer,
            )
        })
        .collect()
}

fn peer_label(peer: &Peer, gateway: Option<&str>) -> String {
    format!(
        "{} mac={} interface={} state={} evidence=\"{}\" role={}{}",
        peer.address,
        peer.mac.as_deref().unwrap_or("unknown"),
        peer.interface.as_deref().unwrap_or("unknown"),
        peer.state.as_deref().unwrap_or("cached"),
        crate::ui::peer_state_meaning(peer.state.as_deref()),
        if gateway == Some(peer.address.as_str()) {
            "gateway"
        } else {
            "peer"
        },
        peer.registrant
            .as_deref()
            .or_else(|| peer.mac_scope.map(|scope| scope.label()))
            .map(|label| format!(" registrant={label}"))
            .unwrap_or_default()
    )
}

fn human_ms(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:.1}ms"))
        .unwrap_or_else(|| "?".into())
}

fn human_dbm(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:.0}dBm"))
        .unwrap_or_else(|| "?".into())
}

fn format_elapsed(duration: Duration) -> String {
    let seconds = duration.as_secs();
    format!(
        "{} +{:02}:{:02}",
        Local::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        seconds / 60,
        seconds % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Health, ProbeResult};

    #[test]
    fn live_probe_line_is_append_only_plain_text() {
        let mut app = App::new();
        let update = MonitorUpdate::ProbeFinished {
            generation: 0,
            kind: ProbeKind::Gateway,
            result: ProbeResult {
                health: Health::Ok,
                detail: "192.168.1.1, 1 attempt(s), 0% loss".into(),
                latency_ms: Some(3.2),
                metrics: None,
            },
        };
        let before = PlainState::from(&app);
        app.apply(update.clone());
        let rendered = format_update(&update, &before, &app).join("\n");
        assert!(rendered.contains("gateway RTT"));
        assert!(rendered.contains("p50=3.0ms"));
        assert!(!rendered.contains('\u{1b}'));
    }

    #[test]
    fn peer_removal_is_not_reported_as_departure() {
        let mut app = App::new();
        app.peers = PeerSnapshot {
            health: Health::Ok,
            detail: "1 cached peer(s); no liveness scan".into(),
            sources: vec!["arp -an".into()],
            failed_sources: Vec::new(),
            peers: vec![Peer {
                address: "192.168.1.9".into(),
                mac: Some("aa:bb:cc:dd:ee:ff".into()),
                interface: Some("en0".into()),
                state: None,
                mac_scope: Some(crate::model::MacScope::Universal),
                registrant: Some("Example Networks".into()),
            }],
            oui_source: Some("test registry".into()),
        };
        let before = PlainState::from(&app);
        let update = MonitorUpdate::Peers {
            generation: 0,
            snapshot: PeerSnapshot {
                health: Health::Ok,
                detail: "0 cached peer(s); no liveness scan".into(),
                sources: vec!["arp -an".into()],
                failed_sources: Vec::new(),
                oui_source: Some("test registry".into()),
                peers: Vec::new(),
            },
        };
        app.apply(update.clone());
        let rendered = format_update(&update, &before, &app).join("\n");
        assert!(rendered.contains("not proof of departure"));
    }
}
