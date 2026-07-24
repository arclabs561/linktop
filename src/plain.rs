use std::collections::BTreeMap;
use std::time::Duration;

use chrono::{Local, SecondsFormat};

use crate::model::{
    App, EvidenceCoverage, LinkSnapshot, MonitorUpdate, Peer, PeerSnapshot, ProbeKind, Situation,
};

#[derive(Debug, Clone)]
pub struct PlainState {
    link: LinkSnapshot,
    peers: PeerSnapshot,
    situation: Situation,
    evidence_coverage: EvidenceCoverage,
}

impl From<&App> for PlainState {
    fn from(app: &App) -> Self {
        Self {
            link: app.link.clone(),
            peers: app.peers.clone(),
            situation: app.situation(),
            evidence_coverage: app.evidence_coverage(),
        }
    }
}

pub fn format_update(update: &MonitorUpdate, before: &PlainState, app: &App) -> Vec<String> {
    let elapsed = format_elapsed(app.uptime());
    let mut lines = match update {
        MonitorUpdate::Link { snapshot: link, .. } if path_changed(&before.link, link) => {
            path_lines(&elapsed, link)
        }
        MonitorUpdate::Wifi {
            ssid,
            telemetry: wifi,
            ..
        } if before.link.wifi.as_ref() != wifi.as_ref()
            || ssid
                .as_deref()
                .is_some_and(|ssid| before.link.ssid.as_deref() != Some(ssid)) =>
        {
            let mut lines = ssid
                .as_deref()
                .filter(|ssid| before.link.ssid.as_deref() != Some(*ssid))
                .map(|ssid| {
                    vec![format!(
                        "+{elapsed} network  SSID={ssid} [source: platform Wi-Fi state]"
                    )]
                })
                .unwrap_or_default();
            match wifi {
                None if lines.is_empty() => lines.push(format!(
                    "+{elapsed} radio    unavailable [source: platform link tools]"
                )),
                None => {}
                Some(wifi) => lines.push(format!(
                    "+{elapsed} radio    signal={} noise={} channel={} tx={} [source: platform link tools]",
                    human_dbm(wifi.signal_dbm.or(wifi.signal_percent)),
                    human_dbm(wifi.noise_dbm),
                    wifi.channel
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "?".into()),
                    wifi.tx_rate_mbps
                        .map(|value| format!("{value:.0}Mb/s"))
                        .unwrap_or_else(|| "?".into())
                )),
            }
            lines
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
        MonitorUpdate::Workload { snapshot, .. } => {
            if snapshot.processes.is_empty() {
                vec![format!(
                    "+{elapsed} workload  {} [source: {}]",
                    snapshot.detail,
                    snapshot.source.as_deref().unwrap_or("unavailable")
                )]
            } else {
                vec![format!(
                    "+{elapsed} workload  {} [window: {}s; source: {}]",
                    snapshot
                        .processes
                        .iter()
                        .take(3)
                        .map(|process| format!(
                            "{}{} rx={} tx={}",
                            process.process,
                            if process.processes > 1 {
                                format!("×{}", process.processes)
                            } else {
                                String::new()
                            },
                            crate::speed::human_rate(Some(
                                process.received_bytes_per_second as f64 * 8.0
                            )),
                            crate::speed::human_rate(Some(
                                process.transmitted_bytes_per_second as f64 * 8.0
                            ))
                        ))
                        .collect::<Vec<_>>()
                        .join("; "),
                    snapshot.interval.as_secs(),
                    snapshot.source.as_deref().unwrap_or("unavailable")
                )]
            }
        }
        MonitorUpdate::ProbeFinished { kind, result, .. } => {
            let mut measurements = result
                .latency_ms
                .map(|value| format!("rtt={value:.1}ms "))
                .unwrap_or_default();
            if *kind == ProbeKind::Gateway
                && let Some(metrics) = &app.gateway_metrics
            {
                measurements = format!(
                    "rtt={} p50={} p95={} mean|ΔRTT|={} loss={} ",
                    human_ms(result.latency_ms),
                    human_ms(metrics.rtt_p50_ms),
                    human_ms(metrics.rtt_p95_ms),
                    human_ms(metrics.mean_abs_adjacent_rtt_delta_ms),
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
        MonitorUpdate::PathSettling { .. } => vec![format!(
            "+{elapsed} path     switching networks; retaining the last confirmed path for up to 3s [source: default route]"
        )],
        MonitorUpdate::Notice(message) => vec![format!("+{elapsed} notice   {message}")],
        MonitorUpdate::Link { .. }
        | MonitorUpdate::Wifi { .. }
        | MonitorUpdate::Peers { .. }
        | MonitorUpdate::Traffic { counters: None, .. }
        | MonitorUpdate::ProbeStarted { .. } => Vec::new(),
    };
    let situation = app.situation();
    let evidence_coverage = app.evidence_coverage();
    if before.situation != situation || before.evidence_coverage != evidence_coverage {
        let diagnosis = crate::ui::overview_diagnosis(app);
        lines.push(format!(
            "+{elapsed} situation path={} coverage={} {}",
            crate::ui::overview_status_label(app),
            evidence_coverage.label(),
            diagnosis.summary
        ));
    }
    lines
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
    if let Some(configuration) = &link.network_configuration {
        lines.push(format!(
            "+{elapsed} config   association={} method={} state={} server={} mask={} lease={} start={} expires={} security={} router_arp_verified={} [source: macOS ipconfig getsummary]",
            configuration.connection_id.as_deref().unwrap_or("unknown"),
            configuration.method.as_deref().unwrap_or("unknown"),
            configuration.state.as_deref().unwrap_or("unknown"),
            configuration.server.as_deref().unwrap_or("unknown"),
            configuration.subnet_mask.as_deref().unwrap_or("unknown"),
            configuration
                .lease_seconds
                .map(|seconds| format!("{seconds}s"))
                .unwrap_or_else(|| "unknown".into()),
            configuration.lease_started_at.as_deref().unwrap_or("unknown"),
            configuration.lease_expires_at.as_deref().unwrap_or("unknown"),
            configuration.security.as_deref().unwrap_or("unknown"),
            configuration
                .router_arp_verified
                .map(|verified| verified.to_string())
                .unwrap_or_else(|| "unknown".into())
        ));
    }
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
        "+{elapsed} neighbors {} [{sources}; cache evidence, not liveness]",
        after.detail
    )];
    let old = peer_map(&before.peers);
    let new = peer_map(&after.peers);
    if before.health == crate::model::Health::Queued {
        lines.extend(
            new.values()
                .map(|peer| format!("+{elapsed} neighbor = {}", peer_label(peer, gateway))),
        );
        return lines;
    }
    for (key, peer) in &new {
        let Some(previous) = old.get(key) else {
            lines.push(format!(
                "+{elapsed} neighbor + {}",
                peer_label(peer, gateway)
            ));
            continue;
        };
        if peer.binding_conflict && !previous.binding_conflict {
            lines.push(format!(
                "+{elapsed} neighbor ~ {} source disagreement [conflicting native binding evidence]",
                peer.address
            ));
        } else if previous.binding_conflict && !peer.binding_conflict {
            lines.push(format!(
                "+{elapsed} neighbor ~ {} source disagreement cleared; current binding {} [source: native neighbor cache]",
                peer.address,
                peer.mac.as_deref().unwrap_or("unknown")
            ));
        } else if !previous.binding_conflict && !peer.binding_conflict && previous.mac != peer.mac {
            lines.push(format!(
                "+{elapsed} neighbor ~ {} binding {} → {} [source: native neighbor cache]",
                peer.address,
                previous.mac.as_deref().unwrap_or("unknown"),
                peer.mac.as_deref().unwrap_or("unknown")
            ));
        }
        if previous.state != peer.state {
            lines.push(format!(
                "+{elapsed} neighbor ~ {} state {} → {} [cache evidence, not liveness]",
                peer.address,
                previous.state.as_deref().unwrap_or("cached"),
                peer.state.as_deref().unwrap_or("cached")
            ));
        }
    }
    if after.failed_sources.is_empty() {
        for (key, peer) in &old {
            if !new.contains_key(key) {
                lines.push(format!(
                    "+{elapsed} neighbor - {} [absent from latest complete cache read; not proof of departure]",
                    peer_label(peer, gateway)
                ));
            }
        }
    }
    lines
}

fn peer_map(peers: &[Peer]) -> BTreeMap<(String, Option<String>), &Peer> {
    peers
        .iter()
        .map(|peer| ((peer.address.clone(), peer.interface.clone()), peer))
        .collect()
}

fn peer_label(peer: &Peer, gateway: Option<&str>) -> String {
    let binding = if peer.binding_conflict {
        "source-conflict"
    } else {
        peer.mac.as_deref().unwrap_or("unknown")
    };
    format!(
        "{} mac={} interface={} state={} evidence=\"{}\" role={}{}",
        peer.address,
        binding,
        peer.interface.as_deref().unwrap_or("unknown"),
        peer.state.as_deref().unwrap_or("cached"),
        crate::ui::peer_state_meaning(peer.state.as_deref()),
        if gateway == Some(peer.address.as_str()) {
            "gateway"
        } else {
            "neighbor"
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
    use crate::model::{Health, ProbePolicy, ProbeResult, ProcessTraffic, WorkloadSnapshot};

    #[test]
    fn live_probe_line_is_append_only_plain_text() {
        let mut app = App::with_probe_policy(ProbePolicy::Active);
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
        assert!(rendered.contains("next-hop RTT"));
        assert!(rendered.contains("p50=3.0ms"));
        assert!(!rendered.contains('\u{1b}'));
    }

    #[test]
    fn route_settling_is_visible_in_plain_streams() {
        let mut app = App::new();
        let update = MonitorUpdate::PathSettling { generation: 0 };
        let before = PlainState::from(&app);
        app.apply(update.clone());
        let rendered = format_update(&update, &before, &app).join("\n");
        assert!(rendered.contains("switching networks"));
        assert!(rendered.contains("retaining the last confirmed path for up to 3s"));
        assert!(rendered.contains("source: default route"));
    }

    #[test]
    fn workload_line_is_numeric_and_names_its_window_and_source() {
        let mut app = App::new();
        let update = MonitorUpdate::Workload {
            generation: 0,
            snapshot: WorkloadSnapshot {
                health: Health::Ok,
                detail: "2 process groups".into(),
                source: Some("nettop external-interface deltas".into()),
                interval: Duration::from_secs(1),
                processes: vec![ProcessTraffic {
                    process: "codex".into(),
                    processes: 2,
                    received_bytes_per_second: 4_096,
                    transmitted_bytes_per_second: 2_048,
                }],
            },
        };
        let before = PlainState::from(&app);
        app.apply(update.clone());
        let rendered = format_update(&update, &before, &app).join("\n");
        assert!(rendered.contains("codex×2"));
        assert!(rendered.contains("rx=32.77 Kbit/s"));
        assert!(rendered.contains("window: 1s"));
        assert!(rendered.contains("source: nettop external-interface deltas"));
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
                binding_conflict: false,
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

    #[test]
    fn peer_state_change_is_reported_without_fabricating_a_new_peer() {
        let before_snapshot = PeerSnapshot {
            health: Health::Ok,
            detail: "1 cached peer".into(),
            sources: vec!["arp -an".into()],
            failed_sources: Vec::new(),
            oui_source: None,
            peers: vec![Peer {
                address: "192.168.1.9".into(),
                mac: Some("aa:bb:cc:dd:ee:ff".into()),
                interface: Some("en0".into()),
                state: Some("STALE".into()),
                binding_conflict: false,
                mac_scope: Some(crate::model::MacScope::Universal),
                registrant: Some("Example Networks".into()),
            }],
        };
        let mut after_snapshot = before_snapshot.clone();
        after_snapshot.peers[0].state = Some("REACHABLE".into());
        let mut app = App::new();
        app.peers = before_snapshot;
        let before = PlainState::from(&app);
        let update = MonitorUpdate::Peers {
            generation: 0,
            snapshot: after_snapshot,
        };
        app.apply(update.clone());
        let rendered = format_update(&update, &before, &app).join("\n");
        assert!(rendered.contains("state STALE → REACHABLE"));
        assert!(!rendered.contains("peer +"));
        assert!(!rendered.contains("peer -"));
    }

    #[test]
    fn peer_source_disagreement_is_not_reported_as_binding_churn() {
        let before_snapshot = PeerSnapshot {
            health: Health::Ok,
            detail: "1 cached peer".into(),
            sources: vec!["arp -an".into(), "ndp -an".into()],
            failed_sources: Vec::new(),
            oui_source: None,
            peers: vec![Peer {
                address: "192.168.1.9".into(),
                mac: Some("aa:bb:cc:dd:ee:ff".into()),
                interface: Some("en0".into()),
                state: Some("STALE".into()),
                binding_conflict: false,
                mac_scope: Some(crate::model::MacScope::Universal),
                registrant: Some("Example Networks".into()),
            }],
        };
        let mut conflicted = before_snapshot.clone();
        conflicted.health = Health::Degraded;
        conflicted.detail = "1 conflicting native binding row".into();
        conflicted.peers[0].mac = None;
        conflicted.peers[0].binding_conflict = true;

        let mut app = App::new();
        app.peers = before_snapshot;
        let before = PlainState::from(&app);
        let update = MonitorUpdate::Peers {
            generation: 0,
            snapshot: conflicted,
        };
        app.apply(update.clone());
        let rendered = format_update(&update, &before, &app).join("\n");

        assert!(rendered.contains("source disagreement"));
        assert!(!rendered.contains("aa:bb:cc:dd:ee:ff → unknown"));
        assert!(!rendered.contains("binding changed"));
    }

    #[test]
    fn supporting_lookup_gap_does_not_turn_plain_path_failed() {
        let mut app = App::with_probe_policy(ProbePolicy::Active);
        app.peers.health = Health::Ok;
        for _ in 0..crate::model::MIN_GATEWAY_ASSESSMENT_SAMPLES {
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
        }
        for kind in [ProbeKind::Dns, ProbeKind::Https] {
            app.apply(MonitorUpdate::ProbeFinished {
                generation: 0,
                kind,
                result: ProbeResult {
                    health: Health::Ok,
                    detail: "path check passed".into(),
                    latency_ms: Some(20.0),
                    metrics: None,
                },
            });
        }
        let before = PlainState::from(&app);
        let update = MonitorUpdate::ProbeFinished {
            generation: 0,
            kind: ProbeKind::PublicIp,
            result: ProbeResult::unavailable("supporting providers timed out"),
        };
        app.apply(update.clone());

        let rendered = format_update(&update, &before, &app).join("\n");
        assert!(rendered.contains("situation path=OK coverage=PARTIAL"));
        assert!(!rendered.contains("situation path=FAILED"));
    }
}
