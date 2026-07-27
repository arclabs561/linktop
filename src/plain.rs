use std::collections::BTreeMap;
use std::time::Duration;

use chrono::{Local, SecondsFormat};

use crate::model::{
    App, DwellCollectorScope, DwellPathIdentity, EvidenceBasis, EvidenceClaim, EvidenceCoverage,
    EvidenceLimitation, EvidenceProgress, EvidenceProgressState, EvidenceScope, LinkSnapshot,
    MAX_COMPLETED_PATH_DWELLS, MonitorMode, MonitorUpdate, PathDwell, Peer, PeerDwellSummary,
    PeerSnapshot, ProbeKind, Situation,
};

#[derive(Debug, Clone)]
pub struct PlainState {
    link: LinkSnapshot,
    peers: PeerSnapshot,
    situation: Situation,
    evidence_coverage: EvidenceCoverage,
    progress: Vec<EvidenceProgress>,
}

impl From<&App> for PlainState {
    fn from(app: &App) -> Self {
        Self::for_mode(app, MonitorMode::Overview)
    }
}

impl PlainState {
    pub fn for_mode(app: &App, mode: MonitorMode) -> Self {
        Self {
            link: app.link.clone(),
            peers: app.peers.clone(),
            situation: app.situation(),
            evidence_coverage: app.projection(mode).assessment.evidence_coverage,
            progress: app.evidence_progress(mode),
        }
    }
}

#[cfg(test)]
pub fn format_update(update: &MonitorUpdate, before: &PlainState, app: &App) -> Vec<String> {
    format_update_for_mode(update, before, app, MonitorMode::Overview)
}

pub fn format_update_for_mode(
    update: &MonitorUpdate,
    before: &PlainState,
    app: &App,
    mode: MonitorMode,
) -> Vec<String> {
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
        MonitorUpdate::Peers {
            snapshot: peers, ..
        } if before.peers.peers != peers.peers
            || before.peers.health != peers.health
            || before.peers.failed_sources != peers.failed_sources =>
        {
            peer_change_lines(
                &elapsed,
                &before.peers,
                peers,
                app.link.observation_gateway(),
                mode,
            )
        }
        MonitorUpdate::Traffic {
            counters: Some(counters),
            ..
        } => {
            let rate_progress = app.progress_for(mode, EvidenceClaim::InterfaceRate);
            app.interface_rate.as_ref().map_or_else(
                || {
                    vec![format!(
                        "+{elapsed} traffic  interface={} totals=rx:{} tx:{} packets=rx:{} tx:{} errors={} drops={} · rate {} n={}/{} valid={} [source: kernel interface counters]",
                        counters.interface,
                        human_bytes(counters.received_bytes),
                        human_bytes(counters.transmitted_bytes),
                        counters.received_packets,
                        counters.transmitted_packets,
                        counters.receive_errors.saturating_add(counters.transmit_errors),
                        counters.drops,
                        rate_progress.state.label(),
                        rate_progress.observations.unwrap_or_default(),
                        rate_progress.required_observations.unwrap_or_default(),
                        rate_progress.valid_intervals.unwrap_or_default()
                    )]
                },
                |rate| {
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
            },
            )
        }
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
            if *kind == ProbeKind::Gateway {
                let variation =
                    app.progress_for(MonitorMode::Overview, EvidenceClaim::GatewayVariation);
                let attempts = variation.observations.unwrap_or_default();
                let required = variation.required_observations.unwrap_or_default();
                let successful = variation.successful_observations.unwrap_or_default();
                measurements = if variation.state == EvidenceProgressState::Available {
                    let metrics = app
                        .gateway_assessment_metrics()
                        .expect("available gateway variation has assessment metrics");
                    format!(
                        "rtt={} assessment=latest-{} p50={} p95={} mean|ΔRTT|={} loss={} ",
                        human_ms(result.latency_ms),
                        metrics.sent,
                        human_ms(metrics.rtt_p50_ms),
                        human_ms(metrics.rtt_p95_ms),
                        human_ms(metrics.mean_abs_adjacent_rtt_delta_ms),
                        metrics
                            .loss_rate
                            .map(|value| format!("{:.0}%", value * 100.0))
                            .unwrap_or_else(|| "?".into())
                    )
                } else if let Some(metrics) = app.gateway_assessment_metrics() {
                    format!(
                        "rtt={} assessment=latest-{} loss={} variation={} n={attempts}/{required} successful={successful} ",
                        human_ms(result.latency_ms),
                        metrics.sent,
                        metrics
                            .loss_rate
                            .map(|value| format!("{:.0}%", value * 100.0))
                            .unwrap_or_else(|| "?".into()),
                        variation.state.label(),
                    )
                } else {
                    format!(
                        "rtt={} distribution={} n={attempts}/{required} successful={successful} ",
                        human_ms(result.latency_ms),
                        variation.state.label()
                    )
                };
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
    let evidence_coverage = app.projection(mode).assessment.evidence_coverage;
    if before.situation != situation || before.evidence_coverage != evidence_coverage {
        let diagnosis = crate::ui::overview_diagnosis(app);
        lines.push(format!(
            "+{elapsed} situation path={} coverage={} {}",
            crate::ui::overview_status_label(app),
            evidence_coverage.label(),
            diagnosis.summary
        ));
    }
    let progress = app.evidence_progress(mode);
    for (before, after) in before.progress.iter().zip(&progress) {
        if progress_materially_changed(before, after) {
            lines.push(format!(
                "+{elapsed} progress  {}",
                format_progress_claim(after)
            ));
        }
    }
    lines
}

pub fn format_progress_snapshot(app: &App, mode: MonitorMode) -> Vec<String> {
    let mut lines = Vec::new();
    let mut groups: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for progress in app.evidence_progress(mode) {
        groups
            .entry(progress.state.label())
            .or_default()
            .push(progress.claim.label());
    }
    if let Some(collecting) = groups.remove(EvidenceProgressState::Collecting.label()) {
        lines.push(format!("plan      collecting: {}", collecting.join(", ")));
    }
    if let Some(not_collected) = groups.remove(EvidenceProgressState::NotCollected.label()) {
        lines.push(format!(
            "policy    not collected: {} [collector scope or passive policy]",
            not_collected.join(", ")
        ));
    }
    for (state, claims) in groups {
        lines.push(format!("plan      {state}: {}", claims.join(", ")));
    }
    lines
}

pub fn format_final_progress_summary(app: &App, mode: MonitorMode) -> Vec<String> {
    let projection = app.final_projection(mode);
    let mut lines = vec![
        "EVIDENCE AT ACQUISITION END  unresolved claims are closed against this bounded window"
            .into(),
    ];
    lines.extend(
        projection
            .progress
            .iter()
            .map(|progress| format!("progress  {}", format_progress_claim(progress))),
    );
    lines
}

fn progress_materially_changed(before: &EvidenceProgress, after: &EvidenceProgress) -> bool {
    before.state != after.state || before.limitations != after.limitations
}

fn format_progress_claim(progress: &EvidenceProgress) -> String {
    let mut support = Vec::new();
    if let Some(observations) = progress.observations {
        support.push(progress.required_observations.map_or_else(
            || format!("n={observations}"),
            |required| format!("n={observations}/{required}"),
        ));
    }
    if let Some(successful) = progress.successful_observations {
        support.push(format!("successful={successful}"));
    }
    if let Some(intervals) = progress.valid_intervals {
        support.push(format!("valid_intervals={intervals}"));
    }
    if let Some(span) = progress.observed_span_ms {
        support.push(format!(
            "span={}",
            compact_duration(Duration::from_millis(span))
        ));
    }
    if let Some(age) = progress.source_age_ms {
        support.push(format!(
            "age={}",
            compact_duration(Duration::from_millis(age))
        ));
    }
    support.push(format!("basis={}", evidence_basis_label(progress.basis)));
    support.push(format!("scope={}", evidence_scope_label(&progress.scope)));
    if !progress.limitations.is_empty() {
        support.push(format!(
            "limits={}",
            progress
                .limitations
                .iter()
                .map(evidence_limitation_label)
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    format!(
        "{}={} [{}]",
        progress.claim.label(),
        progress.state.label(),
        support.join(" · ")
    )
}

fn evidence_limitation_label(limitation: &EvidenceLimitation) -> String {
    match limitation {
        EvidenceLimitation::RouteSettlingLastConfirmed => {
            "default route settling; last confirmed path retained".into()
        }
        EvidenceLimitation::CumulativeCountersNoAttribution => {
            "cumulative counters do not attribute process or peer traffic".into()
        }
        EvidenceLimitation::MinimumCompatibleCounterObservations { required } => {
            format!("requires {required} compatible cumulative counter observations")
        }
        EvidenceLimitation::CounterResetsExcluded { count } => {
            format!("{count} counter reset(s) excluded")
        }
        EvidenceLimitation::PlatformRadioTelemetryUnavailable => {
            "platform exposed no radio telemetry".into()
        }
        EvidenceLimitation::NativeSourcesUnavailable { sources } => {
            format!("native sources unavailable: {}", sources.join(", "))
        }
        EvidenceLimitation::CacheNotLivenessIdentityActivityOrTraffic => {
            "cache evidence is not liveness, identity, activity, or traffic".into()
        }
        EvidenceLimitation::SampledHostAccountingNoEndpointProtocolPeerPersonOrIntent => {
            "sampled host accounting does not attribute endpoint, protocol, peer, person, or intent"
                .into()
        }
        EvidenceLimitation::OlderThanAssessmentFreshnessWindow => {
            "observation older than assessment freshness window".into()
        }
        EvidenceLimitation::PublicEgressNotReachabilityDependency => {
            "public egress identity is not a reachability dependency".into()
        }
        EvidenceLimitation::MinimumCurrentGenerationAttempts { required } => {
            format!("requires {required} current-generation attempts")
        }
        EvidenceLimitation::MinimumSuccessfulRttObservations { required } => {
            format!("requires {required} successful RTT observations")
        }
        EvidenceLimitation::BoundedAcquisitionEndedBeforeAvailability => {
            "bounded acquisition ended before availability".into()
        }
    }
}

fn evidence_basis_label(basis: EvidenceBasis) -> &'static str {
    match basis {
        EvidenceBasis::Observed => "observed",
        EvidenceBasis::Derived => "derived",
    }
}

fn evidence_scope_label(scope: &EvidenceScope) -> String {
    match scope {
        EvidenceScope::CurrentSample {
            generation,
            subject,
        } => format!("g{generation} current sample: {subject}"),
        EvidenceScope::CurrentPathGeneration {
            generation,
            subject,
        } => format!("g{generation} current path: {subject}"),
        EvidenceScope::AssessmentWindow {
            generation,
            subject,
            maximum_observations,
        } => format!("g{generation} latest {maximum_observations} observations: {subject}"),
    }
}

pub fn format_dwell_summary(app: &App, scope: DwellCollectorScope) -> Vec<String> {
    let mut lines = vec![format!(
        "LINKTOP DWELL SUMMARY  collector_scope={} completed_generations={}/{} [bounded process-local evidence]",
        scope.label,
        app.completed_path_dwells.len(),
        MAX_COMPLETED_PATH_DWELLS
    )];
    for completed in &app.completed_path_dwells {
        lines.extend(format_generation_dwell(
            completed.generation,
            "completed",
            &completed.identity,
            completed.observed,
            &completed.dwell,
            completed.peers,
            scope,
        ));
    }
    let identity = DwellPathIdentity::from_link(&app.link);
    lines.extend(format_generation_dwell(
        app.path_generation,
        "current",
        &identity,
        app.uptime().saturating_sub(app.path_observed_since),
        &app.path_dwell,
        app.peer_dwell_summary(),
        scope,
    ));
    lines
}

#[allow(clippy::too_many_arguments)]
fn format_generation_dwell(
    generation: u64,
    state: &str,
    identity: &DwellPathIdentity,
    observed: Duration,
    dwell: &PathDwell,
    peers: PeerDwellSummary,
    scope: DwellCollectorScope,
) -> Vec<String> {
    let interface = &dwell.interface;
    let wifi = &dwell.wifi;
    let workload = &dwell.workload;
    let current_rate = interface.current_rate.as_ref().map_or_else(
        || "unavailable".into(),
        |rate| {
            format!(
                "rx={} tx={}",
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
            "rx={} tx={}",
            crate::speed::human_rate(Some(received)),
            crate::speed::human_rate(Some(transmitted))
        ),
        _ => "unavailable".into(),
    };
    let signal = match (
        wifi.latest_signal_dbm,
        wifi.worst_signal_dbm,
        wifi.latest_signal_percent,
        wifi.worst_signal_percent,
    ) {
        (Some(latest), Some(worst), _, _) => {
            format!("latest={latest:.0}dBm worst={worst:.0}dBm")
        }
        (_, _, Some(latest), Some(worst)) => {
            format!("latest={latest:.0}% worst={worst:.0}%")
        }
        _ => "latest=unavailable worst=unavailable".into(),
    };
    let (latest_process, peak_process) = if workload.sampled_windows == 0 {
        ("not sampled".into(), "not sampled".into())
    } else {
        (
            workload.latest_window_top.as_ref().map_or_else(
                || "none attributed in latest sampled window".into(),
                sampled_process,
            ),
            workload.peak_window_top.as_ref().map_or_else(
                || "none attributed in sampled windows".into(),
                sampled_process,
            ),
        )
    };
    let mut lines = vec![format!(
        "SUMMARY SINCE PATH CHANGE  generation={generation} state={state} observed={} path=\"{}\" association={} resolvers={} address_boundaries={}",
        compact_duration(observed),
        identity.operator_label(),
        identity.connection_id.as_deref().unwrap_or("unavailable"),
        identity.resolvers.len(),
        identity.address_boundaries.len()
    )];
    if scope.interface {
        lines.extend([
        format!(
            "interface  samples={} valid_intervals={} counter_resets={} delta_bytes=rx:{} tx:{} delta_packets=rx:{} tx:{} errors=+{} drops=+{} [source: kernel interface counters]",
            interface.samples,
            interface.valid_intervals,
            interface.counter_resets,
            human_bytes(interface.received_bytes_delta),
            human_bytes(interface.transmitted_bytes_delta),
            interface.received_packets_delta,
            interface.transmitted_packets_delta,
            interface.error_delta,
            interface.drop_delta
        ),
        format!("rates      latest={current_rate} peak={peak_rate} [valid counter intervals only]"),
        ]);
    } else {
        lines.push(format!(
            "interface  not collected [collector scope: {}]",
            scope.label
        ));
    }
    if scope.wifi {
        lines.push(
        format!(
            "radio      samples={} {signal} channel={} observed_channel_changes={} [source: platform link telemetry]",
            wifi.samples,
            wifi.latest_channel
                .map(|channel| channel.to_string())
                .unwrap_or_else(|| "unavailable".into()),
            wifi.channel_changes
        ),
        );
    } else {
        lines.push(format!(
            "radio      not collected [collector scope: {}]",
            scope.label
        ));
    }
    if scope.workload {
        lines.push(
        format!(
            "workload   sampled_windows={} observed={} latest_window_top={latest_process} peak_window_top={peak_process} [sampled host process-accounting windows; not session traffic share]",
            workload.sampled_windows,
            compact_duration(workload.observed)
        ),
        );
    } else {
        lines.push(format!(
            "workload   not collected [collector scope: {}]",
            scope.label
        ));
    }
    if scope.peers {
        lines.push(
        format!(
            "neighbors  cached={} observed={} changed={} absent_from_latest_complete_cache={} [native cache evidence; not liveness, identity, activity, or traffic]",
            peers.current, peers.observed, peers.changed, peers.disappeared
        ));
    } else {
        lines.push(format!(
            "neighbors  not collected [collector scope: {}]",
            scope.label
        ));
    }
    lines
}

fn compact_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds < 60 {
        format!("{seconds}s")
    } else {
        format!("{}m{:02}s", seconds / 60, seconds % 60)
    }
}

fn sampled_process(process: &crate::model::ProcessTraffic) -> String {
    format!(
        "{}{} rx={} tx={}",
        process.process,
        if process.processes > 1 {
            format!("×{}", process.processes)
        } else {
            String::new()
        },
        crate::speed::human_rate(Some(process.received_bytes_per_second as f64 * 8.0)),
        crate::speed::human_rate(Some(process.transmitted_bytes_per_second as f64 * 8.0))
    )
}

fn human_bytes(bytes: u64) -> String {
    let mut value = bytes as f64;
    for unit in ["B", "KB", "MB", "GB", "TB"] {
        if value < 1_000.0 || unit == "TB" {
            return format!("{value:.1}{unit}");
        }
        value /= 1_000.0;
    }
    unreachable!()
}

fn path_changed(before: &LinkSnapshot, after: &LinkSnapshot) -> bool {
    before.host != after.host || before.path_fingerprint() != after.path_fingerprint()
}

fn path_lines(elapsed: &str, link: &LinkSnapshot) -> Vec<String> {
    let mut lines = vec![format!("+{elapsed} path     {}", link.operator_path())];
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
            "+{elapsed} config   association={} BSSID={} method={} state={} server={} mask={} lease={} start={} expires={} security={} router_arp_verified={} [source: macOS ipconfig getsummary]",
            configuration.connection_id.as_deref().unwrap_or("unknown"),
            configuration
                .associated_bssid
                .as_deref()
                .unwrap_or(if configuration.bssid_restricted {
                    "hidden by macOS"
                } else {
                    "unknown"
                }),
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
            .map(|address| {
                format!(
                    "+{elapsed} address  interface={} family=ipv{} address={} default_path={} temporary={} [source: host interface state]",
                    address.interface,
                    address.family,
                    address.address,
                    address.is_default,
                    address.is_temporary
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
    mode: MonitorMode,
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
        if mode != MonitorMode::Peers {
            return lines;
        }
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

pub(crate) fn format_elapsed(duration: Duration) -> String {
    let seconds = duration.as_secs();
    format!(
        "{} +{:02}:{:02}",
        Local::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        seconds / 60,
        seconds % 60
    )
}

pub(crate) fn format_history_update(elapsed: Duration, summary: &str) -> String {
    format!("+{} history  {summary}", format_elapsed(elapsed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Address, Health, InterfaceCounters, InterfaceDwell, InterfaceRate, LinkSnapshot,
        MonitorMode, PathUnderlay, ProbePolicy, ProbeResult, ProcessTraffic, WifiDwell,
        WorkloadDwell, WorkloadSnapshot,
    };

    #[test]
    fn first_counter_sample_reports_totals_and_rate_support_separately() {
        let mut app = App::new();
        let before = PlainState::from(&app);
        let update = MonitorUpdate::Traffic {
            generation: 0,
            counters: Some(InterfaceCounters {
                interface: "en0".into(),
                received_bytes: 1_000,
                transmitted_bytes: 2_000,
                received_packets: 10,
                transmitted_packets: 20,
                receive_errors: 1,
                transmit_errors: 2,
                drops: 3,
            }),
        };
        app.apply(update.clone());
        let rendered = format_update(&update, &before, &app).join("\n");

        assert!(rendered.contains("totals=rx:1.0KB tx:2.0KB"));
        assert!(rendered.contains("rate insufficient n=1/2 valid=0"));
        assert!(rendered.contains("interface totals=available"));
        assert!(rendered.contains("interface rate=insufficient"));
    }

    #[test]
    fn settled_counter_progress_does_not_repeat_on_every_plain_sample() {
        let mut app = App::new();
        let counters = |received_bytes, transmitted_bytes| InterfaceCounters {
            interface: "en0".into(),
            received_bytes,
            transmitted_bytes,
            received_packets: received_bytes / 100,
            transmitted_packets: transmitted_bytes / 100,
            receive_errors: 0,
            transmit_errors: 0,
            drops: 0,
        };
        app.apply(MonitorUpdate::Traffic {
            generation: 0,
            counters: Some(counters(1_000, 2_000)),
        });
        std::thread::sleep(Duration::from_millis(1));
        app.apply(MonitorUpdate::Traffic {
            generation: 0,
            counters: Some(counters(2_000, 4_000)),
        });
        assert_eq!(
            app.progress_for(MonitorMode::Overview, EvidenceClaim::InterfaceRate)
                .state,
            EvidenceProgressState::Available
        );

        let before = PlainState::from(&app);
        let update = MonitorUpdate::Traffic {
            generation: 0,
            counters: Some(counters(3_000, 6_000)),
        };
        std::thread::sleep(Duration::from_millis(1));
        app.apply(update.clone());
        let rendered = format_update(&update, &before, &app).join("\n");
        assert!(rendered.contains("traffic"));
        assert!(!rendered.contains("progress"));
    }

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
        assert!(rendered.contains("rtt=3.2ms"));
        assert!(rendered.contains("distribution=insufficient n=1/5 successful=1"));
        assert!(!rendered.contains("p50="));
        assert!(!rendered.contains('\u{1b}'));
    }

    #[test]
    fn initial_progress_is_a_compact_plan_not_a_schema_dump() {
        let app = App::new();
        let lines = format_progress_snapshot(&app, MonitorMode::Overview);
        assert!(lines.len() <= 3, "{lines:#?}");
        assert!(lines.iter().any(|line| line.starts_with("plan")));
        assert!(lines.iter().any(|line| line.starts_with("policy")));
        assert!(!lines.iter().any(|line| line.contains("basis=")));
    }

    #[test]
    fn bounded_final_progress_closes_every_collecting_claim() {
        let app = App::new();
        let rendered = format_final_progress_summary(&app, MonitorMode::Overview).join("\n");
        assert!(rendered.contains("EVIDENCE AT ACQUISITION END"));
        assert!(!rendered.contains("=collecting"));
        assert!(rendered.contains("bounded acquisition ended before availability"));
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
    fn overview_summarizes_initial_neighbor_inventory_while_peers_lists_it() {
        let snapshot = PeerSnapshot {
            health: Health::Ok,
            detail: "3 cached peer(s); no liveness scan".into(),
            path_filter: crate::model::PeerPathFilter::Applied,
            sources: vec!["arp -an".into()],
            failed_sources: Vec::new(),
            oui_source: None,
            peers: (1..=3)
                .map(|last| Peer {
                    address: format!("192.0.2.{last}"),
                    mac: None,
                    interface: Some("en0".into()),
                    state: None,
                    binding_conflict: false,
                    mac_scope: None,
                    registrant: None,
                })
                .collect(),
        };
        let update = MonitorUpdate::Peers {
            generation: 0,
            snapshot,
        };

        let mut overview_app = App::new();
        let overview_before = PlainState::for_mode(&overview_app, MonitorMode::Overview);
        overview_app.apply(update.clone());
        let overview = format_update_for_mode(
            &update,
            &overview_before,
            &overview_app,
            MonitorMode::Overview,
        )
        .join("\n");
        assert!(overview.contains("neighbors 3 cached peer(s)"));
        assert!(!overview.contains("neighbor ="));

        let mut peers_app = App::new();
        let peers_before = PlainState::for_mode(&peers_app, MonitorMode::Peers);
        peers_app.apply(update.clone());
        let peers = format_update_for_mode(&update, &peers_before, &peers_app, MonitorMode::Peers)
            .join("\n");
        assert_eq!(peers.matches("neighbor =").count(), 3);
    }

    #[test]
    fn path_updates_emit_every_observed_interface_address_with_role_qualifiers() {
        let link = LinkSnapshot {
            host: "workstation".into(),
            interface: Some("utun4".into()),
            link_type: Some("vpn".into()),
            underlay: Some(PathUnderlay {
                interface: "en0".into(),
                link_type: "wifi".into(),
                gateway: Some("192.168.1.1".into()),
            }),
            ssid: Some("house".into()),
            addresses: vec![
                Address {
                    interface: "utun4".into(),
                    address: "100.64.0.2".into(),
                    family: 4,
                    is_default: true,
                    is_temporary: false,
                },
                Address {
                    interface: "en0".into(),
                    address: "192.168.1.10".into(),
                    family: 4,
                    is_default: false,
                    is_temporary: true,
                },
            ],
            ..LinkSnapshot::empty()
        };

        let rendered = path_lines("00:01", &link).join("\n");
        assert!(
            rendered
                .contains("workstation ──▶ utun4 [vpn] over en0 [wifi / house] ──▶ 192.168.1.1")
        );
        assert!(rendered.contains(
            "interface=utun4 family=ipv4 address=100.64.0.2 default_path=true temporary=false"
        ));
        assert!(rendered.contains(
            "interface=en0 family=ipv4 address=192.168.1.10 default_path=false temporary=true"
        ));
    }

    #[test]
    fn dwell_final_summary_uses_bounded_generation_scoped_evidence() {
        let mut app = App::new();
        app.path_generation = 7;
        app.path_dwell.interface = InterfaceDwell {
            samples: 3,
            valid_intervals: 2,
            received_bytes_delta: 12_000,
            transmitted_bytes_delta: 4_000,
            received_packets_delta: 120,
            transmitted_packets_delta: 40,
            current_rate: Some(InterfaceRate {
                received_bits_per_second: 32_000.0,
                transmitted_bits_per_second: 8_000.0,
                received_packets_per_second: 10.0,
                transmitted_packets_per_second: 4.0,
                error_delta: 1,
                drop_delta: 2,
            }),
            peak_received_bits_per_second: Some(64_000.0),
            peak_transmitted_bits_per_second: Some(16_000.0),
            error_delta: 1,
            drop_delta: 2,
            counter_resets: 1,
        };
        app.path_dwell.wifi = WifiDwell {
            samples: 4,
            latest_signal_dbm: Some(-63.0),
            worst_signal_dbm: Some(-78.0),
            latest_channel: Some(44),
            channel_changes: 2,
            ..WifiDwell::default()
        };
        app.path_dwell.workload = WorkloadDwell {
            sampled_windows: 2,
            observed: Duration::from_secs(2),
            latest_window_top: Some(ProcessTraffic {
                process: "codex".into(),
                processes: 2,
                received_bytes_per_second: 4_096,
                transmitted_bytes_per_second: 2_048,
            }),
            peak_window_top: Some(ProcessTraffic {
                process: "browser".into(),
                processes: 1,
                received_bytes_per_second: 8_192,
                transmitted_bytes_per_second: 4_096,
            }),
        };
        let peers = PeerSnapshot {
            health: Health::Ok,
            detail: "1 cached peer".into(),
            path_filter: crate::model::PeerPathFilter::Applied,
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
        app.apply(MonitorUpdate::Peers {
            generation: 7,
            snapshot: peers.clone(),
        });
        app.apply(MonitorUpdate::Peers {
            generation: 7,
            snapshot: peers,
        });

        let rendered =
            format_dwell_summary(&app, MonitorMode::Overview.dwell_collector_scope()).join("\n");
        assert!(rendered.starts_with("LINKTOP DWELL SUMMARY"));
        assert!(rendered.contains("SUMMARY SINCE PATH CHANGE"));
        assert!(rendered.contains("generation=7"));
        assert!(rendered.contains("samples=3 valid_intervals=2 counter_resets=1"));
        assert!(rendered.contains("delta_bytes=rx:12.0KB tx:4.0KB"));
        assert!(rendered.contains("latest=rx=32.00 Kbit/s tx=8.00 Kbit/s"));
        assert!(rendered.contains("peak=rx=64.00 Kbit/s tx=16.00 Kbit/s"));
        assert!(rendered.contains("latest=-63dBm worst=-78dBm"));
        assert!(rendered.contains("observed_channel_changes=2"));
        assert!(rendered.contains("sampled_windows=2 observed=2s"));
        assert!(rendered.contains("latest_window_top=codex×2"));
        assert!(rendered.contains("peak_window_top=browser"));
        assert!(rendered.contains("not session traffic share"));
        assert!(rendered.contains("native cache evidence; not liveness"));
        assert!(!rendered.contains("location"));
        assert!(!rendered.contains("device traffic"));
    }

    #[test]
    fn empty_dwell_final_summary_reports_missing_windows_instead_of_zero_activity() {
        let app = App::new();
        let rendered =
            format_dwell_summary(&app, MonitorMode::Overview.dwell_collector_scope()).join("\n");

        assert!(rendered.contains("samples=0 valid_intervals=0"));
        assert!(rendered.contains("latest=unavailable peak=unavailable"));
        assert!(rendered.contains("latest=unavailable worst=unavailable"));
        assert!(rendered.contains("sampled_windows=0 observed=0s"));
        assert!(rendered.contains("latest_window_top=not sampled"));
        assert!(rendered.contains("peak_window_top=not sampled"));
        assert!(!rendered.contains("latest=peak"));
        assert!(!rendered.contains("no traffic"));
        assert!(!rendered.contains("inactive"));
    }

    #[test]
    fn dwell_final_summary_reports_completed_and_current_path_generations() {
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
        app.path_dwell.interface.samples = 3;
        app.path_dwell.workload.sampled_windows = 1;
        app.path_dwell.workload.observed = Duration::from_secs(1);
        app.apply(MonitorUpdate::Link {
            generation: 2,
            snapshot: LinkSnapshot {
                host: "workstation".into(),
                interface: Some("en0".into()),
                link_type: Some("wifi".into()),
                ssid: Some("hotspot".into()),
                gateway: Some("172.20.10.1".into()),
                resolvers: vec!["172.20.10.1".into()],
                ..LinkSnapshot::empty()
            },
        });
        app.path_dwell.interface.samples = 2;

        let rendered =
            format_dwell_summary(&app, MonitorMode::Overview.dwell_collector_scope()).join("\n");

        assert!(rendered.contains("completed_generations=1/8"));
        assert!(rendered.contains("generation=1 state=completed"));
        assert!(rendered.contains("[wifi / house]"));
        assert!(rendered.contains("generation=2 state=current"));
        assert!(rendered.contains("[wifi / hotspot]"));
        assert_eq!(rendered.matches("SUMMARY SINCE PATH CHANGE").count(), 2);
        assert!(rendered.contains("samples=3"));
        assert!(rendered.contains("samples=2"));
    }

    #[test]
    fn focused_mode_dwell_summaries_name_collectors_that_were_not_run() {
        let app = App::new();
        let link = format_dwell_summary(&app, MonitorMode::Link.dwell_collector_scope()).join("\n");
        assert!(link.contains("collector_scope=link"));
        assert!(link.contains("interface  samples=0"));
        assert!(link.contains("radio      samples=0"));
        assert!(link.contains("workload   not collected [collector scope: link]"));
        assert!(link.contains("neighbors  not collected [collector scope: link]"));

        let peers =
            format_dwell_summary(&app, MonitorMode::Peers.dwell_collector_scope()).join("\n");
        assert!(peers.contains("collector_scope=peers"));
        assert!(peers.contains("interface  not collected [collector scope: peers]"));
        assert!(peers.contains("radio      not collected [collector scope: peers]"));
        assert!(peers.contains("workload   not collected [collector scope: peers]"));
        assert!(peers.contains("neighbors  cached=0 observed=0"));
        assert!(!peers.contains("interface  samples=0"));
    }

    #[test]
    fn peer_removal_is_not_reported_as_departure() {
        let mut app = App::new();
        app.peers = PeerSnapshot {
            health: Health::Ok,
            detail: "1 cached peer(s); no liveness scan".into(),
            path_filter: crate::model::PeerPathFilter::Applied,
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
                path_filter: crate::model::PeerPathFilter::Applied,
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
            path_filter: crate::model::PeerPathFilter::Applied,
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
            path_filter: crate::model::PeerPathFilter::Applied,
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
