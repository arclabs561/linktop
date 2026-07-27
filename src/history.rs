use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use netbraid_evidence::{
    CollectionPolicyV0, CoverageStateV0, CoverageV0, HOST_PATH_SCHEMA_V0, HostPathObservationV0,
    HostPathV0, NetworkNameV0, NetworkNameVisibilityV0, ObservationOrderV0, SourceRefV0,
};
use netbraid_replay::{
    AttachmentCorroborationV0, ContextRecurrenceV0, ContextRelationV0, ExactContextMatchV0,
    JsonlReadWarningV0, append_jsonl, compare_contexts, read_jsonl_recovering_tail,
    summarize_context_recurrence,
};

use crate::model::{App, HistoryContext, HistoryContextKind, LinkSnapshot, MonitorUpdate};

pub struct HistorySession {
    path: PathBuf,
    records: Vec<HostPathObservationV0>,
    recorded_generation: Option<u64>,
    writable: bool,
    recovered_tail: Option<JsonlReadWarningV0>,
    initial: HistoryContext,
}

impl HistorySession {
    pub fn open(path: PathBuf) -> Self {
        if !path.exists() {
            return Self {
                path,
                records: Vec::new(),
                recorded_generation: None,
                writable: true,
                recovered_tail: None,
                initial: HistoryContext {
                    kind: HistoryContextKind::Configured,
                    summary: "history configured; no prior evidence log".into(),
                    compact_summary: "configured · no prior evidence".into(),
                    context_anchor: "pending current context".into(),
                    place_authority: "unknown · assertion source not configured".into(),
                    evidence: "private JSONL · retention explicitly enabled".into(),
                },
            };
        }
        match read_jsonl_recovering_tail(&path) {
            Ok(state) => {
                let count = state.replay.records.len();
                let recovered_tail = state.warning;
                let (kind, summary, compact_summary, evidence, writable) = if let Some(warning) =
                    recovered_tail.as_ref()
                {
                    (
                        HistoryContextKind::Unavailable,
                        format!(
                            "history prefix loaded: {count} record(s); {}",
                            tail_warning(warning)
                        ),
                        format!("read-only prefix · {count} prior · interrupted tail"),
                        "valid prefix available for comparison; append disabled; log left unchanged",
                        false,
                    )
                } else {
                    (
                        HistoryContextKind::Loaded,
                        format!(
                            "history loaded: {count} record(s); current context assessment pending"
                        ),
                        format!("loaded · {count} prior · assessment pending"),
                        "Netbraid history · netmon.host_path_observation.v0 · private JSONL · waiting for current context",
                        true,
                    )
                };
                Self {
                    path,
                    records: state.replay.records,
                    recorded_generation: None,
                    writable,
                    recovered_tail,
                    initial: HistoryContext {
                        kind,
                        summary,
                        compact_summary,
                        context_anchor: "pending current context".into(),
                        place_authority: "unknown · assertion source not configured".into(),
                        evidence: evidence.into(),
                    },
                }
            }
            Err(error) => Self {
                path,
                records: Vec::new(),
                recorded_generation: None,
                writable: false,
                recovered_tail: None,
                initial: HistoryContext {
                    kind: HistoryContextKind::Unavailable,
                    summary: format!("history unavailable: {error}"),
                    compact_summary: "unavailable · live diagnosis unaffected".into(),
                    context_anchor: "unavailable".into(),
                    place_authority: "unknown · history unavailable".into(),
                    evidence: "current live diagnosis is unaffected; log left unchanged".into(),
                },
            },
        }
    }

    pub fn attach(&self, app: &mut App) {
        app.history_context = Some(self.initial.clone());
    }

    pub fn observe_update(&mut self, update: &MonitorUpdate, app: &mut App) -> Option<String> {
        if self.recorded_generation == Some(app.path_generation)
            || !update_completes_context(update, app)
            || app.link.interface.is_none()
            || (!self.writable && self.recovered_tail.is_none())
        {
            return None;
        }

        let mut record = observation_from_app(app);
        record.canonicalize();
        let mut context = summarize(&self.records, &record);
        if let Some(warning) = self.recovered_tail.as_ref() {
            self.recorded_generation = Some(app.path_generation);
            context.kind = HistoryContextKind::Unavailable;
            context.summary = format!(
                "{} · read-only recovered prefix; {}",
                context.summary,
                tail_warning(warning)
            );
            context.compact_summary =
                format!("{} · tail incomplete/read-only", context.compact_summary);
            context.evidence = format!(
                "{} · valid prefix used; append disabled; log left unchanged",
                context.evidence
            );
            app.history_context = Some(context.clone());
            return Some(context.summary);
        }
        if let Err(error) = prepare_private_path(&self.path)
            .and_then(|()| append_jsonl(&self.path, &record).map_err(anyhow::Error::from))
            .and_then(|()| make_private_file(&self.path))
        {
            self.writable = false;
            let status = HistoryContext {
                kind: HistoryContextKind::AppendFailed,
                summary: format!("history append failed: {error}"),
                compact_summary: "append failed · live diagnosis unaffected".into(),
                context_anchor: "current context observed; append failed".into(),
                place_authority: "unknown · assertion source not configured".into(),
                evidence: "current live diagnosis is unaffected; log left unchanged".into(),
            };
            app.history_context = Some(status.clone());
            return Some(status.summary);
        }

        self.recorded_generation = Some(app.path_generation);
        self.records.push(record);
        app.history_context = Some(context.clone());
        Some(context.summary)
    }
}

fn update_completes_context(update: &MonitorUpdate, app: &App) -> bool {
    let wifi = app
        .link
        .link_type
        .as_deref()
        .is_some_and(|kind| kind.eq_ignore_ascii_case("wifi"));
    let generation = match update {
        MonitorUpdate::Link { generation, .. }
        | MonitorUpdate::Wifi { generation, .. }
        | MonitorUpdate::Peers { generation, .. }
        | MonitorUpdate::Traffic { generation, .. }
        | MonitorUpdate::Workload { generation, .. }
        | MonitorUpdate::ProbeStarted { generation, .. }
        | MonitorUpdate::ProbeFinished { generation, .. }
        | MonitorUpdate::PathSettling { generation } => Some(*generation),
        MonitorUpdate::Notice(_) => None,
    };
    generation == Some(app.path_generation)
        && (!wifi || app.wifi_observation_settled)
        && app.peers.health != crate::model::Health::Queued
}

fn observation_from_app(app: &App) -> HostPathObservationV0 {
    let observed_at = unix_millis();
    let (mut observed_sources, mut missing_sources) = coverage_sources(&app.link);
    let next_hop_link_address = next_hop_link_address(app);
    if app.link.gateway.is_some() {
        source(
            next_hop_link_address.is_some(),
            "next_hop_link_address",
            &mut observed_sources,
            &mut missing_sources,
        );
    }
    let coverage = if observed_sources.is_empty() {
        CoverageStateV0::Unavailable
    } else if missing_sources.is_empty() {
        CoverageStateV0::Complete
    } else {
        CoverageStateV0::Partial
    };
    let network_name = match (app.link.ssid.as_deref(), app.link.ssid_restricted) {
        (Some(value), false) => NetworkNameV0 {
            visibility: NetworkNameVisibilityV0::Observed,
            value: Some(value.into()),
        },
        (_, true) => NetworkNameV0 {
            visibility: NetworkNameVisibilityV0::Restricted,
            value: None,
        },
        _ => NetworkNameV0 {
            visibility: NetworkNameVisibilityV0::Unavailable,
            value: None,
        },
    };
    let configuration = app.link.network_configuration.as_deref();
    let observer_id = app.link.host.clone();
    HostPathObservationV0 {
        schema: HOST_PATH_SCHEMA_V0.into(),
        record_id: format!(
            "{observer_id}:{observed_at}:{}:{}",
            std::process::id(),
            app.path_generation
        ),
        order: ObservationOrderV0 {
            event_time_unix_ms: observed_at,
            acquired_time_unix_ms: observed_at,
            source_sequence: observed_at.max(0) as u64,
        },
        source: SourceRefV0 {
            observer_id,
            adapter: "linktop".into(),
            adapter_version: env!("CARGO_PKG_VERSION").into(),
        },
        policy: CollectionPolicyV0::passive_host_local(),
        coverage: CoverageV0 {
            state: coverage,
            observed_sources,
            missing_sources,
        },
        path: HostPathV0 {
            interface: app.link.interface.clone(),
            link_type: app.link.link_type.clone(),
            network_name,
            association_id: configuration.and_then(|value| value.connection_id.clone()),
            associated_bssid: configuration.and_then(|value| value.associated_bssid.clone()),
            next_hop: app.link.gateway.clone(),
            next_hop_link_address,
            resolvers: app.link.resolvers.clone(),
            address_prefixes: app.link.default_path_prefixes(),
        },
    }
}

fn coverage_sources(link: &LinkSnapshot) -> (Vec<String>, Vec<String>) {
    let mut observed = Vec::new();
    let mut missing = Vec::new();
    source(
        link.interface.is_some(),
        "default_route",
        &mut observed,
        &mut missing,
    );
    source(
        link.gateway.is_some(),
        "next_hop",
        &mut observed,
        &mut missing,
    );
    source(
        !link.resolvers.is_empty(),
        "resolver_configuration",
        &mut observed,
        &mut missing,
    );
    source(
        !link.addresses.is_empty(),
        "interface_addresses",
        &mut observed,
        &mut missing,
    );
    if link.requires_radio_evidence() {
        source(
            link.ssid.is_some(),
            "associated_ssid",
            &mut observed,
            &mut missing,
        );
        source(
            link.network_configuration
                .as_deref()
                .and_then(|value| value.associated_bssid.as_ref())
                .is_some(),
            "associated_bssid",
            &mut observed,
            &mut missing,
        );
        source(
            link.network_configuration
                .as_deref()
                .and_then(|value| value.connection_id.as_ref())
                .is_some(),
            "association_id",
            &mut observed,
            &mut missing,
        );
    }
    (observed, missing)
}

fn next_hop_link_address(app: &App) -> Option<String> {
    let gateway = app.link.gateway.as_deref()?;
    app.peers
        .peers
        .iter()
        .find(|peer| {
            peer.address == gateway
                && peer.interface.as_deref() == app.link.interface.as_deref()
                && !peer.binding_conflict
        })
        .and_then(|peer| peer.mac.clone())
}

fn source(available: bool, name: &str, observed: &mut Vec<String>, missing: &mut Vec<String>) {
    if available {
        observed.push(name.into());
    } else {
        missing.push(name.into());
    }
}

fn summarize(
    prior_records: &[HostPathObservationV0],
    current: &HostPathObservationV0,
) -> HistoryContext {
    let same_observer: Vec<_> = prior_records
        .iter()
        .filter(|record| record.source.observer_id == current.source.observer_id)
        .collect();
    let previous = same_observer.last().copied();
    let comparison = compare_contexts(previous, current);
    let recurrence = summarize_context_recurrence(prior_records, current);
    let matching = recurrence.exact_prior_observations;
    let compatible = recurrence.compatible_prior_observations;
    let previous_age = age_since(
        current,
        previous.map(|record| record.order.event_time_unix_ms),
    );
    let exact_age = age_since(current, recurrence.last_exact_observation_unix_ms);
    let dimensions = comparison.changed_dimensions.join(", ");
    let (attachment, compact_attachment) = attachment_evidence(current, &recurrence);
    let exact_match = recurrence.exact_context_match;
    let context_anchor = match (
        current.path.next_hop_link_address.as_ref(),
        current.path.network_name.visibility,
    ) {
        (Some(_), _) => "gateway link binding observed",
        (None, NetworkNameVisibilityV0::Observed) => {
            "limited: network name observed; gateway link binding absent"
        }
        (None, NetworkNameVisibilityV0::Restricted) => {
            "limited: network name restricted; gateway link binding absent"
        }
        (None, NetworkNameVisibilityV0::Unavailable) => {
            "limited: network name and gateway link binding unavailable"
        }
    };
    let place_authority = "unknown · assertion source not configured";
    let (kind, summary, compact_summary) = match (comparison.relation, exact_match) {
        (ContextRelationV0::FirstObservation, _) => (
            HistoryContextKind::FirstObservation,
            format!("first observation for this host · {attachment} · place unknown"),
            format!("first observation · {compact_attachment} · place unknown"),
        ),
        (ContextRelationV0::SameContext, ExactContextMatchV0::AnchoredExactRecurrence) => (
            HistoryContextKind::Recurring,
            format!(
                "recurring network context · {matching} exact prior · last {exact_age} · {attachment} · place unknown{}",
                changed_suffix(&dimensions)
            ),
            format!(
                "recurring · {matching} prior · {} · {compact_attachment} · place unknown",
                compact_age(&exact_age)
            ),
        ),
        (ContextRelationV0::SameContext, ExactContextMatchV0::UnanchoredExactKeyMatch) => (
            HistoryContextKind::Compatible,
            format!(
                "exact host-path key repeated · {matching} prior key match(es) · context identity unanchored · {attachment} · place unknown"
            ),
            format!("key repeated · {matching} prior · identity unanchored · {compact_attachment}"),
        ),
        (ContextRelationV0::SameContext, ExactContextMatchV0::NoPriorExactKeyMatch)
        | (ContextRelationV0::CompatibleContext, ExactContextMatchV0::NoPriorExactKeyMatch) => (
            HistoryContextKind::Compatible,
            format!(
                "compatible/incomplete prior context · {compatible} candidate(s) · changed {dimensions} · prior {previous_age} · {attachment} · place unknown"
            ),
            format!(
                "compatible/incomplete · {compatible} candidate(s) · {compact_attachment} · place unknown"
            ),
        ),
        (ContextRelationV0::CompatibleContext, ExactContextMatchV0::AnchoredExactRecurrence) => (
            HistoryContextKind::Recurring,
            format!(
                "recurring network context · {matching} exact prior · latest comparison incomplete · last exact {exact_age} · {attachment} · place unknown"
            ),
            format!(
                "recurring · {matching} prior · latest incomplete · {compact_attachment} · place unknown"
            ),
        ),
        (ContextRelationV0::CompatibleContext, ExactContextMatchV0::UnanchoredExactKeyMatch) => (
            HistoryContextKind::Compatible,
            format!(
                "compatible current path · {matching} prior exact key match(es), identity unanchored · {compatible} other compatible prior · {attachment} · place unknown"
            ),
            format!("compatible · {matching} key match(es) unanchored · {compact_attachment}"),
        ),
        (ContextRelationV0::ContextChanged, ExactContextMatchV0::AnchoredExactRecurrence) => (
            HistoryContextKind::Returned,
            format!(
                "returned to a known network context · {matching} exact prior · last exact {exact_age} · changed {dimensions} · {attachment} · place unknown"
            ),
            format!(
                "returned · {matching} prior · {} · changed {dimensions} · place unknown",
                compact_age(&exact_age)
            ),
        ),
        (ContextRelationV0::ContextChanged, ExactContextMatchV0::NoPriorExactKeyMatch)
        | (ContextRelationV0::ContextChanged, ExactContextMatchV0::UnanchoredExactKeyMatch) => (
            HistoryContextKind::Changed,
            format!(
                "new network context relative to prior · changed {dimensions} · prior {previous_age} · {}{attachment} · place unknown",
                if matches!(exact_match, ExactContextMatchV0::UnanchoredExactKeyMatch) {
                    "earlier exact key match is identity-unanchored · "
                } else {
                    ""
                }
            ),
            format!("new context · changed {dimensions} · {compact_attachment} · place unknown"),
        ),
    };
    HistoryContext {
        kind,
        summary,
        compact_summary,
        context_anchor: context_anchor.into(),
        place_authority: place_authority.into(),
        evidence: format!(
            "Netbraid history · netmon.host_path_observation.v0 · context anchor: {context_anchor} · place {place_authority}"
        ),
    }
}

fn attachment_evidence(
    current: &HostPathObservationV0,
    recurrence: &ContextRecurrenceV0,
) -> (String, String) {
    match (
        current.path.associated_bssid.as_ref(),
        recurrence.attachment_corroboration,
        recurrence.distinct_prior_associated_bssids,
        current.path.network_name.visibility,
    ) {
        (Some(_), AttachmentCorroborationV0::SeenBefore, variants, _) => (
            format!("known BSSID attachment · {variants} prior BSSID variant(s)"),
            format!("known BSSID · {variants} variant(s)"),
        ),
        (Some(_), AttachmentCorroborationV0::NotSeenBefore, variants, _) => (
            format!("new BSSID attachment · {variants} prior BSSID variant(s)"),
            format!("new BSSID · {variants} prior variant(s)"),
        ),
        (Some(_), AttachmentCorroborationV0::NotObserved, _, _) => (
            "first BSSID attachment evidence".into(),
            "first BSSID evidence".into(),
        ),
        (None, _, _, NetworkNameVisibilityV0::Restricted) => (
            "BSSID unavailable (macOS restricted)".into(),
            "BSSID hidden".into(),
        ),
        (None, _, _, _) => (
            "attachment identity unavailable".into(),
            "attachment unknown".into(),
        ),
    }
}

fn tail_warning(warning: &JsonlReadWarningV0) -> String {
    match warning {
        JsonlReadWarningV0::UnterminatedMalformedRecord {
            line,
            byte_offset,
            fragment_bytes,
        } => format!(
            "interrupted final record at line {line}, byte {byte_offset} ({fragment_bytes} byte fragment); read-only"
        ),
    }
}

fn age_since(current: &HostPathObservationV0, prior_unix_ms: Option<i64>) -> String {
    prior_unix_ms
        .map(|prior| human_age(current.order.event_time_unix_ms.saturating_sub(prior)))
        .unwrap_or_else(|| "unknown".into())
}

fn compact_age(age: &str) -> &str {
    age.strip_suffix(" ago").unwrap_or(age)
}

fn changed_suffix(dimensions: &str) -> String {
    if dimensions.is_empty() {
        String::new()
    } else {
        format!(" · changed {dimensions}")
    }
}

fn unix_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}

fn human_age(milliseconds: i64) -> String {
    let seconds = milliseconds.max(0) / 1_000;
    if seconds < 60 {
        format!("{seconds}s ago")
    } else if seconds < 3_600 {
        format!("{}m ago", seconds / 60)
    } else if seconds < 86_400 {
        format!("{}h ago", seconds / 3_600)
    } else {
        format!("{}d ago", seconds / 86_400)
    }
}

fn prepare_private_path(path: &Path) -> anyhow::Result<()> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    if parent.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(parent)?;
    make_private_directory(parent)
}

#[cfg(unix)]
fn make_private_directory(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn make_private_directory(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn make_private_file(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn make_private_file(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Address, MacScope, MonitorMode, NetworkConfiguration, Peer, PeerPathFilter, PeerSnapshot,
        ProbePolicy,
    };
    use ratatui::{Terminal, backend::TestBackend};

    fn app(ssid: &str, gateway: &str, bssid: &str) -> App {
        let mut app = App::new();
        app.path_generation = 1;
        app.link = LinkSnapshot {
            host: "workstation".into(),
            interface: Some("en0".into()),
            link_type: Some("wifi".into()),
            underlay: None,
            ssid: Some(ssid.into()),
            ssid_restricted: false,
            wifi: None,
            gateway: Some(gateway.into()),
            public_ip: None,
            resolvers: vec![gateway.into()],
            addresses: vec![Address {
                interface: "en0".into(),
                address: "192.0.2.22".into(),
                family: 4,
                is_default: true,
                is_temporary: false,
            }],
            network_configuration: Some(Box::new(NetworkConfiguration {
                connection_id: Some("7".into()),
                associated_bssid: Some(bssid.into()),
                bssid_restricted: false,
                method: Some("DHCP".into()),
                state: Some("BOUND".into()),
                server: Some(gateway.into()),
                subnet_mask: Some("255.255.255.0".into()),
                lease_seconds: None,
                lease_started_at: None,
                lease_expires_at: None,
                router_arp_verified: Some(true),
                security: Some("WPA3".into()),
            })),
        };
        app
    }

    fn with_order(
        mut record: HostPathObservationV0,
        record_id: &str,
        event_time_unix_ms: i64,
    ) -> HostPathObservationV0 {
        record.record_id = record_id.into();
        record.order.event_time_unix_ms = event_time_unix_ms;
        record.order.acquired_time_unix_ms = event_time_unix_ms;
        record.order.source_sequence = event_time_unix_ms.max(0) as u64;
        record
    }

    fn with_gateway_binding(mut app: App) -> App {
        app.peers = PeerSnapshot {
            health: crate::model::Health::Ok,
            detail: "complete native cache".into(),
            path_filter: PeerPathFilter::Applied,
            sources: vec!["arp -an".into(), "ndp -an".into()],
            failed_sources: Vec::new(),
            oui_source: None,
            peers: vec![Peer {
                address: app.link.gateway.clone().unwrap(),
                mac: Some("02:00:00:ff:00:01".into()),
                interface: app.link.interface.clone(),
                state: Some("REACHABLE".into()),
                binding_conflict: false,
                mac_scope: Some(MacScope::Local),
                registrant: None,
            }],
        };
        app
    }

    fn scenario_inputs(scenario_id: &str, checkpoint: &str) -> Vec<HostPathObservationV0> {
        let bundle = netbraid_replay::builtin_scenario_v0(scenario_id)
            .expect("load public synthetic scenario");
        let receipt =
            netbraid_replay::replay_scenario_v0(&bundle, checkpoint).expect("replay checkpoint");
        bundle
            .checkpoint_inputs_v0(&receipt)
            .expect("resolve receipt-bound checkpoint inputs")
            .host_path_records
    }

    fn scenario_app(record: &HostPathObservationV0, context: HistoryContext) -> App {
        let interface = record.path.interface.clone();
        let network_configuration = (record.path.association_id.is_some()
            || record.path.associated_bssid.is_some())
        .then(|| {
            Box::new(NetworkConfiguration {
                connection_id: record.path.association_id.clone(),
                associated_bssid: record.path.associated_bssid.clone(),
                bssid_restricted: false,
                method: None,
                state: None,
                server: None,
                subnet_mask: None,
                lease_seconds: None,
                lease_started_at: None,
                lease_expires_at: None,
                router_arp_verified: None,
                security: None,
            })
        });
        let mut app = App::new();
        app.path_generation = 1;
        app.link = LinkSnapshot {
            host: record.source.observer_id.clone(),
            interface,
            link_type: record.path.link_type.clone(),
            underlay: None,
            ssid: record.path.network_name.value.clone(),
            ssid_restricted: record.path.network_name.visibility
                == NetworkNameVisibilityV0::Restricted,
            wifi: None,
            gateway: record.path.next_hop.clone(),
            public_ip: None,
            resolvers: record.path.resolvers.clone(),
            // A HostPathObservation carries network boundaries, not reversible
            // host-address role or temporary-address evidence.
            addresses: Vec::new(),
            network_configuration,
        };
        app.history_context = Some(context);
        app
    }

    fn render_overview_text(app: &App, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("create deterministic terminal");
        terminal
            .draw(|frame| crate::ui::render(frame, app, MonitorMode::Overview, 0, true))
            .expect("render overview");
        let buffer = terminal.backend().buffer();
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

    #[test]
    fn maps_host_address_to_network_prefix() {
        assert_eq!(
            app("network-a", "192.0.2.1", "02:00:00:00:00:01")
                .link
                .default_path_prefixes(),
            vec!["192.0.2.0/24"]
        );
    }

    #[test]
    fn history_coverage_describes_only_the_serialized_passive_evidence() {
        let passive = with_gateway_binding(app("network-a", "192.0.2.1", "02:00:00:00:00:01"));
        let mut active = with_gateway_binding(app("network-a", "192.0.2.1", "02:00:00:00:00:01"));
        let mut degraded_peers =
            with_gateway_binding(app("network-a", "192.0.2.1", "02:00:00:00:00:01"));
        active.set_probe_policy(ProbePolicy::Active);
        degraded_peers.peers.health = crate::model::Health::Degraded;
        degraded_peers
            .peers
            .failed_sources
            .push("unrelated NDP source".into());

        assert_ne!(passive.evidence_coverage(), active.evidence_coverage());
        let passive_record = observation_from_app(&passive);
        let active_record = observation_from_app(&active);
        let degraded_peer_record = observation_from_app(&degraded_peers);

        assert_eq!(
            passive_record.policy,
            CollectionPolicyV0::passive_host_local()
        );
        assert_eq!(
            active_record.policy,
            CollectionPolicyV0::passive_host_local()
        );
        assert_eq!(passive_record.coverage, active_record.coverage);
        assert_eq!(passive_record.coverage, degraded_peer_record.coverage);
        assert_eq!(active_record.coverage.state, CoverageStateV0::Complete);
        assert!(active_record.coverage.missing_sources.is_empty());
    }

    #[test]
    fn history_coverage_distinguishes_partial_and_unavailable_record_sources() {
        let mut partial = with_gateway_binding(app("network-a", "192.0.2.1", "02:00:00:00:00:01"));
        partial.link.resolvers.clear();
        let partial = observation_from_app(&partial);
        assert_eq!(partial.coverage.state, CoverageStateV0::Partial);
        assert_eq!(
            partial.coverage.missing_sources,
            vec!["resolver_configuration"]
        );

        let unavailable = observation_from_app(&App::new());
        assert_eq!(unavailable.coverage.state, CoverageStateV0::Unavailable);
        assert!(unavailable.coverage.observed_sources.is_empty());
        assert!(!unavailable.coverage.missing_sources.is_empty());
    }

    #[test]
    fn missing_wifi_association_id_is_a_declared_coverage_gap() {
        let mut current = with_gateway_binding(app("network-a", "192.0.2.1", "02:00:00:00:00:01"));
        current
            .link
            .network_configuration
            .as_deref_mut()
            .unwrap()
            .connection_id = None;

        let record = observation_from_app(&current);

        assert_eq!(record.coverage.state, CoverageStateV0::Partial);
        assert!(
            record
                .coverage
                .missing_sources
                .contains(&"association_id".into())
        );
    }

    #[test]
    fn bssid_change_is_recurrence_evidence_not_a_new_context() {
        let mut first = with_order(
            observation_from_app(&app("network-a", "192.0.2.1", "02:00:00:00:00:01")),
            "first",
            1_000,
        );
        first.path.next_hop_link_address = Some("02:00:00:ff:00:01".into());
        let mut second = with_order(
            observation_from_app(&app("network-a", "192.0.2.1", "02:00:00:00:00:02")),
            "second",
            2_000,
        );
        second.path.next_hop_link_address = Some("02:00:00:ff:00:01".into());
        let summary = summarize(&[first], &second);

        assert_eq!(summary.kind, HistoryContextKind::Recurring);
        assert!(summary.summary.contains("recurring network context"));
        assert!(summary.summary.contains("new BSSID attachment"));
        assert!(summary.compact_summary.contains("new BSSID"));
        assert!(summary.evidence.contains("place unknown"));
    }

    #[test]
    fn netbraid_wifi_hotspot_return_is_reduced_as_observer_scoped_recurrence() {
        let records = scenario_inputs("wifi-hotspot-wifi", "wifi-returned");
        let summary = summarize(&records[..2], &records[2]);

        assert_eq!(records.len(), 3);
        assert_eq!(summary.kind, HistoryContextKind::Returned);
        assert!(
            summary
                .summary
                .contains("returned to a known network context")
        );
        assert!(summary.summary.contains("place unknown"));
        assert_eq!(
            summary.place_authority,
            "unknown · assertion source not configured"
        );
        assert!(!summary.summary.contains("owner"));
    }

    #[test]
    fn netbraid_overlay_exit_recurs_without_provider_or_intent_attribution() {
        let records = scenario_inputs("vpn-overlay-transition", "overlay-exited");
        let summary = summarize(&records[..2], &records[2]);

        assert_eq!(records.len(), 3);
        assert_eq!(summary.kind, HistoryContextKind::Returned);
        assert!(
            summary
                .summary
                .contains("returned to a known network context")
        );
        assert!(!summary.summary.to_lowercase().contains("provider"));
        assert!(!summary.summary.to_lowercase().contains("intent"));
        assert_eq!(
            summary.place_authority,
            "unknown · assertion source not configured"
        );
    }

    #[test]
    fn netbraid_cache_gap_remains_a_partial_first_observation_not_presence() {
        let records = scenario_inputs("cache-source-gap", "cache-stale");
        let current = records.last().expect("one cache-backed host-path record");
        let summary = summarize(&[], current);

        assert_eq!(records.len(), 1);
        assert_eq!(current.coverage.state, CoverageStateV0::Partial);
        assert!(
            current
                .coverage
                .missing_sources
                .contains(&"controller".into())
        );
        assert!(
            current
                .coverage
                .missing_sources
                .contains(&"packet_capture".into())
        );
        assert_eq!(summary.kind, HistoryContextKind::FirstObservation);
        assert!(!summary.summary.contains("present"));
        assert!(!summary.summary.contains("departed"));
    }

    #[test]
    fn netbraid_same_ssid_boundary_is_consistent_across_operator_surfaces() {
        for (checkpoint, expected_kind, wire_kind, summary_fragment, tui_fragment) in [
            (
                "mesh-baseline",
                HistoryContextKind::FirstObservation,
                "first_observation",
                "first observation for this host",
                "first observation",
            ),
            (
                "mesh-new-attachment",
                HistoryContextKind::Recurring,
                "recurring",
                "recurring network context",
                "recurring",
            ),
            (
                "same-label-new-boundary",
                HistoryContextKind::Changed,
                "changed",
                "new network context relative to prior",
                "new context",
            ),
        ] {
            let records = scenario_inputs("same-ssid-attachment-boundary", checkpoint);
            let current = records.last().expect("checkpoint has host-path evidence");
            let context = summarize(&records[..records.len() - 1], current);

            assert_eq!(context.kind, expected_kind);
            assert!(context.summary.contains(summary_fragment));
            assert!(context.summary.contains("place unknown"));
            assert_eq!(context.context_anchor, "gateway link binding observed");
            assert_eq!(
                context.place_authority,
                "unknown · assertion source not configured"
            );
            if checkpoint == "mesh-new-attachment" {
                assert!(context.summary.contains("new BSSID attachment"));
            }
            if checkpoint == "same-label-new-boundary" {
                assert!(context.summary.contains("next_hop_link_address"));
                assert!(context.summary.contains("resolvers"));
                assert!(context.summary.contains("address_prefixes"));
            }

            let app = scenario_app(current, context.clone());
            let plain_line =
                crate::plain::format_history_update(std::time::Duration::ZERO, &context.summary);
            assert!(plain_line.contains(summary_fragment));
            assert!(!plain_line.to_lowercase().contains("owner"));
            assert!(!plain_line.contains("802.11 roam"));

            let mut live = crate::output::LiveObservationStream::start(ProbePolicy::Passive, None);
            let document = live
                .observe(
                    crate::output::LiveTrigger::Link,
                    MonitorMode::Overview,
                    &app,
                )
                .expect("first material projection emits a live checkpoint");
            let projection = serde_json::to_value(document).unwrap();
            assert_eq!(projection["schema"], "linktop.live_observation.v1");
            assert_eq!(projection["acquisition"]["policy"], "passive");
            assert_eq!(projection["assessment"]["path_status"], "untested");
            assert_eq!(
                projection
                    .pointer("/evidence/history_context/kind")
                    .and_then(serde_json::Value::as_str),
                Some(wire_kind)
            );
            assert_eq!(
                projection
                    .pointer("/evidence/history_context/summary")
                    .and_then(serde_json::Value::as_str),
                Some(context.summary.as_str())
            );
            assert_eq!(
                projection
                    .pointer("/evidence/history_context/compact_summary")
                    .and_then(serde_json::Value::as_str),
                Some(context.compact_summary.as_str())
            );
            assert_eq!(
                projection
                    .pointer("/evidence/history_context/place_authority")
                    .and_then(serde_json::Value::as_str),
                Some("unknown · assertion source not configured")
            );

            for (width, height) in [(60, 10), (70, 14), (75, 10), (76, 10), (100, 24), (160, 30)] {
                let rendered = render_overview_text(&app, width, height);
                assert!(rendered.contains("Northstar Mesh"));
                assert!(!rendered.contains("location:"));
                assert!(!rendered.to_lowercase().contains("owner:"));
                assert!(!rendered.contains("802.11 roam"));
                if height == 10 {
                    assert!(
                        rendered.contains("default route observed"),
                        "{checkpoint} diagnosis missing at {width}x{height}:\n{rendered}"
                    );
                    assert!(
                        !rendered.contains(tui_fragment),
                        "{checkpoint} context displaced the minimum diagnosis at {width}x{height}:\n{rendered}"
                    );
                    assert!(rendered.contains("UNTESTED"));
                    assert!(rendered.contains("PASSIVE"));
                    assert!(rendered.contains("path"));
                    assert!(rendered.contains("coverage"));
                    assert!(
                        rendered.contains("next: [a] run bounded path probes")
                            || rendered.contains(
                                "next: [a] enables next-hop, DNS, HTTPS, and public-egress probes"
                            ),
                        "{checkpoint} complete action missing at {width}x{height}:\n{rendered}"
                    );
                } else {
                    assert!(
                        rendered.contains(tui_fragment) || rendered.contains(summary_fragment),
                        "{checkpoint} conclusion missing at {width}x{height}:\n{rendered}"
                    );
                }
                if matches!((width, height), (70, 14)) {
                    assert_eq!(
                        rendered.matches(tui_fragment).count(),
                        1,
                        "{checkpoint} context duplicated or omitted at {width}x{height}:\n{rendered}"
                    );
                }
            }
        }
    }

    #[test]
    fn same_ssid_with_a_different_boundary_is_a_new_context() {
        let first = with_order(
            observation_from_app(&app("common-name", "192.0.2.1", "02:00:00:00:00:01")),
            "first",
            1_000,
        );
        let second = with_order(
            observation_from_app(&app("common-name", "198.51.100.1", "02:00:00:00:00:02")),
            "second",
            2_000,
        );
        let summary = summarize(&[first], &second);

        assert_eq!(summary.kind, HistoryContextKind::Changed);
        assert!(summary.summary.contains("new network context"));
        assert!(summary.summary.contains("next_hop"));
    }

    #[test]
    fn known_bssid_is_attachment_evidence_not_place_identity() {
        let first = with_order(
            observation_from_app(&app("network-a", "192.0.2.1", "02:00:00:00:00:01")),
            "first",
            1_000,
        );
        let second = with_order(
            observation_from_app(&app("network-a", "192.0.2.1", "02:00:00:00:00:01")),
            "second",
            2_000,
        );

        let summary = summarize(&[first], &second);

        assert!(summary.summary.contains("known BSSID attachment"));
        assert!(summary.compact_summary.contains("known BSSID"));
        assert!(summary.evidence.contains("context anchor"));
        assert!(summary.evidence.contains("assertion source not configured"));
        assert_eq!(
            summary.place_authority,
            "unknown · assertion source not configured"
        );
    }

    #[test]
    fn sparse_exact_key_match_does_not_claim_recurring_context() {
        let mut first = with_order(
            observation_from_app(&app("network-a", "192.0.2.1", "02:00:00:00:00:01")),
            "first",
            1_000,
        );
        first.path.next_hop_link_address = None;
        first.path.associated_bssid = None;
        let mut second = first.clone();
        second.record_id = "second".into();
        second.order.event_time_unix_ms = 2_000;
        second.order.acquired_time_unix_ms = 2_000;
        second.order.source_sequence = 2_000;

        let summary = summarize(&[first], &second);

        assert_eq!(summary.kind, HistoryContextKind::Compatible);
        assert!(summary.summary.contains("exact host-path key repeated"));
        assert!(summary.summary.contains("identity unanchored"));
        assert!(!summary.summary.contains("recurring network context"));
    }

    #[test]
    fn loaded_history_discloses_that_current_assessment_is_pending() {
        let path = std::env::temp_dir().join(format!(
            "linktop-loaded-history-{}-{}.jsonl",
            std::process::id(),
            unix_millis()
        ));
        let record = with_order(
            observation_from_app(&app("network-a", "192.0.2.1", "02:00:00:00:00:01")),
            "first",
            1_000,
        );
        append_jsonl(&path, &record).expect("append history fixture");

        let session = HistorySession::open(path.clone());

        assert_eq!(session.initial.kind, HistoryContextKind::Loaded);
        assert!(session.initial.summary.contains("assessment pending"));
        assert!(!session.initial.summary.contains("compatible record"));
        std::fs::remove_file(path).expect("remove fixture");
    }

    #[test]
    fn malformed_history_is_disabled_and_left_unchanged() {
        let path = std::env::temp_dir().join(format!(
            "linktop-malformed-history-{}-{}.jsonl",
            std::process::id(),
            unix_millis()
        ));
        let original = b"{not compatible jsonl}\n";
        std::fs::write(&path, original).expect("write malformed fixture");

        let session = HistorySession::open(path.clone());

        assert!(!session.writable);
        assert_eq!(session.initial.kind, HistoryContextKind::Unavailable);
        assert!(session.initial.summary.contains("history unavailable"));
        assert_eq!(std::fs::read(&path).expect("read fixture"), original);
        std::fs::remove_file(path).expect("remove fixture");
    }

    #[test]
    fn interrupted_final_record_uses_valid_prefix_without_appending() {
        let path = std::env::temp_dir().join(format!(
            "linktop-interrupted-history-{}-{}.jsonl",
            std::process::id(),
            unix_millis()
        ));
        let record = with_order(
            observation_from_app(&app("network-a", "192.0.2.1", "02:00:00:00:00:01")),
            "first",
            1_000,
        );
        append_jsonl(&path, &record).expect("append valid prefix");
        let mut original = std::fs::read(&path).expect("read valid prefix");
        original.extend_from_slice(br#"{"schema":"netmon.host_path_observation.v0""#);
        std::fs::write(&path, &original).expect("write interrupted fixture");

        let mut session = HistorySession::open(path.clone());
        assert!(!session.writable);
        assert_eq!(session.records.len(), 1);
        assert!(session.recovered_tail.is_some());
        assert!(session.initial.summary.contains("history prefix loaded"));

        let mut current_app = app("network-a", "192.0.2.1", "02:00:00:00:00:01");
        current_app.peers.health = crate::model::Health::Ok;
        current_app.wifi_observation_settled = true;
        let update = MonitorUpdate::Peers {
            generation: current_app.path_generation,
            snapshot: current_app.peers.clone(),
        };
        let summary = session
            .observe_update(&update, &mut current_app)
            .expect("assess recovered prefix");

        assert!(summary.contains("read-only recovered prefix"));
        assert_eq!(std::fs::read(&path).expect("read fixture"), original);
        std::fs::remove_file(path).expect("remove fixture");
    }
}
