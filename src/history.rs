use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use netmon_evidence::{
    CollectionPolicyV0, CoverageStateV0, CoverageV0, HOST_PATH_SCHEMA_V0, HostPathObservationV0,
    HostPathV0, NetworkNameV0, NetworkNameVisibilityV0, ObservationOrderV0, SourceRefV0,
};
use netmon_replay::{ContextRelationV0, append_jsonl, compare_contexts, read_jsonl};

use crate::model::{
    App, EvidenceCoverage, HistoryContext, HistoryContextKind, LinkSnapshot, MonitorUpdate,
};

pub struct HistorySession {
    path: PathBuf,
    records: Vec<HostPathObservationV0>,
    recorded_generation: Option<u64>,
    writable: bool,
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
                initial: HistoryContext {
                    kind: HistoryContextKind::Configured,
                    summary: "history configured; no prior evidence log".into(),
                    evidence: "private JSONL · retention explicitly enabled".into(),
                },
            };
        }
        match read_jsonl(&path) {
            Ok(state) => {
                let count = state.records.len();
                Self {
                    path,
                    records: state.records,
                    recorded_generation: None,
                    writable: true,
                    initial: HistoryContext {
                        kind: HistoryContextKind::Loaded,
                        summary: format!("history loaded: {count} compatible record(s)"),
                        evidence: "netmon host-path v0 · private JSONL".into(),
                    },
                }
            }
            Err(error) => Self {
                path,
                records: Vec::new(),
                recorded_generation: None,
                writable: false,
                initial: HistoryContext {
                    kind: HistoryContextKind::Unavailable,
                    summary: format!("history unavailable: {error}"),
                    evidence: "current live diagnosis is unaffected; log left unchanged".into(),
                },
            },
        }
    }

    pub fn attach(&self, app: &mut App) {
        app.history_context = Some(self.initial.clone());
    }

    pub fn observe_update(&mut self, update: &MonitorUpdate, app: &mut App) -> Option<String> {
        if !self.writable
            || self.recorded_generation == Some(app.path_generation)
            || !update_completes_context(update, app)
            || app.link.interface.is_none()
        {
            return None;
        }

        let mut record = observation_from_app(app);
        record.canonicalize();
        let context = summarize(&self.records, &record);
        if let Err(error) = prepare_private_path(&self.path)
            .and_then(|()| append_jsonl(&self.path, &record).map_err(anyhow::Error::from))
            .and_then(|()| make_private_file(&self.path))
        {
            self.writable = false;
            let status = HistoryContext {
                kind: HistoryContextKind::AppendFailed,
                summary: format!("history append failed: {error}"),
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
    let coverage = if missing_sources.is_empty() {
        match app.evidence_coverage() {
            EvidenceCoverage::Complete => CoverageStateV0::Complete,
            EvidenceCoverage::Unavailable => CoverageStateV0::Unavailable,
            EvidenceCoverage::Collecting | EvidenceCoverage::Partial => CoverageStateV0::Partial,
        }
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
            address_prefixes: path_prefixes(&app.link),
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
    if link
        .link_type
        .as_deref()
        .is_some_and(|kind| kind.eq_ignore_ascii_case("wifi"))
    {
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
    let matching = same_observer
        .iter()
        .filter(|record| record.context_key() == current.context_key())
        .count();
    let compatible = same_observer
        .iter()
        .filter(|record| netmon_replay::contexts_are_compatible(record, current))
        .count();
    let age = previous
        .map(|record| {
            human_age(
                current
                    .order
                    .event_time_unix_ms
                    .saturating_sub(record.order.event_time_unix_ms),
            )
        })
        .unwrap_or_default();
    let dimensions = comparison.changed_dimensions.join(", ");
    let (kind, summary) = match (comparison.relation, matching) {
        (ContextRelationV0::FirstObservation, _) => (
            HistoryContextKind::FirstObservation,
            "first observation for this host in the evidence log".into(),
        ),
        (ContextRelationV0::SameContext, _) => (
            HistoryContextKind::Recurring,
            format!(
                "recurring network context · {matching} prior observation(s) · last {age}{}",
                changed_suffix(&dimensions)
            ),
        ),
        (ContextRelationV0::CompatibleContext, _) => (
            HistoryContextKind::Compatible,
            format!(
                "compatible prior context · {compatible} candidate(s) · incomplete evidence prevents same/change claim · changed {dimensions} · prior {age}"
            ),
        ),
        (ContextRelationV0::ContextChanged, 0) => (
            HistoryContextKind::Changed,
            format!(
                "new network context relative to the prior record · changed {dimensions} · prior {age}"
            ),
        ),
        (ContextRelationV0::ContextChanged, _) => (
            HistoryContextKind::Returned,
            format!(
                "returned to a known network context · {matching} prior observation(s) · changed {dimensions} · prior {age}"
            ),
        ),
    };
    let place = match (
        current.path.associated_bssid.as_ref(),
        current.path.next_hop_link_address.as_ref(),
        current.path.network_name.visibility,
    ) {
        (Some(_), _, _) => "place candidate evidence: associated BSSID observed; no place asserted",
        (None, Some(_), _) => {
            "place candidate evidence: gateway link binding observed; no place asserted"
        }
        (None, None, NetworkNameVisibilityV0::Restricted) => {
            "place candidate limited: SSID/BSSID restricted by the platform"
        }
        (None, None, _) => "place candidate limited: no BSSID or gateway link binding",
    };
    HistoryContext {
        kind,
        summary,
        evidence: format!("netmon host-path v0 · {place}"),
    }
}

fn changed_suffix(dimensions: &str) -> String {
    if dimensions.is_empty() {
        String::new()
    } else {
        format!(" · changed {dimensions}")
    }
}

fn path_prefixes(link: &LinkSnapshot) -> Vec<String> {
    link.addresses
        .iter()
        .filter(|address| address.is_default)
        .filter_map(|address| match address.address.parse::<IpAddr>().ok()? {
            IpAddr::V4(value) => link
                .network_configuration
                .as_deref()
                .and_then(|configuration| configuration.subnet_mask.as_deref())
                .and_then(|mask| ipv4_prefix(value, mask)),
            IpAddr::V6(value) if value.is_unicast_link_local() => None,
            IpAddr::V6(value) => {
                let segments = value.segments();
                Some(format!(
                    "{:x}:{:x}:{:x}:{:x}::/64",
                    segments[0], segments[1], segments[2], segments[3]
                ))
            }
        })
        .collect()
}

fn ipv4_prefix(address: Ipv4Addr, mask: &str) -> Option<String> {
    let mask = u32::from(mask.parse::<Ipv4Addr>().ok()?);
    let inverted = !mask;
    if inverted & inverted.wrapping_add(1) != 0 {
        return None;
    }
    let prefix = mask.count_ones();
    let network = Ipv4Addr::from(u32::from(address) & mask);
    Some(format!("{network}/{prefix}"))
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
    use crate::model::{Address, NetworkConfiguration};

    fn app(ssid: &str, gateway: &str, bssid: &str) -> App {
        let mut app = App::new();
        app.path_generation = 1;
        app.link = LinkSnapshot {
            host: "workstation".into(),
            interface: Some("en0".into()),
            link_type: Some("wifi".into()),
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

    #[test]
    fn maps_host_address_to_network_prefix() {
        assert_eq!(
            path_prefixes(&app("network-a", "192.0.2.1", "02:00:00:00:00:01").link),
            vec!["192.0.2.0/24"]
        );
    }

    #[test]
    fn bssid_change_is_recurrence_evidence_not_a_new_context() {
        let first = observation_from_app(&app("network-a", "192.0.2.1", "02:00:00:00:00:01"));
        let second = observation_from_app(&app("network-a", "192.0.2.1", "02:00:00:00:00:02"));
        let summary = summarize(&[first], &second);

        assert_eq!(summary.kind, HistoryContextKind::Recurring);
        assert!(summary.summary.contains("recurring network context"));
        assert!(summary.summary.contains("associated_bssid"));
        assert!(summary.evidence.contains("no place asserted"));
    }

    #[test]
    fn same_ssid_with_a_different_boundary_is_a_new_context() {
        let first = observation_from_app(&app("common-name", "192.0.2.1", "02:00:00:00:00:01"));
        let second = observation_from_app(&app("common-name", "198.51.100.1", "02:00:00:00:00:02"));
        let summary = summarize(&[first], &second);

        assert_eq!(summary.kind, HistoryContextKind::Changed);
        assert!(summary.summary.contains("new network context"));
        assert!(summary.summary.contains("next_hop"));
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
}
