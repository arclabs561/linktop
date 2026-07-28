use std::fmt::Write as _;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};
use netbraid::replay::{
    SavedPcapClaimScopeV0, SavedPcapConversationDirectionV0, SavedPcapConversationExclusionCountV0,
    SavedPcapConversationTriageV0, SavedPcapEventWindowV0,
    SavedPcapNegativeClaimAbstentionReasonV1, SavedPcapNegativeClaimQualificationV1,
    SavedPcapPacketTimeBoundsV1, SavedPcapTopConversationV0, SavedPcapTrailingConversationTriageV1,
    SavedPcapTrailingIntervalAnchorV1, SavedPcapTrailingTopConversationV1,
    SavedPcapTrailingWindowTriageV1, SavedPcapTriageOptionsV1, SavedPcapTriageV1,
    SavedPcapWlanTriageV0, project_saved_pcap_triage_v1, read_saved_capture_jsonl,
};
use serde::Serialize;

const MIB: u64 = 1024 * 1024;
const NANOS_PER_SECOND: u64 = 1_000_000_000;

#[derive(Debug, Clone, Copy)]
pub struct TailSecondsArg {
    nanoseconds: u64,
}

impl TailSecondsArg {
    pub fn nanoseconds(self) -> u64 {
        self.nanoseconds
    }
}

impl FromStr for TailSecondsArg {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (whole, fractional) = value.split_once('.').unwrap_or((value, ""));
        if whole.is_empty()
            || !whole.bytes().all(|byte| byte.is_ascii_digit())
            || !fractional.bytes().all(|byte| byte.is_ascii_digit())
            || fractional.len() > 9
        {
            return Err(
                "must be a positive decimal number of seconds with at most 9 fractional digits"
                    .into(),
            );
        }
        let whole = whole
            .parse::<u64>()
            .map_err(|_| "tail duration is too large".to_string())?;
        let fractional_ns = if fractional.is_empty() {
            0
        } else {
            let digits = fractional
                .parse::<u64>()
                .map_err(|_| "tail duration is too large".to_string())?;
            digits
                .checked_mul(10_u64.pow(u32::try_from(9 - fractional.len()).unwrap()))
                .ok_or_else(|| "tail duration is too large".to_string())?
        };
        let nanoseconds = whole
            .checked_mul(NANOS_PER_SECOND)
            .and_then(|value| value.checked_add(fractional_ns))
            .filter(|value| *value > 0 && *value <= i64::MAX as u64)
            .ok_or_else(|| {
                format!(
                    "must be between 0.000000001 and {} seconds",
                    i64::MAX as u64 / NANOS_PER_SECOND
                )
            })?;
        Ok(Self { nanoseconds })
    }
}

pub fn run(
    path: &Path,
    max_input_mib: u64,
    json: bool,
    tail_seconds: Option<TailSecondsArg>,
) -> Result<()> {
    let max_bytes = max_input_mib
        .checked_mul(MIB)
        .context("--max-input-mib is too large")?;
    let triage = load(
        path,
        max_bytes,
        tail_seconds.map(TailSecondsArg::nanoseconds),
    )?;
    let rendered = if json {
        render_json(&triage)?
    } else {
        render_human(&triage)
    };
    let mut stdout = io::stdout().lock();
    stdout.write_all(rendered.as_bytes())?;
    stdout.flush()?;
    Ok(())
}

fn load(path: &Path, max_bytes: u64, tail_window_ns: Option<u64>) -> Result<SavedPcapTriageV1> {
    let records = read_saved_capture_jsonl(path, max_bytes)
        .with_context(|| format!("reading Netbraid evidence {}", path.display()))?;
    project_saved_pcap_triage_v1(&records, SavedPcapTriageOptionsV1 { tail_window_ns })
        .with_context(|| format!("projecting Netbraid evidence {}", path.display()))
}

fn render_json(triage: &SavedPcapTriageV1) -> Result<String> {
    let mut rendered = serde_json::to_string_pretty(triage)?;
    rendered.push('\n');
    Ok(rendered)
}

fn render_human(triage: &SavedPcapTriageV1) -> String {
    let mut output = String::new();
    let normalization = &triage.normalization;
    let source = &triage.source;
    let manifest = &source.manifest;
    let completeness = enum_label(&normalization.completeness);
    writeln!(
        output,
        "LINKTOP  SAVED EVIDENCE REVIEW / READ ONLY / COVERAGE {}",
        humanize(&completeness).to_ascii_uppercase()
    )
    .expect("writing to a String cannot fail");
    writeln!(output, "capture   {}", manifest.capture_id).expect("writing to a String cannot fail");
    writeln!(
        output,
        "artifact  {} / {} bytes",
        manifest.artifact.content_sha256, manifest.artifact.size_bytes
    )
    .expect("writing to a String cannot fail");
    writeln!(output, "records   {}", source.normalized_records_sha256)
        .expect("writing to a String cannot fail");
    writeln!(
        output,
        "observer  {} / acquired {}",
        manifest.observer_id.as_deref().unwrap_or("unknown"),
        manifest
            .acquired_time_unix_ms
            .map(|value| format!("{value} unix ms"))
            .unwrap_or_else(|| "unknown".into())
    )
    .expect("writing to a String cannot fail");
    render_acquisition(&mut output, manifest);
    writeln!(
        output,
        "extract   {} {} / {} {}",
        manifest.extractor.adapter,
        manifest.extractor.adapter_version,
        manifest.extractor.tool,
        manifest.extractor.tool_version
    )
    .expect("writing to a String cannot fail");
    writeln!(
        output,
        "config    {} / registry {}",
        manifest.extractor.configuration_sha256, manifest.extractor.field_registry
    )
    .expect("writing to a String cannot fail");
    render_receipt(&mut output, source.receipt.as_ref());
    writeln!(
        output,
        "normalize {} / {} / {} emitted / {} quarantined / {} inspected / limit {} / limit reached {}",
        humanize(&enum_label(&normalization.state)),
        humanize(&completeness),
        normalization.packet_rows_emitted,
        normalization.packet_rows_quarantined,
        normalization.packet_rows_inspected,
        normalization.packet_limit,
        yes_no(normalization.packet_limit_reached),
    )
    .expect("writing to a String cannot fail");
    if let Some(window) = &normalization.emitted_packet_window {
        render_window(&mut output, "window", window);
    } else {
        writeln!(output, "window    no normalized packet observations")
            .expect("writing to a String cannot fail");
    }

    render_quarantine(&mut output, triage);
    render_wlan(&mut output, &triage.wlan);
    render_conversation(&mut output, &triage.top_capture_conversation);
    if let Some(trailing_window) = &triage.trailing_window {
        render_trailing_window(&mut output, trailing_window);
    }
    writeln!(
        output,
        "classify  not assessed; endpoints and drill-down pivots are not service, application, device, or person identity"
    )
    .expect("writing to a String cannot fail");
    output
}

fn render_acquisition(output: &mut String, manifest: &netbraid::evidence::CaptureManifestV0) {
    let Some(policy) = &manifest.acquisition_policy else {
        writeln!(output, "acquire   policy unknown").expect("writing to a String cannot fail");
        return;
    };
    write!(output, "acquire   {}", humanize(&enum_label(&policy.mode)))
        .expect("writing to a String cannot fail");
    if !policy.active_actions.is_empty() {
        write!(output, " / actions {}", policy.active_actions.join(", "))
            .expect("writing to a String cannot fail");
    }
    output.push('\n');
}

fn render_receipt(output: &mut String, receipt: Option<&netbraid::evidence::CaptureRunReceiptV0>) {
    let Some(receipt) = receipt else {
        writeln!(
            output,
            "receipt   absent / occurrence times and source file extent unknown"
        )
        .expect("writing to a String cannot fail");
        return;
    };
    writeln!(
        output,
        "receipt   {} / run {}..{} unix ns / elapsed {} ns",
        receipt.run_id,
        receipt.started_time_unix_ns,
        receipt.finished_time_unix_ns,
        receipt.elapsed_ns
    )
    .expect("writing to a String cannot fail");
    write!(
        output,
        "file      {} / {} / {} / {} packet(s) / {} bytes",
        receipt.file.file_type,
        receipt.file.encapsulation,
        receipt.file.timestamp_precision,
        receipt.file.packet_count,
        receipt.file.file_size_bytes
    )
    .expect("writing to a String cannot fail");
    match (
        receipt.file.earliest_packet_time_unix_ns,
        receipt.file.latest_packet_time_unix_ns,
    ) {
        (Some(earliest), Some(latest)) => {
            write!(output, " / packet time {earliest}..{latest} unix ns")
                .expect("writing to a String cannot fail");
        }
        _ => {
            write!(output, " / packet time unknown").expect("writing to a String cannot fail");
        }
    }
    output.push('\n');
}

fn render_quarantine(output: &mut String, triage: &SavedPcapTriageV1) {
    let quarantine = &triage.quarantine;
    writeln!(
        output,
        "quarantine {} row(s) / {} distinct reason(s) / {} shown",
        quarantine.rows, quarantine.distinct_reasons, quarantine.reasons_shown
    )
    .expect("writing to a String cannot fail");
    for reason in &quarantine.top_reasons {
        writeln!(
            output,
            "  reason   {} row(s) / {}",
            reason.rows, reason.reason
        )
        .expect("writing to a String cannot fail");
    }
}

fn render_wlan(output: &mut String, wlan: &SavedPcapWlanTriageV0) {
    match wlan {
        SavedPcapWlanTriageV0::Insufficient { scope, reason } => {
            writeln!(
                output,
                "wlan      insufficient / {} / {}",
                scope_label(*scope),
                humanize(&enum_label(reason))
            )
            .expect("writing to a String cannot fail");
        }
        SavedPcapWlanTriageV0::Unsupported { scope, reason } => {
            writeln!(
                output,
                "wlan      unsupported / {} / {}",
                scope_label(*scope),
                humanize(&enum_label(reason))
            )
            .expect("writing to a String cannot fail");
        }
        SavedPcapWlanTriageV0::NotObserved { scope, wlan_window } => {
            writeln!(
                output,
                "wlan      disconnect frames not observed / {}",
                scope_label(*scope)
            )
            .expect("writing to a String cannot fail");
            render_window(output, "  window", wlan_window);
        }
        SavedPcapWlanTriageV0::Observed {
            scope,
            wlan_window,
            disconnects,
        } => {
            writeln!(
                output,
                "wlan      observed / {} / {} disconnect kind(s)",
                scope_label(*scope),
                disconnects.len()
            )
            .expect("writing to a String cannot fail");
            render_window(output, "  window", wlan_window);
            for disconnect in disconnects {
                writeln!(
                    output,
                    "  disconnect {} / {} observation(s) / {}..{} ns / span {} ns",
                    humanize(&enum_label(&disconnect.kind)),
                    disconnect.event_window.observations,
                    disconnect.event_window.earliest_event_time_unix_ns,
                    disconnect.event_window.latest_event_time_unix_ns,
                    disconnect.event_window.observed_span_ns
                )
                .expect("writing to a String cannot fail");
                writeln!(output, "  pivot    {}", disconnect.tshark_display_filter)
                    .expect("writing to a String cannot fail");
            }
        }
    }
}

fn render_conversation(output: &mut String, triage: &SavedPcapConversationTriageV0) {
    match triage {
        SavedPcapConversationTriageV0::Insufficient {
            scope,
            reason,
            packet_envelopes_seen,
            packet_envelopes_excluded,
            exclusions,
        } => {
            writeln!(
                output,
                "conversation insufficient / {} / {} / {} seen / {} excluded",
                scope_label(*scope),
                humanize(&enum_label(reason)),
                packet_envelopes_seen,
                packet_envelopes_excluded
            )
            .expect("writing to a String cannot fail");
            render_exclusions(output, exclusions);
        }
        SavedPcapConversationTriageV0::Unsupported {
            scope,
            reason,
            packet_envelopes_seen,
            packet_envelopes_excluded,
            exclusions,
        } => {
            writeln!(
                output,
                "conversation unsupported / {} / {} / {} seen / {} excluded",
                scope_label(*scope),
                humanize(&enum_label(reason)),
                packet_envelopes_seen,
                packet_envelopes_excluded
            )
            .expect("writing to a String cannot fail");
            render_exclusions(output, exclusions);
        }
        SavedPcapConversationTriageV0::Observed {
            scope,
            packet_envelopes_seen,
            packet_envelopes_grouped,
            packet_envelopes_excluded,
            exclusions,
            conversation,
        } => {
            writeln!(
                output,
                "conversation observed / {} / {} seen / {} grouped / {} excluded",
                scope_label(*scope),
                packet_envelopes_seen,
                packet_envelopes_grouped,
                packet_envelopes_excluded
            )
            .expect("writing to a String cannot fail");
            render_exclusions(output, exclusions);
            render_top_conversation(output, conversation);
        }
    }
}

fn render_exclusions(output: &mut String, exclusions: &[SavedPcapConversationExclusionCountV0]) {
    for exclusion in exclusions {
        writeln!(
            output,
            "  excluded {} packet envelope(s) / {}",
            exclusion.packet_envelopes,
            humanize(&enum_label(&exclusion.reason))
        )
        .expect("writing to a String cannot fail");
    }
}

fn render_top_conversation(output: &mut String, conversation: &SavedPcapTopConversationV0) {
    let endpoint_a = SocketAddr::new(
        conversation.endpoint_a.address,
        conversation.endpoint_a.port,
    );
    let endpoint_b = SocketAddr::new(
        conversation.endpoint_b.address,
        conversation.endpoint_b.port,
    );
    writeln!(
        output,
        "  top      {} {} <-> {} / {} / temporal relevance {}",
        humanize(&enum_label(&conversation.transport)).to_ascii_uppercase(),
        endpoint_a,
        endpoint_b,
        humanize(&enum_label(&conversation.aggregation)),
        humanize(&enum_label(&conversation.temporal_relevance))
    )
    .expect("writing to a String cannot fail");
    writeln!(
        output,
        "  point    section {} / interface {} / encapsulation {}",
        optional_number(conversation.observation_point.section_number),
        optional_number(conversation.observation_point.interface_id),
        optional_number(conversation.observation_point.encapsulation_type)
    )
    .expect("writing to a String cannot fail");
    writeln!(
        output,
        "  frames   {} / {} original frame octets / {} captured frame octets",
        conversation.total_frames,
        conversation.total_original_frame_octets,
        conversation.total_captured_frame_octets
    )
    .expect("writing to a String cannot fail");
    render_direction(output, "a -> b", &conversation.a_to_b);
    render_direction(output, "b -> a", &conversation.b_to_a);
    writeln!(
        output,
        "  time     {}..{} ns / span {} ns",
        conversation.earliest_event_time_unix_ns,
        conversation.latest_event_time_unix_ns,
        conversation.observed_span_ns
    )
    .expect("writing to a String cannot fail");
    writeln!(
        output,
        "  pivot    {}",
        conversation.tshark_candidate_display_filter
    )
    .expect("writing to a String cannot fail");
}

fn render_trailing_window(output: &mut String, trailing: &SavedPcapTrailingWindowTriageV1) {
    writeln!(
        output,
        "trailing  requested {} ns / anchor {}",
        trailing.requested_duration_ns,
        trailing
            .interval_anchor
            .map(trailing_anchor_label)
            .unwrap_or("unavailable")
    )
    .expect("writing to a String cannot fail");
    render_packet_bounds(output, "  request", trailing.requested_interval.as_ref());
    match &trailing.source_artifact_packet_extent {
        Some(bounds) => render_packet_bounds(output, "  source", Some(bounds)),
        None => writeln!(output, "  source   unavailable from occurrence receipt")
            .expect("writing to a String cannot fail"),
    }
    match &trailing.normalized_packet_artifact_extent {
        Some(window) => render_window(output, "  normal", window),
        None => writeln!(output, "  normal   no normalized packet envelopes")
            .expect("writing to a String cannot fail"),
    }
    match &trailing.selected_packet_extent {
        Some(window) => render_window(output, "  selected", window),
        None => writeln!(output, "  selected no packet envelopes")
            .expect("writing to a String cannot fail"),
    }
    match &trailing.negative_claim_qualification {
        SavedPcapNegativeClaimQualificationV1::Qualified { basis } => {
            writeln!(
                output,
                "  negative qualified / {}",
                humanize(&enum_label(basis))
            )
            .expect("writing to a String cannot fail");
        }
        SavedPcapNegativeClaimQualificationV1::Abstained { reasons } => {
            writeln!(
                output,
                "  negative abstained / {}",
                reasons
                    .iter()
                    .map(|reason| negative_claim_reason(*reason))
                    .collect::<Vec<_>>()
                    .join("; ")
            )
            .expect("writing to a String cannot fail");
        }
    }
    render_trailing_conversation(output, &trailing.top_conversation);
}

fn render_packet_bounds(
    output: &mut String,
    label: &str,
    bounds: Option<&SavedPcapPacketTimeBoundsV1>,
) {
    match bounds {
        Some(bounds) => writeln!(
            output,
            "{label:<11}{}..{} unix ns / inclusive",
            bounds.start_event_time_unix_ns, bounds.end_event_time_unix_ns
        )
        .expect("writing to a String cannot fail"),
        None => {
            writeln!(output, "{label:<11}unavailable").expect("writing to a String cannot fail")
        }
    }
}

fn render_trailing_conversation(
    output: &mut String,
    triage: &SavedPcapTrailingConversationTriageV1,
) {
    match triage {
        SavedPcapTrailingConversationTriageV1::Abstained {
            packet_envelopes_seen,
            packet_envelopes_excluded,
            exclusions,
        } => {
            writeln!(
                output,
                "  top      abstained / {packet_envelopes_seen} seen / \
                 {packet_envelopes_excluded} excluded / absence not qualified"
            )
            .expect("writing to a String cannot fail");
            render_exclusions(output, exclusions);
        }
        SavedPcapTrailingConversationTriageV1::NotObserved {
            packet_envelopes_seen,
            packet_envelopes_excluded,
            exclusions,
        } => {
            writeln!(
                output,
                "  top      not observed in qualified interval / {packet_envelopes_seen} seen / \
                 {packet_envelopes_excluded} excluded"
            )
            .expect("writing to a String cannot fail");
            render_exclusions(output, exclusions);
        }
        SavedPcapTrailingConversationTriageV1::Observed {
            packet_envelopes_seen,
            packet_envelopes_grouped,
            packet_envelopes_excluded,
            exclusions,
            conversation,
        } => {
            writeln!(
                output,
                "  top      observed / {packet_envelopes_seen} seen / \
                 {packet_envelopes_grouped} grouped / {packet_envelopes_excluded} excluded"
            )
            .expect("writing to a String cannot fail");
            render_exclusions(output, exclusions);
            render_trailing_top_conversation(output, conversation);
        }
    }
}

fn render_trailing_top_conversation(
    output: &mut String,
    conversation: &SavedPcapTrailingTopConversationV1,
) {
    let endpoint_a = SocketAddr::new(
        conversation.endpoint_a.address,
        conversation.endpoint_a.port,
    );
    let endpoint_b = SocketAddr::new(
        conversation.endpoint_b.address,
        conversation.endpoint_b.port,
    );
    writeln!(
        output,
        "  interval {} {} <-> {} / {} / {}",
        humanize(&enum_label(&conversation.transport)).to_ascii_uppercase(),
        endpoint_a,
        endpoint_b,
        humanize(&enum_label(&conversation.aggregation)),
        humanize(&enum_label(&conversation.temporal_basis))
    )
    .expect("writing to a String cannot fail");
    writeln!(
        output,
        "  point    section {} / interface {} / encapsulation {}",
        optional_number(conversation.observation_point.section_number),
        optional_number(conversation.observation_point.interface_id),
        optional_number(conversation.observation_point.encapsulation_type)
    )
    .expect("writing to a String cannot fail");
    writeln!(
        output,
        "  frames   {} / {} original frame octets / {} captured frame octets",
        conversation.total_frames,
        conversation.total_original_frame_octets,
        conversation.total_captured_frame_octets
    )
    .expect("writing to a String cannot fail");
    render_direction(output, "a -> b", &conversation.a_to_b);
    render_direction(output, "b -> a", &conversation.b_to_a);
    writeln!(
        output,
        "  time     {}..{} ns / span {} ns",
        conversation.earliest_event_time_unix_ns,
        conversation.latest_event_time_unix_ns,
        conversation.observed_span_ns
    )
    .expect("writing to a String cannot fail");
    writeln!(
        output,
        "  pivot    {}",
        conversation.tshark_candidate_display_filter
    )
    .expect("writing to a String cannot fail");
}

fn trailing_anchor_label(anchor: SavedPcapTrailingIntervalAnchorV1) -> &'static str {
    match anchor {
        SavedPcapTrailingIntervalAnchorV1::SourceArtifactLatestPacketTime => {
            "occurrence receipt source-artifact latest packet time"
        }
        SavedPcapTrailingIntervalAnchorV1::LatestNormalizedPacketEventTime => {
            "latest normalized packet event time"
        }
    }
}

fn negative_claim_reason(reason: SavedPcapNegativeClaimAbstentionReasonV1) -> &'static str {
    match reason {
        SavedPcapNegativeClaimAbstentionReasonV1::NoNormalizedPacketEnvelopes => {
            "no normalized packet envelopes"
        }
        SavedPcapNegativeClaimAbstentionReasonV1::PartialNormalization => {
            "normalization is partial"
        }
        SavedPcapNegativeClaimAbstentionReasonV1::MissingOccurrenceReceipt => {
            "occurrence receipt is absent"
        }
        SavedPcapNegativeClaimAbstentionReasonV1::MissingReceiptFilePacketTimeBounds => {
            "receipt has no file packet-time bounds"
        }
        SavedPcapNegativeClaimAbstentionReasonV1::SourceArtifactExtentDoesNotSpanRequestedInterval => {
            "source-artifact extent does not span requested interval"
        }
    }
}

fn render_direction(
    output: &mut String,
    label: &str,
    direction: &SavedPcapConversationDirectionV0,
) {
    write!(
        output,
        "  {label:<8} {} frame(s) / {} original / {} captured",
        direction.frames, direction.original_frame_octets, direction.captured_frame_octets
    )
    .expect("writing to a String cannot fail");
    if let Some(flags) = &direction.tcp_flags {
        write!(
            output,
            " / SYN {} / SYN-ACK {} / FIN {} / RST {}",
            flags.syn_without_ack_frames, flags.syn_ack_frames, flags.fin_frames, flags.rst_frames
        )
        .expect("writing to a String cannot fail");
    }
    output.push('\n');
}

fn render_window(output: &mut String, label: &str, window: &SavedPcapEventWindowV0) {
    writeln!(
        output,
        "{label:<11}{} observation(s) / {}..{} ns / span {} ns",
        window.observations,
        window.earliest_event_time_unix_ns,
        window.latest_event_time_unix_ns,
        window.observed_span_ns
    )
    .expect("writing to a String cannot fail");
}

fn scope_label(scope: SavedPcapClaimScopeV0) -> String {
    humanize(&enum_label(&scope))
}

fn enum_label(value: &impl Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".into())
}

fn humanize(value: &str) -> String {
    value.replace('_', " ")
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn optional_number(value: Option<impl ToString>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(test)]
mod tests;
