use std::io;
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::model::ProbeResult;
use crate::{net, process};

#[derive(Debug, Serialize)]
pub struct SpeedReport {
    pub tool: &'static str,
    pub mode: &'static str,
    pub target: String,
    pub port: u16,
    pub duration_s: u64,
    pub gateway_latency: InterventionLatency,
    pub transfer: TransferSummary,
}

#[derive(Debug, Serialize)]
pub struct InterventionLatency {
    pub before: Option<ProbeResult>,
    pub after_spawn: Option<ProbeResult>,
    pub after_exit: Option<ProbeResult>,
    pub limitations: [&'static str; 3],
}

#[derive(Debug, Serialize)]
pub struct TransferSummary {
    pub sent_bits_per_second: Option<f64>,
    pub received_bits_per_second: Option<f64>,
    pub retransmits: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct IperfReport {
    end: Option<IperfEnd>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IperfEnd {
    sum_sent: Option<IperfSummary>,
    sum_received: Option<IperfSummary>,
}

#[derive(Debug, Deserialize)]
struct IperfSummary {
    bits_per_second: Option<f64>,
    retransmits: Option<u64>,
}

fn parse_iperf_json(stdout: &[u8], stderr: &str) -> Result<IperfReport> {
    serde_json::from_slice(stdout).with_context(|| format!("parse iperf3 JSON: {}", stderr.trim()))
}

fn summarize_iperf_report(report: IperfReport, command_succeeded: bool) -> Result<TransferSummary> {
    if !command_succeeded || report.end.is_none() {
        bail!(
            "iperf3 did not complete: {}",
            report.error.as_deref().unwrap_or("no completed report")
        );
    }
    let end = report.end.expect("checked above");
    Ok(TransferSummary {
        sent_bits_per_second: end
            .sum_sent
            .as_ref()
            .and_then(|summary| summary.bits_per_second),
        received_bits_per_second: end
            .sum_received
            .as_ref()
            .and_then(|summary| summary.bits_per_second),
        retransmits: end
            .sum_sent
            .as_ref()
            .and_then(|summary| summary.retransmits),
    })
}

pub fn run(target: &str, port: u16, duration: Duration) -> Result<SpeedReport> {
    let gateway = net::default_gateway();
    let before = gateway
        .as_deref()
        .map(|gateway| net::probe_gateway(Some(gateway), 5));

    let mut command = Command::new("iperf3");
    command.args([
        "-J",
        "-c",
        target,
        "-p",
        &port.to_string(),
        "-t",
        &duration.as_secs().to_string(),
    ]);
    let (output, after_spawn) =
        match process::run_bounded_with(&mut command, duration + Duration::from_secs(15), || {
            gateway
                .as_deref()
                .map(|gateway| net::probe_gateway(Some(gateway), 5))
        }) {
            Ok((Some(output), after_spawn)) => (output, after_spawn),
            Ok((None, _)) => bail!("iperf3 exceeded its {}s deadline", duration.as_secs() + 15),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                bail!("iperf3 is required for an explicit load test")
            }
            Err(error) => return Err(error).context("run iperf3"),
        };
    let after_exit = gateway
        .as_deref()
        .map(|gateway| net::probe_gateway(Some(gateway), 5));
    let report = parse_iperf_json(&output.stdout, &String::from_utf8_lossy(&output.stderr))?;
    let transfer = summarize_iperf_report(report, output.status.success())?;
    Ok(SpeedReport {
        tool: "iperf3",
        mode: "tcp",
        target: target.into(),
        port,
        duration_s: duration.as_secs(),
        gateway_latency: InterventionLatency {
            before,
            after_spawn,
            after_exit,
            limitations: [
                "the after-spawn probe does not prove overlap with a short-lived transfer",
                "the after-exit probe does not establish recovery",
                "gateway latency is not end-to-end transfer latency",
            ],
        },
        transfer,
    })
}

pub fn human_rate(bits_per_second: Option<f64>) -> String {
    let Some(mut rate) = bits_per_second else {
        return "?".into();
    };
    for unit in ["bit/s", "Kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"] {
        if rate < 1_000.0 || unit == "Tbit/s" {
            return format!("{rate:.2} {unit}");
        }
        rate /= 1_000.0;
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_decimal_network_rates() {
        assert_eq!(human_rate(Some(1_000.0)), "1.00 Kbit/s");
        assert_eq!(human_rate(Some(1_000_000.0)), "1.00 Mbit/s");
        assert_eq!(human_rate(None), "?");
    }

    #[test]
    fn parses_the_bounded_iperf_fields_from_the_production_helper() {
        let report = parse_iperf_json(
            br#"{"end":{"sum_sent":{"bits_per_second":1000000,"retransmits":2},"sum_received":{"bits_per_second":900000}}}"#,
            "",
        )
        .unwrap();
        let transfer = summarize_iperf_report(report, true).unwrap();
        assert_eq!(transfer.sent_bits_per_second, Some(1_000_000.0));
        assert_eq!(transfer.received_bits_per_second, Some(900_000.0));
        assert_eq!(transfer.retransmits, Some(2));
    }

    #[test]
    fn rejects_malformed_or_incomplete_iperf_results() {
        let malformed = parse_iperf_json(b"not json", "server said no").unwrap_err();
        assert!(malformed.to_string().contains("parse iperf3 JSON"));

        let report: IperfReport = serde_json::from_str(
            r#"{"end":{"sum_sent":{"bits_per_second":1000000,"retransmits":2},"sum_received":{"bits_per_second":900000}}}"#,
        )
        .unwrap();
        let failed = summarize_iperf_report(report, false).unwrap_err();
        assert!(failed.to_string().contains("iperf3 did not complete"));

        let report: IperfReport =
            serde_json::from_str(r#"{"error":"connection refused"}"#).unwrap();
        let incomplete = summarize_iperf_report(report, true).unwrap_err();
        assert!(incomplete.to_string().contains("connection refused"));
    }
}
