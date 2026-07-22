use std::io;
use std::process::Command;
use std::thread;
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
    pub gateway_latency: LoadedLatency,
    pub transfer: TransferSummary,
}

#[derive(Debug, Serialize)]
pub struct LoadedLatency {
    pub baseline: Option<ProbeResult>,
    pub loaded: Option<ProbeResult>,
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

pub fn run(target: &str, port: u16, duration: Duration) -> Result<SpeedReport> {
    let gateway = net::default_gateway();
    let baseline = gateway
        .as_deref()
        .map(|gateway| net::probe_gateway(Some(gateway), 5));
    let loaded_gateway = gateway.clone();
    let loaded = thread::spawn(move || {
        loaded_gateway
            .as_deref()
            .map(|gateway| net::probe_gateway(Some(gateway), 5))
    });

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
    let output = match process::run_bounded(&mut command, duration + Duration::from_secs(15)) {
        Ok(Some(output)) => output,
        Ok(None) => bail!("iperf3 exceeded its {}s deadline", duration.as_secs() + 15),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            bail!("iperf3 is required for an explicit load test")
        }
        Err(error) => return Err(error).context("run iperf3"),
    };
    let loaded = loaded
        .join()
        .map_err(|_| anyhow::anyhow!("loaded-latency worker panicked"))?;
    let report: IperfReport = serde_json::from_slice(&output.stdout).with_context(|| {
        let detail = String::from_utf8_lossy(&output.stderr);
        format!("parse iperf3 JSON: {}", detail.trim())
    })?;
    if !output.status.success() || report.end.is_none() {
        bail!(
            "iperf3 did not complete: {}",
            report.error.as_deref().unwrap_or("no completed report")
        );
    }
    let end = report.end.expect("checked above");
    let transfer = TransferSummary {
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
    };
    Ok(SpeedReport {
        tool: "iperf3",
        mode: "tcp",
        target: target.into(),
        port,
        duration_s: duration.as_secs(),
        gateway_latency: LoadedLatency { baseline, loaded },
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
    fn parses_the_bounded_iperf_fields() {
        let report: IperfReport = serde_json::from_str(
            r#"{"end":{"sum_sent":{"bits_per_second":1000000,"retransmits":2},"sum_received":{"bits_per_second":900000}}}"#,
        )
        .unwrap();
        let end = report.end.unwrap();
        assert_eq!(end.sum_sent.unwrap().retransmits, Some(2));
        assert_eq!(end.sum_received.unwrap().bits_per_second, Some(900_000.0));
    }
}
