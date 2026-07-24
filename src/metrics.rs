use serde::Serialize;

use crate::model::{Health, MIN_GATEWAY_ASSESSMENT_SAMPLES};

pub const DEGRADED_MEAN_ABS_RTT_DELTA_MS: f64 = 15.0;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LatencyMetrics {
    pub sent: usize,
    pub received: usize,
    pub lost: usize,
    pub loss_rate: Option<f64>,
    pub rtt_min_ms: Option<f64>,
    pub rtt_mean_ms: Option<f64>,
    pub rtt_p50_ms: Option<f64>,
    pub rtt_p95_ms: Option<f64>,
    pub rtt_p99_ms: Option<f64>,
    pub rtt_max_ms: Option<f64>,
    pub rtt_sample_variance_ms2: Option<f64>,
    pub rtt_sample_stddev_ms: Option<f64>,
    pub mean_abs_adjacent_rtt_delta_ms: Option<f64>,
    pub positive_adjacent_rtt_delta_p95_ms: Option<f64>,
    pub rtt_delta_from_min_p95_ms: Option<f64>,
    pub rtt_delta_from_min_max_ms: Option<f64>,
    pub adjacent_rtt_pairs: usize,
}

impl LatencyMetrics {
    pub fn from_samples(samples: &[f64], sent: usize) -> Self {
        let received = samples.len();
        let lost = sent.saturating_sub(received);
        let mean = (!samples.is_empty()).then(|| samples.iter().sum::<f64>() / received as f64);
        let variance = match (received, mean) {
            (0, _) => None,
            (1, _) => Some(0.0),
            (_, Some(mean)) => Some(
                samples
                    .iter()
                    .map(|sample| (sample - mean).powi(2))
                    .sum::<f64>()
                    / (received - 1) as f64,
            ),
            _ => None,
        };
        let adjacent_rtt_deltas: Vec<_> =
            samples.windows(2).map(|pair| pair[1] - pair[0]).collect();
        let positive_adjacent_rtt_deltas: Vec<_> = adjacent_rtt_deltas
            .iter()
            .copied()
            .filter(|value| *value > 0.0)
            .collect();
        let rtt_deltas_from_min: Vec<_> = samples
            .iter()
            .copied()
            .reduce(f64::min)
            .map(|minimum| samples.iter().map(|sample| sample - minimum).collect())
            .unwrap_or_default();

        Self {
            sent,
            received,
            lost,
            loss_rate: (sent > 0).then(|| lost as f64 / sent as f64),
            rtt_min_ms: samples.iter().copied().reduce(f64::min),
            rtt_mean_ms: mean,
            rtt_p50_ms: percentile(samples, 0.50),
            rtt_p95_ms: percentile(samples, 0.95),
            rtt_p99_ms: percentile(samples, 0.99),
            rtt_max_ms: samples.iter().copied().reduce(f64::max),
            rtt_sample_variance_ms2: variance,
            rtt_sample_stddev_ms: variance.map(f64::sqrt),
            mean_abs_adjacent_rtt_delta_ms: (!adjacent_rtt_deltas.is_empty()).then(|| {
                adjacent_rtt_deltas
                    .iter()
                    .map(|value| value.abs())
                    .sum::<f64>()
                    / adjacent_rtt_deltas.len() as f64
            }),
            positive_adjacent_rtt_delta_p95_ms: percentile(&positive_adjacent_rtt_deltas, 0.95),
            rtt_delta_from_min_p95_ms: percentile(&rtt_deltas_from_min, 0.95),
            rtt_delta_from_min_max_ms: rtt_deltas_from_min.iter().copied().reduce(f64::max),
            adjacent_rtt_pairs: adjacent_rtt_deltas.len(),
        }
    }

    pub fn health(&self) -> Health {
        let (Some(p50), Some(p95)) = (self.rtt_p50_ms, self.rtt_p95_ms) else {
            return Health::Unavailable;
        };
        if self.lost > 0 {
            return Health::Degraded;
        }
        let wide_spread = p95 - p50 >= 20.0 || (p50 > 0.0 && p95 / p50 >= 3.0);
        let sustained_variation = self
            .mean_abs_adjacent_rtt_delta_ms
            .is_some_and(|delta| delta >= DEGRADED_MEAN_ABS_RTT_DELTA_MS);
        if self.sent >= MIN_GATEWAY_ASSESSMENT_SAMPLES && wide_spread && sustained_variation {
            Health::Degraded
        } else {
            Health::Ok
        }
    }
}

fn percentile(values: &[f64], quantile: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut ordered = values.to_vec();
    ordered.sort_by(f64::total_cmp);
    let position = (ordered.len() - 1) as f64 * quantile;
    let lower = position.floor() as usize;
    let upper = position.ceil() as usize;
    if lower == upper {
        Some(ordered[lower])
    } else {
        let fraction = position - lower as f64;
        Some(ordered[lower] + (ordered[upper] - ordered[lower]) * fraction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_distribution_preserves_loss_and_sample_variance() {
        let metrics = LatencyMetrics::from_samples(&[10.0, 12.0, 14.0], 4);
        assert_eq!(metrics.sent, 4);
        assert_eq!(metrics.received, 3);
        assert_eq!(metrics.lost, 1);
        assert_eq!(metrics.loss_rate, Some(0.25));
        assert_eq!(metrics.rtt_p50_ms, Some(12.0));
        assert_eq!(metrics.rtt_sample_variance_ms2, Some(4.0));
        assert_eq!(metrics.mean_abs_adjacent_rtt_delta_ms, Some(2.0));
        assert_eq!(metrics.health(), Health::Degraded);
    }

    #[test]
    fn stable_complete_samples_are_healthy() {
        let metrics = LatencyMetrics::from_samples(&[10.0, 11.0, 12.0], 3);
        assert_eq!(metrics.health(), Health::Ok);
        assert_eq!(metrics.rtt_p95_ms, Some(11.9));
    }

    #[test]
    fn sparse_samples_do_not_diagnose_latency_spread() {
        let sparse = LatencyMetrics::from_samples(&[2.0, 3.0, 4.0, 60.0], 4);
        assert_eq!(sparse.health(), Health::Ok);

        let sufficient = LatencyMetrics::from_samples(&[2.0, 60.0, 2.0, 60.0, 2.0], 5);
        assert_eq!(sufficient.health(), Health::Degraded);
    }

    #[test]
    fn one_latency_spike_stays_visible_without_controlling_health() {
        let metrics = LatencyMetrics::from_samples(&[5.0, 6.0, 5.0, 6.0, 33.0], 5);
        assert!(metrics.rtt_p95_ms.unwrap() - metrics.rtt_p50_ms.unwrap() >= 20.0);
        assert!(metrics.mean_abs_adjacent_rtt_delta_ms.unwrap() < DEGRADED_MEAN_ABS_RTT_DELTA_MS);
        assert_eq!(metrics.health(), Health::Ok);
    }

    #[test]
    fn any_loss_in_the_assessed_metrics_is_material() {
        let samples = vec![10.0; 89];
        let metrics = LatencyMetrics::from_samples(&samples, 90);
        assert_eq!(metrics.loss_rate, Some(1.0 / 90.0));
        assert_eq!(metrics.health(), Health::Degraded);
    }

    #[test]
    fn no_replies_are_unavailable_without_fabricated_latency() {
        let metrics = LatencyMetrics::from_samples(&[], 3);
        assert_eq!(metrics.health(), Health::Unavailable);
        assert_eq!(metrics.loss_rate, Some(1.0));
        assert_eq!(metrics.rtt_p50_ms, None);
    }
}
