// Copyright (c) 2026 Bountyy Oy. All rights reserved.
//
// Signal Generators for Side-Channel Analysis
//
// Each analyzer measures a specific side-channel and produces
// a probabilistic signal for the Bayesian combiner.

pub use crate::inference::bayesian::{Signal, SignalType};
use crate::http_client::HttpResponse;

/// Timing signal analyzer
pub struct TimingAnalyzer {
    baseline_samples: Vec<u64>,
    baseline_mean: f64,
    baseline_stddev: f64,
}

impl TimingAnalyzer {
    pub fn new() -> Self {
        Self {
            baseline_samples: Vec::new(),
            baseline_mean: 0.0,
            baseline_stddev: 0.0,
        }
    }

    /// Collect baseline timing samples
    pub fn add_baseline(&mut self, duration_ms: u64) {
        self.baseline_samples.push(duration_ms);
        self.recalculate_stats();
    }

    fn recalculate_stats(&mut self) {
        if self.baseline_samples.is_empty() {
            return;
        }

        let n = self.baseline_samples.len() as f64;
        let sum: u64 = self.baseline_samples.iter().sum();
        self.baseline_mean = sum as f64 / n;

        let variance: f64 = self.baseline_samples.iter()
            .map(|&x| (x as f64 - self.baseline_mean).powi(2))
            .sum::<f64>() / n;

        self.baseline_stddev = variance.sqrt().max(1.0); // Min 1ms stddev
    }

    /// Analyze timing and produce a signal
    pub fn analyze(&self, test_duration_ms: u64) -> Signal {
        if self.baseline_samples.len() < 3 {
            return Signal::new(
                SignalType::Timing,
                0.5, // Neutral
                test_duration_ms as f64,
                "Insufficient baseline samples",
            );
        }

        // Calculate z-score
        let z_score = (test_duration_ms as f64 - self.baseline_mean) / self.baseline_stddev;

        // Convert z-score to probability
        // z > 2 = very suspicious (slower)
        // z < -2 = suspicious (faster, might indicate error short-circuit)
        let probability = if z_score.abs() > 3.0 {
            0.9 // Very anomalous
        } else if z_score.abs() > 2.0 {
            0.75
        } else if z_score.abs() > 1.0 {
            0.6
        } else {
            0.3 // Normal variation
        };

        Signal::new(
            SignalType::Timing,
            probability,
            z_score,
            &format!(
                "Timing: {:.1}ms (baseline: {:.1}±{:.1}ms, z={:.2})",
                test_duration_ms, self.baseline_mean, self.baseline_stddev, z_score
            ),
        )
    }
}

/// Content length differential analyzer
pub struct LengthAnalyzer {
    baseline_length: usize,
    tolerance_ratio: f64,
}

impl LengthAnalyzer {
    pub fn new(baseline_response: &HttpResponse) -> Self {
        Self {
            baseline_length: baseline_response.body.len(),
            tolerance_ratio: 0.05, // 5% tolerance
        }
    }

    pub fn analyze(&self, test_response: &HttpResponse) -> Signal {
        let test_length = test_response.body.len();
        let diff = (test_length as i64 - self.baseline_length as i64).abs() as f64;
        let ratio = diff / self.baseline_length.max(1) as f64;

        let probability = if ratio > 0.5 {
            0.9 // Huge difference
        } else if ratio > 0.2 {
            0.75
        } else if ratio > 0.1 {
            0.6
        } else if ratio > 0.05 {
            0.5
        } else {
            0.2 // Within tolerance
        };

        Signal::new(
            SignalType::Length,
            probability,
            ratio,
            &format!(
                "Length: {} bytes (baseline: {}, diff: {:.1}%)",
                test_length,
                self.baseline_length,
                ratio * 100.0
            ),
        )
    }
}

/// Response entropy analyzer
pub struct EntropyAnalyzer {
    baseline_entropy: f64,
}

impl EntropyAnalyzer {
    pub fn new(baseline_response: &HttpResponse) -> Self {
        Self {
            baseline_entropy: Self::calculate_entropy(&baseline_response.body),
        }
    }

    /// Calculate Shannon entropy of a string
    fn calculate_entropy(data: &str) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut freq = [0u64; 256];
        for b in data.bytes() {
            freq[b as usize] += 1;
        }

        let len = data.len() as f64;
        freq.iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / len;
                -p * p.log2()
            })
            .sum()
    }

    pub fn analyze(&self, test_response: &HttpResponse) -> Signal {
        let test_entropy = Self::calculate_entropy(&test_response.body);
        let diff = (test_entropy - self.baseline_entropy).abs();

        // SQL errors typically have lower entropy (structured messages)
        // Normal HTML has higher entropy (varied content)
        let probability = if diff > 1.0 {
            0.85
        } else if diff > 0.5 {
            0.7
        } else if diff > 0.2 {
            0.55
        } else {
            0.25
        };

        Signal::new(
            SignalType::Entropy,
            probability,
            diff,
            &format!(
                "Entropy: {:.3} (baseline: {:.3}, diff: {:.3})",
                test_entropy, self.baseline_entropy, diff
            ),
        )
    }
}

/// Resonance pattern analyzer (quote oscillation)
pub struct ResonanceAnalyzer {
    http_client: std::sync::Arc<crate::http_client::HttpClient>,
}

impl ResonanceAnalyzer {
    pub fn new(http_client: std::sync::Arc<crate::http_client::HttpClient>) -> Self {
        Self { http_client }
    }

    /// Detect oscillating pattern from quote injection
    /// Pattern: ', '', ''', '''' should show error/ok/error/ok
    pub async fn analyze(
        &self,
        base_url: &str,
        parameter: &str,
        baseline: &HttpResponse,
    ) -> Signal {
        let mut responses = Vec::new();

        for n in 1..=6 {
            let quotes = "'".repeat(n);
            let payload = format!("{}", quotes);

            // Build test URL (reuse the build_test_url pattern)
            let test_url = if let Ok(mut parsed) = url::Url::parse(base_url) {
                let existing: Vec<(String, String)> = parsed
                    .query_pairs()
                    .filter(|(name, _)| name != parameter)
                    .map(|(n, v)| (n.to_string(), v.to_string()))
                    .collect();

                parsed.set_query(None);
                {
                    let mut qp = parsed.query_pairs_mut();
                    for (name, value) in &existing {
                        qp.append_pair(name, value);
                    }
                    qp.append_pair(parameter, &payload);
                }
                parsed.to_string()
            } else {
                continue;
            };

            if let Ok(resp) = self.http_client.get(&test_url).await {
                responses.push((n, resp));
            }
        }

        if responses.len() < 4 {
            return Signal::new(
                SignalType::Resonance,
                0.5,
                0.0,
                "Insufficient resonance samples",
            );
        }

        // Check for oscillating pattern
        let mut oscillations = 0;
        let baseline_len = baseline.body.len();

        for i in 1..responses.len() {
            let prev_similar = Self::is_similar(&responses[i - 1].1, baseline);
            let curr_similar = Self::is_similar(&responses[i].1, baseline);

            if prev_similar != curr_similar {
                oscillations += 1;
            }
        }

        // Perfect oscillation would have n-1 transitions
        let oscillation_ratio = oscillations as f64 / (responses.len() - 1) as f64;

        let probability = if oscillation_ratio > 0.7 {
            0.95 // Strong oscillation = very likely SQLi
        } else if oscillation_ratio > 0.5 {
            0.8
        } else if oscillation_ratio > 0.3 {
            0.6
        } else {
            0.2
        };

        Signal::new(
            SignalType::Resonance,
            probability,
            oscillation_ratio,
            &format!(
                "Resonance: {} oscillations in {} samples (ratio: {:.2})",
                oscillations,
                responses.len(),
                oscillation_ratio
            ),
        )
    }

    fn is_similar(resp: &HttpResponse, baseline: &HttpResponse) -> bool {
        let len_ratio = resp.body.len() as f64 / baseline.body.len().max(1) as f64;
        let status_same = resp.status_code == baseline.status_code;

        status_same && (0.8..1.2).contains(&len_ratio)
    }
}

/// Status code analyzer
pub struct StatusCodeAnalyzer {
    baseline_status: u16,
}

impl StatusCodeAnalyzer {
    pub fn new(baseline_response: &HttpResponse) -> Self {
        Self {
            baseline_status: baseline_response.status_code,
        }
    }

    pub fn analyze(&self, test_response: &HttpResponse) -> Signal {
        let test_status = test_response.status_code;

        let probability = if test_status == self.baseline_status {
            0.2 // Same status = less suspicious
        } else if test_status >= 500 {
            0.9 // Server error = very suspicious
        } else if test_status >= 400 {
            0.7 // Client error = suspicious
        } else if test_status >= 300 {
            0.5 // Redirect = neutral
        } else {
            0.4
        };

        Signal::new(
            SignalType::StatusCode,
            probability,
            test_status as f64,
            &format!(
                "Status: {} (baseline: {})",
                test_status, self.baseline_status
            ),
        )
    }
}

/// Error pattern detector
pub struct ErrorPatternAnalyzer {
    patterns: Vec<(&'static str, f64)>, // (pattern, confidence)
}

impl Default for ErrorPatternAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl ErrorPatternAnalyzer {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                // MySQL
                ("you have an error in your sql", 0.95),
                ("mysql_fetch", 0.9),
                ("mysql_query", 0.9),
                ("mysqli_", 0.85),
                ("sql syntax", 0.85),  // More specific than just "syntax error"
                ("unexpected end of sql", 0.9),

                // PostgreSQL
                ("pg_query", 0.9),
                ("pg_exec", 0.9),
                ("postgresql error", 0.85),  // Require "error" context
                ("unterminated quoted string", 0.9),

                // MSSQL
                ("microsoft sql server", 0.85),  // More specific
                ("mssql_", 0.9),
                ("unclosed quotation mark", 0.95),
                ("incorrect syntax near", 0.9),

                // Oracle
                ("ora-0", 0.85),  // More specific oracle error code prefix
                ("ora-1", 0.85),
                ("oracle error", 0.9),
                ("quoted string not properly terminated", 0.9),

                // SQLite
                ("sqlite_", 0.85),
                ("sqlite3", 0.85),
                ("unrecognized token", 0.8),

                // Generic
                ("sql syntax", 0.8),
                ("query failed", 0.7),
                ("database error", 0.75),
                ("odbc driver", 0.8),
                ("jdbc", 0.75),
            ],
        }
    }

    pub fn analyze(&self, response: &HttpResponse) -> Signal {
        let body_lower = response.body.to_lowercase();

        let mut best_match: Option<(&str, f64)> = None;

        for (pattern, confidence) in &self.patterns {
            if body_lower.contains(pattern) {
                match &best_match {
                    None => best_match = Some((pattern, *confidence)),
                    Some((_, prev_conf)) if confidence > prev_conf => {
                        best_match = Some((pattern, *confidence));
                    }
                    _ => {}
                }
            }
        }

        match best_match {
            Some((pattern, confidence)) => Signal::new(
                SignalType::ErrorPattern,
                confidence,
                1.0,
                &format!("SQL error pattern detected: '{}'", pattern),
            ),
            None => Signal::new(
                SignalType::ErrorPattern,
                0.1, // Low probability if no pattern found
                0.0,
                "No SQL error patterns detected",
            ),
        }
    }
}

/// Header differential analyzer
pub struct HeaderAnalyzer {
    baseline_headers: std::collections::HashMap<String, String>,
}

impl HeaderAnalyzer {
    pub fn new(baseline_response: &HttpResponse) -> Self {
        Self {
            baseline_headers: baseline_response.headers.clone(),
        }
    }

    pub fn analyze(&self, test_response: &HttpResponse) -> Signal {
        let mut differences = 0;
        let mut suspicious_changes = 0;

        // Check for new or changed headers
        for (key, value) in &test_response.headers {
            match self.baseline_headers.get(key) {
                None => {
                    differences += 1;
                    // New error-related headers are suspicious
                    if key.to_lowercase().contains("error")
                        || key.to_lowercase().contains("debug")
                    {
                        suspicious_changes += 1;
                    }
                }
                Some(baseline_value) if baseline_value != value => {
                    differences += 1;
                }
                _ => {}
            }
        }

        // Check for removed headers
        for key in self.baseline_headers.keys() {
            if !test_response.headers.contains_key(key) {
                differences += 1;
            }
        }

        let probability = if suspicious_changes > 0 {
            0.8
        } else if differences > 3 {
            0.7
        } else if differences > 1 {
            0.55
        } else if differences == 1 {
            0.4
        } else {
            0.2
        };

        Signal::new(
            SignalType::HeaderDiff,
            probability,
            differences as f64,
            &format!("Header differences: {} (suspicious: {})", differences, suspicious_changes),
        )
    }
}

/// Combined side-channel analyzer
pub struct SideChannelSuite {
    pub timing: TimingAnalyzer,
    pub length: LengthAnalyzer,
    pub entropy: EntropyAnalyzer,
    pub status: StatusCodeAnalyzer,
    pub error_pattern: ErrorPatternAnalyzer,
    pub headers: HeaderAnalyzer,
}

impl SideChannelSuite {
    pub fn new(baseline: &HttpResponse) -> Self {
        let mut timing = TimingAnalyzer::new();
        timing.add_baseline(baseline.duration_ms);

        Self {
            timing,
            length: LengthAnalyzer::new(baseline),
            entropy: EntropyAnalyzer::new(baseline),
            status: StatusCodeAnalyzer::new(baseline),
            error_pattern: ErrorPatternAnalyzer::new(),
            headers: HeaderAnalyzer::new(baseline),
        }
    }

    /// Analyze a test response and produce all signals
    pub fn analyze(&self, test_response: &HttpResponse) -> Vec<Signal> {
        vec![
            self.timing.analyze(test_response.duration_ms),
            self.length.analyze(test_response),
            self.entropy.analyze(test_response),
            self.status.analyze(test_response),
            self.error_pattern.analyze(test_response),
            self.headers.analyze(test_response),
        ]
    }
}
