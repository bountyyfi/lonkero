// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Model Scorer
 * Scores extracted features against model weights to determine vulnerability likelihood
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */
use crate::ml::federated::AggregatedModel;
use std::collections::HashMap;

/// Scores extracted features against model weights
pub struct ModelScorer {
    pub weights: HashMap<String, f64>,
    pub bias: f64,
}

impl ModelScorer {
    pub fn from_model(model: &AggregatedModel) -> Self {
        Self {
            weights: model.weights.weights.clone(),
            bias: model.weights.bias,
        }
    }

    /// Score extracted features. Returns raw score.
    /// score > 0.0 means likely vulnerable.
    pub fn score(&self, features: &HashMap<String, f64>) -> f64 {
        let mut score = self.bias;
        for (key, value) in features {
            if let Some(weight) = self.weights.get(key.as_str()) {
                score += value * weight;
            }
        }
        score
    }

    /// Score and return category breakdown for reporting
    pub fn score_detailed(&self, features: &HashMap<String, f64>) -> ScoredResult {
        let mut total = self.bias;
        let mut contributions: Vec<(String, f64)> = Vec::new();

        for (key, value) in features {
            if let Some(weight) = self.weights.get(key.as_str()) {
                let contribution = value * weight;
                total += contribution;
                if contribution.abs() > 0.01 {
                    contributions.push((key.clone(), contribution));
                }
            }
        }

        // Sort by absolute contribution (most impactful first)
        contributions.sort_by(|a, b| b.1.abs().partial_cmp(&a.1.abs()).unwrap_or(std::cmp::Ordering::Equal));

        ScoredResult {
            score: total,
            is_vulnerable: total > 0.0,
            confidence: sigmoid(total),
            top_signals: contributions.into_iter().take(5).collect(),
        }
    }
}

fn sigmoid(x: f64) -> f64 {
    1.0 / (1.0 + (-x).exp())
}

/// Result of scoring features against model weights
pub struct ScoredResult {
    pub score: f64,
    pub is_vulnerable: bool,
    /// 0.0-1.0 confidence score
    pub confidence: f64,
    /// Top contributing features and their score contribution
    pub top_signals: Vec<(String, f64)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scorer_positive() {
        let scorer = ModelScorer {
            weights: [
                ("sqli:error_mysql_syntax".to_string(), 2.0),
                ("signal:error_triggered".to_string(), 0.5),
            ]
            .into_iter()
            .collect(),
            bias: -0.42,
        };

        let mut features = HashMap::new();
        features.insert("sqli:error_mysql_syntax".to_string(), 0.95);
        features.insert("signal:error_triggered".to_string(), 1.0);

        let result = scorer.score_detailed(&features);
        assert!(result.is_vulnerable);
        assert!(result.score > 0.0);
        assert!(result.confidence > 0.5);
    }

    #[test]
    fn test_scorer_negative() {
        let scorer = ModelScorer {
            weights: [
                ("sqli:error_mysql_syntax".to_string(), 0.3),
                ("sqli:waf_blocked_response".to_string(), -1.5),
            ]
            .into_iter()
            .collect(),
            bias: -0.42,
        };

        let mut features = HashMap::new();
        features.insert("sqli:waf_blocked_response".to_string(), 1.0);

        let result = scorer.score_detailed(&features);
        assert!(!result.is_vulnerable);
        assert!(result.score < 0.0);
    }

    #[test]
    fn test_scorer_missing_features() {
        let scorer = ModelScorer {
            weights: [("sqli:error_mysql_syntax".to_string(), 2.0)]
                .into_iter()
                .collect(),
            bias: -0.42,
        };

        let mut features = HashMap::new();
        features.insert("unknown_feature".to_string(), 1.0);

        let result = scorer.score(&features);
        // Only bias contributes, unknown features ignored
        assert!((result - (-0.42)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_sigmoid() {
        assert!((sigmoid(0.0) - 0.5).abs() < f64::EPSILON);
        assert!(sigmoid(5.0) > 0.99);
        assert!(sigmoid(-5.0) < 0.01);
    }

    #[test]
    fn test_top_signals_sorted() {
        let scorer = ModelScorer {
            weights: [
                ("a".to_string(), 0.1),
                ("b".to_string(), 2.0),
                ("c".to_string(), 0.5),
            ]
            .into_iter()
            .collect(),
            bias: 0.0,
        };

        let mut features = HashMap::new();
        features.insert("a".to_string(), 1.0);
        features.insert("b".to_string(), 1.0);
        features.insert("c".to_string(), 1.0);

        let result = scorer.score_detailed(&features);
        assert_eq!(result.top_signals[0].0, "b");
        assert_eq!(result.top_signals[1].0, "c");
        assert_eq!(result.top_signals[2].0, "a");
    }
}
