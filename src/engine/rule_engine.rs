// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use chrono::{DateTime, Utc};
use regex::Regex;
/**
 * High-Performance Rule Engine
 * Rust implementation for fast rule evaluation at scale
 *
 * Features:
 * - JSON-based rule definitions
 * - Rule validation
 * - Parallel evaluation
 * - Rule caching
 * - Performance optimization
 *
 * © 2026 Bountyy Oy
 */
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Rule operator types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum LogicalOperator {
    And,
    Or,
    Not,
}

/// Comparison operator types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonOperator {
    Equals,
    NotEquals,
    Contains,
    NotContains,
    StartsWith,
    EndsWith,
    Regex,
    Gt,
    Gte,
    Lt,
    Lte,
    In,
    NotIn,
    Exists,
    NotExists,
    Between,
    HasLabel,
    NotHasLabel,
}

/// Single condition in a rule
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Condition {
    Simple {
        field: String,
        operator: ComparisonOperator,
        value: Value,
        #[serde(default)]
        case_sensitive: bool,
    },
    Nested {
        operator: LogicalOperator,
        conditions: Vec<Condition>,
    },
}

/// Rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub operator: LogicalOperator,
    pub conditions: Vec<Condition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<RuleMetadata>,
}

/// Rule metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Asset representation for evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub id: i64,
    #[serde(rename = "asset_type")]
    pub type_: String,
    #[serde(rename = "asset_value")]
    pub value: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud_provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud_region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovered_at: Option<DateTime<Utc>>,
}

/// Rule evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationResult {
    pub matches: bool,
    pub evaluated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Cached evaluation result
struct CachedResult {
    result: bool,
    timestamp: DateTime<Utc>,
}

/// High-performance rule engine
pub struct RuleEngine {
    /// Cache for evaluation results
    cache: Arc<RwLock<HashMap<String, CachedResult>>>,
    /// Cache TTL in seconds
    cache_ttl: i64,
    /// Compiled regex cache
    regex_cache: Arc<RwLock<HashMap<String, Regex>>>,
    /// Performance metrics
    metrics: Arc<RwLock<EngineMetrics>>,
}

/// Engine performance metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EngineMetrics {
    pub total_evaluations: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub avg_evaluation_time_ms: f64,
    pub rules_validated: u64,
    pub validation_errors: u64,
}

impl RuleEngine {
    /// Create a new rule engine
    pub fn new(cache_ttl_seconds: i64) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl: cache_ttl_seconds,
            regex_cache: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(EngineMetrics::default())),
        }
    }

    /// Validate a rule
    pub fn validate_rule(&self, rule: &Rule) -> Result<(), String> {
        let mut metrics = self
            .metrics
            .write()
            .map_err(|e| format!("Failed to acquire metrics lock: {}", e))?;
        metrics.rules_validated += 1;

        // Check if rule has at least one condition
        if rule.conditions.is_empty() {
            metrics.validation_errors += 1;
            return Err("Rule must have at least one condition".to_string());
        }

        // Validate each condition
        for condition in &rule.conditions {
            if let Err(e) = self.validate_condition(condition) {
                metrics.validation_errors += 1;
                return Err(e);
            }
        }

        Ok(())
    }

    /// Validate a condition
    fn validate_condition(&self, condition: &Condition) -> Result<(), String> {
        match condition {
            Condition::Simple {
                field,
                operator,
                value,
                ..
            } => {
                // Field must not be empty
                if field.is_empty() {
                    return Err("Field name cannot be empty".to_string());
                }

                // Validate value type based on operator
                match operator {
                    ComparisonOperator::In | ComparisonOperator::NotIn => {
                        if !value.is_array() {
                            return Err(format!("Operator {:?} requires array value", operator));
                        }
                    }
                    ComparisonOperator::Between => {
                        if !value.is_array() {
                            return Err("Between operator requires array value".to_string());
                        }
                        if let Some(arr) = value.as_array() {
                            if arr.len() != 2 {
                                return Err(
                                    "Between operator requires array with exactly 2 values"
                                        .to_string(),
                                );
                            }
                        }
                    }
                    ComparisonOperator::Regex => {
                        if let Some(pattern) = value.as_str() {
                            // Validate regex pattern
                            if Regex::new(pattern).is_err() {
                                return Err(format!("Invalid regex pattern: {}", pattern));
                            }
                        } else {
                            return Err("Regex operator requires string value".to_string());
                        }
                    }
                    _ => {}
                }

                Ok(())
            }
            Condition::Nested { conditions, .. } => {
                if conditions.is_empty() {
                    return Err("Nested condition must have at least one sub-condition".to_string());
                }

                for cond in conditions {
                    self.validate_condition(cond)?;
                }

                Ok(())
            }
        }
    }

    /// Evaluate rule against asset
    pub fn evaluate(&self, rule: &Rule, asset: &Asset) -> Result<EvaluationResult, String> {
        let start = std::time::Instant::now();

        // Update metrics
        {
            let mut metrics = self
                .metrics
                .write()
                .map_err(|e| format!("Failed to acquire metrics lock: {}", e))?;
            metrics.total_evaluations += 1;
        }

        // Check cache
        let cache_key = self.make_cache_key(rule, asset)?;
        if let Some(cached) = self.get_cached(&cache_key)? {
            let mut metrics = self
                .metrics
                .write()
                .map_err(|e| format!("Failed to acquire metrics lock: {}", e))?;
            metrics.cache_hits += 1;

            return Ok(EvaluationResult {
                matches: cached,
                evaluated_at: Utc::now(),
                details: Some("From cache".to_string()),
            });
        }

        // Update cache miss
        {
            let mut metrics = self
                .metrics
                .write()
                .map_err(|e| format!("Failed to acquire metrics lock: {}", e))?;
            metrics.cache_misses += 1;
        }

        // Evaluate
        let matches = self.evaluate_conditions(&rule.operator, &rule.conditions, asset)?;

        // Cache result
        self.cache_result(&cache_key, matches)?;

        // Update metrics
        let duration = start.elapsed();
        {
            let mut metrics = self
                .metrics
                .write()
                .map_err(|e| format!("Failed to acquire metrics lock: {}", e))?;
            let total = metrics.total_evaluations as f64;
            metrics.avg_evaluation_time_ms = (metrics.avg_evaluation_time_ms * (total - 1.0)
                + duration.as_millis() as f64)
                / total;
        }

        Ok(EvaluationResult {
            matches,
            evaluated_at: Utc::now(),
            details: None,
        })
    }

    /// Evaluate conditions with logical operator
    fn evaluate_conditions(
        &self,
        operator: &LogicalOperator,
        conditions: &[Condition],
        asset: &Asset,
    ) -> Result<bool, String> {
        match operator {
            LogicalOperator::And => {
                for condition in conditions {
                    if !self.evaluate_condition(condition, asset)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            LogicalOperator::Or => {
                for condition in conditions {
                    if self.evaluate_condition(condition, asset)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            LogicalOperator::Not => {
                for condition in conditions {
                    if self.evaluate_condition(condition, asset)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
        }
    }

    /// Evaluate single condition
    fn evaluate_condition(&self, condition: &Condition, asset: &Asset) -> Result<bool, String> {
        match condition {
            Condition::Nested {
                operator,
                conditions,
            } => self.evaluate_conditions(operator, conditions, asset),
            Condition::Simple {
                field,
                operator,
                value,
                case_sensitive,
            } => {
                let field_value = self.get_field_value(asset, field);
                self.compare(&field_value, operator, value, *case_sensitive)
            }
        }
    }

    /// Get field value from asset (supports dot notation)
    fn get_field_value(&self, asset: &Asset, field: &str) -> Value {
        let parts: Vec<&str> = field.split('.').collect();

        // Handle direct fields
        if parts.len() == 1 {
            return match parts[0] {
                "id" => Value::Number(asset.id.into()),
                "type" | "asset_type" => Value::String(asset.type_.clone()),
                "value" | "asset_value" => Value::String(asset.value.clone()),
                "status" => Value::String(asset.status.clone()),
                "tags" => asset
                    .tags
                    .as_ref()
                    .and_then(|t| serde_json::to_value(t).ok())
                    .unwrap_or(Value::Null),
                "cloud_provider" => asset
                    .cloud_provider
                    .as_ref()
                    .map(|s| Value::String(s.clone()))
                    .unwrap_or(Value::Null),
                "cloud_region" => asset
                    .cloud_region
                    .as_ref()
                    .map(|s| Value::String(s.clone()))
                    .unwrap_or(Value::Null),
                "risk_score" => asset
                    .risk_score
                    .and_then(|r| serde_json::Number::from_f64(r))
                    .map(Value::Number)
                    .unwrap_or(Value::Null),
                "metadata" => asset.metadata.clone().unwrap_or(Value::Null),
                _ => Value::Null,
            };
        }

        // Handle nested fields (e.g., metadata.provider)
        if parts[0] == "metadata" {
            if let Some(metadata) = &asset.metadata {
                let mut current = metadata.clone();
                for part in &parts[1..] {
                    if let Some(obj) = current.as_object() {
                        current = obj.get(*part).cloned().unwrap_or(Value::Null);
                    } else {
                        return Value::Null;
                    }
                }
                return current;
            }
        }

        Value::Null
    }

    /// Compare values using operator
    fn compare(
        &self,
        field_value: &Value,
        operator: &ComparisonOperator,
        compare_value: &Value,
        case_sensitive: bool,
    ) -> Result<bool, String> {
        match operator {
            ComparisonOperator::Equals => {
                Ok(self.values_equal(field_value, compare_value, case_sensitive))
            }
            ComparisonOperator::NotEquals => {
                Ok(!self.values_equal(field_value, compare_value, case_sensitive))
            }
            ComparisonOperator::Contains => {
                if let (Some(haystack), Some(needle)) =
                    (field_value.as_str(), compare_value.as_str())
                {
                    if case_sensitive {
                        Ok(haystack.contains(needle))
                    } else {
                        Ok(haystack.to_lowercase().contains(&needle.to_lowercase()))
                    }
                } else {
                    Ok(false)
                }
            }
            ComparisonOperator::NotContains => {
                if let (Some(haystack), Some(needle)) =
                    (field_value.as_str(), compare_value.as_str())
                {
                    if case_sensitive {
                        Ok(!haystack.contains(needle))
                    } else {
                        Ok(!haystack.to_lowercase().contains(&needle.to_lowercase()))
                    }
                } else {
                    Ok(true)
                }
            }
            ComparisonOperator::StartsWith => {
                if let (Some(haystack), Some(prefix)) =
                    (field_value.as_str(), compare_value.as_str())
                {
                    if case_sensitive {
                        Ok(haystack.starts_with(prefix))
                    } else {
                        Ok(haystack.to_lowercase().starts_with(&prefix.to_lowercase()))
                    }
                } else {
                    Ok(false)
                }
            }
            ComparisonOperator::EndsWith => {
                if let (Some(haystack), Some(suffix)) =
                    (field_value.as_str(), compare_value.as_str())
                {
                    if case_sensitive {
                        Ok(haystack.ends_with(suffix))
                    } else {
                        Ok(haystack.to_lowercase().ends_with(&suffix.to_lowercase()))
                    }
                } else {
                    Ok(false)
                }
            }
            ComparisonOperator::Regex => {
                if let (Some(text), Some(pattern)) = (field_value.as_str(), compare_value.as_str())
                {
                    let regex = self.get_or_compile_regex(pattern, case_sensitive)?;
                    Ok(regex.is_match(text))
                } else {
                    Ok(false)
                }
            }
            ComparisonOperator::Gt => {
                Ok(self.numeric_compare(field_value, compare_value, |a, b| a > b))
            }
            ComparisonOperator::Gte => {
                Ok(self.numeric_compare(field_value, compare_value, |a, b| a >= b))
            }
            ComparisonOperator::Lt => {
                Ok(self.numeric_compare(field_value, compare_value, |a, b| a < b))
            }
            ComparisonOperator::Lte => {
                Ok(self.numeric_compare(field_value, compare_value, |a, b| a <= b))
            }
            ComparisonOperator::In => {
                if let Some(arr) = compare_value.as_array() {
                    Ok(arr
                        .iter()
                        .any(|v| self.values_equal(field_value, v, case_sensitive)))
                } else {
                    Ok(false)
                }
            }
            ComparisonOperator::NotIn => {
                if let Some(arr) = compare_value.as_array() {
                    Ok(!arr
                        .iter()
                        .any(|v| self.values_equal(field_value, v, case_sensitive)))
                } else {
                    Ok(true)
                }
            }
            ComparisonOperator::Exists => Ok(!field_value.is_null()),
            ComparisonOperator::NotExists => Ok(field_value.is_null()),
            ComparisonOperator::Between => {
                if let Some(arr) = compare_value.as_array() {
                    if arr.len() == 2 {
                        let gte = self.numeric_compare(field_value, &arr[0], |a, b| a >= b);
                        let lte = self.numeric_compare(field_value, &arr[1], |a, b| a <= b);
                        return Ok(gte && lte);
                    }
                }
                Ok(false)
            }
            ComparisonOperator::HasLabel => {
                if let (Some(tags), Some(label)) = (field_value.as_array(), compare_value.as_str())
                {
                    Ok(tags.iter().any(|t| t.as_str() == Some(label)))
                } else {
                    Ok(false)
                }
            }
            ComparisonOperator::NotHasLabel => {
                if let (Some(tags), Some(label)) = (field_value.as_array(), compare_value.as_str())
                {
                    Ok(!tags.iter().any(|t| t.as_str() == Some(label)))
                } else {
                    Ok(true)
                }
            }
        }
    }

    /// Check if two values are equal
    fn values_equal(&self, a: &Value, b: &Value, case_sensitive: bool) -> bool {
        if !case_sensitive {
            if let (Some(a_str), Some(b_str)) = (a.as_str(), b.as_str()) {
                return a_str.to_lowercase() == b_str.to_lowercase();
            }
        }
        a == b
    }

    /// Numeric comparison
    fn numeric_compare<F>(&self, a: &Value, b: &Value, op: F) -> bool
    where
        F: Fn(f64, f64) -> bool,
    {
        match (a.as_f64(), b.as_f64()) {
            (Some(a_num), Some(b_num)) => op(a_num, b_num),
            _ => false,
        }
    }

    /// Get or compile regex
    fn get_or_compile_regex(&self, pattern: &str, case_sensitive: bool) -> Result<Regex, String> {
        let cache_key = if case_sensitive {
            format!("cs:{}", pattern)
        } else {
            format!("ci:{}", pattern)
        };

        // Check cache
        {
            let cache = self
                .regex_cache
                .read()
                .map_err(|e| format!("Failed to acquire regex cache lock: {}", e))?;
            if let Some(regex) = cache.get(&cache_key) {
                return Ok(regex.clone());
            }
        }

        // Compile and cache
        let regex = if case_sensitive {
            Regex::new(pattern)
        } else {
            Regex::new(&format!("(?i){}", pattern))
        };

        match regex {
            Ok(r) => {
                let mut cache = self
                    .regex_cache
                    .write()
                    .map_err(|e| format!("Failed to acquire regex cache lock: {}", e))?;
                cache.insert(cache_key, r.clone());
                Ok(r)
            }
            Err(e) => Err(format!("Invalid regex: {}", e)),
        }
    }

    /// Make cache key
    fn make_cache_key(&self, rule: &Rule, asset: &Asset) -> Result<String, String> {
        let rule_str = serde_json::to_string(rule)
            .map_err(|e| format!("Failed to serialize rule for cache key: {}", e))?;
        Ok(format!("{}:{}", rule_str, asset.id))
    }

    /// Get cached result
    fn get_cached(&self, key: &str) -> Result<Option<bool>, String> {
        let cache = self
            .cache
            .read()
            .map_err(|e| format!("Failed to acquire cache lock: {}", e))?;
        if let Some(cached) = cache.get(key) {
            let age = Utc::now() - cached.timestamp;
            if age.num_seconds() < self.cache_ttl {
                return Ok(Some(cached.result));
            }
        }
        Ok(None)
    }

    /// Cache result
    fn cache_result(&self, key: &str, result: bool) -> Result<(), String> {
        let mut cache = self
            .cache
            .write()
            .map_err(|e| format!("Failed to acquire cache lock: {}", e))?;
        cache.insert(
            key.to_string(),
            CachedResult {
                result,
                timestamp: Utc::now(),
            },
        );
        Ok(())
    }

    /// Clear cache
    pub fn clear_cache(&self) -> Result<(), String> {
        let mut cache = self
            .cache
            .write()
            .map_err(|e| format!("Failed to acquire cache lock: {}", e))?;
        cache.clear();
        Ok(())
    }

    /// Get metrics
    pub fn get_metrics(&self) -> Result<EngineMetrics, String> {
        let metrics = self
            .metrics
            .read()
            .map_err(|e| format!("Failed to acquire metrics lock: {}", e))?;
        Ok(metrics.clone())
    }

    /// Reset metrics
    pub fn reset_metrics(&self) -> Result<(), String> {
        let mut metrics = self
            .metrics
            .write()
            .map_err(|e| format!("Failed to acquire metrics lock: {}", e))?;
        *metrics = EngineMetrics::default();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_asset() -> Asset {
        Asset {
            id: 1,
            type_: "subdomain".to_string(),
            value: "api.example.com".to_string(),
            status: "active".to_string(),
            tags: Some(vec!["production".to_string(), "critical".to_string()]),
            metadata: Some(serde_json::json!({
                "provider": "aws",
                "region": "us-east-1"
            })),
            cloud_provider: Some("aws".to_string()),
            cloud_region: Some("us-east-1".to_string()),
            risk_score: Some(8.5),
            discovered_at: Some(Utc::now()),
        }
    }

    #[test]
    fn test_simple_equals() {
        let engine = RuleEngine::new(300);
        let asset = create_test_asset();

        let rule = Rule {
            operator: LogicalOperator::And,
            conditions: vec![Condition::Simple {
                field: "type".to_string(),
                operator: ComparisonOperator::Equals,
                value: Value::String("subdomain".to_string()),
                case_sensitive: true,
            }],
            metadata: None,
        };

        let result = engine.evaluate(&rule, &asset).unwrap();
        assert!(result.matches);
    }

    #[test]
    fn test_contains() {
        let engine = RuleEngine::new(300);
        let asset = create_test_asset();

        let rule = Rule {
            operator: LogicalOperator::And,
            conditions: vec![Condition::Simple {
                field: "value".to_string(),
                operator: ComparisonOperator::Contains,
                value: Value::String("api".to_string()),
                case_sensitive: false,
            }],
            metadata: None,
        };

        let result = engine.evaluate(&rule, &asset).unwrap();
        assert!(result.matches);
    }

    #[test]
    fn test_nested_metadata() {
        let engine = RuleEngine::new(300);
        let asset = create_test_asset();

        let rule = Rule {
            operator: LogicalOperator::And,
            conditions: vec![Condition::Simple {
                field: "metadata.provider".to_string(),
                operator: ComparisonOperator::Equals,
                value: Value::String("aws".to_string()),
                case_sensitive: true,
            }],
            metadata: None,
        };

        let result = engine.evaluate(&rule, &asset).unwrap();
        assert!(result.matches);
    }

    #[test]
    fn test_and_operator() {
        let engine = RuleEngine::new(300);
        let asset = create_test_asset();

        let rule = Rule {
            operator: LogicalOperator::And,
            conditions: vec![
                Condition::Simple {
                    field: "status".to_string(),
                    operator: ComparisonOperator::Equals,
                    value: Value::String("active".to_string()),
                    case_sensitive: true,
                },
                Condition::Simple {
                    field: "risk_score".to_string(),
                    operator: ComparisonOperator::Gt,
                    value: Value::Number(serde_json::Number::from_f64(7.0).unwrap()),
                    case_sensitive: true,
                },
            ],
            metadata: None,
        };

        let result = engine.evaluate(&rule, &asset).unwrap();
        assert!(result.matches);
    }
}
