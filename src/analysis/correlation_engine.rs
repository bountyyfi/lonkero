// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Vulnerability Correlation Engine
 * Links findings across scanners to discover attack chains and compound vulnerabilities
 *
 * Features:
 * - Attack chain detection (e.g., XSS + CSRF = Account Takeover)
 * - Vulnerability clustering by endpoint/parameter
 * - Severity escalation for compound vulnerabilities
 * - False positive reduction through cross-validation
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */
use crate::types::{Confidence, Severity, Vulnerability};
use std::collections::{HashMap, HashSet};
use tracing::{debug, info};

/// Attack chain patterns that indicate compound vulnerabilities
#[derive(Debug, Clone)]
pub struct AttackChain {
    pub name: String,
    pub description: String,
    pub required_vuln_types: Vec<String>,
    pub escalated_severity: Severity,
    pub escalated_confidence: Confidence,
}

/// Correlation result containing original vulnerabilities and discovered chains
#[derive(Debug)]
pub struct CorrelationResult {
    /// Original vulnerabilities (potentially deduplicated)
    pub vulnerabilities: Vec<Vulnerability>,
    /// Discovered attack chains
    pub attack_chains: Vec<DiscoveredChain>,
    /// Vulnerability clusters by endpoint
    pub endpoint_clusters: HashMap<String, Vec<usize>>,
    /// Summary statistics
    pub stats: CorrelationStats,
}

#[derive(Debug)]
pub struct DiscoveredChain {
    pub chain_type: String,
    pub description: String,
    pub involved_vulns: Vec<usize>, // Indices into vulnerabilities vec
    pub escalated_severity: Severity,
    pub impact: String,
}

#[derive(Debug, Default)]
pub struct CorrelationStats {
    pub total_vulns: usize,
    pub deduplicated_vulns: usize,
    pub attack_chains_found: usize,
    pub severity_escalations: usize,
    pub false_positive_reductions: usize,
}

/// Vulnerability Correlation Engine
pub struct CorrelationEngine {
    /// Known attack chain patterns
    attack_patterns: Vec<AttackChain>,
}

impl CorrelationEngine {
    pub fn new() -> Self {
        Self {
            attack_patterns: Self::initialize_attack_patterns(),
        }
    }

    /// Initialize known attack chain patterns
    fn initialize_attack_patterns() -> Vec<AttackChain> {
        vec![
            // XSS + CSRF = Account Takeover
            AttackChain {
                name: "Account Takeover via XSS+CSRF".to_string(),
                description: "XSS can be used to bypass CSRF protections and perform actions as victim".to_string(),
                required_vuln_types: vec!["XSS".to_string(), "CSRF".to_string()],
                escalated_severity: Severity::Critical,
                escalated_confidence: Confidence::High,
            },
            // IDOR + Sensitive Data = Data Breach
            AttackChain {
                name: "Data Breach via IDOR".to_string(),
                description: "IDOR combined with sensitive data exposure allows mass data exfiltration".to_string(),
                required_vuln_types: vec!["IDOR".to_string(), "Sensitive Data".to_string()],
                escalated_severity: Severity::Critical,
                escalated_confidence: Confidence::High,
            },
            // JWT Vuln + Auth Bypass = Full Compromise
            AttackChain {
                name: "Authentication Bypass Chain".to_string(),
                description: "JWT vulnerability combined with auth bypass enables full authentication compromise".to_string(),
                required_vuln_types: vec!["JWT".to_string(), "Auth".to_string()],
                escalated_severity: Severity::Critical,
                escalated_confidence: Confidence::High,
            },
            // SSRF + Cloud Metadata = Cloud Credential Theft
            AttackChain {
                name: "Cloud Credential Theft".to_string(),
                description: "SSRF can access cloud metadata endpoints to steal IAM credentials".to_string(),
                required_vuln_types: vec!["SSRF".to_string()],  // Single vuln but needs cloud context
                escalated_severity: Severity::Critical,
                escalated_confidence: Confidence::High,
            },
            // SQL Injection + Sensitive Data = Database Compromise
            AttackChain {
                name: "Database Compromise".to_string(),
                description: "SQL injection with sensitive data exposure enables full database access".to_string(),
                required_vuln_types: vec!["SQL".to_string()],
                escalated_severity: Severity::Critical,
                escalated_confidence: Confidence::High,
            },
            // Open Redirect + OAuth = Token Theft
            AttackChain {
                name: "OAuth Token Theft".to_string(),
                description: "Open redirect in OAuth flow can redirect tokens to attacker".to_string(),
                required_vuln_types: vec!["Open Redirect".to_string(), "OAuth".to_string()],
                escalated_severity: Severity::High,
                escalated_confidence: Confidence::High,
            },
            // CORS + Auth Endpoint = Cross-Origin Auth Bypass
            AttackChain {
                name: "Cross-Origin Authentication Bypass".to_string(),
                description: "CORS misconfiguration on auth endpoints allows cross-origin credential theft".to_string(),
                required_vuln_types: vec!["CORS".to_string()],
                escalated_severity: Severity::High,
                escalated_confidence: Confidence::Medium,
            },
            // Host Header + Password Reset = Account Takeover
            AttackChain {
                name: "Password Reset Poisoning".to_string(),
                description: "Host header injection in password reset enables account takeover".to_string(),
                required_vuln_types: vec!["Host Header".to_string(), "Password Reset".to_string()],
                escalated_severity: Severity::Critical,
                escalated_confidence: Confidence::High,
            },
            // Prototype Pollution + XSS = DOM-based RCE
            AttackChain {
                name: "Client-Side Code Execution".to_string(),
                description: "Prototype pollution combined with XSS can lead to arbitrary code execution".to_string(),
                required_vuln_types: vec!["Prototype Pollution".to_string(), "XSS".to_string()],
                escalated_severity: Severity::Critical,
                escalated_confidence: Confidence::High,
            },
            // Race Condition + Payment = Financial Fraud
            AttackChain {
                name: "Financial Fraud via Race Condition".to_string(),
                description: "Race condition in payment processing can lead to financial manipulation".to_string(),
                required_vuln_types: vec!["Race Condition".to_string()],
                escalated_severity: Severity::Critical,
                escalated_confidence: Confidence::High,
            },
        ]
    }

    /// Correlate vulnerabilities to find attack chains and reduce false positives
    pub fn correlate(&self, vulnerabilities: Vec<Vulnerability>) -> CorrelationResult {
        let mut stats = CorrelationStats {
            total_vulns: vulnerabilities.len(),
            ..Default::default()
        };

        // Step 1: Deduplicate similar vulnerabilities
        let deduplicated = self.deduplicate_vulnerabilities(&vulnerabilities);
        stats.deduplicated_vulns = deduplicated.len();

        // Step 2: Cluster by endpoint
        let endpoint_clusters = self.cluster_by_endpoint(&deduplicated);

        // Step 3: Find attack chains
        let attack_chains = self.find_attack_chains(&deduplicated, &endpoint_clusters);
        stats.attack_chains_found = attack_chains.len();

        // Step 4: Count severity escalations
        for chain in &attack_chains {
            if chain.escalated_severity == Severity::Critical {
                stats.severity_escalations += 1;
            }
        }

        info!(
            "Correlation complete: {} vulns -> {} deduplicated, {} attack chains found",
            stats.total_vulns, stats.deduplicated_vulns, stats.attack_chains_found
        );

        CorrelationResult {
            vulnerabilities: deduplicated,
            attack_chains,
            endpoint_clusters,
            stats,
        }
    }

    /// Deduplicate vulnerabilities that are essentially the same finding
    fn deduplicate_vulnerabilities(&self, vulns: &[Vulnerability]) -> Vec<Vulnerability> {
        let mut seen: HashSet<String> = HashSet::new();
        let mut result = Vec::new();

        for vuln in vulns {
            // Create dedup key from type + url + parameter
            let key = format!(
                "{}|{}|{}",
                vuln.vuln_type,
                vuln.url,
                vuln.parameter.as_deref().unwrap_or("")
            );

            if !seen.contains(&key) {
                seen.insert(key);
                result.push(vuln.clone());
            } else {
                debug!("Deduplicated: {} at {}", vuln.vuln_type, vuln.url);
            }
        }

        result
    }

    /// Cluster vulnerabilities by endpoint (URL without parameters)
    fn cluster_by_endpoint(&self, vulns: &[Vulnerability]) -> HashMap<String, Vec<usize>> {
        let mut clusters: HashMap<String, Vec<usize>> = HashMap::new();

        for (idx, vuln) in vulns.iter().enumerate() {
            // Extract base URL (without query string)
            let endpoint = vuln.url.split('?').next().unwrap_or(&vuln.url).to_string();
            clusters.entry(endpoint).or_default().push(idx);
        }

        clusters
    }

    /// Find attack chains from vulnerability combinations
    fn find_attack_chains(
        &self,
        vulns: &[Vulnerability],
        clusters: &HashMap<String, Vec<usize>>,
    ) -> Vec<DiscoveredChain> {
        let mut chains = Vec::new();

        // Get all vuln types present
        let vuln_types: HashSet<String> = vulns
            .iter()
            .map(|v| self.normalize_vuln_type(&v.vuln_type))
            .collect();

        // Check each attack pattern
        for pattern in &self.attack_patterns {
            let matches: Vec<&String> = pattern
                .required_vuln_types
                .iter()
                .filter(|req| vuln_types.iter().any(|vt| vt.contains(req.as_str())))
                .collect();

            if matches.len() == pattern.required_vuln_types.len() {
                // All required vuln types are present - find the involved vulns
                let involved: Vec<usize> = vulns
                    .iter()
                    .enumerate()
                    .filter(|(_, v)| {
                        let vt = self.normalize_vuln_type(&v.vuln_type);
                        pattern
                            .required_vuln_types
                            .iter()
                            .any(|req| vt.contains(req.as_str()))
                    })
                    .map(|(idx, _)| idx)
                    .collect();

                if !involved.is_empty() {
                    chains.push(DiscoveredChain {
                        chain_type: pattern.name.clone(),
                        description: pattern.description.clone(),
                        involved_vulns: involved,
                        escalated_severity: pattern.escalated_severity.clone(),
                        impact: self.generate_impact_description(&pattern.name, vulns),
                    });

                    info!("Attack chain discovered: {}", pattern.name);
                }
            }
        }

        // Check for endpoint-specific chains (multiple vulns on same endpoint)
        for (endpoint, indices) in clusters {
            if indices.len() >= 2 {
                let endpoint_vulns: Vec<&Vulnerability> =
                    indices.iter().map(|&i| &vulns[i]).collect();

                // Check for high-value combinations on same endpoint
                let has_auth_issue = endpoint_vulns.iter().any(|v| {
                    v.vuln_type.contains("Auth")
                        || v.vuln_type.contains("IDOR")
                        || v.vuln_type.contains("JWT")
                });
                let has_injection = endpoint_vulns.iter().any(|v| {
                    v.vuln_type.contains("Injection")
                        || v.vuln_type.contains("XSS")
                        || v.vuln_type.contains("SQL")
                });

                if has_auth_issue && has_injection {
                    chains.push(DiscoveredChain {
                        chain_type: "Endpoint Compromise".to_string(),
                        description: format!(
                            "Multiple vulnerabilities on {} create compound attack surface",
                            endpoint
                        ),
                        involved_vulns: indices.clone(),
                        escalated_severity: Severity::Critical,
                        impact: "Combined vulnerabilities may allow complete endpoint compromise"
                            .to_string(),
                    });
                }
            }
        }

        chains
    }

    /// Normalize vulnerability type for matching
    fn normalize_vuln_type(&self, vuln_type: &str) -> String {
        vuln_type.to_uppercase()
    }

    /// Generate impact description for discovered chain
    fn generate_impact_description(&self, chain_name: &str, vulns: &[Vulnerability]) -> String {
        match chain_name {
            "Account Takeover via XSS+CSRF" => {
                "Attacker can execute JavaScript to bypass CSRF tokens and perform actions as the victim, \
                potentially leading to full account compromise including password changes and data theft.".to_string()
            }
            "Data Breach via IDOR" => {
                "Insecure direct object references combined with sensitive data exposure allows \
                unauthorized access to other users' data through enumeration attacks.".to_string()
            }
            "Cloud Credential Theft" => {
                "SSRF vulnerability can be exploited to access cloud metadata endpoints (169.254.169.254), \
                potentially stealing IAM credentials and enabling cloud account compromise.".to_string()
            }
            "Database Compromise" => {
                "SQL injection vulnerability enables full database access, including extraction of \
                all user data, credentials, and potentially RCE via database features.".to_string()
            }
            _ => format!(
                "Combined vulnerabilities create elevated risk. {} total findings involved.",
                vulns.len()
            ),
        }
    }

    /// Get recommendations for discovered attack chains
    pub fn get_chain_recommendations(&self, chain: &DiscoveredChain) -> Vec<String> {
        match chain.chain_type.as_str() {
            "Account Takeover via XSS+CSRF" => vec![
                "Implement Content Security Policy (CSP) to prevent XSS".to_string(),
                "Use SameSite cookie attribute to prevent CSRF".to_string(),
                "Implement double-submit CSRF tokens".to_string(),
                "Consider using anti-CSRF tokens bound to session".to_string(),
            ],
            "Data Breach via IDOR" => vec![
                "Implement proper authorization checks on all data access".to_string(),
                "Use UUIDs instead of sequential IDs".to_string(),
                "Implement rate limiting to prevent enumeration".to_string(),
                "Log and monitor for unusual data access patterns".to_string(),
            ],
            "Cloud Credential Theft" => vec![
                "Block access to metadata endpoints (169.254.169.254)".to_string(),
                "Use IMDSv2 with required tokens".to_string(),
                "Implement network segmentation".to_string(),
                "Use least-privilege IAM roles".to_string(),
            ],
            _ => vec![
                "Review and remediate all individual vulnerabilities".to_string(),
                "Implement defense in depth".to_string(),
                "Consider a security architecture review".to_string(),
            ],
        }
    }
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_vuln(vuln_type: &str, url: &str, parameter: Option<&str>) -> Vulnerability {
        Vulnerability {
            id: uuid::Uuid::new_v4().to_string(),
            vuln_type: vuln_type.to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: "Test".to_string(),
            url: url.to_string(),
            parameter: parameter.map(|s| s.to_string()),
            payload: None,
            description: format!("Test {} vulnerability", vuln_type),
            evidence: None,
            cwe: None,
            cvss: None,
            verified: false,
            false_positive: false,
            remediation: None,
            discovered_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_attack_chain_detection() {
        let engine = CorrelationEngine::new();

        let vulns = vec![
            create_test_vuln(
                "Cross-Site Scripting (XSS)",
                "https://example.com/page",
                Some("input"),
            ),
            create_test_vuln("CSRF Missing Token", "https://example.com/action", None),
        ];

        let result = engine.correlate(vulns);

        assert!(
            !result.attack_chains.is_empty(),
            "Should detect XSS+CSRF chain"
        );
        assert!(result
            .attack_chains
            .iter()
            .any(|c| c.chain_type.contains("Account Takeover")));
    }

    #[test]
    fn test_deduplication() {
        let engine = CorrelationEngine::new();

        let vulns = vec![
            create_test_vuln("XSS", "https://example.com/page?id=1", Some("input")),
            create_test_vuln("XSS", "https://example.com/page?id=1", Some("input")), // Duplicate
            create_test_vuln("XSS", "https://example.com/page?id=2", Some("input")), // Different URL
        ];

        let result = engine.correlate(vulns);

        assert_eq!(
            result.vulnerabilities.len(),
            2,
            "Should deduplicate identical vulns"
        );
    }

    #[test]
    fn test_endpoint_clustering() {
        let engine = CorrelationEngine::new();

        let vulns = vec![
            create_test_vuln("XSS", "https://example.com/api/users?id=1", Some("id")),
            create_test_vuln("IDOR", "https://example.com/api/users?id=2", Some("id")),
            create_test_vuln("SQLi", "https://example.com/api/other", Some("q")),
        ];

        let result = engine.correlate(vulns);

        // Should have 2 clusters: /api/users and /api/other
        assert_eq!(result.endpoint_clusters.len(), 2);
        assert!(result
            .endpoint_clusters
            .contains_key("https://example.com/api/users"));
    }
}
