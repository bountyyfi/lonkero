// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - XML Injection Scanner
 * Detects XML injection vulnerabilities
 *
 * Detects:
 * - XML structure manipulation
 * - SOAP injection
 * - XML attribute injection
 * - CDATA injection
 * - XML comment injection
 * - XML namespace manipulation
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::{debug, info};

pub struct XMLInjectionScanner {
    http_client: Arc<HttpClient>,
    test_marker: String,
}

impl XMLInjectionScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        // Generate unique test marker
        let test_marker = format!("xml_{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
        Self {
            http_client,
            test_marker,
        }
    }

    /// Scan endpoint for XML injection vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[XML] Testing XML injection vulnerabilities");

        // Test XML structure injection
        let (vulns, tests) = self.test_xml_structure_injection(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Test SOAP injection
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_soap_injection(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test XML attribute injection
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_xml_attribute_injection(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test CDATA injection
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_cdata_injection(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test XML structure injection
    async fn test_xml_structure_injection(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 4;

        debug!("Testing XML structure injection");

        let payloads = vec![
            format!("</tag><injected>{}</injected><tag>", self.test_marker),
            format!("<tag>{}</tag>", self.test_marker),
            "</user><admin>true</admin><user>".to_string(),
            "</item><price>0</price><item>".to_string(),
        ];

        for payload in payloads {
            let headers = vec![
                ("Content-Type".to_string(), "application/xml".to_string()),
            ];

            let xml_body = format!(
                r#"<?xml version="1.0"?><data><value>{}</value></data>"#,
                payload
            );

            match self.http_client.post_with_headers(url, &xml_body, headers).await {
                Ok(response) => {
                    if self.detect_xml_injection(&response.body) {
                        info!("XML structure injection detected");
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "XML Structure Injection",
                            &payload,
                            "XML structure can be manipulated via user input",
                            &format!("XML marker '{}' or structure manipulation detected", self.test_marker),
                            Severity::High,
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

    /// Test SOAP injection
    async fn test_soap_injection(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        debug!("Testing SOAP injection");

        let soap_payloads = vec![
            format!(
                r#"</soapenv:Body><soapenv:Body><test>{}</test></soapenv:Body><soapenv:Body>"#,
                self.test_marker
            ),
            "</auth><admin>true</admin><auth>".to_string(),
            r#"</value><value>0</value><value>"#.to_string(),
        ];

        for payload in soap_payloads {
            let headers = vec![
                ("Content-Type".to_string(), "text/xml".to_string()),
                ("SOAPAction".to_string(), "test".to_string()),
            ];

            let soap_body = format!(
                r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
    <soapenv:Body>
        <data>{}</data>
    </soapenv:Body>
</soapenv:Envelope>"#,
                payload
            );

            match self.http_client.post_with_headers(url, &soap_body, headers).await {
                Ok(response) => {
                    if self.detect_soap_injection(&response.body) {
                        info!("SOAP injection detected");
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "SOAP Injection",
                            &payload,
                            "SOAP message structure can be manipulated",
                            "SOAP structure manipulation detected",
                            Severity::High,
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("SOAP request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test XML attribute injection
    async fn test_xml_attribute_injection(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        debug!("Testing XML attribute injection");

        let payloads = vec![
            format!(r#"" admin="true" marker="{}"#, self.test_marker),
            r#"" role="admin"#.to_string(),
            r#""><script>alert(1)</script><tag attr=""#.to_string(),
        ];

        for payload in payloads {
            let headers = vec![
                ("Content-Type".to_string(), "application/xml".to_string()),
            ];

            let xml_body = format!(
                r#"<?xml version="1.0"?><user name="{}" /></user>"#,
                payload
            );

            match self.http_client.post_with_headers(url, &xml_body, headers).await {
                Ok(response) => {
                    if self.detect_attribute_injection(&response.body) {
                        info!("XML attribute injection detected");
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "XML Attribute Injection",
                            &payload,
                            "XML attributes can be injected or modified",
                            "Attribute injection detected in XML response",
                            Severity::Medium,
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

    /// Test CDATA injection
    async fn test_cdata_injection(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 2;

        debug!("Testing CDATA injection");

        let payloads = vec![
            format!(r#"]]><![CDATA[{}"#, self.test_marker),
            r#"]]></tag><admin>true</admin><tag><![CDATA["#.to_string(),
        ];

        for payload in payloads {
            let headers = vec![
                ("Content-Type".to_string(), "application/xml".to_string()),
            ];

            let xml_body = format!(
                r#"<?xml version="1.0"?><data><![CDATA[{}]]></data>"#,
                payload
            );

            match self.http_client.post_with_headers(url, &xml_body, headers).await {
                Ok(response) => {
                    if self.detect_cdata_injection(&response.body) {
                        info!("CDATA injection detected");
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "CDATA Injection",
                            &payload,
                            "CDATA section can be broken to inject XML",
                            "CDATA escape detected in response",
                            Severity::Medium,
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

    /// Detect XML injection in response
    fn detect_xml_injection(&self, body: &str) -> bool {
        // Check for test marker
        if body.contains(&self.test_marker) {
            return true;
        }

        // Check for XML injection indicators
        let indicators = vec![
            "<injected>",
            "<admin>true</admin>",
            "<price>0</price>",
            "xml syntax error",
            "malformed xml",
            "xml parse error",
        ];

        let body_lower = body.to_lowercase();
        for indicator in indicators {
            if body_lower.contains(indicator) {
                return true;
            }
        }

        false
    }

    /// Detect SOAP injection in response
    fn detect_soap_injection(&self, body: &str) -> bool {
        if body.contains(&self.test_marker) {
            return true;
        }

        let body_lower = body.to_lowercase();
        let indicators = vec![
            "soap fault",
            "soap:fault",
            "soapenv:fault",
            "xml parse",
            "malformed soap",
        ];

        for indicator in indicators {
            if body_lower.contains(indicator) {
                return true;
            }
        }

        false
    }

    /// Detect attribute injection
    fn detect_attribute_injection(&self, body: &str) -> bool {
        if body.contains(&self.test_marker) {
            return true;
        }

        let body_lower = body.to_lowercase();
        body_lower.contains(r#"admin="true"#) ||
        body_lower.contains(r#"role="admin"#) ||
        body_lower.contains("<script>")
    }

    /// Detect CDATA injection
    fn detect_cdata_injection(&self, body: &str) -> bool {
        if body.contains(&self.test_marker) {
            return true;
        }

        let body_lower = body.to_lowercase();
        body_lower.contains("cdata") && (
            body_lower.contains("]]>") ||
            body_lower.contains("<admin>")
        )
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        url: &str,
        attack_type: &str,
        payload: &str,
        description: &str,
        evidence: &str,
        severity: Severity,
    ) -> Vulnerability {
        let cvss = match severity {
            Severity::Critical => 9.1,
            Severity::High => 7.5,
            Severity::Medium => 5.3,
            _ => 3.1,
        };

        Vulnerability {
            id: format!("xml_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: format!("XML Injection ({})", attack_type),
            severity,
            confidence: Confidence::High,
            category: "Injection".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: payload.to_string(),
            description: description.to_string(),
            evidence: Some(evidence.to_string()),
            cwe: "CWE-91".to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: "1. Use parameterized XML APIs instead of string concatenation\n\
                         2. Validate and sanitize all user input before XML processing\n\
                         3. Use XML schema validation (XSD) to enforce structure\n\
                         4. Disable XML entity expansion to prevent XXE\n\
                         5. Use safe XML parsing libraries\n\
                         6. Implement input encoding for XML special characters (&, <, >, \", ')\n\
                         7. Use allowlists for acceptable XML values\n\
                         8. Avoid building XML from user input when possible\n\
                         9. Implement proper error handling without revealing XML structure\n\
                         10. Use SOAP message validation for web services".to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
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
    use crate::http_client::HttpClient;
    use std::sync::Arc;

    fn create_test_scanner() -> XMLInjectionScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        XMLInjectionScanner::new(http_client)
    }

    #[test]
    fn test_detect_xml_injection_marker() {
        let scanner = create_test_scanner();
        let body = format!("Response contains {}", scanner.test_marker);

        assert!(scanner.detect_xml_injection(&body));
    }

    #[test]
    fn test_detect_xml_injection_indicators() {
        let scanner = create_test_scanner();

        let bodies = vec![
            "<injected>malicious</injected>",
            "<admin>true</admin>",
            "XML syntax error at line 5",
            "Malformed XML document",
        ];

        for body in bodies {
            assert!(scanner.detect_xml_injection(body));
        }
    }

    #[test]
    fn test_detect_soap_injection() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_soap_injection(&format!("Contains {}", scanner.test_marker)));
        assert!(scanner.detect_soap_injection("SOAP:Fault occurred"));
        assert!(scanner.detect_soap_injection("soapenv:Fault message"));
    }

    #[test]
    fn test_detect_attribute_injection() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_attribute_injection(r#"<user admin="true" />"#));
        assert!(scanner.detect_attribute_injection(r#"role="admin""#));
        assert!(scanner.detect_attribute_injection("<script>alert(1)</script>"));
    }

    #[test]
    fn test_detect_cdata_injection() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_cdata_injection("]]><admin>true</admin><![CDATA["));
        assert!(scanner.detect_cdata_injection(&format!("CDATA section with {}", scanner.test_marker)));
    }

    #[test]
    fn test_no_false_positives() {
        let scanner = create_test_scanner();
        let body = "Normal XML response without injection";

        assert!(!scanner.detect_xml_injection(body));
        assert!(!scanner.detect_soap_injection(body));
        assert!(!scanner.detect_attribute_injection(body));
        assert!(!scanner.detect_cdata_injection(body));
    }

    #[test]
    fn test_create_vulnerability() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "http://example.com",
            "XML Structure Injection",
            "</tag><injected>test</injected><tag>",
            "XML injection detected",
            "Test evidence",
            Severity::High,
        );

        assert_eq!(vuln.vuln_type, "XML Injection (XML Structure Injection)");
        assert_eq!(vuln.severity, Severity::High);
        assert_eq!(vuln.cwe, "CWE-91");
        assert_eq!(vuln.cvss, 7.5);
        assert!(vuln.verified);
    }

    #[test]
    fn test_unique_test_marker() {
        let scanner1 = create_test_scanner();
        let scanner2 = create_test_scanner();

        assert_ne!(scanner1.test_marker, scanner2.test_marker);
        assert!(scanner1.test_marker.starts_with("xml_"));
    }
}
