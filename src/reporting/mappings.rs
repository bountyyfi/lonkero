// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::types::Vulnerability;
use std::collections::HashMap;

pub struct OWASPMapper;

impl OWASPMapper {
    pub fn map_to_owasp_top10(vulnerabilities: &[Vulnerability]) -> HashMap<String, Vec<Vulnerability>> {
        let mut mapping: HashMap<String, Vec<Vulnerability>> = HashMap::new();

        for vuln in vulnerabilities {
            let owasp_category = Self::get_owasp_category(&vuln.vuln_type, &vuln.cwe);
            mapping
                .entry(owasp_category)
                .or_insert_with(Vec::new)
                .push(vuln.clone());
        }

        mapping
    }

    fn get_owasp_category(vuln_type: &str, cwe: &str) -> String {
        match vuln_type {
            t if t.contains("Injection") || t.contains("SQL") || t.contains("XSS") || t.contains("Command") => {
                "A03:2021 - Injection".to_string()
            }
            t if t.contains("Authentication") || t.contains("Session") || t.contains("JWT") => {
                "A07:2021 - Identification and Authentication Failures".to_string()
            }
            t if t.contains("Authorization") || t.contains("IDOR") || t.contains("Access Control") => {
                "A01:2021 - Broken Access Control".to_string()
            }
            t if t.contains("Cryptographic") || t.contains("Encryption") => {
                "A02:2021 - Cryptographic Failures".to_string()
            }
            t if t.contains("Deserialization") => {
                "A08:2021 - Software and Data Integrity Failures".to_string()
            }
            t if t.contains("XXE") || t.contains("XML") => {
                "A05:2021 - Security Misconfiguration".to_string()
            }
            t if t.contains("Sensitive Data") || t.contains("Information Disclosure") => {
                "A02:2021 - Cryptographic Failures".to_string()
            }
            t if t.contains("SSRF") => {
                "A10:2021 - Server-Side Request Forgery".to_string()
            }
            t if t.contains("Security Headers") || t.contains("CORS") || t.contains("CSP") => {
                "A05:2021 - Security Misconfiguration".to_string()
            }
            _ => {
                if cwe.contains("862") || cwe.contains("639") {
                    "A01:2021 - Broken Access Control".to_string()
                } else if cwe.contains("798") || cwe.contains("259") {
                    "A07:2021 - Identification and Authentication Failures".to_string()
                } else {
                    "A06:2021 - Vulnerable and Outdated Components".to_string()
                }
            }
        }
    }

    pub fn get_owasp_description(category: &str) -> String {
        match category {
            "A01:2021 - Broken Access Control" => {
                "Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of data."
            }
            "A02:2021 - Cryptographic Failures" => {
                "Failures related to cryptography which often lead to exposure of sensitive data. This includes data in transit, at rest, or in use that requires extra protection."
            }
            "A03:2021 - Injection" => {
                "An application is vulnerable to attack when user-supplied data is not validated, filtered, or sanitized. This includes SQL, NoSQL, OS command, ORM, LDAP, and Expression Language injection."
            }
            "A04:2021 - Insecure Design" => {
                "Risks related to design and architectural flaws, with a call for more use of threat modeling, secure design patterns, and reference architectures."
            }
            "A05:2021 - Security Misconfiguration" => {
                "Security misconfiguration is the most commonly seen issue. This is commonly a result of insecure default configurations, incomplete or ad hoc configurations, open cloud storage, misconfigured HTTP headers, and verbose error messages."
            }
            "A06:2021 - Vulnerable and Outdated Components" => {
                "You are likely vulnerable if you do not know the versions of all components you use or if the software is vulnerable, unsupported, or out of date."
            }
            "A07:2021 - Identification and Authentication Failures" => {
                "Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks."
            }
            "A08:2021 - Software and Data Integrity Failures" => {
                "Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations."
            }
            "A09:2021 - Security Logging and Monitoring Failures" => {
                "Without logging and monitoring, breaches cannot be detected. Insufficient logging, detection, monitoring, and active response occurs any time."
            }
            "A10:2021 - Server-Side Request Forgery" => {
                "SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL."
            }
            _ => "Unknown OWASP category"
        }.to_string()
    }
}

pub struct CWEMapper;

impl CWEMapper {
    pub fn map_to_cwe(vulnerabilities: &[Vulnerability]) -> HashMap<String, Vec<Vulnerability>> {
        let mut mapping: HashMap<String, Vec<Vulnerability>> = HashMap::new();

        for vuln in vulnerabilities {
            let cwe_key = format!("{}: {}", vuln.cwe, Self::get_cwe_name(&vuln.cwe));
            mapping
                .entry(cwe_key)
                .or_insert_with(Vec::new)
                .push(vuln.clone());
        }

        mapping
    }

    fn get_cwe_name(cwe: &str) -> String {
        match cwe {
            "CWE-79" => "Cross-site Scripting (XSS)".to_string(),
            "CWE-89" => "SQL Injection".to_string(),
            "CWE-78" => "OS Command Injection".to_string(),
            "CWE-352" => "Cross-Site Request Forgery (CSRF)".to_string(),
            "CWE-22" => "Path Traversal".to_string(),
            "CWE-918" => "Server-Side Request Forgery (SSRF)".to_string(),
            "CWE-611" => "XML External Entity (XXE)".to_string(),
            "CWE-502" => "Deserialization of Untrusted Data".to_string(),
            "CWE-798" => "Use of Hard-coded Credentials".to_string(),
            "CWE-862" => "Missing Authorization".to_string(),
            "CWE-863" => "Incorrect Authorization".to_string(),
            "CWE-200" => "Exposure of Sensitive Information".to_string(),
            "CWE-287" => "Improper Authentication".to_string(),
            "CWE-306" => "Missing Authentication for Critical Function".to_string(),
            "CWE-639" => "Insecure Direct Object Reference (IDOR)".to_string(),
            "CWE-601" => "Open Redirect".to_string(),
            "CWE-94" => "Code Injection".to_string(),
            "CWE-1321" => "Prototype Pollution".to_string(),
            "CWE-434" => "Unrestricted Upload of File with Dangerous Type".to_string(),
            "CWE-319" => "Cleartext Transmission of Sensitive Information".to_string(),
            _ => "Unknown CWE".to_string(),
        }
    }
}

pub struct ComplianceMapper;

impl ComplianceMapper {
    pub fn map_to_pci_dss(vulnerabilities: &[Vulnerability]) -> HashMap<String, Vec<String>> {
        let mut mapping: HashMap<String, Vec<String>> = HashMap::new();

        for vuln in vulnerabilities {
            let requirements = Self::get_pci_dss_requirements(&vuln.vuln_type, &vuln.cwe);
            for req in requirements {
                mapping
                    .entry(req)
                    .or_insert_with(Vec::new)
                    .push(vuln.id.clone());
            }
        }

        mapping
    }

    fn get_pci_dss_requirements(vuln_type: &str, cwe: &str) -> Vec<String> {
        let mut requirements = Vec::new();

        if vuln_type.contains("SQL") || vuln_type.contains("Injection") || vuln_type.contains("XSS") {
            requirements.push("6.5.1 - Injection flaws".to_string());
        }

        if vuln_type.contains("Authentication") || vuln_type.contains("Session") {
            requirements.push("8.2 - Strong authentication".to_string());
            requirements.push("8.3 - Multi-factor authentication".to_string());
        }

        if vuln_type.contains("Encryption") || vuln_type.contains("Cryptographic") || cwe.contains("319") {
            requirements.push("4.1 - Strong cryptography for transmission".to_string());
        }

        if vuln_type.contains("Access Control") || vuln_type.contains("Authorization") {
            requirements.push("7.1 - Limit access by business need-to-know".to_string());
        }

        if vuln_type.contains("CSRF") {
            requirements.push("6.5.9 - Cross-site request forgery".to_string());
        }

        if vuln_type.contains("Sensitive Data") || vuln_type.contains("Information Disclosure") {
            requirements.push("3.4 - Cryptography to protect cardholder data".to_string());
        }

        if requirements.is_empty() {
            requirements.push("6.2 - Security patches and updates".to_string());
        }

        requirements
    }

    pub fn map_to_hipaa(vulnerabilities: &[Vulnerability]) -> HashMap<String, Vec<String>> {
        let mut mapping: HashMap<String, Vec<String>> = HashMap::new();

        for vuln in vulnerabilities {
            let requirements = Self::get_hipaa_requirements(&vuln.vuln_type, &vuln.cwe);
            for req in requirements {
                mapping
                    .entry(req)
                    .or_insert_with(Vec::new)
                    .push(vuln.id.clone());
            }
        }

        mapping
    }

    fn get_hipaa_requirements(vuln_type: &str, _cwe: &str) -> Vec<String> {
        let mut requirements = Vec::new();

        if vuln_type.contains("Authentication") || vuln_type.contains("Authorization") {
            requirements.push("164.308(a)(4) - Access Management".to_string());
            requirements.push("164.312(a)(1) - Access Control".to_string());
        }

        if vuln_type.contains("Encryption") || vuln_type.contains("Sensitive Data") {
            requirements.push("164.312(a)(2)(iv) - Encryption and Decryption".to_string());
            requirements.push("164.312(e)(2)(ii) - Encryption".to_string());
        }

        if vuln_type.contains("Audit") || vuln_type.contains("Logging") {
            requirements.push("164.308(a)(1)(ii)(D) - Information System Activity Review".to_string());
            requirements.push("164.312(b) - Audit Controls".to_string());
        }

        if requirements.is_empty() {
            requirements.push("164.308(a)(5) - Security Awareness and Training".to_string());
        }

        requirements
    }

    pub fn map_to_soc2(vulnerabilities: &[Vulnerability]) -> HashMap<String, Vec<String>> {
        let mut mapping: HashMap<String, Vec<String>> = HashMap::new();

        for vuln in vulnerabilities {
            let requirements = Self::get_soc2_requirements(&vuln.vuln_type);
            for req in requirements {
                mapping
                    .entry(req)
                    .or_insert_with(Vec::new)
                    .push(vuln.id.clone());
            }
        }

        mapping
    }

    fn get_soc2_requirements(vuln_type: &str) -> Vec<String> {
        let mut requirements = Vec::new();

        if vuln_type.contains("Authentication") || vuln_type.contains("Authorization") {
            requirements.push("CC6.1 - Logical and Physical Access Controls".to_string());
            requirements.push("CC6.2 - Authorization".to_string());
        }

        if vuln_type.contains("Encryption") || vuln_type.contains("Cryptographic") {
            requirements.push("CC6.7 - Transmission Security".to_string());
        }

        if vuln_type.contains("Injection") || vuln_type.contains("XSS") || vuln_type.contains("SQL") {
            requirements.push("CC7.1 - Detection of Security Events".to_string());
            requirements.push("CC8.1 - Change Management".to_string());
        }

        if requirements.is_empty() {
            requirements.push("CC7.2 - Monitoring of Controls".to_string());
        }

        requirements
    }

    /// Map vulnerabilities to ISO 27001 controls
    pub fn map_to_iso27001(vulnerabilities: &[Vulnerability]) -> HashMap<String, Vec<String>> {
        let mut mapping: HashMap<String, Vec<String>> = HashMap::new();

        for vuln in vulnerabilities {
            let requirements = Self::get_iso27001_requirements(&vuln.vuln_type, &vuln.cwe);
            for req in requirements {
                mapping
                    .entry(req)
                    .or_insert_with(Vec::new)
                    .push(vuln.id.clone());
            }
        }

        mapping
    }

    fn get_iso27001_requirements(vuln_type: &str, cwe: &str) -> Vec<String> {
        let mut requirements = Vec::new();

        // Access Control (A.9)
        if vuln_type.contains("Authentication") || vuln_type.contains("Authorization") ||
           vuln_type.contains("IDOR") || vuln_type.contains("BOLA") ||
           cwe.contains("862") || cwe.contains("863") {
            requirements.push("A.9.1.1 - Access control policy".to_string());
            requirements.push("A.9.2.1 - User registration and de-registration".to_string());
            requirements.push("A.9.4.1 - Information access restriction".to_string());
            requirements.push("A.9.4.2 - Secure log-on procedures".to_string());
        }

        // Session Management
        if vuln_type.contains("Session") || vuln_type.contains("JWT") || vuln_type.contains("Token") {
            requirements.push("A.9.4.2 - Secure log-on procedures".to_string());
            requirements.push("A.9.4.3 - Password management system".to_string());
            requirements.push("A.14.1.2 - Securing application services on public networks".to_string());
        }

        // Cryptography (A.10)
        if vuln_type.contains("Encryption") || vuln_type.contains("Cryptographic") ||
           vuln_type.contains("SSL") || vuln_type.contains("TLS") ||
           cwe.contains("327") || cwe.contains("295") || cwe.contains("319") {
            requirements.push("A.10.1.1 - Policy on the use of cryptographic controls".to_string());
            requirements.push("A.10.1.2 - Key management".to_string());
            requirements.push("A.14.1.2 - Securing application services on public networks".to_string());
            requirements.push("A.14.1.3 - Protecting application services transactions".to_string());
        }

        // Communications Security (A.13)
        if vuln_type.contains("CORS") || vuln_type.contains("Headers") || vuln_type.contains("HSTS") {
            requirements.push("A.13.1.1 - Network controls".to_string());
            requirements.push("A.13.1.2 - Security of network services".to_string());
            requirements.push("A.13.2.1 - Information transfer policies and procedures".to_string());
        }

        // System Acquisition, Development and Maintenance (A.14)
        if vuln_type.contains("Injection") || vuln_type.contains("XSS") || vuln_type.contains("SQL") ||
           vuln_type.contains("Command") || vuln_type.contains("SSTI") {
            requirements.push("A.14.2.1 - Secure development policy".to_string());
            requirements.push("A.14.2.5 - Secure system engineering principles".to_string());
            requirements.push("A.14.2.8 - System security testing".to_string());
            requirements.push("A.14.2.9 - System acceptance testing".to_string());
        }

        // Input Validation
        if vuln_type.contains("Path Traversal") || vuln_type.contains("File Upload") ||
           vuln_type.contains("XXE") || vuln_type.contains("XML") {
            requirements.push("A.14.2.5 - Secure system engineering principles".to_string());
            requirements.push("A.14.1.2 - Securing application services on public networks".to_string());
        }

        // SSRF
        if vuln_type.contains("SSRF") {
            requirements.push("A.13.1.1 - Network controls".to_string());
            requirements.push("A.13.1.3 - Segregation in networks".to_string());
            requirements.push("A.14.2.5 - Secure system engineering principles".to_string());
        }

        // CSRF
        if vuln_type.contains("CSRF") {
            requirements.push("A.14.1.2 - Securing application services on public networks".to_string());
            requirements.push("A.14.2.5 - Secure system engineering principles".to_string());
        }

        // Information Leakage
        if vuln_type.contains("Information Disclosure") || vuln_type.contains("Sensitive Data") ||
           vuln_type.contains("Exposure") || cwe.contains("200") {
            requirements.push("A.8.2.1 - Classification of information".to_string());
            requirements.push("A.8.2.3 - Handling of assets".to_string());
            requirements.push("A.18.1.3 - Protection of records".to_string());
        }

        // Business Logic
        if vuln_type.contains("Business Logic") || vuln_type.contains("Race Condition") ||
           vuln_type.contains("Price") || vuln_type.contains("Quantity") {
            requirements.push("A.14.2.1 - Secure development policy".to_string());
            requirements.push("A.14.2.5 - Secure system engineering principles".to_string());
        }

        // Security Misconfiguration
        if vuln_type.contains("Misconfiguration") || vuln_type.contains("Default") {
            requirements.push("A.12.1.2 - Change management".to_string());
            requirements.push("A.12.6.1 - Management of technical vulnerabilities".to_string());
            requirements.push("A.14.2.2 - System change control procedures".to_string());
        }

        // GraphQL specific
        if vuln_type.contains("GraphQL") {
            requirements.push("A.14.2.5 - Secure system engineering principles".to_string());
            requirements.push("A.14.2.8 - System security testing".to_string());
        }

        if requirements.is_empty() {
            requirements.push("A.12.6.1 - Management of technical vulnerabilities".to_string());
        }

        requirements
    }

    /// Map vulnerabilities to GDPR articles
    pub fn map_to_gdpr(vulnerabilities: &[Vulnerability]) -> HashMap<String, Vec<String>> {
        let mut mapping: HashMap<String, Vec<String>> = HashMap::new();

        for vuln in vulnerabilities {
            let requirements = Self::get_gdpr_requirements(&vuln.vuln_type, &vuln.cwe);
            for req in requirements {
                mapping
                    .entry(req)
                    .or_insert_with(Vec::new)
                    .push(vuln.id.clone());
            }
        }

        mapping
    }

    fn get_gdpr_requirements(vuln_type: &str, cwe: &str) -> Vec<String> {
        let mut requirements = Vec::new();

        // Article 5 - Principles relating to processing of personal data
        // (integrity, confidentiality)
        if vuln_type.contains("Injection") || vuln_type.contains("XSS") ||
           vuln_type.contains("SQL") || vuln_type.contains("Authentication") ||
           vuln_type.contains("Authorization") {
            requirements.push("Art. 5(1)(f) - Integrity and confidentiality".to_string());
        }

        // Article 25 - Data protection by design and default
        if vuln_type.contains("Sensitive Data") || vuln_type.contains("Information Disclosure") ||
           vuln_type.contains("Exposure") || cwe.contains("200") || cwe.contains("359") {
            requirements.push("Art. 25(1) - Data protection by design".to_string());
            requirements.push("Art. 25(2) - Data protection by default".to_string());
        }

        // Article 32 - Security of processing
        if vuln_type.contains("Encryption") || vuln_type.contains("Cryptographic") ||
           vuln_type.contains("SSL") || vuln_type.contains("TLS") ||
           cwe.contains("327") || cwe.contains("295") || cwe.contains("319") {
            requirements.push("Art. 32(1)(a) - Pseudonymisation and encryption".to_string());
            requirements.push("Art. 32(1)(b) - Confidentiality, integrity, availability".to_string());
        }

        // Access Control relates to Article 32
        if vuln_type.contains("IDOR") || vuln_type.contains("BOLA") ||
           vuln_type.contains("Access Control") || cwe.contains("862") || cwe.contains("863") {
            requirements.push("Art. 32(1)(b) - Confidentiality, integrity, availability".to_string());
            requirements.push("Art. 32(1)(d) - Regular testing and evaluation".to_string());
        }

        // Session Management
        if vuln_type.contains("Session") || vuln_type.contains("JWT") || vuln_type.contains("Token") {
            requirements.push("Art. 32(1)(b) - Confidentiality, integrity, availability".to_string());
        }

        // SSRF - can access internal data
        if vuln_type.contains("SSRF") {
            requirements.push("Art. 32(1)(b) - Confidentiality, integrity, availability".to_string());
            requirements.push("Art. 5(1)(f) - Integrity and confidentiality".to_string());
        }

        // Business Logic - data manipulation
        if vuln_type.contains("Business Logic") || vuln_type.contains("Race Condition") {
            requirements.push("Art. 5(1)(d) - Accuracy".to_string());
            requirements.push("Art. 5(1)(f) - Integrity and confidentiality".to_string());
        }

        // Article 33 - Notification of personal data breach
        // Article 34 - Communication of personal data breach
        if vuln_type.contains("Critical") || vuln_type.contains("Data Breach") ||
           vuln_type.contains("Data Leak") {
            requirements.push("Art. 33 - Breach notification to supervisory authority".to_string());
            requirements.push("Art. 34 - Breach communication to data subject".to_string());
        }

        // Testing and auditing requirement
        if !requirements.is_empty() {
            requirements.push("Art. 32(1)(d) - Regular testing and evaluation".to_string());
        }

        if requirements.is_empty() {
            requirements.push("Art. 32(1)(d) - Regular testing and evaluation".to_string());
        }

        requirements
    }

    /// Map vulnerabilities to NIST Cybersecurity Framework
    pub fn map_to_nist_csf(vulnerabilities: &[Vulnerability]) -> HashMap<String, Vec<String>> {
        let mut mapping: HashMap<String, Vec<String>> = HashMap::new();

        for vuln in vulnerabilities {
            let requirements = Self::get_nist_csf_requirements(&vuln.vuln_type, &vuln.cwe);
            for req in requirements {
                mapping
                    .entry(req)
                    .or_insert_with(Vec::new)
                    .push(vuln.id.clone());
            }
        }

        mapping
    }

    fn get_nist_csf_requirements(vuln_type: &str, cwe: &str) -> Vec<String> {
        let mut requirements = Vec::new();

        // Protect - Access Control (PR.AC)
        if vuln_type.contains("Authentication") || vuln_type.contains("Authorization") ||
           vuln_type.contains("IDOR") || vuln_type.contains("Session") ||
           cwe.contains("862") || cwe.contains("863") || cwe.contains("287") {
            requirements.push("PR.AC-1 - Identities and credentials management".to_string());
            requirements.push("PR.AC-4 - Access permissions managed".to_string());
            requirements.push("PR.AC-7 - Users, devices, assets authenticated".to_string());
        }

        // Protect - Data Security (PR.DS)
        if vuln_type.contains("Encryption") || vuln_type.contains("SSL") ||
           vuln_type.contains("Sensitive Data") || cwe.contains("319") || cwe.contains("200") {
            requirements.push("PR.DS-1 - Data-at-rest protected".to_string());
            requirements.push("PR.DS-2 - Data-in-transit protected".to_string());
            requirements.push("PR.DS-5 - Protections against data leaks".to_string());
        }

        // Protect - Information Protection (PR.IP)
        if vuln_type.contains("Injection") || vuln_type.contains("XSS") ||
           vuln_type.contains("Input") || vuln_type.contains("Validation") {
            requirements.push("PR.IP-2 - System development life cycle".to_string());
            requirements.push("PR.IP-12 - Vulnerability management plan".to_string());
        }

        // Identify - Risk Assessment (ID.RA)
        if !requirements.is_empty() {
            requirements.push("ID.RA-1 - Asset vulnerabilities identified".to_string());
            requirements.push("ID.RA-5 - Threats, vulnerabilities, likelihoods, impacts".to_string());
        }

        // Detect (DE)
        requirements.push("DE.CM-8 - Vulnerability scans performed".to_string());

        if requirements.is_empty() {
            requirements.push("PR.IP-12 - Vulnerability management plan".to_string());
        }

        requirements
    }

    /// Map vulnerabilities to DORA (Digital Operational Resilience Act) requirements
    /// For EU financial services sector
    pub fn map_to_dora(vulnerabilities: &[Vulnerability]) -> HashMap<String, Vec<String>> {
        let mut mapping: HashMap<String, Vec<String>> = HashMap::new();

        for vuln in vulnerabilities {
            let requirements = Self::get_dora_requirements(&vuln.vuln_type, &vuln.cwe, vuln.severity.clone());
            for req in requirements {
                mapping
                    .entry(req)
                    .or_insert_with(Vec::new)
                    .push(vuln.id.clone());
            }
        }

        mapping
    }

    fn get_dora_requirements(vuln_type: &str, cwe: &str, severity: crate::types::Severity) -> Vec<String> {
        let mut requirements = Vec::new();

        // Chapter II - ICT Risk Management (Articles 5-16)
        // Article 5: ICT risk management framework
        if vuln_type.contains("Misconfiguration") || vuln_type.contains("Default") ||
           vuln_type.contains("Exposure") {
            requirements.push("Art. 5 - ICT risk management framework".to_string());
        }

        // Article 6: ICT systems, protocols and tools
        if vuln_type.contains("SSL") || vuln_type.contains("TLS") ||
           vuln_type.contains("Cryptographic") || vuln_type.contains("Encryption") ||
           cwe.contains("327") || cwe.contains("295") {
            requirements.push("Art. 6(1) - ICT systems protocols and tools".to_string());
            requirements.push("Art. 6(2) - Secure network connectivity".to_string());
        }

        // Article 7: Identification of ICT risks
        requirements.push("Art. 7 - Identification of ICT risks".to_string());

        // Article 8: Protection and prevention
        if vuln_type.contains("Injection") || vuln_type.contains("XSS") ||
           vuln_type.contains("SQL") || vuln_type.contains("Command") {
            requirements.push("Art. 8(1) - Protection of ICT systems".to_string());
            requirements.push("Art. 8(2) - ICT security policies".to_string());
        }

        // Article 9: Detection
        if vuln_type.contains("Information Disclosure") || vuln_type.contains("Sensitive Data") ||
           cwe.contains("200") {
            requirements.push("Art. 9(1) - Anomaly detection mechanisms".to_string());
            requirements.push("Art. 9(3) - Intrusion detection".to_string());
        }

        // Article 10: Response and recovery
        if matches!(severity, crate::types::Severity::Critical | crate::types::Severity::High) {
            requirements.push("Art. 10(1) - ICT business continuity policy".to_string());
            requirements.push("Art. 10(2) - Crisis management procedures".to_string());
        }

        // Article 11: Backup policies
        if vuln_type.contains("Ransomware") || vuln_type.contains("Data Loss") ||
           vuln_type.contains("Integrity") {
            requirements.push("Art. 11(1) - Backup policies and procedures".to_string());
            requirements.push("Art. 11(4) - Backup restoration testing".to_string());
        }

        // Article 12: Learning and evolving
        requirements.push("Art. 12(1) - Post-incident reviews".to_string());

        // Article 13: Communication
        if vuln_type.contains("CORS") || vuln_type.contains("CSRF") ||
           vuln_type.contains("Header") {
            requirements.push("Art. 13 - Communication policies".to_string());
        }

        // Authentication and access control
        if vuln_type.contains("Authentication") || vuln_type.contains("Authorization") ||
           vuln_type.contains("Session") || vuln_type.contains("IDOR") ||
           vuln_type.contains("JWT") || cwe.contains("287") || cwe.contains("862") {
            requirements.push("Art. 8(3) - Access control policies".to_string());
            requirements.push("Art. 8(4) - Strong authentication mechanisms".to_string());
        }

        // Chapter III - ICT-related Incident Management (Articles 17-23)
        if matches!(severity, crate::types::Severity::Critical) {
            requirements.push("Art. 17 - ICT-related incident management process".to_string());
            requirements.push("Art. 19 - Reporting of major ICT-related incidents".to_string());
        }

        // Chapter IV - Digital Operational Resilience Testing (Articles 24-27)
        requirements.push("Art. 24 - General requirements for resilience testing".to_string());
        requirements.push("Art. 25 - Testing ICT tools and systems".to_string());

        // SSRF/SSRF - network segregation
        if vuln_type.contains("SSRF") {
            requirements.push("Art. 6(2) - Secure network connectivity".to_string());
            requirements.push("Art. 8(5) - Network segmentation".to_string());
        }

        // API Security
        if vuln_type.contains("API") || vuln_type.contains("GraphQL") {
            requirements.push("Art. 6(1) - ICT systems protocols and tools".to_string());
            requirements.push("Art. 8(2) - ICT security policies".to_string());
        }

        // Chapter V - ICT Third-party Risk (Articles 28-44)
        if vuln_type.contains("Third-party") || vuln_type.contains("Supply Chain") ||
           vuln_type.contains("Dependency") {
            requirements.push("Art. 28 - ICT third-party risk".to_string());
            requirements.push("Art. 30 - Key contractual provisions".to_string());
        }

        if requirements.len() == 1 {
            // Default to general testing requirement
            requirements.push("Art. 25 - Testing ICT tools and systems".to_string());
        }

        requirements
    }

    /// Map vulnerabilities to NIS2 (Network and Information Security Directive 2) requirements
    /// For EU critical infrastructure sectors
    pub fn map_to_nis2(vulnerabilities: &[Vulnerability]) -> HashMap<String, Vec<String>> {
        let mut mapping: HashMap<String, Vec<String>> = HashMap::new();

        for vuln in vulnerabilities {
            let requirements = Self::get_nis2_requirements(&vuln.vuln_type, &vuln.cwe, vuln.severity.clone());
            for req in requirements {
                mapping
                    .entry(req)
                    .or_insert_with(Vec::new)
                    .push(vuln.id.clone());
            }
        }

        mapping
    }

    fn get_nis2_requirements(vuln_type: &str, cwe: &str, severity: crate::types::Severity) -> Vec<String> {
        let mut requirements = Vec::new();

        // Article 21 - Cybersecurity risk-management measures
        // (a) policies on risk analysis and information system security
        requirements.push("Art. 21(2)(a) - Risk analysis and information system security policies".to_string());

        // (b) incident handling
        if matches!(severity, crate::types::Severity::Critical | crate::types::Severity::High) {
            requirements.push("Art. 21(2)(b) - Incident handling".to_string());
        }

        // (c) business continuity and crisis management
        if vuln_type.contains("DoS") || vuln_type.contains("Denial of Service") ||
           vuln_type.contains("Availability") {
            requirements.push("Art. 21(2)(c) - Business continuity, backup, disaster recovery, crisis management".to_string());
        }

        // (d) supply chain security
        if vuln_type.contains("Supply Chain") || vuln_type.contains("Dependency") ||
           vuln_type.contains("Third-party") || vuln_type.contains("Component") {
            requirements.push("Art. 21(2)(d) - Supply chain security".to_string());
        }

        // (e) security in acquisition, development and maintenance
        if vuln_type.contains("Injection") || vuln_type.contains("XSS") ||
           vuln_type.contains("SQL") || vuln_type.contains("Command") ||
           vuln_type.contains("SSTI") || vuln_type.contains("Deserialization") {
            requirements.push("Art. 21(2)(e) - Security in network/info system acquisition, development, maintenance".to_string());
            requirements.push("Art. 21(2)(e) - Vulnerability handling and disclosure".to_string());
        }

        // (f) policies and procedures to assess effectiveness
        requirements.push("Art. 21(2)(f) - Policies to assess cybersecurity risk-management effectiveness".to_string());

        // (g) basic cyber hygiene practices and training
        if vuln_type.contains("Misconfiguration") || vuln_type.contains("Default") ||
           vuln_type.contains("Weak Password") {
            requirements.push("Art. 21(2)(g) - Basic cyber hygiene practices and cybersecurity training".to_string());
        }

        // (h) policies on cryptography and encryption
        if vuln_type.contains("Cryptographic") || vuln_type.contains("SSL") ||
           vuln_type.contains("TLS") || vuln_type.contains("Encryption") ||
           cwe.contains("327") || cwe.contains("295") || cwe.contains("319") {
            requirements.push("Art. 21(2)(h) - Policies on use of cryptography and encryption".to_string());
        }

        // (i) human resources security, access control, asset management
        if vuln_type.contains("Authentication") || vuln_type.contains("Authorization") ||
           vuln_type.contains("Session") || vuln_type.contains("IDOR") ||
           vuln_type.contains("BOLA") || vuln_type.contains("Access Control") ||
           cwe.contains("287") || cwe.contains("862") || cwe.contains("863") {
            requirements.push("Art. 21(2)(i) - Human resources security, access control policies, asset management".to_string());
        }

        // (j) multi-factor authentication
        if vuln_type.contains("MFA") || vuln_type.contains("2FA") ||
           vuln_type.contains("Authentication") || vuln_type.contains("Session") {
            requirements.push("Art. 21(2)(j) - Multi-factor authentication, continuous authentication, secured communications".to_string());
        }

        // Article 23 - Reporting obligations
        if matches!(severity, crate::types::Severity::Critical) {
            requirements.push("Art. 23 - Reporting obligations for significant incidents".to_string());
        }

        // SSRF - network security
        if vuln_type.contains("SSRF") {
            requirements.push("Art. 21(2)(a) - Risk analysis and information system security policies".to_string());
            requirements.push("Art. 21(2)(e) - Security in network/info system acquisition, development, maintenance".to_string());
        }

        // API/GraphQL
        if vuln_type.contains("API") || vuln_type.contains("GraphQL") {
            requirements.push("Art. 21(2)(e) - Security in network/info system acquisition, development, maintenance".to_string());
        }

        // Business Logic
        if vuln_type.contains("Business Logic") || vuln_type.contains("Race Condition") {
            requirements.push("Art. 21(2)(e) - Security in network/info system acquisition, development, maintenance".to_string());
        }

        // Information Disclosure
        if vuln_type.contains("Information Disclosure") || vuln_type.contains("Sensitive Data") ||
           vuln_type.contains("Exposure") || cwe.contains("200") {
            requirements.push("Art. 21(2)(a) - Risk analysis and information system security policies".to_string());
        }

        // WAF Bypass
        if vuln_type.contains("WAF") || vuln_type.contains("Bypass") {
            requirements.push("Art. 21(2)(e) - Security in network/info system acquisition, development, maintenance".to_string());
            requirements.push("Art. 21(2)(f) - Policies to assess cybersecurity risk-management effectiveness".to_string());
        }

        requirements
    }

    /// Get compliance summary for all frameworks
    pub fn get_compliance_summary(vulnerabilities: &[Vulnerability]) -> ComplianceSummary {
        ComplianceSummary {
            pci_dss_violations: Self::map_to_pci_dss(vulnerabilities).len(),
            hipaa_violations: Self::map_to_hipaa(vulnerabilities).len(),
            soc2_violations: Self::map_to_soc2(vulnerabilities).len(),
            iso27001_violations: Self::map_to_iso27001(vulnerabilities).len(),
            gdpr_violations: Self::map_to_gdpr(vulnerabilities).len(),
            nist_csf_violations: Self::map_to_nist_csf(vulnerabilities).len(),
            dora_violations: Self::map_to_dora(vulnerabilities).len(),
            nis2_violations: Self::map_to_nis2(vulnerabilities).len(),
            total_unique_controls_affected: Self::count_unique_controls(vulnerabilities),
        }
    }

    fn count_unique_controls(vulnerabilities: &[Vulnerability]) -> usize {
        let mut all_controls = std::collections::HashSet::new();

        for (control, _) in Self::map_to_pci_dss(vulnerabilities) {
            all_controls.insert(control);
        }
        for (control, _) in Self::map_to_hipaa(vulnerabilities) {
            all_controls.insert(control);
        }
        for (control, _) in Self::map_to_soc2(vulnerabilities) {
            all_controls.insert(control);
        }
        for (control, _) in Self::map_to_iso27001(vulnerabilities) {
            all_controls.insert(control);
        }
        for (control, _) in Self::map_to_gdpr(vulnerabilities) {
            all_controls.insert(control);
        }
        for (control, _) in Self::map_to_nist_csf(vulnerabilities) {
            all_controls.insert(control);
        }
        for (control, _) in Self::map_to_dora(vulnerabilities) {
            all_controls.insert(control);
        }
        for (control, _) in Self::map_to_nis2(vulnerabilities) {
            all_controls.insert(control);
        }

        all_controls.len()
    }
}

/// Summary of compliance violations across all frameworks
#[derive(Debug, Clone)]
pub struct ComplianceSummary {
    pub pci_dss_violations: usize,
    pub hipaa_violations: usize,
    pub soc2_violations: usize,
    pub iso27001_violations: usize,
    pub gdpr_violations: usize,
    pub nist_csf_violations: usize,
    pub dora_violations: usize,
    pub nis2_violations: usize,
    pub total_unique_controls_affected: usize,
}
