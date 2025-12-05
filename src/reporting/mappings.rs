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
}
