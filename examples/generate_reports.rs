// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use anyhow::Result;
use chrono::Utc;
use lonkero_scanner::reporting::{
    engine::ReportEngine,
    types::{BrandingConfig, ReportConfig, ReportFormat},
};
use lonkero_scanner::types::{Confidence, ScanResults, Severity, Vulnerability};

#[tokio::main]
async fn main() -> Result<()> {
    println!("[SECURITY] Generating Sample Security Reports\n");

    let scan_results = create_sample_scan_results();

    let branding = BrandingConfig {
        company_name: "Bountyy Security".to_string(),
        logo_path: None,
        primary_color: "#2563eb".to_string(),
        secondary_color: "#1e40af".to_string(),
        report_title: Some("Enterprise Security Assessment Report".to_string()),
        footer_text: Some("Confidential - For Internal Use Only | © 2024 Bountyy Security".to_string()),
    };

    let engine = ReportEngine::new();

    println!("Generating PDF Report...");
    generate_report(&engine, &scan_results, &branding, ReportFormat::Pdf).await?;

    println!("Generating HTML Report...");
    generate_report(&engine, &scan_results, &branding, ReportFormat::Html).await?;

    println!("Generating JSON Report...");
    generate_report(&engine, &scan_results, &branding, ReportFormat::Json).await?;

    println!("Generating CSV Report...");
    generate_report(&engine, &scan_results, &branding, ReportFormat::Csv).await?;

    println!("Generating SARIF Report...");
    generate_report(&engine, &scan_results, &branding, ReportFormat::Sarif).await?;

    println!("Generating JUnit XML Report...");
    generate_report(&engine, &scan_results, &branding, ReportFormat::JunitXml).await?;

    println!("[STATS] Generating XLSX Report...");
    generate_report(&engine, &scan_results, &branding, ReportFormat::Xlsx).await?;

    println!("[NOTE] Generating Markdown Report...");
    generate_report(&engine, &scan_results, &branding, ReportFormat::Markdown).await?;

    println!("\n[SUCCESS] All sample reports generated successfully!");
    println!("[FOLDER] Reports saved to ./sample_reports/ directory");

    Ok(())
}

async fn generate_report(
    engine: &ReportEngine,
    scan_results: &ScanResults,
    branding: &BrandingConfig,
    format: ReportFormat,
) -> Result<()> {
    let config = ReportConfig {
        format: format.clone(),
        include_executive_summary: true,
        include_charts: true,
        include_remediation: true,
        include_compliance_mapping: true,
        include_owasp_mapping: true,
        deduplicate: true,
        filter_false_positives: true,
        min_severity: None,
        branding: Some(branding.clone()),
        template: None,
        compare_with: None,
    };

    let report_output = engine.generate_report(scan_results.clone(), config).await?;

    std::fs::create_dir_all("./sample_reports")?;

    let file_path = format!("./sample_reports/{}", report_output.filename);
    std::fs::write(&file_path, report_output.data)?;

    println!("   [SUCCESS] Saved: {}", file_path);

    Ok(())
}

fn create_sample_scan_results() -> ScanResults {
    let vulnerabilities = vec![
        Vulnerability {
            id: "vuln-001".to_string(),
            vuln_type: "SQL Injection".to_string(),
            severity: Severity::Critical,
            confidence: Confidence::High,
            category: "Injection".to_string(),
            url: "https://api.example.com/users".to_string(),
            parameter: Some("id".to_string()),
            payload: "' OR '1'='1".to_string(),
            description: "SQL injection vulnerability detected in the user ID parameter. The application does not properly sanitize user input, allowing attackers to manipulate database queries.".to_string(),
            evidence: Some("SQL error: 'You have an error in your SQL syntax'".to_string()),
            cwe: "CWE-89".to_string(),
            cvss: 9.8,
            verified: true,
            false_positive: false,
            remediation: "Use parameterized queries or prepared statements. Implement input validation and sanitization. Apply principle of least privilege for database accounts.".to_string(),
            discovered_at: Utc::now().to_rfc3339(),
        },
        Vulnerability {
            id: "vuln-002".to_string(),
            vuln_type: "Cross-Site Scripting (XSS)".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: "Injection".to_string(),
            url: "https://app.example.com/search".to_string(),
            parameter: Some("q".to_string()),
            payload: "<script>alert('XSS')</script>".to_string(),
            description: "Reflected XSS vulnerability in search functionality. User input is reflected in the response without proper encoding.".to_string(),
            evidence: Some("Payload was reflected in HTML response without encoding".to_string()),
            cwe: "CWE-79".to_string(),
            cvss: 7.5,
            verified: true,
            false_positive: false,
            remediation: "Implement output encoding/escaping. Use Content Security Policy headers. Enable X-XSS-Protection header.".to_string(),
            discovered_at: Utc::now().to_rfc3339(),
        },
        Vulnerability {
            id: "vuln-003".to_string(),
            vuln_type: "Insecure Direct Object Reference (IDOR)".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: "Broken Access Control".to_string(),
            url: "https://api.example.com/documents/12345".to_string(),
            parameter: Some("id".to_string()),
            payload: "12346".to_string(),
            description: "Users can access documents belonging to other users by changing the document ID parameter.".to_string(),
            evidence: Some("Accessed document ID 12346 belonging to different user".to_string()),
            cwe: "CWE-639".to_string(),
            cvss: 8.1,
            verified: true,
            false_positive: false,
            remediation: "Implement proper access control checks. Use indirect references. Validate user authorization for each request.".to_string(),
            discovered_at: Utc::now().to_rfc3339(),
        },
        Vulnerability {
            id: "vuln-004".to_string(),
            vuln_type: "Missing Security Headers".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            category: "Security Misconfiguration".to_string(),
            url: "https://app.example.com".to_string(),
            parameter: None,
            payload: "N/A".to_string(),
            description: "Critical security headers are missing: X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security".to_string(),
            evidence: Some("No security headers found in HTTP response".to_string()),
            cwe: "CWE-16".to_string(),
            cvss: 5.3,
            verified: true,
            false_positive: false,
            remediation: "Add security headers: X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Strict-Transport-Security: max-age=31536000".to_string(),
            discovered_at: Utc::now().to_rfc3339(),
        },
        Vulnerability {
            id: "vuln-005".to_string(),
            vuln_type: "CORS Misconfiguration".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            category: "Security Misconfiguration".to_string(),
            url: "https://api.example.com/data".to_string(),
            parameter: None,
            payload: "Origin: https://evil.com".to_string(),
            description: "CORS policy allows requests from any origin using wildcard (*). This could allow malicious sites to make authenticated requests.".to_string(),
            evidence: Some("Access-Control-Allow-Origin: *".to_string()),
            cwe: "CWE-942".to_string(),
            cvss: 6.5,
            verified: true,
            false_positive: false,
            remediation: "Restrict CORS to specific trusted domains. Avoid using wildcard (*) in production.".to_string(),
            discovered_at: Utc::now().to_rfc3339(),
        },
        Vulnerability {
            id: "vuln-006".to_string(),
            vuln_type: "Sensitive Data Exposure".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: "Cryptographic Failures".to_string(),
            url: "https://api.example.com/users/profile".to_string(),
            parameter: None,
            payload: "N/A".to_string(),
            description: "API endpoint exposes sensitive user information including SSN, email, and phone numbers without proper access controls.".to_string(),
            evidence: Some("Response contains: ssn, email, phone, address".to_string()),
            cwe: "CWE-200".to_string(),
            cvss: 7.5,
            verified: true,
            false_positive: false,
            remediation: "Implement field-level encryption. Add access controls. Remove unnecessary sensitive fields from API responses.".to_string(),
            discovered_at: Utc::now().to_rfc3339(),
        },
        Vulnerability {
            id: "vuln-007".to_string(),
            vuln_type: "Server-Side Request Forgery (SSRF)".to_string(),
            severity: Severity::Critical,
            confidence: Confidence::Medium,
            category: "Injection".to_string(),
            url: "https://api.example.com/fetch".to_string(),
            parameter: Some("url".to_string()),
            payload: "http://169.254.169.254/latest/meta-data/".to_string(),
            description: "Application fetches content from user-supplied URLs without validation, allowing access to internal resources.".to_string(),
            evidence: Some("Successfully accessed AWS metadata endpoint".to_string()),
            cwe: "CWE-918".to_string(),
            cvss: 9.1,
            verified: true,
            false_positive: false,
            remediation: "Implement URL allowlisting. Validate and sanitize user-supplied URLs. Use network segmentation.".to_string(),
            discovered_at: Utc::now().to_rfc3339(),
        },
        Vulnerability {
            id: "vuln-008".to_string(),
            vuln_type: "Broken Authentication".to_string(),
            severity: Severity::Critical,
            confidence: Confidence::High,
            category: "Authentication Failures".to_string(),
            url: "https://api.example.com/auth/login".to_string(),
            parameter: None,
            payload: "N/A".to_string(),
            description: "Authentication endpoint lacks rate limiting, enabling brute force attacks. No account lockout mechanism detected.".to_string(),
            evidence: Some("Successfully sent 1000 login attempts without rate limiting".to_string()),
            cwe: "CWE-307".to_string(),
            cvss: 9.8,
            verified: true,
            false_positive: false,
            remediation: "Implement rate limiting. Add account lockout after failed attempts. Use CAPTCHA. Enable multi-factor authentication.".to_string(),
            discovered_at: Utc::now().to_rfc3339(),
        },
        Vulnerability {
            id: "vuln-009".to_string(),
            vuln_type: "Command Injection".to_string(),
            severity: Severity::Critical,
            confidence: Confidence::High,
            category: "Injection".to_string(),
            url: "https://api.example.com/tools/ping".to_string(),
            parameter: Some("host".to_string()),
            payload: "127.0.0.1; whoami".to_string(),
            description: "OS command injection vulnerability in ping utility. Application executes user input as system commands.".to_string(),
            evidence: Some("Command output: www-data".to_string()),
            cwe: "CWE-78".to_string(),
            cvss: 9.8,
            verified: true,
            false_positive: false,
            remediation: "Avoid executing system commands with user input. Use parameterized APIs. Implement strict input validation.".to_string(),
            discovered_at: Utc::now().to_rfc3339(),
        },
        Vulnerability {
            id: "vuln-010".to_string(),
            vuln_type: "Path Traversal".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: "Injection".to_string(),
            url: "https://app.example.com/download".to_string(),
            parameter: Some("file".to_string()),
            payload: "../../../../etc/passwd".to_string(),
            description: "File download functionality is vulnerable to path traversal, allowing access to arbitrary files on the server.".to_string(),
            evidence: Some("Successfully accessed /etc/passwd file".to_string()),
            cwe: "CWE-22".to_string(),
            cvss: 7.5,
            verified: true,
            false_positive: false,
            remediation: "Implement strict file path validation. Use allowlisting for permitted files. Canonicalize file paths.".to_string(),
            discovered_at: Utc::now().to_rfc3339(),
        },
    ];

    ScanResults {
        scan_id: "sample-scan-001".to_string(),
        target: "https://api.example.com".to_string(),
        tests_run: 1247,
        vulnerabilities,
        started_at: (Utc::now() - chrono::Duration::hours(1)).to_rfc3339(),
        completed_at: Utc::now().to_rfc3339(),
        duration_seconds: 3600.0,
        early_terminated: false,
        termination_reason: None,
    }
}
