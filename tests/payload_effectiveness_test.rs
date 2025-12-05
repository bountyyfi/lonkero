// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Payload Effectiveness Tests
 * Tests to verify XSS, SQLi, and Command Injection payloads work correctly
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use lonkero_scanner::payloads;

#[test]
fn test_xss_payloads_fast_mode() {
    let payloads = payloads::get_xss_payloads("fast");

    assert!(!payloads.is_empty(), "Fast mode should return payloads");
    assert!(payloads.len() >= 10, "Fast mode should have at least 10 payloads");
    assert!(payloads.len() <= 100, "Fast mode should not exceed 100 payloads");

    assert!(payloads.iter().any(|p| p.contains("<script>")), "Should include basic script tag");
    assert!(payloads.iter().any(|p| p.contains("alert")), "Should include alert payload");
}

#[test]
fn test_xss_payloads_normal_mode() {
    let payloads = payloads::get_xss_payloads("normal");

    assert!(payloads.len() > 100, "Normal mode should have more payloads than fast");
    assert!(payloads.len() <= 1000, "Normal mode should not exceed 1000 payloads");
}

#[test]
fn test_xss_payloads_thorough_mode() {
    let payloads = payloads::get_xss_payloads("thorough");

    assert!(payloads.len() > 1000, "Thorough mode should have many payloads");
    assert!(payloads.len() <= 10000, "Thorough mode should be reasonable");
}

#[test]
fn test_xss_payloads_insane_mode() {
    let payloads = payloads::get_xss_payloads("insane");

    assert!(payloads.len() > 10000, "Insane mode should have comprehensive payloads");
}

#[test]
fn test_xss_payload_variety() {
    let payloads = payloads::get_xss_payloads("normal");

    assert!(payloads.iter().any(|p| p.contains("<img")), "Should include image-based XSS");
    assert!(payloads.iter().any(|p| p.contains("onerror")), "Should include event handler XSS");
    assert!(payloads.iter().any(|p| p.contains("javascript:")), "Should include javascript: protocol");
    assert!(payloads.iter().any(|p| p.contains("<svg")), "Should include SVG-based XSS");
}

#[test]
fn test_xss_payload_encoding() {
    let payloads = payloads::get_xss_payloads("normal");

    assert!(payloads.iter().any(|p| p.contains("&#")), "Should include HTML entity encoding");
    assert!(payloads.iter().any(|p| p.to_lowercase().contains("%3c")), "Should include URL encoding");
}

#[test]
fn test_sqli_payloads_fast_mode() {
    let payloads = payloads::get_sqli_payloads("fast");

    assert!(!payloads.is_empty(), "Fast mode should return SQLi payloads");
    assert!(payloads.len() >= 10, "Fast mode should have at least 10 SQLi payloads");

    assert!(payloads.iter().any(|p| p.contains("' OR '1'='1")), "Should include basic OR bypass");
    assert!(payloads.iter().any(|p| p.contains("--")), "Should include comment-based injection");
}

#[test]
fn test_sqli_payloads_normal_mode() {
    let payloads = payloads::get_sqli_payloads("normal");

    assert!(payloads.len() > 100, "Normal mode should have many SQLi payloads");
}

#[test]
fn test_sqli_payloads_thorough_mode() {
    let payloads = payloads::get_sqli_payloads("thorough");

    assert!(payloads.len() > 1000, "Thorough mode should have comprehensive SQLi payloads");
}

#[test]
fn test_sqli_payload_variety() {
    let payloads = payloads::get_sqli_payloads("normal");

    assert!(payloads.iter().any(|p| p.contains("UNION")), "Should include UNION-based SQLi");
    assert!(payloads.iter().any(|p| p.contains("SLEEP")), "Should include time-based blind SQLi");
    assert!(payloads.iter().any(|p| p.contains("AND") || p.contains("OR")), "Should include boolean-based SQLi");
}

#[test]
fn test_sqli_database_specific_payloads() {
    let payloads = payloads::get_sqli_payloads("thorough");

    assert!(payloads.iter().any(|p| p.contains("@@version")), "Should include MySQL-specific payloads");
    assert!(payloads.iter().any(|p| p.contains("pg_sleep")), "Should include PostgreSQL-specific payloads");
    assert!(payloads.iter().any(|p| p.contains("WAITFOR")), "Should include MSSQL-specific payloads");
}

#[test]
fn test_path_traversal_payloads() {
    let payloads = payloads::get_path_traversal_payloads();

    assert!(!payloads.is_empty(), "Should return path traversal payloads");

    assert!(payloads.iter().any(|p| p.contains("../")), "Should include Unix path traversal");
    assert!(payloads.iter().any(|p| p.contains("..\\")), "Should include Windows path traversal");
    assert!(payloads.iter().any(|p| p.contains("..../")), "Should include double-encoded traversal");
}

#[test]
fn test_path_traversal_depth_variety() {
    let payloads = payloads::get_path_traversal_payloads();

    assert!(payloads.iter().any(|p| p == "../"), "Should include single level");
    assert!(payloads.iter().any(|p| p.contains("../../")), "Should include double level");
    assert!(payloads.iter().any(|p| p.contains("../../../")), "Should include triple level");
    assert!(payloads.iter().any(|p| p.contains("../../../../")), "Should include quad level");
}

#[test]
fn test_command_injection_payloads() {
    let payloads = payloads::get_command_injection_payloads();

    assert!(!payloads.is_empty(), "Should return command injection payloads");

    assert!(payloads.iter().any(|p| p.contains("; ls")), "Should include semicolon separator");
    assert!(payloads.iter().any(|p| p.contains("| ls")), "Should include pipe operator");
    assert!(payloads.iter().any(|p| p.contains("&& ls")), "Should include AND operator");
    assert!(payloads.iter().any(|p| p.contains("`ls`")), "Should include backtick execution");
    assert!(payloads.iter().any(|p| p.contains("$(ls)")), "Should include command substitution");
}

#[test]
fn test_command_injection_unix_commands() {
    let payloads = payloads::get_command_injection_payloads();

    assert!(payloads.iter().any(|p| p.contains("cat /etc/passwd")), "Should include passwd reading");
    assert!(payloads.iter().any(|p| p.contains("ping")), "Should include ping command");
}

#[test]
fn test_xxe_payloads() {
    let payloads = payloads::get_xxe_payloads();

    assert!(!payloads.is_empty(), "Should return XXE payloads");

    assert!(payloads.iter().any(|p| p.contains("<!ENTITY")), "Should include entity declaration");
    assert!(payloads.iter().any(|p| p.contains("file://")), "Should include file protocol");
    assert!(payloads.iter().any(|p| p.contains("/etc/passwd")), "Should include passwd file");
}

#[test]
fn test_xxe_cloud_metadata() {
    let payloads = payloads::get_xxe_payloads();

    assert!(payloads.iter().any(|p| p.contains("169.254.169.254")), "Should include AWS metadata");
    assert!(payloads.iter().any(|p| p.contains("metadata.google.internal")), "Should include GCP metadata");
}

#[test]
fn test_xxe_ssrf_payloads() {
    let payloads = payloads::get_xxe_payloads();

    assert!(payloads.iter().any(|p| p.contains("localhost:22")), "Should include SSH port check");
    assert!(payloads.iter().any(|p| p.contains("localhost:3306")), "Should include MySQL port check");
    assert!(payloads.iter().any(|p| p.contains("localhost:6379")), "Should include Redis port check");
}

#[test]
fn test_ldap_payloads() {
    let payloads = payloads::get_ldap_payloads();

    assert!(!payloads.is_empty(), "Should return LDAP injection payloads");

    assert!(payloads.iter().any(|p| p == "*"), "Should include wildcard");
    assert!(payloads.iter().any(|p| p.contains("objectclass")), "Should include objectclass filter");
    assert!(payloads.iter().any(|p| p.contains("uid=*")), "Should include uid wildcard");
}

#[test]
fn test_ldap_authentication_bypass() {
    let payloads = payloads::get_ldap_payloads();

    assert!(payloads.iter().any(|p| p.contains("*)(uid=*")), "Should include bypass patterns");
    assert!(payloads.iter().any(|p| p.contains("*)(&")), "Should include AND operator bypass");
}

#[test]
fn test_crlf_payloads() {
    let payloads = payloads::get_crlf_payloads();

    assert!(!payloads.is_empty(), "Should return CRLF injection payloads");

    assert!(payloads.iter().any(|p| p.contains("%0d%0a")), "Should include URL-encoded CRLF");
    assert!(payloads.iter().any(|p| p.contains("Set-Cookie")), "Should include cookie injection");
    assert!(payloads.iter().any(|p| p.contains("Location:")), "Should include redirect injection");
}

#[test]
fn test_crlf_xss_combination() {
    let payloads = payloads::get_crlf_payloads();

    assert!(payloads.iter().any(|p| p.contains("<script>") && p.contains("%0d%0a")),
        "Should include CRLF to XSS payloads");
}

#[test]
fn test_crlf_security_header_bypass() {
    let payloads = payloads::get_crlf_payloads();

    assert!(payloads.iter().any(|p| p.contains("X-XSS-Protection")), "Should include XSS protection bypass");
    assert!(payloads.iter().any(|p| p.contains("Access-Control-Allow-Origin")), "Should include CORS bypass");
}

#[test]
fn test_deserialization_payloads() {
    let payloads = payloads::get_deserialization_payloads();

    assert!(!payloads.is_empty(), "Should return deserialization payloads");

    assert!(payloads.iter().any(|p| p.contains("rO0AB")), "Should include Java serialized marker");
    assert!(payloads.iter().any(|p| p.contains("O:") && p.contains("stdClass")), "Should include PHP serialize");
}

#[test]
fn test_deserialization_python_payloads() {
    let payloads = payloads::get_deserialization_payloads();

    assert!(payloads.iter().any(|p| p.contains("pickle") || p.contains("cos\\nsystem")),
        "Should include Python pickle payloads");
    assert!(payloads.iter().any(|p| p.contains("!!python")), "Should include PyYAML payloads");
}

#[test]
fn test_deserialization_nodejs_payloads() {
    let payloads = payloads::get_deserialization_payloads();

    assert!(payloads.iter().any(|p| p.contains("_$$ND_FUNC$$_")),
        "Should include Node.js serialization payloads");
}

#[test]
fn test_payload_uniqueness() {
    let xss = payloads::get_xss_payloads("normal");
    let sqli = payloads::get_sqli_payloads("normal");

    let xss_set: std::collections::HashSet<_> = xss.iter().collect();
    assert_eq!(xss_set.len(), xss.len(), "XSS payloads should be unique");

    let sqli_set: std::collections::HashSet<_> = sqli.iter().collect();
    assert_eq!(sqli_set.len(), sqli.len(), "SQLi payloads should be unique");
}

#[test]
fn test_payload_not_empty_strings() {
    let xss = payloads::get_xss_payloads("fast");
    assert!(xss.iter().all(|p| !p.is_empty()), "No XSS payload should be empty");

    let sqli = payloads::get_sqli_payloads("fast");
    assert!(sqli.iter().all(|p| !p.is_empty()), "No SQLi payload should be empty");

    let path_trav = payloads::get_path_traversal_payloads();
    assert!(path_trav.iter().all(|p| !p.is_empty()), "No path traversal payload should be empty");

    let cmdi = payloads::get_command_injection_payloads();
    assert!(cmdi.iter().all(|p| !p.is_empty()), "No command injection payload should be empty");
}

#[test]
fn test_xss_context_breaking() {
    let payloads = payloads::get_xss_payloads("normal");

    assert!(payloads.iter().any(|p| p.contains("\">")), "Should break out of attributes");
    assert!(payloads.iter().any(|p| p.contains("'>")), "Should break single quote attributes");
    assert!(payloads.iter().any(|p| p.contains("</script>")), "Should close script tags");
}

#[test]
fn test_sqli_comment_styles() {
    let payloads = payloads::get_sqli_payloads("normal");

    assert!(payloads.iter().any(|p| p.contains("--")), "Should include SQL comment --");
    assert!(payloads.iter().any(|p| p.contains("/*")), "Should include SQL comment /* */");
    assert!(payloads.iter().any(|p| p.contains("#")), "Should include MySQL comment #");
}

#[test]
fn test_payload_mode_scaling() {
    let xss_fast = payloads::get_xss_payloads("fast");
    let xss_normal = payloads::get_xss_payloads("normal");
    let xss_thorough = payloads::get_xss_payloads("thorough");
    let xss_insane = payloads::get_xss_payloads("insane");

    assert!(xss_normal.len() > xss_fast.len(), "Normal should have more than fast");
    assert!(xss_thorough.len() > xss_normal.len(), "Thorough should have more than normal");
    assert!(xss_insane.len() > xss_thorough.len(), "Insane should have more than thorough");

    let sqli_fast = payloads::get_sqli_payloads("fast");
    let sqli_normal = payloads::get_sqli_payloads("normal");
    let sqli_thorough = payloads::get_sqli_payloads("thorough");

    assert!(sqli_normal.len() > sqli_fast.len(), "SQLi normal should have more than fast");
    assert!(sqli_thorough.len() > sqli_normal.len(), "SQLi thorough should have more than normal");
}

#[test]
fn test_xxe_xml_well_formed() {
    let payloads = payloads::get_xxe_payloads();

    for payload in &payloads {
        assert!(payload.contains("<?xml"), "XXE payloads should start with XML declaration");
        assert!(payload.contains("<!DOCTYPE") || payload.contains("<!ENTITY") || payload.contains("xmlns"),
            "XXE payloads should contain DOCTYPE, ENTITY, or xmlns");
    }
}

#[test]
fn test_crlf_header_injection_formats() {
    let payloads = payloads::get_crlf_payloads();

    let has_lowercase = payloads.iter().any(|p| p.contains("%0d%0a"));
    let has_uppercase = payloads.iter().any(|p| p.contains("%0D%0A"));

    assert!(has_lowercase || has_uppercase, "Should include URL-encoded CRLF in some form");
}

#[test]
fn test_ldap_filter_characters() {
    let payloads = payloads::get_ldap_payloads();

    assert!(payloads.iter().any(|p| p.contains("(")), "Should include LDAP filter parentheses");
    assert!(payloads.iter().any(|p| p.contains(")")), "Should include closing parentheses");
    assert!(payloads.iter().any(|p| p.contains("|")), "Should include OR operator");
    assert!(payloads.iter().any(|p| p.contains("&")), "Should include AND operator");
}
