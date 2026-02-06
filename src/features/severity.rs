// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use super::HttpResponse;
use std::collections::HashMap;

/// Extract severity features from URL path, parameter names, and response content.
/// Run ONCE per endpoint+param.
pub fn extract_severity_features(
    url: &str,
    method: &str,
    param_name: &str,
    response: &HttpResponse,
    is_authenticated: bool,
    is_admin: bool,
) -> HashMap<String, f64> {
    let mut features = HashMap::new();
    let url_lower = url.to_lowercase();
    let param_lower = param_name.to_lowercase();
    let body_lower = response.body.to_lowercase();

    // Endpoint type detection
    if url_lower.contains("/login")
        || url_lower.contains("/signin")
        || url_lower.contains("/auth")
        || url_lower.contains("/oauth")
        || url_lower.contains("/sso")
    {
        features.insert("severity:endpoint_is_login".into(), 1.0);
    }
    if url_lower.contains("/pay")
        || url_lower.contains("/checkout")
        || url_lower.contains("/billing")
        || url_lower.contains("/invoice")
        || url_lower.contains("/transaction")
        || url_lower.contains("/order")
    {
        features.insert("severity:endpoint_is_payment".into(), 1.0);
    }
    if url_lower.contains("/admin")
        || url_lower.contains("/dashboard")
        || url_lower.contains("/manage")
        || url_lower.contains("/console")
        || url_lower.contains("/panel")
    {
        features.insert("severity:endpoint_is_admin".into(), 1.0);
    }
    if url_lower.contains("/api/")
        || url_lower.contains("/v1/")
        || url_lower.contains("/v2/")
        || url_lower.contains("/graphql")
        || url_lower.contains("/rest/")
    {
        features.insert("severity:endpoint_is_api".into(), 1.0);
    }

    // PII handling
    if body_lower.contains("email")
        || body_lower.contains("phone")
        || body_lower.contains("address")
        || body_lower.contains("ssn")
        || body_lower.contains("social security")
        || body_lower.contains("date_of_birth")
        || body_lower.contains("credit_card")
    {
        features.insert("severity:endpoint_handles_pii".into(), 1.0);
    }

    // File handling
    if url_lower.contains("/upload")
        || url_lower.contains("/file")
        || url_lower.contains("/download")
        || url_lower.contains("/import")
        || url_lower.contains("/export")
        || url_lower.contains("/attachment")
    {
        features.insert("severity:endpoint_handles_files".into(), 1.0);
    }

    // Public access (no auth required for this endpoint)
    if !is_authenticated {
        features.insert("severity:endpoint_is_public".into(), 1.0);
    }

    // State-changing method
    if ["POST", "PUT", "PATCH", "DELETE"]
        .contains(&method.to_uppercase().as_str())
    {
        features.insert("severity:endpoint_modifies_state".into(), 1.0);
    }

    // Parameter analysis
    if param_lower.contains("pass")
        || param_lower.contains("pwd")
        || param_lower.contains("secret")
    {
        features.insert("severity:param_is_password".into(), 1.0);
    }
    if param_lower.contains("email") || param_lower.contains("mail") {
        features.insert("severity:param_is_email".into(), 1.0);
    }
    if param_lower.contains("query")
        || param_lower.contains("search")
        || param_lower.contains("filter")
        || param_lower.contains("where")
        || param_lower.contains("order")
        || param_lower.contains("sort")
        || param_lower.contains("select")
        || param_lower.contains("table")
    {
        features.insert("severity:param_is_sql_like".into(), 1.0);
    }

    // Param in URL path (e.g., /users/123/profile)
    if url.contains(&format!("/{}/", param_name))
        || url.ends_with(&format!("/{}", param_name))
    {
        features.insert("severity:param_in_url_path".into(), 1.0);
    }

    // Auth context
    if is_authenticated {
        features.insert("severity:authenticated_context".into(), 1.0);
    }
    if is_admin {
        features.insert("severity:high_privilege_context".into(), 1.0);
    }

    // Production detection
    if !url_lower.contains("localhost")
        && !url_lower.contains("staging")
        && !url_lower.contains("dev.")
        && !url_lower.contains("test.")
        && !url_lower.contains("127.0.0.1")
    {
        features.insert("severity:production_environment".into(), 1.0);
    }

    // Sensitive data in response
    if body_lower.contains("password")
        || body_lower.contains("api_key")
        || body_lower.contains("secret_key")
        || body_lower.contains("access_token")
        || body_lower.contains("private_key")
    {
        features.insert("severity:sensitive_data_in_scope".into(), 1.0);
    }

    features
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_response(body: &str, status: u16) -> HttpResponse {
        HttpResponse {
            status,
            headers: HashMap::new(),
            body: body.to_string(),
            body_bytes: body.len(),
            response_time_ms: 100,
        }
    }

    #[test]
    fn test_login_endpoint() {
        let resp = make_response("OK", 200);
        let features = extract_severity_features(
            "https://example.com/api/login",
            "POST",
            "username",
            &resp,
            false,
            false,
        );
        assert!(features.contains_key("severity:endpoint_is_login"));
        assert!(features.contains_key("severity:endpoint_is_api"));
        assert!(features.contains_key("severity:endpoint_modifies_state"));
        assert!(features.contains_key("severity:endpoint_is_public"));
        assert!(features.contains_key("severity:production_environment"));
    }

    #[test]
    fn test_payment_endpoint() {
        let resp = make_response("OK", 200);
        let features = extract_severity_features(
            "https://shop.example.com/checkout",
            "POST",
            "card_number",
            &resp,
            true,
            false,
        );
        assert!(features.contains_key("severity:endpoint_is_payment"));
        assert!(features.contains_key("severity:authenticated_context"));
        assert!(!features.contains_key("severity:endpoint_is_public"));
    }

    #[test]
    fn test_admin_endpoint() {
        let resp = make_response("OK", 200);
        let features = extract_severity_features(
            "https://example.com/admin/users",
            "DELETE",
            "user_id",
            &resp,
            true,
            true,
        );
        assert!(features.contains_key("severity:endpoint_is_admin"));
        assert!(features.contains_key("severity:high_privilege_context"));
        assert!(features.contains_key("severity:endpoint_modifies_state"));
    }

    #[test]
    fn test_password_param() {
        let resp = make_response("OK", 200);
        let features = extract_severity_features(
            "https://example.com/settings",
            "POST",
            "password",
            &resp,
            true,
            false,
        );
        assert!(features.contains_key("severity:param_is_password"));
    }

    #[test]
    fn test_email_param() {
        let resp = make_response("OK", 200);
        let features = extract_severity_features(
            "https://example.com/register",
            "POST",
            "email",
            &resp,
            false,
            false,
        );
        assert!(features.contains_key("severity:param_is_email"));
    }

    #[test]
    fn test_sql_like_param() {
        let resp = make_response("OK", 200);
        let features = extract_severity_features(
            "https://example.com/search",
            "GET",
            "query",
            &resp,
            false,
            false,
        );
        assert!(features.contains_key("severity:param_is_sql_like"));
    }

    #[test]
    fn test_pii_in_response() {
        let resp = make_response(
            "{\"email\": \"user@example.com\", \"phone\": \"555-1234\"}",
            200,
        );
        let features = extract_severity_features(
            "https://example.com/api/v1/profile",
            "GET",
            "user_id",
            &resp,
            true,
            false,
        );
        assert!(features.contains_key("severity:endpoint_handles_pii"));
        assert!(features.contains_key("severity:endpoint_is_api"));
    }

    #[test]
    fn test_sensitive_data_in_response() {
        let resp = make_response(
            "{\"api_key\": \"sk-abc123\", \"access_token\": \"tok_xyz\"}",
            200,
        );
        let features = extract_severity_features(
            "https://example.com/api/v1/settings",
            "GET",
            "id",
            &resp,
            true,
            false,
        );
        assert!(features.contains_key("severity:sensitive_data_in_scope"));
    }

    #[test]
    fn test_localhost_not_production() {
        let resp = make_response("OK", 200);
        let features = extract_severity_features(
            "http://localhost:8080/api/login",
            "POST",
            "username",
            &resp,
            false,
            false,
        );
        assert!(!features.contains_key("severity:production_environment"));
    }

    #[test]
    fn test_file_handling_endpoint() {
        let resp = make_response("OK", 200);
        let features = extract_severity_features(
            "https://example.com/upload",
            "POST",
            "file",
            &resp,
            true,
            false,
        );
        assert!(features.contains_key("severity:endpoint_handles_files"));
    }

    #[test]
    fn test_param_in_url_path() {
        let resp = make_response("OK", 200);
        let features = extract_severity_features(
            "https://example.com/users/id/profile",
            "GET",
            "id",
            &resp,
            true,
            false,
        );
        assert!(features.contains_key("severity:param_in_url_path"));
    }

    #[test]
    fn test_get_method_not_state_changing() {
        let resp = make_response("OK", 200);
        let features = extract_severity_features(
            "https://example.com/api/users",
            "GET",
            "id",
            &resp,
            false,
            false,
        );
        assert!(!features.contains_key("severity:endpoint_modifies_state"));
    }
}
