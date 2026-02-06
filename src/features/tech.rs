// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use super::HttpResponse;
use std::collections::HashMap;

/// Extract technology fingerprinting features from response headers, body, and error messages.
/// Run ONCE per target (not per probe) and cache the results.
pub fn extract_tech_features(responses: &[HttpResponse]) -> HashMap<String, f64> {
    let mut features = HashMap::new();

    // Combine signals from multiple responses for accuracy
    for resp in responses {
        let server = resp
            .headers
            .get("server")
            .map(|s| s.to_lowercase())
            .unwrap_or_default();
        let powered = resp
            .headers
            .get("x-powered-by")
            .map(|s| s.to_lowercase())
            .unwrap_or_default();
        let body_lower = resp.body.to_lowercase();
        let all_headers = resp
            .headers
            .keys()
            .map(|k| k.to_lowercase())
            .collect::<Vec<_>>()
            .join(" ");

        // Server detection
        if server.contains("apache") {
            features.insert("tech:server_apache".into(), 1.0);
        }
        if server.contains("nginx") {
            features.insert("tech:server_nginx".into(), 1.0);
        }
        if server.contains("microsoft-iis") {
            features.insert("tech:server_iis".into(), 1.0);
        }
        if server.contains("cloudflare") || all_headers.contains("cf-ray") {
            features.insert("tech:server_cloudflare".into(), 1.0);
            features.insert("tech:cdn_present".into(), 1.0);
        }

        // Runtime detection
        if powered.contains("php")
            || resp.headers.contains_key("x-php-version")
            || body_lower.contains("php fatal error")
            || body_lower.contains("php warning")
        {
            features.insert("tech:runtime_php".into(), 1.0);
        }
        if powered.contains("express")
            || powered.contains("node")
            || body_lower.contains("node_modules")
            || body_lower.contains("cannot get /")
        {
            features.insert("tech:runtime_node".into(), 1.0);
        }
        if powered.contains("asp.net")
            || server.contains("microsoft-iis")
            || resp.headers.contains_key("x-aspnet-version")
            || resp.headers.contains_key("x-aspnetmvc-version")
        {
            features.insert("tech:runtime_dotnet".into(), 1.0);
        }
        if server.contains("tomcat")
            || server.contains("jetty")
            || powered.contains("servlet")
            || body_lower.contains("java.lang")
            || body_lower.contains("at org.apache")
        {
            features.insert("tech:runtime_java".into(), 1.0);
        }
        if powered.contains("phusion")
            || body_lower.contains("actioncontroller")
            || body_lower.contains("ruby")
            || resp.headers.contains_key("x-rack-cache")
        {
            features.insert("tech:runtime_ruby".into(), 1.0);
        }
        if body_lower.contains("wsgiref")
            || body_lower.contains("django")
            || body_lower.contains("flask")
            || body_lower.contains("traceback (most recent call last)")
        {
            features.insert("tech:runtime_python".into(), 1.0);
        }

        // Framework detection
        if body_lower.contains("wp-content")
            || body_lower.contains("wp-includes")
            || body_lower.contains("wordpress")
        {
            features.insert("tech:framework_wordpress".into(), 1.0);
        }
        if body_lower.contains("drupal")
            || body_lower.contains("sites/default")
            || resp.headers.contains_key("x-drupal-cache")
        {
            features.insert("tech:framework_drupal".into(), 1.0);
        }
        if body_lower.contains("/joomla") || body_lower.contains("com_content") {
            features.insert("tech:framework_joomla".into(), 1.0);
        }
        if body_lower.contains("laravel_session")
            || (body_lower.contains("csrf-token") && powered.contains("php"))
        {
            features.insert("tech:framework_laravel".into(), 1.0);
        }
        if body_lower.contains("spring")
            || body_lower.contains("whitelabel error page")
        {
            features.insert("tech:framework_spring".into(), 1.0);
        }
        if body_lower.contains("csrfmiddlewaretoken")
            || body_lower.contains("django")
        {
            features.insert("tech:framework_django".into(), 1.0);
        }
        if resp.headers.contains_key("x-rack-cache")
            || body_lower.contains("rails")
            || body_lower.contains("authenticity_token")
        {
            features.insert("tech:framework_rails".into(), 1.0);
        }
        if powered.contains("express") {
            features.insert("tech:framework_express".into(), 1.0);
        }
        if body_lower.contains("__next") || body_lower.contains("_next/static") {
            features.insert("tech:framework_nextjs".into(), 1.0);
        }
        if body_lower.contains("struts")
            || body_lower.contains("org.apache.struts")
        {
            features.insert("tech:framework_struts".into(), 1.0);
        }

        // Database detection (from errors/headers)
        if body_lower.contains("mysql") || body_lower.contains("mariadb") {
            features.insert("tech:db_mysql".into(), 1.0);
        }
        if body_lower.contains("postgresql") || body_lower.contains("pg_") {
            features.insert("tech:db_postgresql".into(), 1.0);
        }
        if body_lower.contains("microsoft sql")
            || body_lower.contains("mssql")
            || body_lower.contains("sqlserver")
        {
            features.insert("tech:db_mssql".into(), 1.0);
        }
        if body_lower.contains("mongodb") || body_lower.contains("mongoose") {
            features.insert("tech:db_mongodb".into(), 1.0);
        }
        if body_lower.contains("redis") {
            features.insert("tech:db_redis".into(), 1.0);
        }

        // Infrastructure
        // WAF detection
        let waf_signs = [
            "mod_security",
            "imperva",
            "sucuri",
            "barracuda",
            "fortiweb",
            "f5 big-ip",
            "akamai",
            "wallarm",
            "aws-waf",
        ];
        for waf in &waf_signs {
            if server.contains(waf)
                || body_lower.contains(waf)
                || (resp.status == 403 && body_lower.contains("blocked"))
            {
                features.insert("tech:waf_present".into(), 1.0);
                break;
            }
        }

        // CDN
        if all_headers.contains("x-cdn")
            || all_headers.contains("x-cache")
            || server.contains("cloudfront")
            || server.contains("fastly")
            || server.contains("akamai")
        {
            features.insert("tech:cdn_present".into(), 1.0);
        }

        // API gateway
        if all_headers.contains("x-amzn-requestid")
            || all_headers.contains("x-kong-")
            || server.contains("kong")
            || server.contains("envoy")
        {
            features.insert("tech:api_gateway".into(), 1.0);
        }

        // Container hints
        if body_lower.contains("kubernetes")
            || body_lower.contains("docker")
            || resp
                .headers
                .get("server")
                .map(|s| s == "envoy")
                .unwrap_or(false)
        {
            features.insert("tech:container_environment".into(), 1.0);
        }

        // Legacy software (outdated versions in headers)
        if powered.contains("php/5.")
            || powered.contains("php/4.")
            || server.contains("apache/2.2")
            || server.contains("apache/2.0")
            || server.contains("iis/6")
            || server.contains("iis/7")
        {
            features.insert("tech:legacy_software".into(), 1.0);
        }
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

    fn make_response_with_headers(
        body: &str,
        status: u16,
        headers: Vec<(&str, &str)>,
    ) -> HttpResponse {
        let mut h = HashMap::new();
        for (k, v) in headers {
            h.insert(k.to_string(), v.to_string());
        }
        HttpResponse {
            status,
            headers: h,
            body: body.to_string(),
            body_bytes: body.len(),
            response_time_ms: 100,
        }
    }

    #[test]
    fn test_server_apache() {
        let resp = make_response_with_headers("OK", 200, vec![("server", "Apache/2.4.41")]);
        let features = extract_tech_features(&[resp]);
        assert!(features.contains_key("tech:server_apache"));
    }

    #[test]
    fn test_server_nginx() {
        let resp = make_response_with_headers("OK", 200, vec![("server", "nginx/1.21.0")]);
        let features = extract_tech_features(&[resp]);
        assert!(features.contains_key("tech:server_nginx"));
    }

    #[test]
    fn test_server_cloudflare() {
        let resp = make_response_with_headers(
            "OK",
            200,
            vec![("server", "cloudflare"), ("cf-ray", "abc123")],
        );
        let features = extract_tech_features(&[resp]);
        assert!(features.contains_key("tech:server_cloudflare"));
        assert!(features.contains_key("tech:cdn_present"));
    }

    #[test]
    fn test_runtime_php() {
        let resp =
            make_response_with_headers("OK", 200, vec![("x-powered-by", "PHP/8.1.2")]);
        let features = extract_tech_features(&[resp]);
        assert!(features.contains_key("tech:runtime_php"));
    }

    #[test]
    fn test_runtime_node() {
        let resp =
            make_response_with_headers("OK", 200, vec![("x-powered-by", "Express")]);
        let features = extract_tech_features(&[resp]);
        assert!(features.contains_key("tech:runtime_node"));
        assert!(features.contains_key("tech:framework_express"));
    }

    #[test]
    fn test_runtime_java() {
        let resp = make_response(
            "java.lang.NullPointerException at org.apache.catalina",
            500,
        );
        let features = extract_tech_features(&[resp]);
        assert!(features.contains_key("tech:runtime_java"));
    }

    #[test]
    fn test_runtime_python() {
        let resp = make_response("Traceback (most recent call last)", 500);
        let features = extract_tech_features(&[resp]);
        assert!(features.contains_key("tech:runtime_python"));
    }

    #[test]
    fn test_framework_wordpress() {
        let resp = make_response(
            "<link rel='stylesheet' href='/wp-content/themes/theme/style.css'>",
            200,
        );
        let features = extract_tech_features(&[resp]);
        assert!(features.contains_key("tech:framework_wordpress"));
    }

    #[test]
    fn test_framework_django() {
        let resp = make_response(
            "<input type='hidden' name='csrfmiddlewaretoken' value='abc123'>",
            200,
        );
        let features = extract_tech_features(&[resp]);
        assert!(features.contains_key("tech:framework_django"));
    }

    #[test]
    fn test_framework_rails() {
        let resp = make_response(
            "<meta name='csrf-param' content='authenticity_token' />",
            200,
        );
        let features = extract_tech_features(&[resp]);
        assert!(features.contains_key("tech:framework_rails"));
    }

    #[test]
    fn test_framework_spring() {
        let resp = make_response("Whitelabel Error Page", 500);
        let features = extract_tech_features(&[resp]);
        assert!(features.contains_key("tech:framework_spring"));
    }

    #[test]
    fn test_framework_nextjs() {
        let resp = make_response(
            "<script src='/_next/static/chunks/main.js'></script><div id='__next'>",
            200,
        );
        let features = extract_tech_features(&[resp]);
        assert!(features.contains_key("tech:framework_nextjs"));
    }

    #[test]
    fn test_db_mysql() {
        let resp = make_response(
            "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
            500,
        );
        let features = extract_tech_features(&[resp]);
        assert!(features.contains_key("tech:db_mysql"));
    }

    #[test]
    fn test_db_postgresql() {
        let resp = make_response("ERROR: relation \"users\" does not exist (PostgreSQL)", 500);
        let features = extract_tech_features(&[resp]);
        assert!(features.contains_key("tech:db_postgresql"));
    }

    #[test]
    fn test_waf_detection() {
        let resp = make_response_with_headers(
            "Request blocked by mod_security",
            403,
            vec![("server", "Apache/2.4.41")],
        );
        let features = extract_tech_features(&[resp]);
        assert!(features.contains_key("tech:waf_present"));
    }

    #[test]
    fn test_cdn_via_headers() {
        let resp = make_response_with_headers(
            "OK",
            200,
            vec![("server", "CloudFront"), ("x-cache", "Hit from cloudfront")],
        );
        let features = extract_tech_features(&[resp]);
        assert!(features.contains_key("tech:cdn_present"));
    }

    #[test]
    fn test_api_gateway() {
        let resp = make_response_with_headers(
            "OK",
            200,
            vec![
                ("server", "kong/3.0"),
                ("x-kong-upstream-latency", "5"),
            ],
        );
        let features = extract_tech_features(&[resp]);
        assert!(features.contains_key("tech:api_gateway"));
    }

    #[test]
    fn test_legacy_software() {
        let resp = make_response_with_headers(
            "OK",
            200,
            vec![("x-powered-by", "PHP/5.6.40")],
        );
        let features = extract_tech_features(&[resp]);
        assert!(features.contains_key("tech:legacy_software"));
        assert!(features.contains_key("tech:runtime_php"));
    }

    #[test]
    fn test_multiple_responses_merged() {
        let resp1 = make_response_with_headers(
            "OK",
            200,
            vec![("server", "nginx/1.21.0")],
        );
        let resp2 = make_response(
            "You have an error in your SQL syntax; MySQL server",
            500,
        );
        let features = extract_tech_features(&[resp1, resp2]);
        assert!(features.contains_key("tech:server_nginx"));
        assert!(features.contains_key("tech:db_mysql"));
    }

    #[test]
    fn test_empty_responses() {
        let features = extract_tech_features(&[]);
        assert!(features.is_empty());
    }

    #[test]
    fn test_container_environment() {
        let resp = make_response("kubernetes dashboard", 200);
        let features = extract_tech_features(&[resp]);
        assert!(features.contains_key("tech:container_environment"));
    }

    #[test]
    fn test_runtime_dotnet() {
        let resp = make_response_with_headers(
            "OK",
            200,
            vec![
                ("x-powered-by", "ASP.NET"),
                ("x-aspnet-version", "4.0.30319"),
            ],
        );
        let features = extract_tech_features(&[resp]);
        assert!(features.contains_key("tech:runtime_dotnet"));
    }

    #[test]
    fn test_runtime_ruby() {
        let resp = make_response_with_headers(
            "OK",
            200,
            vec![("x-rack-cache", "miss")],
        );
        let features = extract_tech_features(&[resp]);
        assert!(features.contains_key("tech:runtime_ruby"));
    }
}
