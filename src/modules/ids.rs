// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Module IDs for server-side authorization
//!
//! These IDs MUST match the server's MODULE_REQUIREMENTS exactly.
//! The server validates that only authorized modules are used.

/// Free tier modules - available to all users
pub mod free {
    /// Basic port scanning
    pub const PORT_SCANNER: &str = "port_scanner";
    /// HTTP security headers analysis
    pub const HTTP_HEADERS: &str = "http_headers";
    /// SSL/TLS certificate checking
    pub const SSL_CHECKER: &str = "ssl_checker";
    /// Basic DNS enumeration
    pub const DNS_ENUM: &str = "dns_enum";
    /// Basic security headers scanner
    pub const SECURITY_HEADERS: &str = "security_headers";
    /// Basic CORS checking
    pub const CORS_BASIC: &str = "cors_basic";
    /// Clickjacking detection
    pub const CLICKJACKING: &str = "clickjacking";
    /// Information disclosure (basic)
    pub const INFO_DISCLOSURE_BASIC: &str = "info_disclosure_basic";
    /// ArcGIS REST Services data exposure scanner
    pub const ARCGIS_REST: &str = "arcgis_rest";
}

/// Personal+ tier modules - requires cms_security feature
pub mod cms_security {
    /// WordPress security scanner
    pub const WORDPRESS_SCANNER: &str = "wordpress_scanner";
    /// Drupal security scanner
    pub const DRUPAL_SCANNER: &str = "drupal_scanner";
    /// Joomla security scanner
    pub const JOOMLA_SCANNER: &str = "joomla_scanner";
    /// Laravel security scanner
    pub const LARAVEL_SCANNER: &str = "laravel_scanner";
    /// Django security scanner
    pub const DJANGO_SCANNER: &str = "django_scanner";
    /// Rails security scanner
    pub const RAILS_SCANNER: &str = "rails_scanner";
    /// Next.js security scanner
    pub const NEXTJS_SCANNER: &str = "nextjs_scanner";
    /// SvelteKit security scanner
    pub const SVELTEKIT_SCANNER: &str = "sveltekit_scanner";
    /// React security scanner
    pub const REACT_SCANNER: &str = "react_scanner";
    /// Express.js security scanner
    pub const EXPRESS_SCANNER: &str = "express_scanner";
    /// Liferay security scanner
    pub const LIFERAY_SCANNER: &str = "liferay_scanner";
    /// Spring security scanner
    pub const SPRING_SCANNER: &str = "spring_scanner";
    /// FastAPI security scanner
    pub const FASTAPI_SCANNER: &str = "fastapi_scanner";
    /// Go frameworks security scanner (Gin, Echo, Fiber, Chi)
    pub const GO_FRAMEWORKS_SCANNER: &str = "go_frameworks_scanner";
}

/// Professional+ tier modules - requires advanced_scanning feature
pub mod advanced_scanning {
    /// SQL injection scanner (all techniques including OOBZero inference)
    pub const SQLI_SCANNER: &str = "sqli_scanner";
    /// Cross-site scripting scanner (hybrid taint analysis)
    pub const XSS_SCANNER: &str = "xss_scanner";
    /// Proof-based XSS scanner (context + escape analysis, no Chrome)
    pub const PROOF_XSS_SCANNER: &str = "proof_xss_scanner";
    /// Reflection-based XSS scanner (no Chrome required)
    pub const REFLECTION_XSS_SCANNER: &str = "reflection_xss_scanner";
    /// Command injection scanner
    pub const COMMAND_INJECTION: &str = "command_injection";
    /// Path traversal scanner
    pub const PATH_TRAVERSAL: &str = "path_traversal";
    /// SSRF scanner
    pub const SSRF_SCANNER: &str = "ssrf_scanner";
    /// Blind SSRF scanner
    pub const SSRF_BLIND: &str = "ssrf_blind";
    /// XXE scanner
    pub const XXE_SCANNER: &str = "xxe_scanner";
    /// SSTI scanner
    pub const SSTI_SCANNER: &str = "ssti_scanner";
    /// Advanced SSTI scanner
    pub const SSTI_ADVANCED: &str = "ssti_advanced";
    /// NoSQL injection scanner
    pub const NOSQL_SCANNER: &str = "nosql_scanner";
    /// LDAP injection scanner
    pub const LDAP_INJECTION: &str = "ldap_injection";
    /// Code injection scanner
    pub const CODE_INJECTION: &str = "code_injection";
    /// API fuzzer
    pub const API_FUZZER: &str = "api_fuzzer";
    /// Authentication bypass scanner
    pub const AUTH_BYPASS: &str = "auth_bypass";
    /// Client route authorization bypass scanner
    pub const CLIENT_ROUTE_AUTH_BYPASS: &str = "client_route_auth_bypass";
    /// JWT vulnerabilities scanner
    pub const JWT_SCANNER: &str = "jwt_scanner";
    /// OAuth security scanner
    pub const OAUTH_SCANNER: &str = "oauth_scanner";
    /// SAML security scanner
    pub const SAML_SCANNER: &str = "saml_scanner";
    /// GraphQL security scanner
    pub const GRAPHQL_SCANNER: &str = "graphql_scanner";
    /// HTTP request smuggling scanner
    pub const HTTP_SMUGGLING: &str = "http_smuggling";
    /// Race condition scanner
    pub const RACE_CONDITION: &str = "race_condition";
    /// Mass assignment scanner
    pub const MASS_ASSIGNMENT: &str = "mass_assignment";
    /// Deserialization scanner
    pub const DESERIALIZATION: &str = "deserialization";
    /// Prototype pollution scanner
    pub const PROTOTYPE_POLLUTION: &str = "prototype_pollution";
    /// Host header injection scanner
    pub const HOST_HEADER_INJECTION: &str = "host_header_injection";
    /// AWS Cognito user enumeration scanner
    pub const COGNITO_ENUM: &str = "cognito_enum";
    /// Source map detection scanner
    pub const SOURCE_MAP_DETECTION: &str = "source_map_detection";
    /// Favicon hash fingerprinting scanner
    pub const FAVICON_HASH_DETECTION: &str = "favicon_hash_detection";
    /// Cache poisoning scanner
    pub const CACHE_POISONING: &str = "cache_poisoning";
    /// CRLF injection scanner
    pub const CRLF_INJECTION: &str = "crlf_injection";
    /// Open redirect scanner
    pub const OPEN_REDIRECT: &str = "open_redirect";
    /// File upload scanner
    pub const FILE_UPLOAD: &str = "file_upload";
    /// IDOR scanner
    pub const IDOR_SCANNER: &str = "idor_scanner";
    /// BOLA scanner
    pub const BOLA_SCANNER: &str = "bola_scanner";
    /// WAF bypass scanner
    pub const WAF_BYPASS: &str = "waf_bypass";
    /// ReDoS scanner
    pub const REDOS_SCANNER: &str = "redos_scanner";
    /// HTTP Parameter Pollution scanner
    pub const HPP_SCANNER: &str = "hpp_scanner";
    /// Merlin JS library scanner
    pub const MERLIN_SCANNER: &str = "merlin_scanner";
    /// Session management scanner
    pub const SESSION_MANAGEMENT: &str = "session_management";
    /// MFA bypass scanner
    pub const MFA_SCANNER: &str = "mfa_scanner";
    /// WebSocket security scanner
    pub const WEBSOCKET_SCANNER: &str = "websocket_scanner";
    /// gRPC security scanner
    pub const GRPC_SCANNER: &str = "grpc_scanner";
    /// Business logic scanner
    pub const BUSINESS_LOGIC: &str = "business_logic";
    /// CSRF scanner
    pub const CSRF_SCANNER: &str = "csrf_scanner";
    /// CORS misconfiguration scanner
    pub const CORS_MISCONFIG: &str = "cors_misconfig";
    /// Sensitive data scanner
    pub const SENSITIVE_DATA: &str = "sensitive_data";
    /// JS sensitive info scanner
    pub const JS_SENSITIVE_INFO: &str = "js_sensitive_info";
    /// JS miner scanner
    pub const JS_MINER: &str = "js_miner";
    /// Baseline detector (anomaly detection)
    pub const BASELINE_DETECTOR: &str = "baseline_detector";
    /// HTML injection scanner
    pub const HTML_INJECTION: &str = "html_injection";
    /// Rate limiting scanner
    pub const RATE_LIMITING: &str = "rate_limiting";
    /// Tomcat misconfiguration scanner
    pub const TOMCAT_MISCONFIG: &str = "tomcat_misconfig";
    /// Varnish misconfiguration scanner
    pub const VARNISH_MISCONFIG: &str = "varnish_misconfig";
    /// Firebase scanner
    pub const FIREBASE_SCANNER: &str = "firebase_scanner";
    /// Email header injection scanner
    pub const EMAIL_HEADER_INJECTION: &str = "email_header_injection";
    /// XML injection scanner
    pub const XML_INJECTION: &str = "xml_injection";
    /// XPath injection scanner
    pub const XPATH_INJECTION: &str = "xpath_injection";
    /// SSI injection scanner
    pub const SSI_INJECTION: &str = "ssi_injection";
    /// API security scanner
    pub const API_SECURITY: &str = "api_security";
    /// API gateway scanner
    pub const API_GATEWAY: &str = "api_gateway";
    /// HTTP/3 scanner
    pub const HTTP3_SCANNER: &str = "http3_scanner";
    /// WebAuthn scanner
    pub const WEBAUTHN_SCANNER: &str = "webauthn_scanner";
    /// Framework vulnerabilities scanner
    pub const FRAMEWORK_VULNS: &str = "framework_vulns";
    /// Advanced auth scanner
    pub const ADVANCED_AUTH: &str = "advanced_auth";
    /// Auth manager scanner
    pub const AUTH_MANAGER: &str = "auth_manager";
    /// Azure APIM scanner
    pub const AZURE_APIM: &str = "azure_apim";
    /// Google Dorking scanner
    pub const GOOGLE_DORKING: &str = "google_dorking";
    /// Endpoint discovery (multilingual path brute-force)
    pub const ENDPOINT_DISCOVERY: &str = "endpoint_discovery";

    // === Phase 1: Bug Bounty Critical Scanners ===
    /// Subdomain takeover scanner (25+ cloud services)
    pub const SUBDOMAIN_TAKEOVER: &str = "subdomain_takeover";
    /// DOM XSS scanner (source-to-sink flow analysis)
    pub const DOM_XSS_SCANNER: &str = "dom_xss_scanner";
    /// Account takeover scanner (OAuth chains, session fixation)
    pub const ACCOUNT_TAKEOVER: &str = "account_takeover";
    /// Password reset poisoning scanner
    pub const PASSWORD_RESET_POISONING: &str = "password_reset_poisoning";
    /// 2FA bypass scanner (rate limiting, backup codes)
    pub const TWOFA_BYPASS: &str = "twofa_bypass";
    /// OIDC security scanner (Okta, Auth0, Azure AD, Keycloak, Cognito)
    pub const OIDC_SCANNER: &str = "oidc_scanner";

    // === Phase 2: API Security Scanners ===
    /// Broken Function Level Authorization scanner (BFLA)
    pub const BROKEN_FUNCTION_AUTH: &str = "broken_function_auth";
    /// API versioning attacks scanner
    pub const API_VERSIONING: &str = "api_versioning";
    /// GraphQL batching attack scanner (DoS, alias abuse)
    pub const GRAPHQL_BATCHING: &str = "graphql_batching";
    /// OpenAPI/Swagger specification analyzer
    pub const OPENAPI_ANALYZER: &str = "openapi_analyzer";
    /// Advanced mass assignment scanner (nested objects, dot notation)
    pub const MASS_ASSIGNMENT_ADVANCED: &str = "mass_assignment_advanced";

    // === Phase 3: Advanced Web Scanners ===
    /// CSP bypass scanner (script gadgets, nonce reuse)
    pub const CSP_BYPASS: &str = "csp_bypass";
    /// PostMessage vulnerabilities scanner
    pub const POSTMESSAGE_VULNS: &str = "postmessage_vulns";
    /// Web cache deception scanner
    pub const WEB_CACHE_DECEPTION: &str = "web_cache_deception";
    /// DOM clobbering scanner
    pub const DOM_CLOBBERING: &str = "dom_clobbering";
    /// Timing attacks scanner (auth timing, user enumeration)
    pub const TIMING_ATTACKS: &str = "timing_attacks";

    /// IDOR analyzer (advanced object reference testing with baseline)
    pub const IDOR_ANALYZER: &str = "idor_analyzer";
    /// JWT analyzer (token analysis and vulnerability detection)
    pub const JWT_ANALYZER: &str = "jwt_analyzer";
    /// Session analyzer (session token analysis)
    pub const SESSION_ANALYZER: &str = "session_analyzer";

    // === New Scanners (v3.1) ===
    /// Second-order injection scanner (stored payloads, delayed execution)
    pub const SECOND_ORDER_INJECTION: &str = "second_order_injection";
    /// Authentication flow tester (session fixation, password reset IDOR, MFA bypass)
    pub const AUTH_FLOW_TESTER: &str = "auth_flow_tester";
}

/// Team+ tier modules - requires cloud_scanning feature
pub mod cloud_scanning {
    /// Container scanner
    pub const CONTAINER_SCANNER: &str = "container_scanner";
    /// Cloud storage scanner
    pub const CLOUD_STORAGE: &str = "cloud_storage";
    /// Cloud security scanner
    pub const CLOUD_SECURITY: &str = "cloud_security";
}

/// Enterprise tier modules - requires custom_integrations feature
pub mod enterprise {
    /// Custom module support
    pub const CUSTOM_MODULE: &str = "custom_module";
    /// Compliance scanner (SOC2, PCI-DSS, etc.)
    pub const COMPLIANCE_SCANNER: &str = "compliance_scanner";
    /// DORA compliance scanner
    pub const DORA_SCANNER: &str = "dora_scanner";
    /// NIS2 compliance scanner
    pub const NIS2_SCANNER: &str = "nis2_scanner";
}

/// CVE-specific scanner modules
pub mod cve_scanners {
    /// CVE-2025-55182 React Server Components RCE
    pub const CVE_2025_55182: &str = "cve_2025_55182";
    /// CVE-2025-55183 RSC Source Code Exposure
    pub const CVE_2025_55183: &str = "cve_2025_55183";
    /// CVE-2025-55184 RSC Denial of Service
    pub const CVE_2025_55184: &str = "cve_2025_55184";
}

/// Get the tier/feature required for a module
pub fn get_required_feature(module_id: &str) -> Option<&'static str> {
    // Free modules - no feature required
    match module_id {
        "port_scanner"
        | "http_headers"
        | "ssl_checker"
        | "dns_enum"
        | "security_headers"
        | "cors_basic"
        | "clickjacking"
        | "info_disclosure_basic" => return None,
        _ => {}
    }

    // CMS security modules (Personal+)
    match module_id {
        "wordpress_scanner"
        | "drupal_scanner"
        | "joomla_scanner"
        | "laravel_scanner"
        | "django_scanner"
        | "rails_scanner"
        | "nextjs_scanner"
        | "sveltekit_scanner"
        | "react_scanner"
        | "express_scanner"
        | "liferay_scanner"
        | "spring_scanner"
        | "fastapi_scanner"
        | "go_frameworks_scanner" => {
            return Some("cms_security");
        }
        _ => {}
    }

    // Cloud scanning modules (Team+)
    match module_id {
        "container_scanner" | "cloud_storage" | "cloud_security" => {
            return Some("cloud_scanning");
        }
        _ => {}
    }

    // Enterprise modules
    match module_id {
        "custom_module" | "compliance_scanner" | "dora_scanner" | "nis2_scanner" => {
            return Some("custom_integrations");
        }
        _ => {}
    }

    // All other modules require advanced_scanning (Professional+)
    Some("advanced_scanning")
}

/// Get all module IDs as a list
pub fn get_all_module_ids() -> Vec<&'static str> {
    vec![
        // Free
        free::PORT_SCANNER,
        free::HTTP_HEADERS,
        free::SSL_CHECKER,
        free::DNS_ENUM,
        free::SECURITY_HEADERS,
        free::CORS_BASIC,
        free::CLICKJACKING,
        free::INFO_DISCLOSURE_BASIC,
        // CMS Security (Personal+)
        cms_security::WORDPRESS_SCANNER,
        cms_security::DRUPAL_SCANNER,
        cms_security::JOOMLA_SCANNER,
        cms_security::LARAVEL_SCANNER,
        cms_security::DJANGO_SCANNER,
        cms_security::RAILS_SCANNER,
        cms_security::NEXTJS_SCANNER,
        cms_security::SVELTEKIT_SCANNER,
        cms_security::REACT_SCANNER,
        cms_security::EXPRESS_SCANNER,
        cms_security::LIFERAY_SCANNER,
        cms_security::SPRING_SCANNER,
        cms_security::FASTAPI_SCANNER,
        cms_security::GO_FRAMEWORKS_SCANNER,
        // Advanced Scanning (Professional+)
        advanced_scanning::SQLI_SCANNER,
        advanced_scanning::XSS_SCANNER,
        advanced_scanning::PROOF_XSS_SCANNER,
        advanced_scanning::REFLECTION_XSS_SCANNER,
        advanced_scanning::COMMAND_INJECTION,
        advanced_scanning::PATH_TRAVERSAL,
        advanced_scanning::SSRF_SCANNER,
        advanced_scanning::SSRF_BLIND,
        advanced_scanning::XXE_SCANNER,
        advanced_scanning::SSTI_SCANNER,
        advanced_scanning::SSTI_ADVANCED,
        advanced_scanning::NOSQL_SCANNER,
        advanced_scanning::LDAP_INJECTION,
        advanced_scanning::CODE_INJECTION,
        advanced_scanning::API_FUZZER,
        advanced_scanning::AUTH_BYPASS,
        advanced_scanning::CLIENT_ROUTE_AUTH_BYPASS,
        advanced_scanning::JWT_SCANNER,
        advanced_scanning::OAUTH_SCANNER,
        advanced_scanning::SAML_SCANNER,
        advanced_scanning::GRAPHQL_SCANNER,
        advanced_scanning::HTTP_SMUGGLING,
        advanced_scanning::RACE_CONDITION,
        advanced_scanning::MASS_ASSIGNMENT,
        advanced_scanning::DESERIALIZATION,
        advanced_scanning::PROTOTYPE_POLLUTION,
        advanced_scanning::CACHE_POISONING,
        advanced_scanning::HOST_HEADER_INJECTION,
        advanced_scanning::COGNITO_ENUM,
        advanced_scanning::CRLF_INJECTION,
        advanced_scanning::OPEN_REDIRECT,
        advanced_scanning::FILE_UPLOAD,
        advanced_scanning::IDOR_SCANNER,
        advanced_scanning::BOLA_SCANNER,
        advanced_scanning::WAF_BYPASS,
        advanced_scanning::REDOS_SCANNER,
        advanced_scanning::HPP_SCANNER,
        advanced_scanning::MERLIN_SCANNER,
        advanced_scanning::SESSION_MANAGEMENT,
        advanced_scanning::MFA_SCANNER,
        advanced_scanning::WEBSOCKET_SCANNER,
        advanced_scanning::GRPC_SCANNER,
        advanced_scanning::BUSINESS_LOGIC,
        advanced_scanning::CSRF_SCANNER,
        advanced_scanning::CORS_MISCONFIG,
        advanced_scanning::SENSITIVE_DATA,
        advanced_scanning::JS_SENSITIVE_INFO,
        advanced_scanning::JS_MINER,
        advanced_scanning::BASELINE_DETECTOR,
        advanced_scanning::HTML_INJECTION,
        advanced_scanning::RATE_LIMITING,
        advanced_scanning::TOMCAT_MISCONFIG,
        advanced_scanning::VARNISH_MISCONFIG,
        advanced_scanning::FIREBASE_SCANNER,
        advanced_scanning::EMAIL_HEADER_INJECTION,
        advanced_scanning::XML_INJECTION,
        advanced_scanning::XPATH_INJECTION,
        advanced_scanning::SSI_INJECTION,
        advanced_scanning::API_SECURITY,
        advanced_scanning::API_GATEWAY,
        advanced_scanning::HTTP3_SCANNER,
        advanced_scanning::WEBAUTHN_SCANNER,
        advanced_scanning::FRAMEWORK_VULNS,
        advanced_scanning::ADVANCED_AUTH,
        advanced_scanning::AUTH_MANAGER,
        advanced_scanning::AZURE_APIM,
        advanced_scanning::GOOGLE_DORKING,
        advanced_scanning::ENDPOINT_DISCOVERY,
        // Phase 1: Bug Bounty Critical
        advanced_scanning::SUBDOMAIN_TAKEOVER,
        advanced_scanning::DOM_XSS_SCANNER,
        advanced_scanning::ACCOUNT_TAKEOVER,
        advanced_scanning::PASSWORD_RESET_POISONING,
        advanced_scanning::TWOFA_BYPASS,
        advanced_scanning::OIDC_SCANNER,
        // Phase 2: API Security
        advanced_scanning::BROKEN_FUNCTION_AUTH,
        advanced_scanning::API_VERSIONING,
        advanced_scanning::GRAPHQL_BATCHING,
        advanced_scanning::OPENAPI_ANALYZER,
        advanced_scanning::MASS_ASSIGNMENT_ADVANCED,
        // Phase 3: Advanced Web
        advanced_scanning::CSP_BYPASS,
        advanced_scanning::POSTMESSAGE_VULNS,
        advanced_scanning::WEB_CACHE_DECEPTION,
        advanced_scanning::DOM_CLOBBERING,
        advanced_scanning::TIMING_ATTACKS,
        // Advanced Analyzers
        advanced_scanning::IDOR_ANALYZER,
        advanced_scanning::JWT_ANALYZER,
        advanced_scanning::SESSION_ANALYZER,
        // New Scanners (v3.1)
        advanced_scanning::SECOND_ORDER_INJECTION,
        advanced_scanning::AUTH_FLOW_TESTER,
        // Cloud Scanning (Team+)
        cloud_scanning::CONTAINER_SCANNER,
        cloud_scanning::CLOUD_STORAGE,
        cloud_scanning::CLOUD_SECURITY,
        // Enterprise
        enterprise::CUSTOM_MODULE,
        enterprise::COMPLIANCE_SCANNER,
        enterprise::DORA_SCANNER,
        enterprise::NIS2_SCANNER,
        // CVE Scanners
        cve_scanners::CVE_2025_55182,
        cve_scanners::CVE_2025_55183,
        cve_scanners::CVE_2025_55184,
    ]
}
