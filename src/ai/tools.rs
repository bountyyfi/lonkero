// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Tool definitions that expose Lonkero capabilities to the LLM.
//!
//! Each tool maps to a specific lonkero CLI invocation.
//! The AI agent calls these tools to perform surgical security testing.

use serde::{Deserialize, Serialize};
use serde_json::json;

/// A tool definition the LLM can invoke.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

/// Get all tool definitions for the LLM.
/// These give the AI surgical control over lonkero's scanners.
pub fn get_tool_definitions() -> Vec<ToolDefinition> {
    vec![
        // ===================================================================
        // RECONNAISSANCE
        // ===================================================================
        ToolDefinition {
            name: "recon".into(),
            description: "Quick reconnaissance scan. Checks HTTP headers, SSL/TLS, security headers, \
                and basic info disclosure. Does NOT run injection tests. Use this first on a new target \
                to understand the tech stack and attack surface before deeper testing."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL to scan (e.g. https://example.com)"
                    }
                },
                "required": ["url"]
            }),
        },
        ToolDefinition {
            name: "crawl".into(),
            description: "Crawl the target to discover endpoints, forms, parameters, and API routes. \
                Returns a list of discovered URLs with their parameters. Use this to map the attack \
                surface before running targeted scans. Does NOT run any vulnerability tests."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL to crawl"
                    },
                    "max_depth": {
                        "type": "integer",
                        "description": "Maximum crawl depth (default: 3)",
                        "default": 3
                    }
                },
                "required": ["url"]
            }),
        },
        ToolDefinition {
            name: "subdomain_enum".into(),
            description: "Enumerate subdomains for a domain. Discovers additional attack surface \
                like staging, admin, api subdomains. Use when you want to expand the scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Domain to enumerate subdomains for (e.g. example.com)"
                    }
                },
                "required": ["domain"]
            }),
        },

        // ===================================================================
        // SINGLE-MODULE TARGETED SCANS
        // ===================================================================
        ToolDefinition {
            name: "scan_xss".into(),
            description: "Test a specific URL/endpoint for Cross-Site Scripting (XSS). \
                Uses proof-based detection: identifies reflection context, tests escape handling, \
                and confirms exploitability without a browser. Fast and accurate."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL with parameters to test (e.g. https://example.com/search?q=test)"
                    },
                    "intensity": {
                        "type": "string",
                        "enum": ["minimal", "standard", "extended", "maximum"],
                        "description": "Payload intensity. Use 'minimal' for quick check, 'maximum' for WAF bypass attempts.",
                        "default": "standard"
                    }
                },
                "required": ["url"]
            }),
        },
        ToolDefinition {
            name: "scan_sqli".into(),
            description: "Test a specific URL/endpoint for SQL Injection. \
                Uses OOBZero engine: boolean differential, arithmetic evaluation, quote cancellation, \
                and time-based correlation. No external callback server needed."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL with parameters to test"
                    },
                    "intensity": {
                        "type": "string",
                        "enum": ["minimal", "standard", "extended", "maximum"],
                        "default": "standard"
                    }
                },
                "required": ["url"]
            }),
        },
        ToolDefinition {
            name: "scan_ssrf".into(),
            description: "Test for Server-Side Request Forgery (SSRF). \
                Checks if the server can be tricked into making requests to internal services. \
                Tests both direct and blind SSRF."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL with parameters to test"
                    },
                    "intensity": {
                        "type": "string",
                        "enum": ["minimal", "standard", "extended", "maximum"],
                        "default": "standard"
                    }
                },
                "required": ["url"]
            }),
        },
        ToolDefinition {
            name: "scan_idor".into(),
            description: "Test for Insecure Direct Object Reference (IDOR) and Broken Object Level \
                Authorization (BOLA). Checks if resources belonging to other users can be accessed. \
                Works best with multi-role credentials."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL with object reference to test (e.g. /api/user/123)"
                    },
                    "intensity": {
                        "type": "string",
                        "enum": ["minimal", "standard", "extended", "maximum"],
                        "default": "standard"
                    }
                },
                "required": ["url"]
            }),
        },
        ToolDefinition {
            name: "scan_auth".into(),
            description: "Test authentication mechanisms: JWT vulnerabilities (alg:none, key confusion), \
                OAuth misconfigurations, session management issues, auth bypass techniques. \
                Use on login pages, token endpoints, and authenticated routes."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL to test (login page, token endpoint, or authenticated route)"
                    },
                    "intensity": {
                        "type": "string",
                        "enum": ["minimal", "standard", "extended", "maximum"],
                        "default": "standard"
                    }
                },
                "required": ["url"]
            }),
        },
        ToolDefinition {
            name: "scan_injection".into(),
            description: "Test for various injection vulnerabilities: command injection, SSTI, \
                NoSQL injection, XXE, LDAP injection, code injection. Use when a parameter \
                might flow into server-side processing."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL with parameters to test"
                    },
                    "intensity": {
                        "type": "string",
                        "enum": ["minimal", "standard", "extended", "maximum"],
                        "default": "standard"
                    }
                },
                "required": ["url"]
            }),
        },
        ToolDefinition {
            name: "scan_graphql".into(),
            description: "Test GraphQL endpoints: introspection enabled, batching attacks, \
                query depth/cost abuse, field suggestion exploitation. Use when you detect \
                a GraphQL endpoint (typically /graphql)."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "GraphQL endpoint URL"
                    },
                    "intensity": {
                        "type": "string",
                        "enum": ["minimal", "standard", "extended", "maximum"],
                        "default": "standard"
                    }
                },
                "required": ["url"]
            }),
        },
        ToolDefinition {
            name: "scan_api".into(),
            description: "Test API security: broken function level auth (BFLA), API versioning attacks, \
                mass assignment, OpenAPI spec analysis. Use on REST API endpoints."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "API endpoint URL"
                    },
                    "intensity": {
                        "type": "string",
                        "enum": ["minimal", "standard", "extended", "maximum"],
                        "default": "standard"
                    }
                },
                "required": ["url"]
            }),
        },
        ToolDefinition {
            name: "scan_framework".into(),
            description: "Run framework-specific security checks for a detected technology. \
                Tests known vulnerabilities, misconfigurations, and default credentials \
                specific to the framework."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL"
                    },
                    "framework": {
                        "type": "string",
                        "enum": ["wordpress", "drupal", "joomla", "laravel", "django",
                                 "rails", "nextjs", "sveltekit", "react", "express",
                                 "spring", "fastapi", "go_frameworks"],
                        "description": "Framework to test for"
                    }
                },
                "required": ["url", "framework"]
            }),
        },
        ToolDefinition {
            name: "scan_waf_bypass".into(),
            description: "Attempt WAF bypass techniques. Use after discovering a WAF is blocking \
                your payloads. Tests encoding tricks, HTTP method switching, header manipulation, \
                and payload mutation. Use 'maximum' intensity for thorough bypass testing."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL where WAF is blocking payloads"
                    }
                },
                "required": ["url"]
            }),
        },
        ToolDefinition {
            name: "scan_business_logic".into(),
            description: "Test for business logic vulnerabilities: race conditions, price manipulation, \
                workflow bypass, privilege escalation. Use on e-commerce, payment, and state-changing \
                endpoints."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL to test for business logic issues"
                    },
                    "intensity": {
                        "type": "string",
                        "enum": ["minimal", "standard", "extended", "maximum"],
                        "default": "standard"
                    }
                },
                "required": ["url"]
            }),
        },

        // ===================================================================
        // ADVANCED / SPECIFIC SCANNERS
        // ===================================================================
        ToolDefinition {
            name: "scan_custom".into(),
            description: "Run one or more specific scanner modules by ID. Use this when you need \
                a specific scanner not covered by the other tools, or when you want to combine \
                multiple specific scanners. Available module IDs include: \
                cors_misconfig, cache_poisoning, crlf_injection, open_redirect, file_upload, \
                prototype_pollution, deserialization, host_header_injection, http_smuggling, \
                websocket_scanner, timing_attacks, csp_bypass, postmessage_vulns, \
                web_cache_deception, dom_clobbering, dom_xss_scanner, subdomain_takeover, \
                account_takeover, password_reset_poisoning, twofa_bypass, oidc_scanner, \
                second_order_injection, readme_prompt_injection, and more."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL"
                    },
                    "modules": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "List of scanner module IDs to run"
                    },
                    "intensity": {
                        "type": "string",
                        "enum": ["minimal", "standard", "extended", "maximum"],
                        "default": "standard"
                    }
                },
                "required": ["url", "modules"]
            }),
        },

        // ===================================================================
        // FULL SCAN
        // ===================================================================
        ToolDefinition {
            name: "full_scan".into(),
            description: "Run a full intelligent scan with all modules. This runs tech detection, \
                crawling, endpoint deduplication, per-parameter risk scoring, and ALL applicable \
                scanners. Only use when explicitly asked for a full scan — prefer targeted scans \
                for interactive testing."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL"
                    },
                    "intensity": {
                        "type": "string",
                        "enum": ["minimal", "standard", "extended", "maximum"],
                        "description": "Global payload intensity override (default: auto/intelligent)",
                        "default": "auto"
                    },
                    "max_depth": {
                        "type": "integer",
                        "description": "Maximum crawl depth",
                        "default": 3
                    }
                },
                "required": ["url"]
            }),
        },

        // ===================================================================
        // RESULTS & REPORTING
        // ===================================================================
        ToolDefinition {
            name: "list_findings".into(),
            description: "List all vulnerabilities found in this session so far. \
                Returns findings grouped by severity with details. Use to review progress \
                and decide what to investigate next."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        },
        ToolDefinition {
            name: "generate_report".into(),
            description: "Generate a formatted report of all findings from this session. \
                Available formats: json, html, pdf, sarif, markdown, csv, xlsx."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "format": {
                        "type": "string",
                        "enum": ["json", "html", "pdf", "sarif", "markdown", "csv", "xlsx"],
                        "description": "Output format",
                        "default": "json"
                    },
                    "output_path": {
                        "type": "string",
                        "description": "File path to write the report to (optional, prints to stdout if omitted)"
                    }
                },
                "required": ["format"]
            }),
        },
        ToolDefinition {
            name: "list_modules".into(),
            description: "List all available scanner modules with their IDs and descriptions. \
                Use when you need to check what scanners are available or find the right module \
                ID for a specific test."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        },
    ]
}

// ---------------------------------------------------------------------------
// Tool-to-CLI mapping: translates a tool call to lonkero CLI arguments
// ---------------------------------------------------------------------------

/// Maps a tool call name + input to the corresponding lonkero CLI arguments.
pub fn tool_to_cli_args(tool_name: &str, input: &serde_json::Value) -> Option<Vec<String>> {
    let url = input["url"].as_str().unwrap_or("").to_string();
    let intensity = input["intensity"].as_str().unwrap_or("standard");

    match tool_name {
        "recon" => Some(vec![
            "scan".into(),
            url,
            "--only".into(), "http_headers".into(),
            "--only".into(), "ssl_checker".into(),
            "--only".into(), "security_headers".into(),
            "--only".into(), "info_disclosure_basic".into(),
            "--only".into(), "cors_basic".into(),
            "--only".into(), "clickjacking".into(),
            "--crawl".into(), "false".into(),
            "--format".into(), "json".into(),
        ]),

        "crawl" => {
            let depth = input["max_depth"].as_u64().unwrap_or(3).to_string();
            Some(vec![
                "scan".into(),
                url,
                "--only".into(), "endpoint_discovery".into(),
                "--crawl".into(), "true".into(),
                "--max-depth".into(), depth,
                "--format".into(), "json".into(),
            ])
        }

        "subdomain_enum" => {
            let domain = input["domain"].as_str().unwrap_or("").to_string();
            Some(vec![
                "scan".into(),
                format!("https://{}", domain),
                "--subdomains".into(),
                "--only".into(), "dns_enum".into(),
                "--crawl".into(), "false".into(),
                "--format".into(), "json".into(),
            ])
        }

        "scan_xss" => Some(vec![
            "scan".into(),
            url,
            "--only".into(), "proof_xss_scanner".into(),
            "--only".into(), "reflection_xss_scanner".into(),
            "--only".into(), "xss_scanner".into(),
            "--only".into(), "dom_xss_scanner".into(),
            "--payload-intensity".into(), intensity.into(),
            "--crawl".into(), "false".into(),
            "--format".into(), "json".into(),
        ]),

        "scan_sqli" => Some(vec![
            "scan".into(),
            url,
            "--only".into(), "sqli_scanner".into(),
            "--payload-intensity".into(), intensity.into(),
            "--crawl".into(), "false".into(),
            "--format".into(), "json".into(),
        ]),

        "scan_ssrf" => Some(vec![
            "scan".into(),
            url,
            "--only".into(), "ssrf_scanner".into(),
            "--only".into(), "ssrf_blind".into(),
            "--payload-intensity".into(), intensity.into(),
            "--crawl".into(), "false".into(),
            "--format".into(), "json".into(),
        ]),

        "scan_idor" => Some(vec![
            "scan".into(),
            url,
            "--only".into(), "idor_scanner".into(),
            "--only".into(), "idor_analyzer".into(),
            "--only".into(), "bola_scanner".into(),
            "--payload-intensity".into(), intensity.into(),
            "--crawl".into(), "false".into(),
            "--format".into(), "json".into(),
        ]),

        "scan_auth" => Some(vec![
            "scan".into(),
            url,
            "--only".into(), "jwt_scanner".into(),
            "--only".into(), "jwt_analyzer".into(),
            "--only".into(), "oauth_scanner".into(),
            "--only".into(), "saml_scanner".into(),
            "--only".into(), "auth_bypass".into(),
            "--only".into(), "session_management".into(),
            "--only".into(), "session_analyzer".into(),
            "--only".into(), "mfa_scanner".into(),
            "--only".into(), "oidc_scanner".into(),
            "--only".into(), "advanced_auth".into(),
            "--only".into(), "auth_flow_tester".into(),
            "--payload-intensity".into(), intensity.into(),
            "--crawl".into(), "false".into(),
            "--format".into(), "json".into(),
        ]),

        "scan_injection" => Some(vec![
            "scan".into(),
            url,
            "--only".into(), "command_injection".into(),
            "--only".into(), "ssti_scanner".into(),
            "--only".into(), "ssti_advanced".into(),
            "--only".into(), "nosql_scanner".into(),
            "--only".into(), "xxe_scanner".into(),
            "--only".into(), "ldap_injection".into(),
            "--only".into(), "code_injection".into(),
            "--only".into(), "path_traversal".into(),
            "--only".into(), "xml_injection".into(),
            "--only".into(), "xpath_injection".into(),
            "--only".into(), "ssi_injection".into(),
            "--payload-intensity".into(), intensity.into(),
            "--crawl".into(), "false".into(),
            "--format".into(), "json".into(),
        ]),

        "scan_graphql" => Some(vec![
            "scan".into(),
            url,
            "--only".into(), "graphql_scanner".into(),
            "--only".into(), "graphql_batching".into(),
            "--payload-intensity".into(), intensity.into(),
            "--crawl".into(), "false".into(),
            "--format".into(), "json".into(),
        ]),

        "scan_api" => Some(vec![
            "scan".into(),
            url,
            "--only".into(), "api_security".into(),
            "--only".into(), "api_gateway".into(),
            "--only".into(), "api_versioning".into(),
            "--only".into(), "api_fuzzer".into(),
            "--only".into(), "broken_function_auth".into(),
            "--only".into(), "mass_assignment".into(),
            "--only".into(), "mass_assignment_advanced".into(),
            "--only".into(), "openapi_analyzer".into(),
            "--payload-intensity".into(), intensity.into(),
            "--crawl".into(), "false".into(),
            "--format".into(), "json".into(),
        ]),

        "scan_framework" => {
            let framework = input["framework"].as_str().unwrap_or("nextjs");
            let module = format!("{}_scanner", framework);
            Some(vec![
                "scan".into(),
                url,
                "--only".into(), module,
                "--only".into(), "framework_vulns".into(),
                "--crawl".into(), "false".into(),
                "--format".into(), "json".into(),
            ])
        }

        "scan_waf_bypass" => Some(vec![
            "scan".into(),
            url,
            "--only".into(), "waf_bypass".into(),
            "--payload-intensity".into(), "maximum".into(),
            "--crawl".into(), "false".into(),
            "--format".into(), "json".into(),
        ]),

        "scan_business_logic" => Some(vec![
            "scan".into(),
            url,
            "--only".into(), "business_logic".into(),
            "--only".into(), "race_condition".into(),
            "--only".into(), "mass_assignment".into(),
            "--only".into(), "mass_assignment_advanced".into(),
            "--only".into(), "timing_attacks".into(),
            "--payload-intensity".into(), intensity.into(),
            "--crawl".into(), "false".into(),
            "--format".into(), "json".into(),
        ]),

        "scan_custom" => {
            let mut args = vec!["scan".into(), url];
            if let Some(modules) = input["modules"].as_array() {
                for module in modules {
                    if let Some(m) = module.as_str() {
                        args.push("--only".into());
                        args.push(m.to_string());
                    }
                }
            }
            args.extend_from_slice(&[
                "--payload-intensity".into(), intensity.into(),
                "--crawl".into(), "false".into(),
                "--format".into(), "json".into(),
            ]);
            Some(args)
        }

        "full_scan" => {
            let depth = input["max_depth"].as_u64().unwrap_or(3).to_string();
            let mut args = vec![
                "scan".into(),
                url,
                "--crawl".into(), "true".into(),
                "--max-depth".into(), depth,
                "--format".into(), "json".into(),
            ];
            if intensity != "auto" {
                args.extend_from_slice(&[
                    "--payload-intensity".into(), intensity.into(),
                ]);
            }
            Some(args)
        }

        // Non-CLI tools handled in agent.rs or server-side
        "list_findings" | "generate_report" | "list_modules" => None,

        // Server-side tool — Anthropic handles execution, not us
        "web_search" => None,

        _ => None,
    }
}
