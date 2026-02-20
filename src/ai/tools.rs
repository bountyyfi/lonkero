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

        // ===================================================================
        // CAT 1: MEMORY & SESSION MANAGEMENT
        // ===================================================================
        ToolDefinition {
            name: "save_session".into(),
            description: "Save the current session state to a JSON file. Persists all findings, \
                hypotheses, attack plans, knowledge graph, and audit log. Use to checkpoint \
                progress or before ending a session that may be resumed later."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path to save the session to (e.g. session-example.com.json)"
                    }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "load_session".into(),
            description: "Load a previously saved session from a JSON file. Restores all findings, \
                hypotheses, knowledge graph, and attack patterns. Use to resume a previous assessment."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path to load the session from"
                    }
                },
                "required": ["path"]
            }),
        },

        // ===================================================================
        // CAT 2: REASONING & PLANNING
        // ===================================================================
        ToolDefinition {
            name: "add_hypothesis".into(),
            description: "Record a hypothesis about the target. Use to track your reasoning — \
                e.g. 'The API likely uses JWT with a weak secret based on the x-powered-by header'. \
                Hypotheses can be confirmed or refuted with evidence as testing proceeds."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "description": {
                        "type": "string",
                        "description": "The hypothesis (e.g. 'JWT tokens use HS256 with a weak/default secret')"
                    },
                    "basis": {
                        "type": "string",
                        "description": "What evidence or reasoning led to this hypothesis"
                    }
                },
                "required": ["description", "basis"]
            }),
        },
        ToolDefinition {
            name: "update_hypothesis".into(),
            description: "Update a hypothesis with new evidence. Mark it as confirmed or refuted \
                based on scan results. This maintains the reasoning chain for the audit log."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "hypothesis_id": {
                        "type": "string",
                        "description": "Hypothesis ID to update (e.g. H-1)"
                    },
                    "confirmed": {
                        "type": "boolean",
                        "description": "true if evidence supports the hypothesis, false if it refutes it"
                    },
                    "evidence": {
                        "type": "string",
                        "description": "The evidence that confirms or refutes the hypothesis"
                    }
                },
                "required": ["hypothesis_id", "confirmed", "evidence"]
            }),
        },
        ToolDefinition {
            name: "list_hypotheses".into(),
            description: "List all hypotheses with their current status (proposed, testing, \
                confirmed, refuted). Shows confidence scores and evidence for/against."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        },
        ToolDefinition {
            name: "log_reasoning".into(),
            description: "Record a reasoning step in the audit log. Use to document WHY you \
                chose a particular scan or approach. Creates an audit trail of decision-making."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "description": "What you are about to do"
                    },
                    "reasoning": {
                        "type": "string",
                        "description": "Why you chose this action over alternatives"
                    }
                },
                "required": ["action", "reasoning"]
            }),
        },

        // ===================================================================
        // CAT 3: CUSTOM HTTP REQUESTS
        // ===================================================================
        ToolDefinition {
            name: "send_http".into(),
            description: "Send a custom HTTP request. Use for manual probing when the scanner \
                tools don't cover your exact need — e.g. testing a specific header injection, \
                sending a crafted JWT, or checking a specific API endpoint behavior. \
                Returns status code, headers, and body."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL"
                    },
                    "method": {
                        "type": "string",
                        "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
                        "description": "HTTP method",
                        "default": "GET"
                    },
                    "headers": {
                        "type": "object",
                        "description": "Custom headers to include (key-value pairs)",
                        "additionalProperties": { "type": "string" }
                    },
                    "body": {
                        "type": "string",
                        "description": "Request body (for POST/PUT/PATCH)"
                    }
                },
                "required": ["url"]
            }),
        },

        // ===================================================================
        // CAT 4: ANALYSIS & POST-PROCESSING
        // ===================================================================
        ToolDefinition {
            name: "analyze_findings".into(),
            description: "Run analysis on current findings: false-positive triage, exploit chain \
                synthesis, and severity re-assessment. Call this after a batch of scans to get \
                a refined view of results. Returns FP-flagged findings, identified chains, and \
                any severity adjustments."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "actions": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["triage_fp", "synthesize_chains", "reassess_severity", "all"]
                        },
                        "description": "Which analyses to run. Use 'all' to run everything.",
                        "default": ["all"]
                    }
                },
                "required": []
            }),
        },

        // ===================================================================
        // CAT 6: SCOPE & GUARDRAILS
        // ===================================================================
        ToolDefinition {
            name: "check_scope".into(),
            description: "Check if a URL is within the configured scope before scanning. \
                Returns whether the URL is allowed. Use this before scanning third-party \
                resources or URLs outside the original target domain."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL to check"
                    }
                },
                "required": ["url"]
            }),
        },
        ToolDefinition {
            name: "configure_scope".into(),
            description: "Modify the scope configuration. Add or remove allowed/excluded patterns, \
                set rate limits, or adjust maximum intensity. Use when the user expands or restricts \
                the testing scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "add_allowed": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "URL patterns to add to the allowed list"
                    },
                    "add_excluded": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "URL patterns to add to the exclusion list"
                    },
                    "max_intensity": {
                        "type": "string",
                        "enum": ["minimal", "standard", "extended", "maximum"],
                        "description": "Maximum allowed scan intensity"
                    },
                    "rate_limit_rpm": {
                        "type": "integer",
                        "description": "Maximum requests per minute (0 = unlimited)"
                    },
                    "allow_third_party": {
                        "type": "boolean",
                        "description": "Whether to allow scanning third-party services"
                    }
                },
                "required": []
            }),
        },

        // ===================================================================
        // CAT 7: USER EXPERIENCE
        // ===================================================================
        ToolDefinition {
            name: "show_progress".into(),
            description: "Show current assessment progress: phase, completion percentage, \
                scan count, finding count, and knowledge graph size. Use to give the user \
                a clear picture of where the assessment stands."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        },
        ToolDefinition {
            name: "export_session".into(),
            description: "Export the full session as a markdown document including conversation \
                history, findings, exploit chains, and audit log. Useful for generating a \
                comprehensive assessment record. Sensitive data is automatically redacted."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "output_path": {
                        "type": "string",
                        "description": "File path to write the export (optional, returns content if omitted)"
                    }
                },
                "required": []
            }),
        },
        ToolDefinition {
            name: "get_audit_log".into(),
            description: "Retrieve the full audit log of all reasoning decisions and actions \
                taken during this session. Shows the decision chain: what was done, why, and \
                what resulted."
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

        // Non-CLI tools handled in agent.rs (instant, no subprocess)
        "list_findings" | "generate_report" | "list_modules" => None,
        // Cat 1: Session persistence
        "save_session" | "load_session" => None,
        // Cat 2: Reasoning & planning
        "add_hypothesis" | "update_hypothesis" | "list_hypotheses" | "log_reasoning" => None,
        // Cat 3: Custom HTTP (handled as instant tool in agent.rs)
        "send_http" => None,
        // Cat 4: Analysis
        "analyze_findings" => None,
        // Cat 6: Scope
        "check_scope" | "configure_scope" => None,
        // Cat 7: UX
        "show_progress" | "export_session" | "get_audit_log" => None,

        // Server-side tool — Anthropic handles execution, not us
        "web_search" => None,

        _ => None,
    }
}
