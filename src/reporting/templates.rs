// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use std::collections::HashMap;

pub struct TemplateManager {
    templates: HashMap<String, ReportTemplate>,
}

impl TemplateManager {
    pub fn new() -> Self {
        let mut manager = Self {
            templates: HashMap::new(),
        };

        manager.load_default_templates();
        manager
    }

    fn load_default_templates(&mut self) {
        self.templates.insert(
            "executive".to_string(),
            ReportTemplate {
                name: "Executive Summary Report".to_string(),
                description: "High-level overview for executives and management".to_string(),
                include_technical_details: false,
                include_executive_summary: true,
                include_charts: true,
                include_remediation: false,
                include_compliance_mapping: true,
                include_owasp_mapping: false,
                max_vulnerabilities: Some(20),
            },
        );

        self.templates.insert(
            "technical".to_string(),
            ReportTemplate {
                name: "Technical Deep Dive Report".to_string(),
                description: "Detailed technical report for security teams".to_string(),
                include_technical_details: true,
                include_executive_summary: true,
                include_charts: true,
                include_remediation: true,
                include_compliance_mapping: true,
                include_owasp_mapping: true,
                max_vulnerabilities: None,
            },
        );

        self.templates.insert(
            "compliance".to_string(),
            ReportTemplate {
                name: "Compliance Report".to_string(),
                description: "Focus on compliance requirements and mappings".to_string(),
                include_technical_details: false,
                include_executive_summary: true,
                include_charts: false,
                include_remediation: true,
                include_compliance_mapping: true,
                include_owasp_mapping: true,
                max_vulnerabilities: None,
            },
        );

        self.templates.insert(
            "developer".to_string(),
            ReportTemplate {
                name: "Developer Report".to_string(),
                description: "Actionable report for development teams".to_string(),
                include_technical_details: true,
                include_executive_summary: false,
                include_charts: false,
                include_remediation: true,
                include_compliance_mapping: false,
                include_owasp_mapping: true,
                max_vulnerabilities: None,
            },
        );

        self.templates.insert(
            "pentest".to_string(),
            ReportTemplate {
                name: "Penetration Testing Report".to_string(),
                description: "Comprehensive report with all findings and PoCs".to_string(),
                include_technical_details: true,
                include_executive_summary: true,
                include_charts: true,
                include_remediation: true,
                include_compliance_mapping: true,
                include_owasp_mapping: true,
                max_vulnerabilities: None,
            },
        );
    }

    pub fn get_template(&self, name: &str) -> Option<&ReportTemplate> {
        self.templates.get(name)
    }

    pub fn list_templates(&self) -> Vec<String> {
        self.templates.keys().cloned().collect()
    }
}

impl Default for TemplateManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct ReportTemplate {
    pub name: String,
    pub description: String,
    pub include_technical_details: bool,
    pub include_executive_summary: bool,
    pub include_charts: bool,
    pub include_remediation: bool,
    pub include_compliance_mapping: bool,
    pub include_owasp_mapping: bool,
    pub max_vulnerabilities: Option<usize>,
}
