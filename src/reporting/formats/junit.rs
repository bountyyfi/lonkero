// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::reporting::types::{
    EnhancedReport, JunitFailure, JunitTestCase, JunitTestSuite, JunitTestSuites,
};
use anyhow::Result;

pub struct JunitReportGenerator;

impl JunitReportGenerator {
    pub fn new() -> Self {
        Self
    }

    pub async fn generate(&self, report: &EnhancedReport) -> Result<Vec<u8>> {
        let junit_report = self.create_junit_report(report);
        let xml = self.serialize_to_xml(&junit_report)?;
        Ok(xml.into_bytes())
    }

    fn create_junit_report(&self, report: &EnhancedReport) -> JunitTestSuites {
        let total_vulns = report.scan_results.vulnerabilities.len();

        let test_suite = JunitTestSuite {
            name: format!("Security Scan: {}", report.scan_results.target),
            tests: total_vulns,
            failures: total_vulns,
            time: report.scan_results.duration_seconds,
            testcases: report
                .scan_results
                .vulnerabilities
                .iter()
                .map(|vuln| self.create_test_case(vuln))
                .collect(),
        };

        JunitTestSuites {
            name: "Security Assessment".to_string(),
            tests: total_vulns,
            failures: total_vulns,
            time: report.scan_results.duration_seconds,
            testsuites: vec![test_suite],
        }
    }

    fn create_test_case(&self, vuln: &crate::types::Vulnerability) -> JunitTestCase {
        JunitTestCase {
            name: vuln.vuln_type.clone(),
            classname: vuln.category.clone(),
            time: 0.0,
            failure: Some(JunitFailure {
                message: format!("[{}] {}", vuln.severity, vuln.description),
                failure_type: vuln.cwe.clone(),
                text: format!(
                    "URL: {}\nParameter: {}\nCVSS: {}\nRemediation: {}",
                    vuln.url,
                    vuln.parameter.clone().unwrap_or_default(),
                    vuln.cvss,
                    vuln.remediation
                ),
            }),
        }
    }

    fn serialize_to_xml(&self, report: &JunitTestSuites) -> Result<String> {
        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str(&format!(
            "<testsuites name=\"{}\" tests=\"{}\" failures=\"{}\" time=\"{:.2}\">\n",
            self.escape_xml(&report.name),
            report.tests,
            report.failures,
            report.time
        ));

        for suite in &report.testsuites {
            xml.push_str(&format!(
                "  <testsuite name=\"{}\" tests=\"{}\" failures=\"{}\" time=\"{:.2}\">\n",
                self.escape_xml(&suite.name),
                suite.tests,
                suite.failures,
                suite.time
            ));

            for testcase in &suite.testcases {
                xml.push_str(&format!(
                    "    <testcase name=\"{}\" classname=\"{}\" time=\"{:.2}\">\n",
                    self.escape_xml(&testcase.name),
                    self.escape_xml(&testcase.classname),
                    testcase.time
                ));

                if let Some(failure) = &testcase.failure {
                    xml.push_str(&format!(
                        "      <failure message=\"{}\" type=\"{}\">{}</failure>\n",
                        self.escape_xml(&failure.message),
                        self.escape_xml(&failure.failure_type),
                        self.escape_xml(&failure.text)
                    ));
                }

                xml.push_str("    </testcase>\n");
            }

            xml.push_str("  </testsuite>\n");
        }

        xml.push_str("</testsuites>\n");
        Ok(xml)
    }

    fn escape_xml(&self, text: &str) -> String {
        text.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }
}

impl Default for JunitReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}
