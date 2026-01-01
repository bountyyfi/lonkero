// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Merlin - Advanced JavaScript Library Vulnerability Scanner
//! Detects vulnerable third-party JavaScript libraries and frameworks

use crate::types::ScanConfig;
use crate::http_client::HttpClient;
use crate::types::{Confidence, Severity, Vulnerability};
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Merlin Scanner - Detects vulnerable JavaScript libraries
pub struct MerlinScanner {
    http_client: Arc<HttpClient>,
    vuln_db: VulnerabilityDatabase,
}

/// Version range for vulnerability matching
#[derive(Debug, Clone)]
pub struct VersionRange {
    pub from_version: Option<String>,
    pub to_version: String,
    pub cves: Vec<String>,
    pub references: Vec<String>,
    pub severity: Severity,
    pub description: String,
}

/// Library vulnerability database entry
#[derive(Debug, Clone)]
pub struct LibraryVulnerability {
    pub library: String,
    pub vulnerabilities: Vec<VersionRange>,
}

/// In-memory vulnerability database
pub struct VulnerabilityDatabase {
    libraries: HashMap<String, Vec<VersionRange>>,
}

impl VulnerabilityDatabase {
    pub fn new() -> Self {
        let mut db = Self {
            libraries: HashMap::new(),
        };
        db.populate();
        db
    }

    fn populate(&mut self) {
        // jQuery vulnerabilities
        self.add_library("jquery", vec![
            VersionRange {
                from_version: None,
                to_version: "1.6.3".to_string(),
                cves: vec!["CVE-2011-4969".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2011-4969".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in jQuery before 1.6.3".to_string(),
            },
            VersionRange {
                from_version: None,
                to_version: "1.9.0".to_string(),
                cves: vec!["CVE-2012-6708".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2012-6708".to_string()],
                severity: Severity::Medium,
                description: "Selector-interpreted XSS vulnerability".to_string(),
            },
            VersionRange {
                from_version: Some("1.4.0".to_string()),
                to_version: "3.0.0".to_string(),
                cves: vec!["CVE-2015-9251".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2015-9251".to_string()],
                severity: Severity::Medium,
                description: "Cross-site scripting vulnerability in jQuery".to_string(),
            },
            VersionRange {
                from_version: Some("1.1.4".to_string()),
                to_version: "3.4.0".to_string(),
                cves: vec!["CVE-2019-11358".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2019-11358".to_string()],
                severity: Severity::Medium,
                description: "Prototype pollution via object extend function".to_string(),
            },
            VersionRange {
                from_version: Some("1.0.3".to_string()),
                to_version: "3.5.0".to_string(),
                cves: vec!["CVE-2020-11022".to_string(), "CVE-2020-11023".to_string()],
                references: vec!["https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/".to_string()],
                severity: Severity::Medium,
                description: "XSS when passing HTML to DOM manipulation methods".to_string(),
            },
        ]);

        // jQuery UI vulnerabilities
        self.add_library("jquery-ui", vec![
            VersionRange {
                from_version: Some("1.7.0".to_string()),
                to_version: "1.10.0".to_string(),
                cves: vec!["CVE-2010-5312".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2010-5312".to_string()],
                severity: Severity::Medium,
                description: "XSS in dialog closeText".to_string(),
            },
            VersionRange {
                from_version: None,
                to_version: "1.12.0".to_string(),
                cves: vec!["CVE-2016-7103".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2016-7103".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in dialog function".to_string(),
            },
            VersionRange {
                from_version: None,
                to_version: "1.13.0".to_string(),
                cves: vec!["CVE-2021-41182".to_string(), "CVE-2021-41183".to_string(), "CVE-2021-41184".to_string()],
                references: vec!["https://github.com/jquery/jquery-ui/security/advisories/GHSA-9gj3-hwp5-pmwc".to_string()],
                severity: Severity::Medium,
                description: "Multiple XSS vulnerabilities in jQuery UI".to_string(),
            },
            VersionRange {
                from_version: None,
                to_version: "1.13.2".to_string(),
                cves: vec!["CVE-2022-31160".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2022-31160".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in checkboxradio widget".to_string(),
            },
        ]);

        // AngularJS vulnerabilities
        self.add_library("angularjs", vec![
            VersionRange {
                from_version: None,
                to_version: "1.5.0-beta.1".to_string(),
                cves: vec!["CVE-2020-7676".to_string()],
                references: vec!["https://github.com/advisories/GHSA-r5fx-8r73-v86c".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in AngularJS".to_string(),
            },
            VersionRange {
                from_version: None,
                to_version: "1.6.0".to_string(),
                cves: vec![],
                references: vec!["https://github.com/advisories/GHSA-28hp-fgcr-2r4h".to_string()],
                severity: Severity::High,
                description: "Sandbox escape in AngularJS".to_string(),
            },
            VersionRange {
                from_version: Some("1.5.0".to_string()),
                to_version: "1.6.9".to_string(),
                cves: vec![],
                references: vec!["https://vulnerabledoma.in/ngSanitize1.6.8_bypass.html".to_string()],
                severity: Severity::High,
                description: "ngSanitize bypass vulnerability".to_string(),
            },
            VersionRange {
                from_version: None,
                to_version: "1.8.0".to_string(),
                cves: vec!["CVE-2020-7676".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-7676".to_string()],
                severity: Severity::Medium,
                description: "Prototype pollution vulnerability".to_string(),
            },
            VersionRange {
                from_version: Some("1.3.0".to_string()),
                to_version: "1.8.4".to_string(),
                cves: vec!["CVE-2024-21490".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-21490".to_string()],
                severity: Severity::High,
                description: "ReDoS vulnerability in ng-srcset".to_string(),
            },
            VersionRange {
                from_version: Some("0".to_string()),
                to_version: "1.8.4".to_string(),
                cves: vec!["CVE-2024-8373".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-8373".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in AngularJS".to_string(),
            },
        ]);

        // Angular (modern) vulnerabilities
        self.add_library("angular", vec![
            VersionRange {
                from_version: Some("0".to_string()),
                to_version: "10.2.5".to_string(),
                cves: vec!["CVE-2021-4231".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-4231".to_string()],
                severity: Severity::Medium,
                description: "XSS via bypassSecurityTrust methods".to_string(),
            },
            VersionRange {
                from_version: Some("11.0.0".to_string()),
                to_version: "11.0.5".to_string(),
                cves: vec!["CVE-2021-4231".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-4231".to_string()],
                severity: Severity::Medium,
                description: "XSS via bypassSecurityTrust methods".to_string(),
            },
        ]);

        // Bootstrap vulnerabilities
        self.add_library("bootstrap", vec![
            VersionRange {
                from_version: None,
                to_version: "3.4.0".to_string(),
                cves: vec!["CVE-2018-20676".to_string(), "CVE-2018-20677".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2018-20676".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in Bootstrap tooltip/popover".to_string(),
            },
            VersionRange {
                from_version: Some("1.4.0".to_string()),
                to_version: "3.4.1".to_string(),
                cves: vec!["CVE-2024-6485".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-6485".to_string()],
                severity: Severity::Medium,
                description: "XSS in carousel component".to_string(),
            },
            VersionRange {
                from_version: Some("4.0.0".to_string()),
                to_version: "4.3.1".to_string(),
                cves: vec!["CVE-2019-8331".to_string()],
                references: vec!["https://github.com/twbs/bootstrap/issues/28236".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in Bootstrap".to_string(),
            },
        ]);

        // Lodash vulnerabilities
        self.add_library("lodash", vec![
            VersionRange {
                from_version: None,
                to_version: "4.17.5".to_string(),
                cves: vec!["CVE-2018-3721".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2018-3721".to_string()],
                severity: Severity::Medium,
                description: "Prototype pollution in lodash".to_string(),
            },
            VersionRange {
                from_version: None,
                to_version: "4.17.11".to_string(),
                cves: vec!["CVE-2018-16487".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2018-16487".to_string()],
                severity: Severity::High,
                description: "Prototype pollution via merge/mergeWith/defaultsDeep".to_string(),
            },
            VersionRange {
                from_version: None,
                to_version: "4.17.12".to_string(),
                cves: vec!["CVE-2019-10744".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2019-10744".to_string()],
                severity: Severity::Critical,
                description: "Prototype pollution in defaultsDeep".to_string(),
            },
            VersionRange {
                from_version: Some("3.7.0".to_string()),
                to_version: "4.17.19".to_string(),
                cves: vec!["CVE-2020-8203".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-8203".to_string()],
                severity: Severity::High,
                description: "Prototype pollution via zipObjectDeep".to_string(),
            },
            VersionRange {
                from_version: None,
                to_version: "4.17.21".to_string(),
                cves: vec!["CVE-2021-23337".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-23337".to_string()],
                severity: Severity::High,
                description: "Command injection via template function".to_string(),
            },
            VersionRange {
                from_version: Some("4.0.0".to_string()),
                to_version: "4.17.21".to_string(),
                cves: vec!["CVE-2020-28500".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-28500".to_string()],
                severity: Severity::Medium,
                description: "ReDoS in toNumber, trim functions".to_string(),
            },
        ]);

        // Moment.js vulnerabilities
        self.add_library("moment", vec![
            VersionRange {
                from_version: None,
                to_version: "2.11.2".to_string(),
                cves: vec![],
                references: vec!["https://github.com/moment/moment/issues/2936".to_string()],
                severity: Severity::Low,
                description: "ReDoS vulnerability in moment".to_string(),
            },
            VersionRange {
                from_version: None,
                to_version: "2.19.3".to_string(),
                cves: vec!["CVE-2017-18214".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2017-18214".to_string()],
                severity: Severity::High,
                description: "ReDoS via crafted date string".to_string(),
            },
            VersionRange {
                from_version: None,
                to_version: "2.29.2".to_string(),
                cves: vec!["CVE-2022-24785".to_string()],
                references: vec!["https://github.com/moment/moment/security/advisories/GHSA-8hfj-j24r-96c4".to_string()],
                severity: Severity::High,
                description: "Path traversal vulnerability".to_string(),
            },
            VersionRange {
                from_version: Some("2.18.0".to_string()),
                to_version: "2.29.4".to_string(),
                cves: vec!["CVE-2022-31129".to_string()],
                references: vec!["https://github.com/moment/moment/security/advisories/GHSA-wc69-rhjr-hc9g".to_string()],
                severity: Severity::High,
                description: "ReDoS via RFC 2822 date parsing".to_string(),
            },
        ]);

        // Axios vulnerabilities
        self.add_library("axios", vec![
            VersionRange {
                from_version: None,
                to_version: "0.18.1".to_string(),
                cves: vec!["CVE-2019-10742".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2019-10742".to_string()],
                severity: Severity::High,
                description: "Server-side request forgery".to_string(),
            },
            VersionRange {
                from_version: None,
                to_version: "0.21.1".to_string(),
                cves: vec!["CVE-2020-28168".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-28168".to_string()],
                severity: Severity::Medium,
                description: "SSRF via follow redirect".to_string(),
            },
            VersionRange {
                from_version: None,
                to_version: "0.21.2".to_string(),
                cves: vec!["CVE-2021-3749".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-3749".to_string()],
                severity: Severity::High,
                description: "ReDoS vulnerability".to_string(),
            },
            VersionRange {
                from_version: Some("0.8.1".to_string()),
                to_version: "1.6.0".to_string(),
                cves: vec!["CVE-2023-45857".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2023-45857".to_string()],
                severity: Severity::Medium,
                description: "XSRF token exposure via CORS".to_string(),
            },
            VersionRange {
                from_version: Some("1.3.2".to_string()),
                to_version: "1.7.4".to_string(),
                cves: vec!["CVE-2024-39338".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-39338".to_string()],
                severity: Severity::High,
                description: "SSRF vulnerability".to_string(),
            },
            VersionRange {
                from_version: None,
                to_version: "1.6.8".to_string(),
                cves: vec!["CVE-2025-27152".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2025-27152".to_string(), "https://github.com/axios/axios/pull/6300".to_string()],
                severity: Severity::Medium,
                description: "SSRF and credential leakage via absolute URL - depends on follow-redirects before 1.15.6".to_string(),
            },
        ]);

        // Vue.js vulnerabilities
        self.add_library("vue", vec![
            VersionRange {
                from_version: None,
                to_version: "2.5.17".to_string(),
                cves: vec![],
                references: vec!["https://github.com/vuejs/vue/releases/tag/v2.5.17".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in Vue".to_string(),
            },
            VersionRange {
                from_version: Some("2.0.0".to_string()),
                to_version: "2.7.17".to_string(),
                cves: vec!["CVE-2024-9506".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-9506".to_string()],
                severity: Severity::Medium,
                description: "ReDoS vulnerability exploitable through inefficient regex evaluation in parseHTML function".to_string(),
            },
        ]);

        // React vulnerabilities
        self.add_library("react", vec![
            VersionRange {
                from_version: Some("0.0.1".to_string()),
                to_version: "0.14.0".to_string(),
                cves: vec![],
                references: vec!["https://facebook.github.io/react/blog/2015/10/07/react-v0.14.html".to_string()],
                severity: Severity::High,
                description: "XSS via spoofed React element".to_string(),
            },
            VersionRange {
                from_version: Some("16.0.0".to_string()),
                to_version: "16.4.2".to_string(),
                cves: vec!["CVE-2018-6341".to_string()],
                references: vec!["https://reactjs.org/blog/2018/08/01/react-v-16-4-2.html".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in server-side rendering".to_string(),
            },
        ]);

        // Handlebars vulnerabilities
        self.add_library("handlebars", vec![
            VersionRange {
                from_version: None,
                to_version: "4.0.14".to_string(),
                cves: vec!["CVE-2019-19919".to_string()],
                references: vec!["https://snyk.io/vuln/SNYK-JS-HANDLEBARS-174183".to_string()],
                severity: Severity::Critical,
                description: "Prototype pollution via lookup helper".to_string(),
            },
            VersionRange {
                from_version: Some("4.0.0".to_string()),
                to_version: "4.5.3".to_string(),
                cves: vec!["CVE-2019-20920".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2019-20920".to_string()],
                severity: Severity::Critical,
                description: "Arbitrary code execution via lookup helper".to_string(),
            },
            VersionRange {
                from_version: None,
                to_version: "4.7.7".to_string(),
                cves: vec!["CVE-2021-23369".to_string(), "CVE-2021-23383".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-23369".to_string()],
                severity: Severity::Critical,
                description: "Remote code execution vulnerability".to_string(),
            },
        ]);

        // DOMPurify vulnerabilities
        self.add_library("dompurify", vec![
            VersionRange {
                from_version: Some("0".to_string()),
                to_version: "2.4.2".to_string(),
                cves: vec!["CVE-2024-48910".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-48910".to_string()],
                severity: Severity::High,
                description: "Mutation XSS vulnerability".to_string(),
            },
            VersionRange {
                from_version: Some("0".to_string()),
                to_version: "2.5.4".to_string(),
                cves: vec!["CVE-2024-45801".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-45801".to_string()],
                severity: Severity::High,
                description: "XSS bypass via nesting".to_string(),
            },
            VersionRange {
                from_version: Some("0".to_string()),
                to_version: "3.2.4".to_string(),
                cves: vec!["CVE-2025-26791".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2025-26791".to_string()],
                severity: Severity::High,
                description: "XSS bypass vulnerability".to_string(),
            },
        ]);

        // Next.js vulnerabilities
        self.add_library("next", vec![
            VersionRange {
                from_version: Some("11.1.4".to_string()),
                to_version: "14.2.25".to_string(),
                cves: vec!["CVE-2025-29927".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2025-29927".to_string()],
                severity: Severity::Critical,
                description: "Middleware authorization bypass".to_string(),
            },
            VersionRange {
                from_version: Some("9.5.5".to_string()),
                to_version: "14.2.15".to_string(),
                cves: vec!["CVE-2024-51479".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-51479".to_string()],
                severity: Severity::High,
                description: "Authorization bypass vulnerability".to_string(),
            },
            VersionRange {
                from_version: Some("13.5.1".to_string()),
                to_version: "14.2.10".to_string(),
                cves: vec!["CVE-2024-46982".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-46982".to_string()],
                severity: Severity::High,
                description: "Cache poisoning vulnerability".to_string(),
            },
        ]);

        // TinyMCE vulnerabilities
        self.add_library("tinymce", vec![
            VersionRange {
                from_version: None,
                to_version: "5.10.9".to_string(),
                cves: vec!["CVE-2023-48219".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2023-48219".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in TinyMCE".to_string(),
            },
            VersionRange {
                from_version: Some("0".to_string()),
                to_version: "6.8.4".to_string(),
                cves: vec!["CVE-2024-38356".to_string(), "CVE-2024-38357".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-38356".to_string()],
                severity: Severity::Medium,
                description: "Multiple XSS vulnerabilities".to_string(),
            },
        ]);

        // CKEditor vulnerabilities
        self.add_library("ckeditor4", vec![
            VersionRange {
                from_version: None,
                to_version: "4.21.0".to_string(),
                cves: vec!["CVE-2023-28439".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2023-28439".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in CKEditor 4".to_string(),
            },
            VersionRange {
                from_version: None,
                to_version: "4.18.0".to_string(),
                cves: vec!["CVE-2022-24728".to_string()],
                references: vec!["https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-f6rf-9m92-x2hh".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in HTML processor".to_string(),
            },
        ]);

        // CKEditor 5 vulnerabilities
        self.add_library("ckeditor5", vec![
            VersionRange {
                from_version: Some("40.0.0".to_string()),
                to_version: "43.1.1".to_string(),
                cves: vec!["CVE-2024-45613".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-45613".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in CKEditor 5".to_string(),
            },
        ]);

        // Underscore.js vulnerabilities
        self.add_library("underscore", vec![
            VersionRange {
                from_version: Some("1.3.2".to_string()),
                to_version: "1.12.1".to_string(),
                cves: vec!["CVE-2021-23358".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-23358".to_string()],
                severity: Severity::High,
                description: "Arbitrary code execution via template function".to_string(),
            },
        ]);

        // Ember.js vulnerabilities
        self.add_library("ember", vec![
            VersionRange {
                from_version: None,
                to_version: "3.24.7".to_string(),
                cves: vec![],
                references: vec!["https://blog.emberjs.com/ember-4-8-1-released/".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in Ember".to_string(),
            },
            VersionRange {
                from_version: Some("4.0.0".to_string()),
                to_version: "4.8.1".to_string(),
                cves: vec![],
                references: vec!["https://blog.emberjs.com/ember-4-8-1-released/".to_string()],
                severity: Severity::Medium,
                description: "Security vulnerability in Ember 4".to_string(),
            },
        ]);

        // PDF.js vulnerabilities
        self.add_library("pdfjs", vec![
            VersionRange {
                from_version: Some("0".to_string()),
                to_version: "4.2.67".to_string(),
                cves: vec!["CVE-2024-4367".to_string()],
                references: vec!["https://github.com/mozilla/pdf.js/security/advisories/GHSA-wgrm-67xf-hhpq".to_string()],
                severity: Severity::Critical,
                description: "Arbitrary JavaScript execution".to_string(),
            },
        ]);

        // Highcharts vulnerabilities
        self.add_library("highcharts", vec![
            VersionRange {
                from_version: None,
                to_version: "9.0.0".to_string(),
                cves: vec!["CVE-2021-29489".to_string()],
                references: vec!["https://security.snyk.io/vuln/SNYK-JS-HIGHCHARTS-1290057".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in Highcharts".to_string(),
            },
        ]);

        // Chart.js vulnerabilities
        self.add_library("chartjs", vec![
            VersionRange {
                from_version: None,
                to_version: "2.9.4".to_string(),
                cves: vec![],
                references: vec!["https://github.com/advisories/GHSA-h68q-55jf-x68w".to_string()],
                severity: Severity::Medium,
                description: "Prototype pollution in Chart.js".to_string(),
            },
        ]);

        // Dojo vulnerabilities
        self.add_library("dojo", vec![
            VersionRange {
                from_version: Some("1.10.0".to_string()),
                to_version: "1.17.0".to_string(),
                cves: vec!["CVE-2020-4051".to_string()],
                references: vec!["https://github.com/dojo/dojo/security/advisories/GHSA-jxfh-8wgv-vfr2".to_string()],
                severity: Severity::Critical,
                description: "Prototype pollution in Dojo".to_string(),
            },
        ]);

        // jsZip vulnerabilities
        self.add_library("jszip", vec![
            VersionRange {
                from_version: None,
                to_version: "3.8.0".to_string(),
                cves: vec!["CVE-2021-23413".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-23413".to_string()],
                severity: Severity::Medium,
                description: "ReDoS vulnerability in jsZip".to_string(),
            },
        ]);

        // Knockout vulnerabilities
        self.add_library("knockout", vec![
            VersionRange {
                from_version: None,
                to_version: "3.5.0".to_string(),
                cves: vec![],
                references: vec!["https://github.com/knockout/knockout/issues/1244".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in Knockout".to_string(),
            },
        ]);

        // ua-parser-js vulnerabilities
        self.add_library("ua-parser-js", vec![
            VersionRange {
                from_version: Some("0".to_string()),
                to_version: "0.7.33".to_string(),
                cves: vec!["CVE-2022-25927".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2022-25927".to_string()],
                severity: Severity::High,
                description: "ReDoS vulnerability".to_string(),
            },
            VersionRange {
                from_version: Some("0.7.29".to_string()),
                to_version: "0.7.30".to_string(),
                cves: vec![],
                references: vec!["https://github.com/faisalman/ua-parser-js/issues/536".to_string()],
                severity: Severity::Critical,
                description: "Supply chain attack - malicious code".to_string(),
            },
        ]);

        // Svelte vulnerabilities
        self.add_library("svelte", vec![
            VersionRange {
                from_version: None,
                to_version: "4.2.19".to_string(),
                cves: vec!["CVE-2024-45047".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-45047".to_string()],
                severity: Severity::High,
                description: "XSS vulnerability in Svelte".to_string(),
            },
        ]);

        // Select2 vulnerabilities
        self.add_library("select2", vec![
            VersionRange {
                from_version: Some("0".to_string()),
                to_version: "4.0.6".to_string(),
                cves: vec!["CVE-2016-10744".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2016-10744".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in Select2".to_string(),
            },
        ]);

        // Mustache vulnerabilities
        self.add_library("mustache", vec![
            VersionRange {
                from_version: None,
                to_version: "2.2.1".to_string(),
                cves: vec![],
                references: vec!["https://github.com/janl/mustache.js/pull/530".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in Mustache".to_string(),
            },
        ]);

        // EasyXDM vulnerabilities
        self.add_library("easyxdm", vec![
            VersionRange {
                from_version: None,
                to_version: "2.5.0".to_string(),
                cves: vec!["CVE-2013-5212".to_string(), "CVE-2014-1403".to_string()],
                references: vec!["https://github.com/oyvindkinsey/easyXDM/releases/tag/2.5.0".to_string()],
                severity: Severity::High,
                description: "XSS vulnerability in EasyXDM".to_string(),
            },
        ]);

        // Prototype.js vulnerabilities
        self.add_library("prototype", vec![
            VersionRange {
                from_version: None,
                to_version: "1.6.0.2".to_string(),
                cves: vec!["CVE-2008-7220".to_string()],
                references: vec!["https://cvedetails.com/cve/CVE-2008-7220/".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in Prototype".to_string(),
            },
        ]);

        // YUI vulnerabilities
        self.add_library("yui", vec![
            VersionRange {
                from_version: Some("3.0.0".to_string()),
                to_version: "3.10.3".to_string(),
                cves: vec!["CVE-2013-4939".to_string()],
                references: vec!["https://cvedetails.com/cve/CVE-2013-4939/".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in YUI".to_string(),
            },
        ]);

        // Froala Editor vulnerabilities
        self.add_library("froala", vec![
            VersionRange {
                from_version: Some("0".to_string()),
                to_version: "4.3.1".to_string(),
                cves: vec!["CVE-2024-51434".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-51434".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in Froala Editor".to_string(),
            },
        ]);

        // DataTables vulnerabilities
        self.add_library("datatables", vec![
            VersionRange {
                from_version: None,
                to_version: "1.11.3".to_string(),
                cves: vec!["CVE-2020-28458".to_string()],
                references: vec!["https://github.com/advisories/GHSA-h73q-5wmj-q8pj".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in DataTables".to_string(),
            },
        ]);

        // Plupload vulnerabilities
        self.add_library("plupload", vec![
            VersionRange {
                from_version: None,
                to_version: "2.3.9".to_string(),
                cves: vec!["CVE-2021-23562".to_string()],
                references: vec!["https://github.com/moxiecode/plupload/releases/tag/v2.3.9".to_string()],
                severity: Severity::Medium,
                description: "Security vulnerability in Plupload".to_string(),
            },
        ]);

        // jQuery Validation vulnerabilities
        self.add_library("jquery-validation", vec![
            VersionRange {
                from_version: Some("0".to_string()),
                to_version: "1.20.0".to_string(),
                cves: vec!["CVE-2025-3573".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2025-3573".to_string()],
                severity: Severity::Medium,
                description: "ReDoS vulnerability in jQuery Validation".to_string(),
            },
        ]);

        // jQuery Mobile vulnerabilities
        self.add_library("jquery-mobile", vec![
            VersionRange {
                from_version: None,
                to_version: "1.5.0".to_string(),
                cves: vec![],
                references: vec!["https://github.com/jquery/jquery-mobile/issues/8640".to_string()],
                severity: Severity::High,
                description: "XSS vulnerability in jQuery Mobile (unpatched)".to_string(),
            },
        ]);

        // Markdown-it vulnerabilities
        self.add_library("markdown-it", vec![
            VersionRange {
                from_version: None,
                to_version: "12.3.2".to_string(),
                cves: vec!["CVE-2022-21670".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2022-21670".to_string()],
                severity: Severity::Medium,
                description: "ReDoS vulnerability in markdown-it".to_string(),
            },
        ]);

        // MathJax vulnerabilities
        self.add_library("mathjax", vec![
            VersionRange {
                from_version: Some("0".to_string()),
                to_version: "2.7.10".to_string(),
                cves: vec!["CVE-2023-39663".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2023-39663".to_string()],
                severity: Severity::High,
                description: "XSS vulnerability in MathJax".to_string(),
            },
        ]);

        // TableExport vulnerabilities
        self.add_library("tableexport", vec![
            VersionRange {
                from_version: None,
                to_version: "1.25.0".to_string(),
                cves: vec![],
                references: vec!["https://github.com/hhurz/tableexport.jquery.plugin/commit/dcbaee23cf98328397a153e71556f75202988ec9".to_string()],
                severity: Severity::Medium,
                description: "Security vulnerability in TableExport".to_string(),
            },
        ]);

        // jPlayer vulnerabilities
        self.add_library("jplayer", vec![
            VersionRange {
                from_version: None,
                to_version: "2.3.1".to_string(),
                cves: vec!["CVE-2013-2022".to_string(), "CVE-2013-2023".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2013-2022".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerabilities in jPlayer".to_string(),
            },
        ]);

        // Flowplayer vulnerabilities
        self.add_library("flowplayer", vec![
            VersionRange {
                from_version: None,
                to_version: "5.4.3".to_string(),
                cves: vec![],
                references: vec!["https://github.com/flowplayer/flowplayer/issues/381".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in Flowplayer".to_string(),
            },
        ]);

        // Backbone.js vulnerabilities
        self.add_library("backbone", vec![
            VersionRange {
                from_version: None,
                to_version: "0.5.0".to_string(),
                cves: vec![],
                references: vec!["http://backbonejs.org/#changelog".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in Backbone.js".to_string(),
            },
        ]);

        // jQuery prettyPhoto vulnerabilities
        self.add_library("prettyphoto", vec![
            VersionRange {
                from_version: None,
                to_version: "3.1.6".to_string(),
                cves: vec!["CVE-2013-6837".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2013-6837".to_string()],
                severity: Severity::Medium,
                description: "DOM XSS vulnerability in prettyPhoto".to_string(),
            },
        ]);

        // Ext JS vulnerabilities
        self.add_library("extjs", vec![
            VersionRange {
                from_version: Some("4.0.0".to_string()),
                to_version: "6.6.0".to_string(),
                cves: vec!["CVE-2018-8046".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2018-8046".to_string()],
                severity: Severity::High,
                description: "XSS vulnerability in Ext JS".to_string(),
            },
        ]);

        // jQuery Terminal vulnerabilities
        self.add_library("jquery.terminal", vec![
            VersionRange {
                from_version: None,
                to_version: "2.31.1".to_string(),
                cves: vec!["CVE-2021-43862".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-43862".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in jQuery Terminal".to_string(),
            },
        ]);

        // Bootstrap Select vulnerabilities
        self.add_library("bootstrap-select", vec![
            VersionRange {
                from_version: None,
                to_version: "1.13.6".to_string(),
                cves: vec![],
                references: vec!["https://github.com/snapappointments/bootstrap-select/issues/2199".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in Bootstrap Select".to_string(),
            },
        ]);

        // Blueimp File Upload vulnerabilities
        self.add_library("blueimp-file-upload", vec![
            VersionRange {
                from_version: None,
                to_version: "9.22.1".to_string(),
                cves: vec!["CVE-2018-9206".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2018-9206".to_string()],
                severity: Severity::Critical,
                description: "Arbitrary file upload vulnerability".to_string(),
            },
        ]);

        // Showdown (Markdown) vulnerabilities
        self.add_library("showdown", vec![
            VersionRange {
                from_version: None,
                to_version: "1.9.1".to_string(),
                cves: vec!["CVE-2020-26289".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-26289".to_string()],
                severity: Severity::High,
                description: "ReDoS vulnerability in Showdown".to_string(),
            },
            VersionRange {
                from_version: None,
                to_version: "2.1.0".to_string(),
                cves: vec!["CVE-2022-24788".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2022-24788".to_string()],
                severity: Severity::High,
                description: "XSS vulnerability via crafted input".to_string(),
            },
        ]);

        // Marked.js vulnerabilities
        self.add_library("marked", vec![
            VersionRange {
                from_version: None,
                to_version: "0.3.6".to_string(),
                cves: vec!["CVE-2017-17461".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2017-17461".to_string()],
                severity: Severity::High,
                description: "ReDoS vulnerability in marked".to_string(),
            },
            VersionRange {
                from_version: None,
                to_version: "0.3.9".to_string(),
                cves: vec!["CVE-2017-1000427".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2017-1000427".to_string()],
                severity: Severity::High,
                description: "XSS vulnerability in marked".to_string(),
            },
            VersionRange {
                from_version: None,
                to_version: "4.0.10".to_string(),
                cves: vec!["CVE-2022-21680".to_string(), "CVE-2022-21681".to_string()],
                references: vec!["https://github.com/advisories/GHSA-5v2h-r2cx-5xgj".to_string()],
                severity: Severity::High,
                description: "ReDoS vulnerability via crafted markdown".to_string(),
            },
        ]);

        // Video.js vulnerabilities
        self.add_library("video.js", vec![
            VersionRange {
                from_version: None,
                to_version: "7.14.3".to_string(),
                cves: vec!["CVE-2021-23414".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-23414".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in Video.js".to_string(),
            },
        ]);

        // serialize-javascript vulnerabilities
        self.add_library("serialize-javascript", vec![
            VersionRange {
                from_version: None,
                to_version: "2.1.1".to_string(),
                cves: vec!["CVE-2019-16769".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2019-16769".to_string()],
                severity: Severity::Critical,
                description: "Arbitrary code execution vulnerability".to_string(),
            },
            VersionRange {
                from_version: None,
                to_version: "3.1.0".to_string(),
                cves: vec!["CVE-2020-7660".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-7660".to_string()],
                severity: Severity::Critical,
                description: "Remote code execution via crafted input".to_string(),
            },
        ]);

        // js-yaml vulnerabilities
        self.add_library("js-yaml", vec![
            VersionRange {
                from_version: None,
                to_version: "3.13.0".to_string(),
                cves: vec!["CVE-2019-1010266".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2019-1010266".to_string()],
                severity: Severity::High,
                description: "Code injection via untrusted YAML".to_string(),
            },
            VersionRange {
                from_version: None,
                to_version: "3.13.1".to_string(),
                cves: vec!["CVE-2021-23449".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-23449".to_string()],
                severity: Severity::Critical,
                description: "Arbitrary code execution via load()".to_string(),
            },
        ]);

        // node-forge vulnerabilities
        self.add_library("node-forge", vec![
            VersionRange {
                from_version: None,
                to_version: "1.0.0".to_string(),
                cves: vec!["CVE-2020-7720".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-7720".to_string()],
                severity: Severity::High,
                description: "Prototype pollution vulnerability".to_string(),
            },
            VersionRange {
                from_version: None,
                to_version: "1.3.0".to_string(),
                cves: vec!["CVE-2022-24771".to_string(), "CVE-2022-24772".to_string(), "CVE-2022-24773".to_string()],
                references: vec!["https://github.com/digitalbazaar/forge/security/advisories/GHSA-cfm4-qjh2-4765".to_string()],
                severity: Severity::High,
                description: "RSA signature forgery vulnerabilities".to_string(),
            },
        ]);

        // fast-xml-parser vulnerabilities
        self.add_library("fast-xml-parser", vec![
            VersionRange {
                from_version: None,
                to_version: "4.2.4".to_string(),
                cves: vec!["CVE-2023-26920".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2023-26920".to_string()],
                severity: Severity::High,
                description: "Prototype pollution vulnerability".to_string(),
            },
        ]);

        // SweetAlert vulnerabilities
        self.add_library("sweetalert", vec![
            VersionRange {
                from_version: None,
                to_version: "1.1.3".to_string(),
                cves: vec![],
                references: vec!["https://github.com/t4t5/sweetalert/issues/667".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in SweetAlert".to_string(),
            },
        ]);

        // SweetAlert2 vulnerabilities
        self.add_library("sweetalert2", vec![
            VersionRange {
                from_version: None,
                to_version: "9.10.13".to_string(),
                cves: vec!["CVE-2020-15270".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-15270".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in SweetAlert2".to_string(),
            },
        ]);

        // Summernote vulnerabilities
        self.add_library("summernote", vec![
            VersionRange {
                from_version: None,
                to_version: "0.8.18".to_string(),
                cves: vec!["CVE-2020-10671".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-10671".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in Summernote".to_string(),
            },
            VersionRange {
                from_version: None,
                to_version: "0.8.20".to_string(),
                cves: vec!["CVE-2023-42805".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2023-42805".to_string()],
                severity: Severity::Medium,
                description: "XSS via code view textarea".to_string(),
            },
        ]);

        // CodeMirror vulnerabilities
        self.add_library("codemirror", vec![
            VersionRange {
                from_version: None,
                to_version: "5.58.2".to_string(),
                cves: vec!["CVE-2020-7774".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-7774".to_string()],
                severity: Severity::Medium,
                description: "Prototype pollution in CodeMirror".to_string(),
            },
        ]);

        // D3.js vulnerabilities
        self.add_library("d3", vec![
            VersionRange {
                from_version: None,
                to_version: "5.16.0".to_string(),
                cves: vec![],
                references: vec!["https://github.com/d3/d3/issues/3199".to_string()],
                severity: Severity::Medium,
                description: "Potential XSS via unsanitized SVG".to_string(),
            },
        ]);

        // Socket.io-client vulnerabilities
        self.add_library("socket.io-client", vec![
            VersionRange {
                from_version: None,
                to_version: "2.4.0".to_string(),
                cves: vec!["CVE-2020-28481".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-28481".to_string()],
                severity: Severity::Medium,
                description: "Unauthorized namespace access".to_string(),
            },
        ]);

        // Socket.io vulnerabilities
        self.add_library("socket.io", vec![
            VersionRange {
                from_version: None,
                to_version: "2.4.0".to_string(),
                cves: vec!["CVE-2020-28481".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-28481".to_string()],
                severity: Severity::Medium,
                description: "Unauthorized namespace access".to_string(),
            },
        ]);

        // Dropzone vulnerabilities
        self.add_library("dropzone", vec![
            VersionRange {
                from_version: None,
                to_version: "5.5.0".to_string(),
                cves: vec![],
                references: vec!["https://github.com/dropzone/dropzone/blob/main/CHANGELOG.md".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in Dropzone".to_string(),
            },
        ]);

        // Quill vulnerabilities
        self.add_library("quill", vec![
            VersionRange {
                from_version: None,
                to_version: "1.3.7".to_string(),
                cves: vec!["CVE-2021-32819".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-32819".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in Quill".to_string(),
            },
            VersionRange {
                from_version: None,
                to_version: "2.0.0-dev.4".to_string(),
                cves: vec!["CVE-2023-37466".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2023-37466".to_string()],
                severity: Severity::Medium,
                description: "XSS via video handler".to_string(),
            },
        ]);

        // Prism.js vulnerabilities
        self.add_library("prismjs", vec![
            VersionRange {
                from_version: None,
                to_version: "1.25.0".to_string(),
                cves: vec!["CVE-2021-3801".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-3801".to_string()],
                severity: Severity::High,
                description: "ReDoS vulnerability in Prism".to_string(),
            },
            VersionRange {
                from_version: None,
                to_version: "1.27.0".to_string(),
                cves: vec!["CVE-2022-23647".to_string()],
                references: vec!["https://github.com/PrismJS/prism/security/advisories/GHSA-3949-f494-cm99".to_string()],
                severity: Severity::High,
                description: "XSS vulnerability in command-line plugin".to_string(),
            },
        ]);

        // highlight.js vulnerabilities
        self.add_library("highlight.js", vec![
            VersionRange {
                from_version: None,
                to_version: "9.18.2".to_string(),
                cves: vec!["CVE-2020-26237".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-26237".to_string()],
                severity: Severity::Medium,
                description: "Prototype pollution vulnerability".to_string(),
            },
            VersionRange {
                from_version: Some("10.0.0".to_string()),
                to_version: "10.4.1".to_string(),
                cves: vec!["CVE-2020-26237".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-26237".to_string()],
                severity: Severity::Medium,
                description: "Prototype pollution vulnerability".to_string(),
            },
        ]);

        // sanitize-html vulnerabilities
        self.add_library("sanitize-html", vec![
            VersionRange {
                from_version: None,
                to_version: "2.3.2".to_string(),
                cves: vec!["CVE-2021-26539".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-26539".to_string()],
                severity: Severity::Medium,
                description: "XSS bypass vulnerability".to_string(),
            },
            VersionRange {
                from_version: None,
                to_version: "2.7.1".to_string(),
                cves: vec!["CVE-2022-25887".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2022-25887".to_string()],
                severity: Severity::Medium,
                description: "XSS via crafted HTML".to_string(),
            },
        ]);

        // Ajv (JSON Schema) vulnerabilities
        self.add_library("ajv", vec![
            VersionRange {
                from_version: None,
                to_version: "6.12.3".to_string(),
                cves: vec!["CVE-2020-15366".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-15366".to_string()],
                severity: Severity::Medium,
                description: "Prototype pollution vulnerability".to_string(),
            },
        ]);

        // Modernizr vulnerabilities
        self.add_library("modernizr", vec![
            VersionRange {
                from_version: None,
                to_version: "3.11.0".to_string(),
                cves: vec!["CVE-2022-24725".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2022-24725".to_string()],
                severity: Severity::Medium,
                description: "ReDoS vulnerability in Modernizr".to_string(),
            },
        ]);

        // Leaflet vulnerabilities
        self.add_library("leaflet", vec![
            VersionRange {
                from_version: None,
                to_version: "1.4.0".to_string(),
                cves: vec![],
                references: vec!["https://github.com/Leaflet/Leaflet/releases/tag/v1.4.0".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in Leaflet".to_string(),
            },
        ]);

        // three.js vulnerabilities
        self.add_library("three", vec![
            VersionRange {
                from_version: None,
                to_version: "r125".to_string(),
                cves: vec![],
                references: vec!["https://github.com/mrdoob/three.js/releases".to_string()],
                severity: Severity::Low,
                description: "Potential security issues in older versions".to_string(),
            },
        ]);

        // GSAP vulnerabilities
        self.add_library("gsap", vec![
            VersionRange {
                from_version: None,
                to_version: "3.6.0".to_string(),
                cves: vec![],
                references: vec!["https://greensock.com/gsap/".to_string()],
                severity: Severity::Low,
                description: "Potential prototype pollution in older versions".to_string(),
            },
        ]);

        // Owl Carousel vulnerabilities
        self.add_library("owl.carousel", vec![
            VersionRange {
                from_version: None,
                to_version: "2.3.4".to_string(),
                cves: vec![],
                references: vec!["https://github.com/OwlCarousel2/OwlCarousel2/issues/2307".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in Owl Carousel".to_string(),
            },
        ]);

        // Slick Carousel vulnerabilities
        self.add_library("slick", vec![
            VersionRange {
                from_version: None,
                to_version: "1.8.1".to_string(),
                cves: vec![],
                references: vec!["https://github.com/kenwheeler/slick/issues".to_string()],
                severity: Severity::Low,
                description: "Potential XSS in older versions".to_string(),
            },
        ]);

        // RequireJS vulnerabilities
        self.add_library("requirejs", vec![
            VersionRange {
                from_version: None,
                to_version: "2.3.5".to_string(),
                cves: vec![],
                references: vec!["https://requirejs.org/docs/download.html".to_string()],
                severity: Severity::Low,
                description: "Known issues in older versions".to_string(),
            },
        ]);

        // SystemJS vulnerabilities
        self.add_library("systemjs", vec![
            VersionRange {
                from_version: None,
                to_version: "6.8.3".to_string(),
                cves: vec![],
                references: vec!["https://github.com/systemjs/systemjs/releases".to_string()],
                severity: Severity::Low,
                description: "Module loading security considerations".to_string(),
            },
        ]);

        // hls.js vulnerabilities
        self.add_library("hls.js", vec![
            VersionRange {
                from_version: None,
                to_version: "0.14.17".to_string(),
                cves: vec!["CVE-2021-23409".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-23409".to_string()],
                severity: Severity::High,
                description: "XSS vulnerability in hls.js".to_string(),
            },
        ]);

        // flv.js vulnerabilities
        self.add_library("flv.js", vec![
            VersionRange {
                from_version: None,
                to_version: "1.6.2".to_string(),
                cves: vec![],
                references: vec!["https://github.com/bilibili/flv.js/issues".to_string()],
                severity: Severity::Low,
                description: "Potential security issues in abandoned project".to_string(),
            },
        ]);

        // MediaElement.js vulnerabilities
        self.add_library("mediaelement", vec![
            VersionRange {
                from_version: None,
                to_version: "4.2.16".to_string(),
                cves: vec!["CVE-2020-8100".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-8100".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in MediaElement".to_string(),
            },
        ]);

        // Magnific Popup vulnerabilities
        self.add_library("magnific-popup", vec![
            VersionRange {
                from_version: None,
                to_version: "1.1.0".to_string(),
                cves: vec![],
                references: vec!["https://github.com/dimsemenov/Magnific-Popup/issues".to_string()],
                severity: Severity::Medium,
                description: "Potential XSS in older versions".to_string(),
            },
        ]);

        // PhotoSwipe vulnerabilities
        self.add_library("photoswipe", vec![
            VersionRange {
                from_version: None,
                to_version: "4.1.3".to_string(),
                cves: vec![],
                references: vec!["https://github.com/dimsemenov/PhotoSwipe/releases".to_string()],
                severity: Severity::Low,
                description: "Security improvements in newer versions".to_string(),
            },
        ]);

        // Clipboard.js vulnerabilities
        self.add_library("clipboard", vec![
            VersionRange {
                from_version: None,
                to_version: "2.0.4".to_string(),
                cves: vec![],
                references: vec!["https://github.com/zenorocha/clipboard.js/releases".to_string()],
                severity: Severity::Low,
                description: "Security improvements in newer versions".to_string(),
            },
        ]);

        // Cropper.js vulnerabilities
        self.add_library("cropperjs", vec![
            VersionRange {
                from_version: None,
                to_version: "1.5.6".to_string(),
                cves: vec![],
                references: vec!["https://github.com/fengyuanchen/cropperjs/releases".to_string()],
                severity: Severity::Low,
                description: "Security fixes in newer versions".to_string(),
            },
        ]);

        // Toastr vulnerabilities
        self.add_library("toastr", vec![
            VersionRange {
                from_version: None,
                to_version: "2.1.4".to_string(),
                cves: vec![],
                references: vec!["https://github.com/CodeSeven/toastr/issues".to_string()],
                severity: Severity::Low,
                description: "Potential XSS if unsanitized input used".to_string(),
            },
        ]);

        // Intro.js vulnerabilities
        self.add_library("intro.js", vec![
            VersionRange {
                from_version: None,
                to_version: "4.2.2".to_string(),
                cves: vec![],
                references: vec!["https://github.com/usablica/intro.js/releases".to_string()],
                severity: Severity::Low,
                description: "Security improvements in newer versions".to_string(),
            },
        ]);

        // Popper.js vulnerabilities
        self.add_library("popper.js", vec![
            VersionRange {
                from_version: None,
                to_version: "1.16.1".to_string(),
                cves: vec![],
                references: vec!["https://github.com/popperjs/popper-core/releases".to_string()],
                severity: Severity::Low,
                description: "Legacy version, upgrade to @popperjs/core".to_string(),
            },
        ]);

        // SheetJS (xlsx) vulnerabilities
        self.add_library("xlsx", vec![
            VersionRange {
                from_version: None,
                to_version: "0.17.0".to_string(),
                cves: vec!["CVE-2021-32012".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-32012".to_string()],
                severity: Severity::High,
                description: "Arbitrary file write vulnerability".to_string(),
            },
            VersionRange {
                from_version: None,
                to_version: "0.19.3".to_string(),
                cves: vec!["CVE-2023-30533".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2023-30533".to_string()],
                severity: Severity::High,
                description: "Remote code execution via crafted file".to_string(),
            },
        ]);

        // PapaParse vulnerabilities
        self.add_library("papaparse", vec![
            VersionRange {
                from_version: None,
                to_version: "5.2.0".to_string(),
                cves: vec!["CVE-2020-36363".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-36363".to_string()],
                severity: Severity::High,
                description: "ReDoS vulnerability in PapaParse".to_string(),
            },
        ]);

        // Nuxt.js vulnerabilities
        self.add_library("nuxt", vec![
            VersionRange {
                from_version: None,
                to_version: "2.15.3".to_string(),
                cves: vec!["CVE-2021-29473".to_string()],
                references: vec!["https://github.com/nuxt/nuxt.js/security/advisories/GHSA-vh95-rmgr-6w4m".to_string()],
                severity: Severity::High,
                description: "Path traversal vulnerability".to_string(),
            },
        ]);

        // Gatsby vulnerabilities
        self.add_library("gatsby", vec![
            VersionRange {
                from_version: None,
                to_version: "2.26.0".to_string(),
                cves: vec!["CVE-2021-32611".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-32611".to_string()],
                severity: Severity::Medium,
                description: "XSS vulnerability in Gatsby".to_string(),
            },
        ]);

        // Immer vulnerabilities
        self.add_library("immer", vec![
            VersionRange {
                from_version: None,
                to_version: "9.0.6".to_string(),
                cves: vec!["CVE-2021-23436".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-23436".to_string()],
                severity: Severity::Critical,
                description: "Prototype pollution vulnerability".to_string(),
            },
        ]);

        // json-schema vulnerabilities
        self.add_library("json-schema", vec![
            VersionRange {
                from_version: None,
                to_version: "0.4.0".to_string(),
                cves: vec!["CVE-2021-3918".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-3918".to_string()],
                severity: Severity::Critical,
                description: "Prototype pollution vulnerability".to_string(),
            },
        ]);

        // NOTE: minimist removed - it's a Node.js CLI argument parser, not exploitable in browsers
        // The library parses process.argv which doesn't exist in browser context

        // qs vulnerabilities
        self.add_library("qs", vec![
            VersionRange {
                from_version: None,
                to_version: "6.2.3".to_string(),
                cves: vec!["CVE-2017-1000048".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2017-1000048".to_string()],
                severity: Severity::High,
                description: "Prototype pollution vulnerability".to_string(),
            },
            VersionRange {
                from_version: None,
                to_version: "6.10.3".to_string(),
                cves: vec!["CVE-2022-24999".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2022-24999".to_string()],
                severity: Severity::High,
                description: "Prototype pollution via qs.parse".to_string(),
            },
        ]);

        // path-parse vulnerabilities
        self.add_library("path-parse", vec![
            VersionRange {
                from_version: None,
                to_version: "1.0.7".to_string(),
                cves: vec!["CVE-2021-23343".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-23343".to_string()],
                severity: Severity::High,
                description: "ReDoS vulnerability in path-parse".to_string(),
            },
        ]);

        // glob-parent vulnerabilities
        self.add_library("glob-parent", vec![
            VersionRange {
                from_version: None,
                to_version: "5.1.2".to_string(),
                cves: vec!["CVE-2020-28469".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-28469".to_string()],
                severity: Severity::High,
                description: "ReDoS vulnerability in glob-parent".to_string(),
            },
        ]);

        // async vulnerabilities
        self.add_library("async", vec![
            VersionRange {
                from_version: None,
                to_version: "2.6.4".to_string(),
                cves: vec!["CVE-2021-43138".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-43138".to_string()],
                severity: Severity::High,
                description: "Prototype pollution vulnerability".to_string(),
            },
        ]);

        // set-value vulnerabilities
        self.add_library("set-value", vec![
            VersionRange {
                from_version: None,
                to_version: "4.0.1".to_string(),
                cves: vec!["CVE-2021-23440".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-23440".to_string()],
                severity: Severity::High,
                description: "Prototype pollution vulnerability".to_string(),
            },
        ]);

        // deep-extend vulnerabilities
        self.add_library("deep-extend", vec![
            VersionRange {
                from_version: None,
                to_version: "0.5.1".to_string(),
                cves: vec!["CVE-2018-3750".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2018-3750".to_string()],
                severity: Severity::Critical,
                description: "Prototype pollution vulnerability".to_string(),
            },
        ]);

        // merge vulnerabilities
        self.add_library("merge", vec![
            VersionRange {
                from_version: None,
                to_version: "2.1.1".to_string(),
                cves: vec!["CVE-2020-28499".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-28499".to_string()],
                severity: Severity::Critical,
                description: "Prototype pollution vulnerability".to_string(),
            },
        ]);

        // flat vulnerabilities
        self.add_library("flat", vec![
            VersionRange {
                from_version: None,
                to_version: "5.0.1".to_string(),
                cves: vec!["CVE-2020-36632".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-36632".to_string()],
                severity: Severity::Critical,
                description: "Prototype pollution vulnerability".to_string(),
            },
        ]);

        // object-path vulnerabilities
        self.add_library("object-path", vec![
            VersionRange {
                from_version: None,
                to_version: "0.11.5".to_string(),
                cves: vec!["CVE-2020-15256".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-15256".to_string()],
                severity: Severity::Critical,
                description: "Prototype pollution vulnerability".to_string(),
            },
        ]);

        // dot-prop vulnerabilities
        self.add_library("dot-prop", vec![
            VersionRange {
                from_version: None,
                to_version: "5.3.0".to_string(),
                cves: vec!["CVE-2020-8116".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-8116".to_string()],
                severity: Severity::High,
                description: "Prototype pollution vulnerability".to_string(),
            },
        ]);

        // ini vulnerabilities
        self.add_library("ini", vec![
            VersionRange {
                from_version: None,
                to_version: "1.3.6".to_string(),
                cves: vec!["CVE-2020-7788".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-7788".to_string()],
                severity: Severity::High,
                description: "Prototype pollution vulnerability".to_string(),
            },
        ]);

        // y18n vulnerabilities
        self.add_library("y18n", vec![
            VersionRange {
                from_version: None,
                to_version: "5.0.5".to_string(),
                cves: vec!["CVE-2020-7774".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-7774".to_string()],
                severity: Severity::High,
                description: "Prototype pollution vulnerability".to_string(),
            },
        ]);

        // kind-of vulnerabilities
        self.add_library("kind-of", vec![
            VersionRange {
                from_version: Some("6.0.0".to_string()),
                to_version: "6.0.3".to_string(),
                cves: vec!["CVE-2019-20149".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2019-20149".to_string()],
                severity: Severity::High,
                description: "Validation bypass vulnerability".to_string(),
            },
        ]);

        // class-validator vulnerabilities
        self.add_library("class-validator", vec![
            VersionRange {
                from_version: None,
                to_version: "0.14.0".to_string(),
                cves: vec!["CVE-2019-18413".to_string()],
                references: vec!["https://github.com/typestack/class-validator/issues/1873".to_string()],
                severity: Severity::High,
                description: "Validation bypass vulnerability".to_string(),
            },
        ]);
    }

    fn add_library(&mut self, name: &str, vulns: Vec<VersionRange>) {
        self.libraries.insert(name.to_lowercase(), vulns);
    }

    pub fn check_library(&self, name: &str, version: &str) -> Vec<&VersionRange> {
        let name_lower = name.to_lowercase();
        let mut matches = Vec::new();

        if let Some(vulns) = self.libraries.get(&name_lower) {
            for vuln in vulns {
                if self.version_in_range(version, &vuln.from_version, &vuln.to_version) {
                    matches.push(vuln);
                }
            }
        }

        matches
    }

    fn version_in_range(&self, version: &str, from: &Option<String>, to: &str) -> bool {
        let (parsed_version, _is_prerelease) = self.parse_version_with_prerelease(version);
        let (parsed_to, _) = self.parse_version_with_prerelease(to);

        // Check upper bound (strictly less than)
        let cmp = self.version_compare(&parsed_version, &parsed_to);
        if cmp >= 0 {
            return false;
        }

        // Check lower bound if exists (greater than or equal)
        if let Some(from_ver) = from {
            let (parsed_from, _) = self.parse_version_with_prerelease(from_ver);
            let cmp_from = self.version_compare(&parsed_version, &parsed_from);
            if cmp_from < 0 {
                return false;
            }
        }

        true
    }

    /// Parse version string, handling pre-release tags (alpha, beta, rc)
    fn parse_version_with_prerelease(&self, version: &str) -> (Vec<u32>, bool) {
        let lower = version.to_lowercase();
        let is_prerelease = lower.contains("alpha") ||
                           lower.contains("beta") ||
                           lower.contains("rc") ||
                           lower.contains("dev") ||
                           lower.contains("snapshot");

        // Extract only the numeric parts (major.minor.patch)
        let numeric_part: String = version
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();

        let parts: Vec<u32> = numeric_part
            .split('.')
            .filter(|s| !s.is_empty())
            .map(|s| s.parse::<u32>().unwrap_or(0))
            .collect();

        (parts, is_prerelease)
    }

    /// Compare two version vectors: -1 if a < b, 0 if a == b, 1 if a > b
    fn version_compare(&self, a: &[u32], b: &[u32]) -> i32 {
        let max_len = a.len().max(b.len());
        for i in 0..max_len {
            let av = a.get(i).copied().unwrap_or(0);
            let bv = b.get(i).copied().unwrap_or(0);
            if av < bv {
                return -1;
            }
            if av > bv {
                return 1;
            }
        }
        0
    }

    /// Validate that a detected library/version is likely correct (reduce false positives)
    fn validate_detection(&self, library: &str, version: &str, source: &str) -> bool {
        // Version must have at least major.minor
        let parts: Vec<&str> = version.split('.').collect();
        if parts.is_empty() {
            return false;
        }

        // Reject suspiciously short versions for most libraries
        if version.len() < 3 && !version.contains('.') {
            // Exception for three.js which uses "r125" format
            if library != "three" {
                return false;
            }
        }

        // For generic library names, require more context in the source
        let generic_names = ["async", "flat", "merge", "ini", "qs", "dot-prop", "set-value", "clipboard"];
        if generic_names.contains(&library) {
            // Require the full library name pattern in source
            let required_pattern = format!("/{}/", library);
            let required_pattern2 = format!("{}@", library);
            let required_pattern3 = format!("{}.js", library);
            let required_pattern4 = format!("{}.min.js", library);

            if !source.contains(&required_pattern) &&
               !source.contains(&required_pattern2) &&
               !source.contains(&required_pattern3) &&
               !source.contains(&required_pattern4) {
                return false;
            }
        }

        true
    }
}

impl MerlinScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self {
            http_client,
            vuln_db: VulnerabilityDatabase::new(),
        }
    }

    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;
        let mut seen_libs: std::collections::HashSet<String> = std::collections::HashSet::new();

        info!("[Merlin] Scanning for vulnerable JavaScript libraries");

        // Fetch the main page
        tests_run += 1;
        match self.http_client.get(url).await {
            Ok(response) => {
                // Extract library versions from HTML
                let detected = self.extract_libraries(&response.body);

                for (library, version) in &detected {
                    // Validate detection to reduce false positives
                    if !self.vuln_db.validate_detection(library, version, &response.body) {
                        debug!("[Merlin] Skipping invalid detection: {} v{}", library, version);
                        continue;
                    }

                    // Skip if we've already seen this library+version
                    let key = format!("{}:{}", library, version);
                    if seen_libs.contains(&key) {
                        continue;
                    }
                    seen_libs.insert(key);

                    info!("[Merlin] Detected: {} v{}", library, version);

                    let vulns = self.vuln_db.check_library(library, version);
                    for vuln in vulns {
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            library,
                            version,
                            vuln,
                        ));
                    }
                }

                // Extract and check external JS files
                let js_urls = self.extract_js_urls(&response.body, url);
                info!("[Merlin] Found {} JavaScript files to analyze", js_urls.len());
                for js_url in &js_urls {
                    debug!("[Merlin] JS file: {}", js_url);
                }

                for js_url in js_urls.iter().take(20) {
                    tests_run += 1;
                    if let Ok(js_response) = self.http_client.get(js_url).await {
                        info!("[Merlin] Analyzing {} ({} bytes)", js_url, js_response.body.len());
                        let js_detected = self.extract_libraries_from_js(&js_response.body);

                        if js_detected.is_empty() {
                            debug!("[Merlin] No libraries detected in {}", js_url);
                        } else {
                            info!("[Merlin] Found {} potential libraries in {}", js_detected.len(), js_url);
                        }

                        for (library, version) in &js_detected {
                            // Validate detection
                            if !self.vuln_db.validate_detection(library, version, &js_response.body) {
                                debug!("[Merlin] Skipping invalid JS detection: {} v{}", library, version);
                                continue;
                            }

                            // Skip if we've already seen this library+version
                            let key = format!("{}:{}", library, version);
                            if seen_libs.contains(&key) {
                                continue;
                            }
                            seen_libs.insert(key);

                            info!("[Merlin] Detected in JS: {} v{}", library, version);

                            let vulns = self.vuln_db.check_library(library, version);
                            for vuln in vulns {
                                vulnerabilities.push(self.create_vulnerability(
                                    js_url,
                                    library,
                                    version,
                                    vuln,
                                ));
                            }
                        }
                    }
                }
            }
            Err(e) => {
                warn!("[Merlin] Failed to fetch page: {}", e);
            }
        }

        // Consolidate findings by library+version - combine multiple CVEs into one finding
        let mut consolidated: std::collections::HashMap<String, Vulnerability> = std::collections::HashMap::new();

        for vuln in vulnerabilities {
            // Key by vuln_type which contains "library vX.Y.Z"
            let lib_version_key = vuln.vuln_type.clone();

            if let Some(existing) = consolidated.get_mut(&lib_version_key) {
                // Merge evidence (CVE lists)
                if let (Some(existing_evidence), Some(new_evidence)) = (&existing.evidence, &vuln.evidence) {
                    // Extract CVEs from both and combine
                    let mut combined = existing_evidence.clone();
                    // Only add if the CVE isn't already present
                    if !combined.contains(&new_evidence.split('|').next().unwrap_or("")) {
                        combined = format!("{} | {}", combined, new_evidence);
                        existing.evidence = Some(combined);
                    }
                }
                // Keep highest severity
                if vuln.cvss > existing.cvss {
                    existing.severity = vuln.severity;
                    existing.cvss = vuln.cvss;
                }
                // Combine descriptions
                if !existing.description.contains(&vuln.description) {
                    existing.description = format!("{}; {}", existing.description, vuln.description);
                }
            } else {
                consolidated.insert(lib_version_key, vuln);
            }
        }

        let unique_vulns: Vec<Vulnerability> = consolidated.into_values().collect();

        info!(
            "[Merlin] Scan complete: {} vulnerable libraries found",
            unique_vulns.len()
        );

        Ok((unique_vulns, tests_run))
    }

    fn extract_libraries(&self, html: &str) -> Vec<(String, String)> {
        let mut detected = Vec::new();

        // jQuery detection patterns
        detected.extend(self.detect_jquery(html));
        detected.extend(self.detect_angular(html));
        detected.extend(self.detect_vue(html));
        detected.extend(self.detect_react(html));
        detected.extend(self.detect_bootstrap(html));
        detected.extend(self.detect_lodash(html));
        detected.extend(self.detect_moment(html));
        detected.extend(self.detect_generic_libs(html));

        detected
    }

    fn extract_libraries_from_js(&self, js: &str) -> Vec<(String, String)> {
        let mut detected = Vec::new();

        // jQuery version detection
        if let Some(caps) = Regex::new(r#"jQuery\s*(?:JavaScript Library\s+)?v?(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("jquery".to_string(), version.as_str().to_string()));
            }
        }

        // jQuery alternative pattern
        if let Some(caps) = Regex::new(r#"jquery[._-]?(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("jquery".to_string(), version.as_str().to_string()));
            }
        }

        // Angular detection
        if let Some(caps) = Regex::new(r#"angular(?:\.js)?\s*(?:v|version)?[:\s]*['"]?(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("angularjs".to_string(), version.as_str().to_string()));
            }
        }

        // AngularJS specific
        if let Some(caps) = Regex::new(r#"AngularJS v(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("angularjs".to_string(), version.as_str().to_string()));
            }
        }

        // Vue.js detection - multiple patterns for different build formats
        let vue_patterns = [
            r#"Vue\.js v(\d+\.\d+(?:\.\d+)?)"#,                           // "Vue.js v2.6.14"
            r#"Vue\.version\s*=\s*['"](\d+\.\d+(?:\.\d+)?)"#,            // Vue.version = "2.6.14"
            r#"(?i)\.version\s*=\s*['"](\d+\.\d+(?:\.\d+)?)['"]\s*[,;][^}]*__vue"#, // minified: e.version="2.6.14",...__vue
            r#"version:\s*['"](\d+\.\d+(?:\.\d+)?)['"]\s*,\s*\w+:\s*['"]Vue"#, // minified: version:"2.6.14",...,name:"Vue"
            r#"\bVue\b[^}]*version:\s*['"](\d+\.\d+(?:\.\d+)?)"#,        // Vue...version:"2.6.14"
            r#"vue[@/](\d+\.\d+(?:\.\d+)?)"#,                            // CDN: vue@2.6.14 or vue/2.6.14
            r#"vue\.(?:min\.)?js[?/]v?=?(\d+\.\d+(?:\.\d+)?)"#,          // vue.min.js?v=2.6.14
            r#"['"]vue['"]:\s*['"][\^~]?(\d+\.\d+(?:\.\d+)?)"#,          // package.json style: "vue": "^2.6.14"
            r#"__VUE_VERSION__\s*[=:]\s*['"](\d+\.\d+(?:\.\d+)?)"#,      // Webpack define: __VUE_VERSION__ = "2.6.14"
            r#"\.version\s*=\s*['"](\d+\.\d+(?:\.\d+)?)['"][^}]{0,100}createApp"#, // minified Vue 3: .version="3.2.0"...createApp
            r#"createApp[^}]{0,200}version:\s*['"](\d+\.\d+(?:\.\d+)?)"#, // Vue 3 pattern
            r#"Vue,\s*\{[^}]*version:\s*['"](\d+\.\d+(?:\.\d+)?)"#,      // export Vue,{version:"2.6.14"
            r#"['"]\s*2\.6\.(?:14|13|12|11|10|9|8|7|6|5|4|3|2|1|0)\s*['"]\s*[,}][^}]{0,50}(?:Vue|_vue|__vue)"#, // Known vuln versions near Vue identifier
            // Quasar/webpack minified Vue patterns
            r#"n\["a"\]\.extend\([^)]+\).*version.*['"](2\.\d+\.\d+)['"]"#, // Quasar Vue extend pattern
            r#"\$mount.*version.*['"](2\.\d+\.\d+)['"]"#,               // $mount with version
            r#"['"]QIcon['"][^}]*Vue[^}]*['"](2\.\d+\.\d+)['"]"#,       // Quasar QIcon with Vue
        ];
        for pattern in vue_patterns {
            if let Some(caps) = Regex::new(pattern).ok().and_then(|re| re.captures(js)) {
                if let Some(version) = caps.get(1) {
                    detected.push(("vue".to_string(), version.as_str().to_string()));
                    break; // Only detect once per JS file
                }
            }
        }

        // Vue 2.x special: search for known vulnerable version strings with Vue context
        if !detected.iter().any(|(lib, _)| lib == "vue") {
            // Check for Vue 2.x (CVE-2024-9506 affected)
            if js.contains("Vue") || js.contains("__vue") || js.contains("_Vue") || js.contains("$mount") || js.contains("createApp") || js.contains("QIcon") {
                let vue2_versions = [
                    r#"['"](2\.6\.1[0-4]|2\.6\.[0-9]|2\.[0-5]\.\d+)['"]\s*[,;}]"#,
                    r#"version['"]\s*:\s*['"](2\.6\.1[0-4]|2\.6\.[0-9]|2\.[0-5]\.\d+)['"]\s*"#,
                    // Webpack minified patterns: t.version="2.6.14" or e.version="2.6.14"
                    r#"\.\s*version\s*=\s*['"](2\.\d+\.\d+)['"]"#,
                    // minified: n("2.6.14"),Vue
                    r#"[("'](2\.\d+\.\d+)['")\]][^}]{0,50}Vue"#,
                    // Vue 2 often has: VERSION:"2.6.14" nearby $mount or __patch__
                    r#"VERSION\s*:\s*['"](2\.\d+\.\d+)['"]"#,
                    // Quasar components use Vue.extend - look for version nearby
                    r#"extend\([^)]+\)[^}]{0,500}['"](2\.\d+\.\d+)['"]"#,
                ];
                for pattern in vue2_versions {
                    if let Some(caps) = Regex::new(pattern).ok().and_then(|re| re.captures(js)) {
                        if let Some(version) = caps.get(1) {
                            // Double-check Vue context nearby (within 500 chars)
                            let version_pos = js.find(version.as_str()).unwrap_or(0);
                            let context_start = version_pos.saturating_sub(300);
                            let context_end = (version_pos + 300).min(js.len());
                            let context = &js[context_start..context_end];
                            if context.contains("Vue") || context.contains("__vue") || context.contains("createApp") || context.contains("$mount") || context.contains("__patch__") || context.contains("_init") || context.contains("QIcon") || context.contains("extend") {
                                detected.push(("vue".to_string(), version.as_str().to_string()));
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Brute-force Vue version extraction: Search for semver strings near Vue keywords
        if !detected.iter().any(|(lib, _)| lib == "vue") && (js.contains("Vue") || js.contains("$mount") || js.contains("QIcon")) {
            // Look for any 2.x.x version string
            if let Some(caps) = Regex::new(r#"['"](\d+\.\d+\.\d+)['"]"#).ok() {
                for cap in caps.captures_iter(js) {
                    if let Some(version) = cap.get(1) {
                        let v = version.as_str();
                        // Only check Vue 2.x versions
                        if v.starts_with("2.") {
                            let version_pos = version.start();
                            let context_start = version_pos.saturating_sub(500);
                            let context_end = (version_pos + 500).min(js.len());
                            let context = &js[context_start..context_end];
                            // Broad Vue fingerprints
                            if context.contains("Vue") || context.contains("$mount") ||
                               context.contains("__patch__") || context.contains("_init") ||
                               context.contains("$emit") || context.contains("$on") ||
                               context.contains("computed") || context.contains("mixins") {
                                info!("[Merlin] Detected Vue {} via context fingerprinting", v);
                                detected.push(("vue".to_string(), v.to_string()));
                                break;
                            }
                        }
                    }
                }
            }
        }

        // React detection
        if let Some(caps) = Regex::new(r#"React v?(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("react".to_string(), version.as_str().to_string()));
            }
        }

        // Lodash detection
        if let Some(caps) = Regex::new(r#"lodash(?:\.js)?\s*(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("lodash".to_string(), version.as_str().to_string()));
            }
        }

        // Underscore detection
        if let Some(caps) = Regex::new(r#"Underscore\.js\s*(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("underscore".to_string(), version.as_str().to_string()));
            }
        }

        // Moment.js detection
        if let Some(caps) = Regex::new(r#"moment(?:\.js)?\s*[:\s]*['"]?(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("moment".to_string(), version.as_str().to_string()));
            }
        }

        // Bootstrap detection
        if let Some(caps) = Regex::new(r#"Bootstrap\s*v?(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("bootstrap".to_string(), version.as_str().to_string()));
            }
        }

        // Handlebars detection
        if let Some(caps) = Regex::new(r#"Handlebars\s*v?(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("handlebars".to_string(), version.as_str().to_string()));
            }
        }

        // Ember detection
        if let Some(caps) = Regex::new(r#"Ember\s*:?\s*(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("ember".to_string(), version.as_str().to_string()));
            }
        }

        // Backbone detection
        if let Some(caps) = Regex::new(r#"Backbone\.js\s*(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("backbone".to_string(), version.as_str().to_string()));
            }
        }

        // DOMPurify detection
        if let Some(caps) = Regex::new(r#"DOMPurify\s*(?:version)?\s*[:\s]*['"]?(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("dompurify".to_string(), version.as_str().to_string()));
            }
        }

        // Axios detection - multiple patterns for different build formats
        let axios_patterns = [
            r#"axios[/\\](\d+\.\d+(?:\.\d+)?)"#,                          // path: axios/0.21.4
            r#"axios\.VERSION\s*=\s*['"](\d+\.\d+(?:\.\d+)?)"#,           // axios.VERSION = "0.21.4"
            r#"axios@(\d+\.\d+(?:\.\d+)?)"#,                              // CDN: axios@0.21.4
            r#"['"]axios['"]:\s*['"][\^~]?(\d+\.\d+(?:\.\d+)?)"#,         // package.json: "axios": "^0.21.4"
            r#"name:\s*['"]axios['"][^}]*version:\s*['"](\d+\.\d+(?:\.\d+)?)"#, // minified: name:"axios",...,version:"0.21.4"
            r#"version:\s*['"](\d+\.\d+(?:\.\d+)?)['"]\s*[,}][^}]*['"]axios"#,  // minified reverse
            r#"\baxios\b[^}]{0,50}version['"]?\s*[:=]\s*['"](\d+\.\d+(?:\.\d+)?)"#, // axios...version:"0.21.4"
            r#"VERSION:\s*['"](\d+\.\d+(?:\.\d+)?)['"]\s*[,}][^}]{0,100}(?:interceptors|request|response)"#, // minified axios signature
        ];
        for pattern in axios_patterns {
            if let Some(caps) = Regex::new(pattern).ok().and_then(|re| re.captures(js)) {
                if let Some(version) = caps.get(1) {
                    detected.push(("axios".to_string(), version.as_str().to_string()));
                    break; // Only detect once per JS file
                }
            }
        }

        // Axios special: search for known vulnerable versions with axios context
        if !detected.iter().any(|(lib, _)| lib == "axios") {
            if js.contains("axios") || js.contains("Axios") || js.contains("interceptors") || js.contains("XMLHttpRequest") {
                let axios_versions = [
                    r#"['"](0\.2[01]\.[0-4]|0\.1[89]\.\d+|1\.[0-6]\.\d+)['"]\s*[,;}]"#, // Known vuln versions
                    r#"VERSION['"]\s*:\s*['"](0\.2[01]\.[0-4]|0\.1[89]\.\d+)['"]\s*"#,
                    // Webpack minified: t.version="0.21.4" near http/request
                    r#"\.\s*version\s*=\s*['"](0\.\d+\.\d+|1\.[0-6]\.\d+)['"]"#,
                    // minified: n("0.21.4"),axios
                    r#"[("'](0\.\d+\.\d+)['")\]][^}]{0,50}(?:axios|interceptors)"#,
                ];
                for pattern in axios_versions {
                    if let Some(caps) = Regex::new(pattern).ok().and_then(|re| re.captures(js)) {
                        if let Some(version) = caps.get(1) {
                            // Double-check axios context nearby
                            let version_pos = js.find(version.as_str()).unwrap_or(0);
                            let context_start = version_pos.saturating_sub(400);
                            let context_end = (version_pos + 400).min(js.len());
                            let context = &js[context_start..context_end];
                            if context.contains("axios") || context.contains("Axios") ||
                               (context.contains("interceptors") && context.contains("request")) ||
                               context.contains("XMLHttpRequest") {
                                detected.push(("axios".to_string(), version.as_str().to_string()));
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Brute-force axios version extraction: Search for semver strings near axios keywords
        if !detected.iter().any(|(lib, _)| lib == "axios") && (js.contains("axios") || js.contains("interceptors")) {
            if let Some(caps) = Regex::new(r#"['"](\d+\.\d+\.\d+)['"]"#).ok() {
                for cap in caps.captures_iter(js) {
                    if let Some(version) = cap.get(1) {
                        let v = version.as_str();
                        // Only check axios-like versions (0.x.x or 1.x.x)
                        if v.starts_with("0.") || v.starts_with("1.") {
                            let version_pos = version.start();
                            let context_start = version_pos.saturating_sub(500);
                            let context_end = (version_pos + 500).min(js.len());
                            let context = &js[context_start..context_end];
                            // Axios fingerprints
                            if context.contains("axios") || context.contains("Axios") ||
                               context.contains("interceptors") ||
                               (context.contains("request") && context.contains("response") && context.contains("headers")) {
                                info!("[Merlin] Detected axios {} via context fingerprinting", v);
                                detected.push(("axios".to_string(), v.to_string()));
                                break;
                            }
                        }
                    }
                }
            }
        }

        // TinyMCE detection
        if let Some(caps) = Regex::new(r#"tinymce\s*[:\s]*['"]?(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("tinymce".to_string(), version.as_str().to_string()));
            }
        }

        // CKEditor detection
        if let Some(caps) = Regex::new(r#"CKEDITOR\.version\s*=\s*['"](\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("ckeditor4".to_string(), version.as_str().to_string()));
            }
        }

        // jQuery UI detection
        if let Some(caps) = Regex::new(r#"jQuery UI\s*-?\s*v?(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("jquery-ui".to_string(), version.as_str().to_string()));
            }
        }

        // DataTables detection
        if let Some(caps) = Regex::new(r#"DataTables\s*(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("datatables".to_string(), version.as_str().to_string()));
            }
        }

        // Select2 detection
        if let Some(caps) = Regex::new(r#"Select2\s*(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("select2".to_string(), version.as_str().to_string()));
            }
        }

        // Highcharts detection
        if let Some(caps) = Regex::new(r#"Highcharts\s*(?:JS)?\s*v?(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("highcharts".to_string(), version.as_str().to_string()));
            }
        }

        // Chart.js detection
        if let Some(caps) = Regex::new(r#"Chart\.js\s*v?(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("chartjs".to_string(), version.as_str().to_string()));
            }
        }

        // PDF.js detection
        if let Some(caps) = Regex::new(r#"pdf\.js\s*v?(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("pdfjs".to_string(), version.as_str().to_string()));
            }
        }

        // Dojo detection
        if let Some(caps) = Regex::new(r#"dojo\.version\s*=\s*\{[^}]*major:\s*(\d+)[^}]*minor:\s*(\d+)"#).ok().and_then(|re| re.captures(js)) {
            if let (Some(major), Some(minor)) = (caps.get(1), caps.get(2)) {
                detected.push(("dojo".to_string(), format!("{}.{}.0", major.as_str(), minor.as_str())));
            }
        }

        // Ext JS detection
        if let Some(caps) = Regex::new(r#"Ext\.version\s*=\s*['"](\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("extjs".to_string(), version.as_str().to_string()));
            }
        }

        // Knockout detection
        if let Some(caps) = Regex::new(r#"knockout[.-](\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("knockout".to_string(), version.as_str().to_string()));
            }
        }

        // jsZip detection
        if let Some(caps) = Regex::new(r#"JSZip\s*v?(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("jszip".to_string(), version.as_str().to_string()));
            }
        }

        // Mustache detection
        if let Some(caps) = Regex::new(r#"Mustache\.version\s*=\s*['"](\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("mustache".to_string(), version.as_str().to_string()));
            }
        }

        // Svelte detection
        if let Some(caps) = Regex::new(r#"svelte[/\\](\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("svelte".to_string(), version.as_str().to_string()));
            }
        }

        // ua-parser-js detection
        if let Some(caps) = Regex::new(r#"ua-parser-js[/\\](\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("ua-parser-js".to_string(), version.as_str().to_string()));
            }
        }

        // Prototype detection
        if let Some(caps) = Regex::new(r#"Prototype JavaScript framework,\s*version\s*(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("prototype".to_string(), version.as_str().to_string()));
            }
        }

        // YUI detection
        if let Some(caps) = Regex::new(r#"YUI\s*(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("yui".to_string(), version.as_str().to_string()));
            }
        }

        // Showdown detection
        if let Some(caps) = Regex::new(r#"showdown\s*v?(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("showdown".to_string(), version.as_str().to_string()));
            }
        }

        // Marked detection
        if let Some(caps) = Regex::new(r#"marked\s*-?\s*(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("marked".to_string(), version.as_str().to_string()));
            }
        }

        // Video.js detection
        if let Some(caps) = Regex::new(r#"video\.?js[:\s]+['"]?(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("video.js".to_string(), version.as_str().to_string()));
            }
        }

        // Socket.io detection
        if let Some(caps) = Regex::new(r#"socket\.io[:\s]+['"]?(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("socket.io".to_string(), version.as_str().to_string()));
            }
        }

        // Quill detection
        if let Some(caps) = Regex::new(r#"Quill\s*v?(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("quill".to_string(), version.as_str().to_string()));
            }
        }

        // Prism detection
        if let Some(caps) = Regex::new(r#"Prism\s*v?(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("prismjs".to_string(), version.as_str().to_string()));
            }
        }

        // highlight.js detection
        if let Some(caps) = Regex::new(r#"highlight\.js\s*v?(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("highlight.js".to_string(), version.as_str().to_string()));
            }
        }

        // D3 detection
        if let Some(caps) = Regex::new(r#"d3\.version\s*=\s*['"](\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("d3".to_string(), version.as_str().to_string()));
            }
        }

        // Leaflet detection
        if let Some(caps) = Regex::new(r#"Leaflet\s*(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("leaflet".to_string(), version.as_str().to_string()));
            }
        }

        // Three.js detection
        if let Some(caps) = Regex::new(r#"three\.(?:REVISION|version)\s*=\s*['"]?(\d+|\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("three".to_string(), version.as_str().to_string()));
            }
        }

        // GSAP detection
        if let Some(caps) = Regex::new(r#"gsap\s*(?:version)?\s*[:\s]*['"]?(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("gsap".to_string(), version.as_str().to_string()));
            }
        }

        // Modernizr detection
        if let Some(caps) = Regex::new(r#"Modernizr\s*(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("modernizr".to_string(), version.as_str().to_string()));
            }
        }

        // Summernote detection
        if let Some(caps) = Regex::new(r#"summernote\s*v?(\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("summernote".to_string(), version.as_str().to_string()));
            }
        }

        // CodeMirror detection
        if let Some(caps) = Regex::new(r#"CodeMirror\.version\s*=\s*['"](\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("codemirror".to_string(), version.as_str().to_string()));
            }
        }

        // Immer detection
        if let Some(caps) = Regex::new(r#"immer[/@.-](\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("immer".to_string(), version.as_str().to_string()));
            }
        }

        // xlsx/SheetJS detection
        if let Some(caps) = Regex::new(r#"xlsx\.version\s*=\s*['"](\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("xlsx".to_string(), version.as_str().to_string()));
            }
        }

        // MathJax detection
        if let Some(caps) = Regex::new(r#"MathJax\.version\s*=\s*['"](\d+\.\d+(?:\.\d+)?)"#).ok().and_then(|re| re.captures(js)) {
            if let Some(version) = caps.get(1) {
                detected.push(("mathjax".to_string(), version.as_str().to_string()));
            }
        }

        // Package.json style dependencies embedded in webpack/vite bundles
        // Format: "package-name":"^1.2.3" or "package-name":"1.2.3"
        detected.extend(self.extract_package_json_deps(js));

        detected
    }

    /// Extract package.json style dependencies from bundled JS
    /// Webpack/Vite often embed package metadata in the bundle
    fn extract_package_json_deps(&self, js: &str) -> Vec<(String, String)> {
        let mut detected = Vec::new();

        // Known vulnerable libraries to look for in package.json format
        // EXCLUDES Node.js-only libraries like minimist, yargs-parser that can't be exploited in browsers
        let vulnerable_libs = [
            "vue", "axios", "lodash", "jquery", "angular", "react", "react-dom",
            "moment", "handlebars", "bootstrap", "underscore",
            "dompurify", "marked", "showdown", "highlight.js", "prismjs",
            "socket.io", "socket.io-client", "chart.js", "d3", "three",
            "sweetalert", "sweetalert2", "tinymce", "ckeditor", "quill",
            "codemirror", "ace-builds", "leaflet", "gsap", "modernizr",
            "summernote", "froala-editor", "datatables.net", "select2",
            "jquery-ui", "jquery-validation", "jquery-mobile", "jquery.terminal",
            "backbone", "knockout", "mustache", "pug", "ejs", "nunjucks",
            "ua-parser-js", "serialize-javascript", "js-yaml",
            "fast-xml-parser", "xml2js", "ajv",
            "immer", "xlsx", "mathjax", "video.js", "plyr", "dropzone",
            "sanitize-html", "easyxdm", "prototype", "yui",
            "prettyphoto", "extjs", "markdown-it", "tableexport", "jplayer",
            "flowplayer",
        ];

        // Node.js-only packages that can't be exploited in browser context
        // These are often bundled in devDependencies metadata but not actually used
        let nodejs_only_packages = [
            "minimist", "yargs-parser", "yargs", "commander", "express",
            "node-forge", "follow-redirects", "webpack-dev-server",
            "karma", "grunt", "gulp", "mocha", "jest", "chai",
        ];

        // Pattern: "package-name":"^1.2.3" or "package-name":"~1.2.3" or "package-name":"1.2.3"
        let dep_pattern = Regex::new(r#"["']([a-z@][a-z0-9._/-]*)["']\s*:\s*["'][\^~]?(\d+\.\d+(?:\.\d+)?)["']"#);

        if let Ok(re) = dep_pattern {
            for caps in re.captures_iter(js) {
                if let (Some(name), Some(version)) = (caps.get(1), caps.get(2)) {
                    let lib_name = name.as_str().to_lowercase();
                    // Only track known vulnerable libraries
                    if vulnerable_libs.iter().any(|&vl| lib_name == vl || lib_name.contains(vl)) {
                        detected.push((lib_name, version.as_str().to_string()));
                    }
                }
            }
        }

        // Also check for node_modules path patterns in source maps or webpack metadata
        // Pattern: /node_modules/package-name or node_modules/package-name/version
        let node_modules_pattern = Regex::new(r#"node_modules/([a-z@][a-z0-9._/-]*)/(\d+\.\d+(?:\.\d+)?)"#);
        if let Ok(re) = node_modules_pattern {
            for caps in re.captures_iter(js) {
                if let (Some(name), Some(version)) = (caps.get(1), caps.get(2)) {
                    let lib_name = name.as_str().to_lowercase();
                    if vulnerable_libs.iter().any(|&vl| lib_name == vl || lib_name.contains(vl)) {
                        detected.push((lib_name, version.as_str().to_string()));
                    }
                }
            }
        }

        detected
    }

    fn detect_jquery(&self, html: &str) -> Vec<(String, String)> {
        let mut detected = Vec::new();

        // CDN URL patterns
        let cdn_patterns = vec![
            r#"jquery[.-](\d+\.\d+(?:\.\d+)?)"#,
            r#"jquery/(\d+\.\d+(?:\.\d+)?)/jquery"#,
            r#"jquery@(\d+\.\d+(?:\.\d+)?)"#,
        ];

        for pattern in cdn_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for caps in re.captures_iter(html) {
                    if let Some(version) = caps.get(1) {
                        detected.push(("jquery".to_string(), version.as_str().to_string()));
                    }
                }
            }
        }

        detected
    }

    fn detect_angular(&self, html: &str) -> Vec<(String, String)> {
        let mut detected = Vec::new();

        // AngularJS (1.x)
        let angular1_patterns = vec![
            r#"angular[.-](\d+\.\d+(?:\.\d+)?)"#,
            r#"angularjs/(\d+\.\d+(?:\.\d+)?)"#,
        ];

        for pattern in angular1_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for caps in re.captures_iter(html) {
                    if let Some(version) = caps.get(1) {
                        let ver = version.as_str();
                        if ver.starts_with("1.") {
                            detected.push(("angularjs".to_string(), ver.to_string()));
                        }
                    }
                }
            }
        }

        // Angular (2+)
        if let Ok(re) = Regex::new(r#"@angular/core[/@](\d+\.\d+(?:\.\d+)?)"#) {
            for caps in re.captures_iter(html) {
                if let Some(version) = caps.get(1) {
                    detected.push(("angular".to_string(), version.as_str().to_string()));
                }
            }
        }

        detected
    }

    fn detect_vue(&self, html: &str) -> Vec<(String, String)> {
        let mut detected = Vec::new();

        let vue_patterns = vec![
            r#"vue[.-](\d+\.\d+(?:\.\d+)?)"#,                    // vue-2.6.14 or vue.2.6.14
            r#"vue/(\d+\.\d+(?:\.\d+)?)"#,                       // vue/2.6.14
            r#"vue@(\d+\.\d+(?:\.\d+)?)"#,                       // vue@2.6.14
            r#"vue\.(?:min\.)?js\?v=(\d+\.\d+(?:\.\d+)?)"#,      // vue.min.js?v=2.6.14
            r#"vue\.(?:runtime\.)?(?:esm\.)?js[?/](\d+\.\d+(?:\.\d+)?)"#, // vue.runtime.esm.js
            r#"unpkg\.com/vue@(\d+\.\d+(?:\.\d+)?)"#,            // unpkg.com/vue@2.6.14
            r#"cdn\.jsdelivr\.net/npm/vue@(\d+\.\d+(?:\.\d+)?)"#, // jsdelivr CDN
            r#"cdnjs\.cloudflare\.com/ajax/libs/vue/(\d+\.\d+(?:\.\d+)?)"#, // cloudflare CDN
        ];

        for pattern in vue_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for caps in re.captures_iter(html) {
                    if let Some(version) = caps.get(1) {
                        detected.push(("vue".to_string(), version.as_str().to_string()));
                    }
                }
            }
        }

        detected
    }

    fn detect_react(&self, html: &str) -> Vec<(String, String)> {
        let mut detected = Vec::new();

        let react_patterns = vec![
            r#"react[.-](\d+\.\d+(?:\.\d+)?)"#,
            r#"react/(\d+\.\d+(?:\.\d+)?)"#,
            r#"react@(\d+\.\d+(?:\.\d+)?)"#,
            r#"react-dom[/@](\d+\.\d+(?:\.\d+)?)"#,
        ];

        for pattern in react_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for caps in re.captures_iter(html) {
                    if let Some(version) = caps.get(1) {
                        detected.push(("react".to_string(), version.as_str().to_string()));
                    }
                }
            }
        }

        detected
    }

    fn detect_bootstrap(&self, html: &str) -> Vec<(String, String)> {
        let mut detected = Vec::new();

        let bootstrap_patterns = vec![
            r#"bootstrap[.-](\d+\.\d+(?:\.\d+)?)"#,
            r#"bootstrap/(\d+\.\d+(?:\.\d+)?)"#,
            r#"bootstrap@(\d+\.\d+(?:\.\d+)?)"#,
        ];

        for pattern in bootstrap_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for caps in re.captures_iter(html) {
                    if let Some(version) = caps.get(1) {
                        detected.push(("bootstrap".to_string(), version.as_str().to_string()));
                    }
                }
            }
        }

        detected
    }

    fn detect_lodash(&self, html: &str) -> Vec<(String, String)> {
        let mut detected = Vec::new();

        let lodash_patterns = vec![
            r#"lodash[.-](\d+\.\d+(?:\.\d+)?)"#,
            r#"lodash/(\d+\.\d+(?:\.\d+)?)"#,
            r#"lodash@(\d+\.\d+(?:\.\d+)?)"#,
        ];

        for pattern in lodash_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for caps in re.captures_iter(html) {
                    if let Some(version) = caps.get(1) {
                        detected.push(("lodash".to_string(), version.as_str().to_string()));
                    }
                }
            }
        }

        detected
    }

    fn detect_moment(&self, html: &str) -> Vec<(String, String)> {
        let mut detected = Vec::new();

        let moment_patterns = vec![
            r#"moment[.-](\d+\.\d+(?:\.\d+)?)"#,
            r#"moment/(\d+\.\d+(?:\.\d+)?)"#,
            r#"moment@(\d+\.\d+(?:\.\d+)?)"#,
        ];

        for pattern in moment_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for caps in re.captures_iter(html) {
                    if let Some(version) = caps.get(1) {
                        detected.push(("moment".to_string(), version.as_str().to_string()));
                    }
                }
            }
        }

        detected
    }

    fn detect_generic_libs(&self, html: &str) -> Vec<(String, String)> {
        let mut detected = Vec::new();

        // Generic library patterns from CDN URLs
        let lib_patterns = vec![
            (r#"axios[/@](\d+\.\d+(?:\.\d+)?)"#, "axios"),
            (r#"handlebars[/@.-](\d+\.\d+(?:\.\d+)?)"#, "handlebars"),
            (r#"underscore[/@.-](\d+\.\d+(?:\.\d+)?)"#, "underscore"),
            (r#"backbone[/@.-](\d+\.\d+(?:\.\d+)?)"#, "backbone"),
            (r#"ember[/@.-](\d+\.\d+(?:\.\d+)?)"#, "ember"),
            (r#"dompurify[/@.-](\d+\.\d+(?:\.\d+)?)"#, "dompurify"),
            (r#"tinymce[/@.-](\d+\.\d+(?:\.\d+)?)"#, "tinymce"),
            (r#"ckeditor[/@.-](\d+\.\d+(?:\.\d+)?)"#, "ckeditor4"),
            (r#"jquery-ui[/@.-](\d+\.\d+(?:\.\d+)?)"#, "jquery-ui"),
            (r#"datatables[/@.-](\d+\.\d+(?:\.\d+)?)"#, "datatables"),
            (r#"select2[/@.-](\d+\.\d+(?:\.\d+)?)"#, "select2"),
            (r#"highcharts[/@.-](\d+\.\d+(?:\.\d+)?)"#, "highcharts"),
            (r#"chart\.?js[/@.-](\d+\.\d+(?:\.\d+)?)"#, "chartjs"),
            (r#"pdf\.?js[/@.-](\d+\.\d+(?:\.\d+)?)"#, "pdfjs"),
            (r#"next[/@.-](\d+\.\d+(?:\.\d+)?)"#, "next"),
            (r#"svelte[/@.-](\d+\.\d+(?:\.\d+)?)"#, "svelte"),
            (r#"knockout[/@.-](\d+\.\d+(?:\.\d+)?)"#, "knockout"),
            (r#"jszip[/@.-](\d+\.\d+(?:\.\d+)?)"#, "jszip"),
            (r#"mustache[/@.-](\d+\.\d+(?:\.\d+)?)"#, "mustache"),
            (r#"froala[/@.-](\d+\.\d+(?:\.\d+)?)"#, "froala"),
            (r#"plupload[/@.-](\d+\.\d+(?:\.\d+)?)"#, "plupload"),
            (r#"jquery-validation[/@.-](\d+\.\d+(?:\.\d+)?)"#, "jquery-validation"),
            (r#"jquery[.-]mobile[/@.-](\d+\.\d+(?:\.\d+)?)"#, "jquery-mobile"),
            (r#"bootstrap-select[/@.-](\d+\.\d+(?:\.\d+)?)"#, "bootstrap-select"),
            (r#"blueimp-file-upload[/@.-](\d+\.\d+(?:\.\d+)?)"#, "blueimp-file-upload"),
            // Additional libraries
            (r#"showdown[/@.-](\d+\.\d+(?:\.\d+)?)"#, "showdown"),
            (r#"marked[/@.-](\d+\.\d+(?:\.\d+)?)"#, "marked"),
            (r#"video\.?js[/@.-](\d+\.\d+(?:\.\d+)?)"#, "video.js"),
            (r#"serialize-javascript[/@.-](\d+\.\d+(?:\.\d+)?)"#, "serialize-javascript"),
            (r#"js-yaml[/@.-](\d+\.\d+(?:\.\d+)?)"#, "js-yaml"),
            (r#"node-forge[/@.-](\d+\.\d+(?:\.\d+)?)"#, "node-forge"),
            (r#"fast-xml-parser[/@.-](\d+\.\d+(?:\.\d+)?)"#, "fast-xml-parser"),
            (r#"sweetalert2?[/@.-](\d+\.\d+(?:\.\d+)?)"#, "sweetalert2"),
            (r#"summernote[/@.-](\d+\.\d+(?:\.\d+)?)"#, "summernote"),
            (r#"codemirror[/@.-](\d+\.\d+(?:\.\d+)?)"#, "codemirror"),
            (r#"d3[/@.-](\d+\.\d+(?:\.\d+)?)"#, "d3"),
            (r#"socket\.io[/@.-](\d+\.\d+(?:\.\d+)?)"#, "socket.io"),
            (r#"socket\.io-client[/@.-](\d+\.\d+(?:\.\d+)?)"#, "socket.io-client"),
            (r#"dropzone[/@.-](\d+\.\d+(?:\.\d+)?)"#, "dropzone"),
            (r#"quill[/@.-](\d+\.\d+(?:\.\d+)?)"#, "quill"),
            (r#"prismjs[/@.-](\d+\.\d+(?:\.\d+)?)"#, "prismjs"),
            (r#"prism[/@.-](\d+\.\d+(?:\.\d+)?)"#, "prismjs"),
            (r#"highlight\.js[/@.-](\d+\.\d+(?:\.\d+)?)"#, "highlight.js"),
            (r#"hljs[/@.-](\d+\.\d+(?:\.\d+)?)"#, "highlight.js"),
            (r#"sanitize-html[/@.-](\d+\.\d+(?:\.\d+)?)"#, "sanitize-html"),
            (r#"ajv[/@.-](\d+\.\d+(?:\.\d+)?)"#, "ajv"),
            (r#"modernizr[/@.-](\d+\.\d+(?:\.\d+)?)"#, "modernizr"),
            (r#"leaflet[/@.-](\d+\.\d+(?:\.\d+)?)"#, "leaflet"),
            (r#"three[/@.-](\d+\.\d+(?:\.\d+)?)"#, "three"),
            (r#"three\.js[/@.-](\d+\.\d+(?:\.\d+)?)"#, "three"),
            (r#"gsap[/@.-](\d+\.\d+(?:\.\d+)?)"#, "gsap"),
            (r#"owl[.-]carousel[/@.-](\d+\.\d+(?:\.\d+)?)"#, "owl.carousel"),
            (r#"slick[/@.-](\d+\.\d+(?:\.\d+)?)"#, "slick"),
            (r#"requirejs[/@.-](\d+\.\d+(?:\.\d+)?)"#, "requirejs"),
            (r#"require\.js[/@.-](\d+\.\d+(?:\.\d+)?)"#, "requirejs"),
            (r#"systemjs[/@.-](\d+\.\d+(?:\.\d+)?)"#, "systemjs"),
            (r#"system\.js[/@.-](\d+\.\d+(?:\.\d+)?)"#, "systemjs"),
            (r#"hls\.js[/@.-](\d+\.\d+(?:\.\d+)?)"#, "hls.js"),
            (r#"flv\.js[/@.-](\d+\.\d+(?:\.\d+)?)"#, "flv.js"),
            (r#"mediaelement[/@.-](\d+\.\d+(?:\.\d+)?)"#, "mediaelement"),
            (r#"magnific-popup[/@.-](\d+\.\d+(?:\.\d+)?)"#, "magnific-popup"),
            (r#"photoswipe[/@.-](\d+\.\d+(?:\.\d+)?)"#, "photoswipe"),
            (r#"clipboard[/@.-](\d+\.\d+(?:\.\d+)?)"#, "clipboard"),
            (r#"cropperjs[/@.-](\d+\.\d+(?:\.\d+)?)"#, "cropperjs"),
            (r#"cropper\.js[/@.-](\d+\.\d+(?:\.\d+)?)"#, "cropperjs"),
            (r#"toastr[/@.-](\d+\.\d+(?:\.\d+)?)"#, "toastr"),
            (r#"intro\.js[/@.-](\d+\.\d+(?:\.\d+)?)"#, "intro.js"),
            (r#"popper\.js[/@.-](\d+\.\d+(?:\.\d+)?)"#, "popper.js"),
            (r#"@popperjs/core[/@.-](\d+\.\d+(?:\.\d+)?)"#, "popper.js"),
            (r#"xlsx[/@.-](\d+\.\d+(?:\.\d+)?)"#, "xlsx"),
            (r#"sheetjs[/@.-](\d+\.\d+(?:\.\d+)?)"#, "xlsx"),
            (r#"papaparse[/@.-](\d+\.\d+(?:\.\d+)?)"#, "papaparse"),
            (r#"nuxt[/@.-](\d+\.\d+(?:\.\d+)?)"#, "nuxt"),
            (r#"gatsby[/@.-](\d+\.\d+(?:\.\d+)?)"#, "gatsby"),
            (r#"immer[/@.-](\d+\.\d+(?:\.\d+)?)"#, "immer"),
            (r#"json-schema[/@.-](\d+\.\d+(?:\.\d+)?)"#, "json-schema"),
            // minimist removed - Node.js CLI parser, not browser-exploitable
            (r#"qs[/@.-](\d+\.\d+(?:\.\d+)?)"#, "qs"),
            (r#"path-parse[/@.-](\d+\.\d+(?:\.\d+)?)"#, "path-parse"),
            (r#"glob-parent[/@.-](\d+\.\d+(?:\.\d+)?)"#, "glob-parent"),
            (r#"async[/@.-](\d+\.\d+(?:\.\d+)?)"#, "async"),
            (r#"set-value[/@.-](\d+\.\d+(?:\.\d+)?)"#, "set-value"),
            (r#"deep-extend[/@.-](\d+\.\d+(?:\.\d+)?)"#, "deep-extend"),
            (r#"merge[/@.-](\d+\.\d+(?:\.\d+)?)"#, "merge"),
            (r#"flat[/@.-](\d+\.\d+(?:\.\d+)?)"#, "flat"),
            (r#"object-path[/@.-](\d+\.\d+(?:\.\d+)?)"#, "object-path"),
            (r#"dot-prop[/@.-](\d+\.\d+(?:\.\d+)?)"#, "dot-prop"),
            (r#"ini[/@.-](\d+\.\d+(?:\.\d+)?)"#, "ini"),
            (r#"y18n[/@.-](\d+\.\d+(?:\.\d+)?)"#, "y18n"),
            (r#"kind-of[/@.-](\d+\.\d+(?:\.\d+)?)"#, "kind-of"),
            (r#"class-validator[/@.-](\d+\.\d+(?:\.\d+)?)"#, "class-validator"),
            (r#"markdown-it[/@.-](\d+\.\d+(?:\.\d+)?)"#, "markdown-it"),
            (r#"mathjax[/@.-](\d+\.\d+(?:\.\d+)?)"#, "mathjax"),
        ];

        for (pattern, lib_name) in lib_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for caps in re.captures_iter(html) {
                    if let Some(version) = caps.get(1) {
                        detected.push((lib_name.to_string(), version.as_str().to_string()));
                    }
                }
            }
        }

        detected
    }

    fn extract_js_urls(&self, html: &str, base_url: &str) -> Vec<String> {
        let mut urls = Vec::new();

        // Match script src with or without quotes: src="...", src='...', or src=/path/to/file.js
        if let Ok(re) = Regex::new(r#"<script[^>]*\ssrc=["']?([^"'\s>]+)["']?"#) {
            for caps in re.captures_iter(html) {
                if let Some(src) = caps.get(1) {
                    let url = src.as_str();

                    // Build absolute URL
                    let absolute_url = if url.starts_with("http") {
                        url.to_string()
                    } else if url.starts_with("//") {
                        format!("https:{}", url)
                    } else if url.starts_with('/') {
                        if let Ok(parsed) = url::Url::parse(base_url) {
                            format!("{}://{}{}", parsed.scheme(), parsed.host_str().unwrap_or(""), url)
                        } else {
                            continue;
                        }
                    } else {
                        format!("{}/{}", base_url.trim_end_matches('/'), url)
                    };

                    urls.push(absolute_url);
                }
            }
        }

        urls
    }

    fn create_vulnerability(
        &self,
        url: &str,
        library: &str,
        version: &str,
        vuln: &VersionRange,
    ) -> Vulnerability {
        let cve_str = if vuln.cves.is_empty() {
            "N/A".to_string()
        } else {
            vuln.cves.join(", ")
        };

        let cvss = match vuln.severity {
            Severity::Critical => 9.8,
            Severity::High => 7.5,
            Severity::Medium => 5.3,
            Severity::Low => 3.1,
            Severity::Info => 0.0,
        };

        Vulnerability {
            id: format!(
                "merlin_{}_{}_{}",
                library.replace('-', "_"),
                version.replace('.', "_"),
                rand::random::<u16>()
            ),
            vuln_type: format!("Vulnerable JavaScript Library: {} v{}", library, version),
            severity: vuln.severity.clone(),
            confidence: Confidence::High,
            category: "Component with Known Vulnerability".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: "-".to_string(), // No PoC for version detection findings
            description: format!(
                "{} v{} detected - {}. Fixed in version {}.",
                library,
                version,
                vuln.description,
                vuln.to_version
            ),
            evidence: Some(format!(
                "CVE: {} | References: {}",
                cve_str,
                vuln.references.first().cloned().unwrap_or_default()
            )),
            cwe: "CWE-1035".to_string(), // Using Components with Known Vulnerabilities
            cvss,
            verified: true,
            false_positive: false,
            remediation: format!(
                "Upgrade {} from version {} to version {} or later. CVEs: {}. References: {}",
                library,
                version,
                vuln.to_version,
                cve_str,
                vuln.references.join(", ")
            ),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
        }
    }
}
