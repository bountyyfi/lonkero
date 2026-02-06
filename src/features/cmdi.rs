// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use super::ProbeContext;
use std::collections::HashMap;

/// Extract Command Injection features from a probe response
pub fn extract_cmdi_features(ctx: &ProbeContext, features: &mut HashMap<String, f64>) {
    let body = &ctx.response.body;
    let body_lower = body.to_lowercase();

    // cmdi:os_output_detected - common OS command output patterns
    let os_patterns = [
        "uid=",              // id command
        "root:x:",           // /etc/passwd
        "www-data",          // Linux user
        "total ",            // ls -la output
        "drwx",              // directory listing
        "Directory of",      // Windows dir command
        "Volume Serial",     // Windows dir command
        "Windows IP Config", // ipconfig
        "inet ",             // ifconfig
    ];

    for pattern in &os_patterns {
        if body.contains(pattern) && !ctx.baseline.body.contains(pattern) {
            features.insert("cmdi:os_output_detected".into(), 0.95);
            break;
        }
    }

    // cmdi:etc_passwd_leaked
    if body.contains("root:x:0:0") || body.contains("root:*:0:0") {
        features.insert("cmdi:etc_passwd_leaked".into(), 1.0);
    }

    // cmdi:command_error_message
    let cmd_errors = [
        "command not found",
        "not recognized as an internal",
        "sh: ",
        "bash: ",
        "cmd.exe",
        "Permission denied",
        "No such file or directory",
    ];
    for err in &cmd_errors {
        if body_lower.contains(&err.to_lowercase()) && !ctx.baseline.body.to_lowercase().contains(&err.to_lowercase()) {
            features.insert("cmdi:command_error_message".into(), 0.85);
            break;
        }
    }

    // Time-based detection for command injection
    if let Some(injected_delay) = ctx.injected_delay {
        let actual_delay_s = (ctx.response.response_time_ms as f64) / 1000.0;
        let baseline_s = (ctx.baseline.response_time_ms as f64) / 1000.0;
        let extra_delay = actual_delay_s - baseline_s;

        if extra_delay > (injected_delay * 0.7) {
            features.insert(
                "cmdi:time_delay_detected".into(),
                (extra_delay / injected_delay).min(1.0),
            );
        }
    }

    // cmdi:waf_blocked
    if ctx.response.status == 403
        || body_lower.contains("blocked")
        || body_lower.contains("waf")
        || body_lower.contains("firewall")
    {
        features.insert("cmdi:waf_blocked".into(), 1.0);
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::*;
    use super::*;

    #[test]
    fn test_etc_passwd_leak() {
        let response = make_response("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:", 200);
        let ctx = make_ctx("cmdi", ";cat /etc/passwd", response);
        let mut features = HashMap::new();
        extract_cmdi_features(&ctx, &mut features);

        assert!(features.contains_key("cmdi:etc_passwd_leaked"));
        assert!(features.contains_key("cmdi:os_output_detected"));
    }

    #[test]
    fn test_command_error() {
        let response = make_response("sh: 1: test_cmd: not found", 200);
        let ctx = make_ctx("cmdi", ";test_cmd", response);
        let mut features = HashMap::new();
        extract_cmdi_features(&ctx, &mut features);

        assert!(features.contains_key("cmdi:command_error_message"));
    }

    #[test]
    fn test_cmdi_time_based() {
        let mut response = make_response("OK", 200);
        response.response_time_ms = 5100;
        let mut ctx = make_ctx("cmdi", ";sleep 5", response);
        ctx.injected_delay = Some(5.0);
        ctx.baseline.response_time_ms = 100;

        let mut features = HashMap::new();
        extract_cmdi_features(&ctx, &mut features);

        assert!(features.contains_key("cmdi:time_delay_detected"));
    }
}
