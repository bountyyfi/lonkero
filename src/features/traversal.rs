// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use super::ProbeContext;
use std::collections::HashMap;

/// Extract Path Traversal features from a probe response
pub fn extract_traversal_features(ctx: &ProbeContext, features: &mut HashMap<String, f64>) {
    let body = &ctx.response.body;

    // traversal:etc_passwd_content - Linux passwd file content
    if body.contains("root:x:0:0") || body.contains("root:*:0:0") {
        features.insert("traversal:etc_passwd_content".into(), 1.0);
    }

    // traversal:etc_shadow_content
    if body.contains("root:$") || body.contains("root:!") {
        features.insert("traversal:etc_shadow_content".into(), 1.0);
    }

    // traversal:windows_system_file
    if body.contains("[boot loader]")    // boot.ini
        || body.contains("[operating systems]")
        || body.contains("[extensions]") // win.ini
    {
        features.insert("traversal:windows_system_file".into(), 1.0);
    }

    // traversal:known_config_file - application config files
    let config_patterns = [
        "DB_PASSWORD",
        "DATABASE_URL",
        "SECRET_KEY",
        "AWS_SECRET",
        "PRIVATE_KEY",
        "-----BEGIN",
        "<?php",
        "<?xml version",
    ];
    for pattern in &config_patterns {
        if body.contains(pattern) && !ctx.baseline.body.contains(pattern) {
            features.insert("traversal:known_config_file".into(), 0.9);
            break;
        }
    }

    // traversal:directory_listing
    if (body.contains("Index of /") || body.contains("Directory listing"))
        && !ctx.baseline.body.contains("Index of /")
    {
        features.insert("traversal:directory_listing".into(), 0.85);
    }

    // traversal:path_in_error - path disclosed in error message
    let path_patterns = ["/var/www", "/home/", "/usr/", "/opt/", "C:\\", "D:\\"];
    for pattern in &path_patterns {
        if body.contains(pattern) && !ctx.baseline.body.contains(pattern) {
            features.insert("traversal:path_in_error".into(), 0.8);
            break;
        }
    }

    // traversal:null_byte_bypass
    if ctx.probe_payload.contains("%00") || ctx.probe_payload.contains('\0') {
        if ctx.response.status == 200 && ctx.response.body_bytes != ctx.baseline.body_bytes {
            features.insert("traversal:null_byte_bypass".into(), 0.9);
        }
    }

    // traversal:waf_blocked
    if ctx.response.status == 403
        || ctx.response.body.to_lowercase().contains("blocked")
        || ctx.response.body.to_lowercase().contains("waf")
    {
        features.insert("traversal:waf_blocked".into(), 1.0);
    }

    // FP suppressor: traversal:404_on_traversal - server returned 404, path doesn't exist
    if ctx.response.status == 404 {
        features.insert("traversal:404_on_traversal".into(), 1.0);
    }

    // FP suppressor: traversal:same_response_all_paths - response body identical to baseline
    if ctx.response.body == ctx.baseline.body {
        features.insert("traversal:same_response_all_paths".into(), 1.0);
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::*;
    use super::*;

    #[test]
    fn test_etc_passwd_traversal() {
        let response = make_response(
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:",
            200,
        );
        let ctx = make_ctx("traversal", "../../../../etc/passwd", response);
        let mut features = HashMap::new();
        extract_traversal_features(&ctx, &mut features);

        assert!(features.contains_key("traversal:etc_passwd_content"));
    }

    #[test]
    fn test_config_file_leak() {
        let response = make_response(
            "DB_PASSWORD=secretpass123\nDATABASE_URL=postgres://...",
            200,
        );
        let ctx = make_ctx("traversal", "../../../../.env", response);
        let mut features = HashMap::new();
        extract_traversal_features(&ctx, &mut features);

        assert!(features.contains_key("traversal:known_config_file"));
    }

    #[test]
    fn test_windows_system_file() {
        let response = make_response(
            "[boot loader]\ntimeout=30\n[operating systems]",
            200,
        );
        let ctx = make_ctx("traversal", "..\\..\\boot.ini", response);
        let mut features = HashMap::new();
        extract_traversal_features(&ctx, &mut features);

        assert!(features.contains_key("traversal:windows_system_file"));
    }
}
