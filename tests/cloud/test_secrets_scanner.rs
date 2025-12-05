// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Cloud Secrets Scanner Unit Tests
 * Tests for secret detection patterns and entropy calculation
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

#[cfg(test)]
mod tests {
    use lonkero_scanner::scanners::cloud::CloudSecretsScanner;

    #[test]
    fn test_entropy_calculation_high() {
        let scanner = CloudSecretsScanner::new();
        let high_entropy_string = "aK3!pQz9@mN7xR5$vB2";
        let entropy = scanner.calculate_entropy(high_entropy_string);

        assert!(entropy > 3.5, "High entropy string should have entropy > 3.5");
    }

    #[test]
    fn test_entropy_calculation_low() {
        let scanner = CloudSecretsScanner::new();
        let low_entropy_string = "aaaaaaaaaa";
        let entropy = scanner.calculate_entropy(low_entropy_string);

        assert!(entropy < 1.0, "Low entropy string should have entropy < 1.0");
    }

    #[test]
    fn test_aws_access_key_detection() {
        let scanner = CloudSecretsScanner::new();
        let text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let findings = scanner.scan_text_for_secrets(text);

        assert!(!findings.is_empty(), "Should detect AWS access key");
    }

    #[test]
    fn test_aws_secret_key_detection() {
        let scanner = CloudSecretsScanner::new();
        let text = "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let findings = scanner.scan_text_for_secrets(text);

        assert!(!findings.is_empty(), "Should detect AWS secret key");
    }

    #[test]
    fn test_gcp_api_key_detection() {
        let scanner = CloudSecretsScanner::new();
        let text = "api_key: AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe";
        let findings = scanner.scan_text_for_secrets(text);

        assert!(!findings.is_empty(), "Should detect GCP API key");
    }

    #[test]
    fn test_private_key_detection() {
        let scanner = CloudSecretsScanner::new();
        let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
        let findings = scanner.scan_text_for_secrets(text);

        assert!(!findings.is_empty(), "Should detect private key");
    }

    #[test]
    fn test_slack_token_detection() {
        let scanner = CloudSecretsScanner::new();
        let text = "SLACK_TOKEN=xoxb-FAKE-TOKEN-FOR-TESTING-ONLY";
        let findings = scanner.scan_text_for_secrets(text);

        assert!(!findings.is_empty(), "Should detect Slack token");
    }

    #[test]
    fn test_github_token_detection() {
        let scanner = CloudSecretsScanner::new();
        let text = "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz";
        let findings = scanner.scan_text_for_secrets(text);

        assert!(!findings.is_empty(), "Should detect GitHub token");
    }

    #[test]
    fn test_no_false_positives() {
        let scanner = CloudSecretsScanner::new();
        let text = "This is a normal text without any secrets.";
        let findings = scanner.scan_text_for_secrets(text);

        assert!(findings.is_empty(), "Should not detect secrets in normal text");
    }

    #[test]
    fn test_password_detection() {
        let scanner = CloudSecretsScanner::new();
        let text = "password=MySup3rS3cr3tP@ssw0rd";
        let findings = scanner.scan_text_for_secrets(text);

        assert!(!findings.is_empty(), "Should detect password");
    }

    #[test]
    fn test_database_connection_string() {
        let scanner = CloudSecretsScanner::new();
        let text = "DATABASE_URL=postgresql://user:password@localhost:5432/dbname";
        let findings = scanner.scan_text_for_secrets(text);

        assert!(!findings.is_empty(), "Should detect database connection string");
    }

    #[test]
    fn test_multiple_secrets_in_text() {
        let scanner = CloudSecretsScanner::new();
        let text = r#"
            AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
            AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
            DATABASE_URL=mysql://user:pass@localhost:3306/db
        "#;
        let findings = scanner.scan_text_for_secrets(text);

        assert!(findings.len() >= 2, "Should detect multiple secrets");
    }

    #[test]
    fn test_confidence_calculation() {
        let scanner = CloudSecretsScanner::new();

        let low_confidence = scanner.calculate_confidence(3.0, 4.0);
        let high_confidence = scanner.calculate_confidence(8.0, 4.0);

        assert!(low_confidence < high_confidence, "Higher entropy should give higher confidence");
        assert!(high_confidence <= 100.0, "Confidence should not exceed 100%");
    }
}
