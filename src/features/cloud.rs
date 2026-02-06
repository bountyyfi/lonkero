// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use super::ProbeContext;
use std::collections::HashMap;

/// Extract cloud misconfiguration features from HTTP response content and headers.
/// 24 features total: 5 storage, 4 metadata/IAM, 6 serverless/container,
/// 3 cloud service misconfig, 6 CI/CD.
pub fn extract_cloud_features(ctx: &ProbeContext, features: &mut HashMap<String, f64>) {
    let body_lower = ctx.response.body.to_lowercase();
    let url_lower = ctx.request_url.to_lowercase();

    // === Storage ===

    // cloud:s3_bucket_public_read — S3 object accessible without auth
    if url_lower.contains(".s3.amazonaws.com")
        || url_lower.contains("s3.")
        || body_lower.contains("<listbucketresult")
    {
        if ctx.response.status == 200 {
            features.insert("cloud:s3_bucket_public_read".into(), 1.0);
        }
    }

    // cloud:s3_bucket_public_write — S3 PUT succeeded without auth
    if url_lower.contains(".s3.amazonaws.com") && ctx.request_method == "PUT" {
        if ctx.response.status < 300 {
            features.insert("cloud:s3_bucket_public_write".into(), 1.0);
        }
    }

    // cloud:s3_bucket_listing — response body contains <ListBucketResult>
    if body_lower.contains("<listbucketresult") {
        features.insert("cloud:s3_bucket_listing".into(), 1.0);
    }

    // cloud:gcs_bucket_public — storage.googleapis.com accessible without auth
    if url_lower.contains("storage.googleapis.com") && ctx.response.status == 200 {
        features.insert("cloud:gcs_bucket_public".into(), 1.0);
    }

    // cloud:azure_blob_public — Azure Blob accessible without SAS token
    if (url_lower.contains(".blob.core.windows.net")
        || url_lower.contains("azure"))
        && !url_lower.contains("sig=")
        && ctx.response.status == 200
    {
        features.insert("cloud:azure_blob_public".into(), 1.0);
    }

    // === Metadata/IAM ===

    // cloud:imds_v1_accessible — 169.254.169.254/latest/meta-data returned data
    if (body_lower.contains("169.254.169.254") || url_lower.contains("169.254.169.254"))
        && ctx.response.status == 200
    {
        features.insert("cloud:imds_v1_accessible".into(), 1.0);
    }

    // cloud:iam_role_credentials_leaked — response contains AccessKeyId + SecretAccessKey
    if (body_lower.contains("accesskeyid") && body_lower.contains("secretaccesskey"))
        || has_aws_key_pattern(&ctx.response.body)
    {
        features.insert("cloud:iam_role_credentials_leaked".into(), 1.0);
    }

    // cloud:service_account_key_leaked — GCP service account key
    if body_lower.contains("\"type\": \"service_account\"")
        || body_lower.contains("\"type\":\"service_account\"")
    {
        if body_lower.contains("private_key") {
            features.insert("cloud:service_account_key_leaked".into(), 1.0);
        }
    }

    // cloud:iam_policy_misconfigured — overly permissive IAM
    if body_lower.contains("\"effect\":\"allow\"")
        || body_lower.contains("\"effect\": \"allow\"")
    {
        if body_lower.contains("\"action\":\"*\"") || body_lower.contains("\"action\": \"*\"") {
            if body_lower.contains("\"resource\":\"*\"")
                || body_lower.contains("\"resource\": \"*\"")
            {
                features.insert("cloud:iam_policy_misconfigured".into(), 1.0);
            }
        }
    }

    // === Serverless/Container ===

    // cloud:lambda_env_leaked — AWS Lambda environment variables in response
    if body_lower.contains("aws_lambda_function_name")
        || body_lower.contains("aws_lambda_log_group")
        || body_lower.contains("_handler")
            && body_lower.contains("aws_region")
    {
        features.insert("cloud:lambda_env_leaked".into(), 1.0);
    }

    // cloud:lambda_layer_accessible — Lambda layer ARN accessible
    if body_lower.contains("arn:aws:lambda") && body_lower.contains(":layer:") {
        features.insert("cloud:lambda_layer_accessible".into(), 1.0);
    }

    // cloud:ecs_task_metadata — ECS task metadata endpoint
    if body_lower.contains("169.254.170.2") || url_lower.contains("169.254.170.2") {
        if ctx.response.status == 200 {
            features.insert("cloud:ecs_task_metadata".into(), 1.0);
        }
    }

    // cloud:k8s_api_unauthenticated — Kubernetes API accessible
    if body_lower.contains("\"kind\":\"namespacelist\"")
        || body_lower.contains("\"kind\": \"namespacelist\"")
        || (body_lower.contains("\"apiversion\":\"v1\"")
            && body_lower.contains("\"kind\""))
    {
        features.insert("cloud:k8s_api_unauthenticated".into(), 1.0);
    }

    // cloud:k8s_dashboard_exposed — K8s dashboard UI accessible
    if body_lower.contains("kubernetes dashboard")
        || body_lower.contains("k8s-dashboard")
    {
        features.insert("cloud:k8s_dashboard_exposed".into(), 1.0);
    }

    // cloud:docker_registry_public — /v2/_catalog returns repository list
    if url_lower.contains("/v2/_catalog") && ctx.response.status == 200 {
        if body_lower.contains("\"repositories\"") {
            features.insert("cloud:docker_registry_public".into(), 1.0);
        }
    }

    // === Cloud service misconfig ===

    // cloud:cognito_pool_misconfigured — self-signup with admin attributes
    if body_lower.contains("cognito") && body_lower.contains("userpool") {
        features.insert("cloud:cognito_pool_misconfigured".into(), 1.0);
    }

    // cloud:firebase_db_public — firebaseio.com returns valid JSON
    if url_lower.contains("firebaseio.com") && ctx.response.status == 200 {
        if body_lower.starts_with('{') || body_lower.starts_with('[') {
            features.insert("cloud:firebase_db_public".into(), 1.0);
        }
    }

    // cloud:elasticsearch_unauthenticated — ES cluster accessible
    if body_lower.contains("\"cluster_name\"")
        || body_lower.contains("/_cat/indices")
        || (body_lower.contains("\"tagline\"")
            && body_lower.contains("you know, for search"))
    {
        features.insert("cloud:elasticsearch_unauthenticated".into(), 1.0);
    }

    // === CI/CD ===

    // cloud:github_actions_secret_leak — GitHub Actions secret in response
    if body_lower.contains("github_token") || body_lower.contains("actions_runtime_token") {
        features.insert("cloud:github_actions_secret_leak".into(), 1.0);
    }

    // cloud:terraform_state_public — Terraform state file accessible
    if body_lower.contains("\"terraform_version\"") && body_lower.contains("\"serial\"") {
        features.insert("cloud:terraform_state_public".into(), 1.0);
    }

    // cloud:jenkins_unauthenticated — Jenkins dashboard accessible
    if body_lower.contains("<title>dashboard [jenkins]</title>")
        || ctx.response.headers.contains_key("x-jenkins")
    {
        features.insert("cloud:jenkins_unauthenticated".into(), 1.0);
    }

    // cloud:gitlab_ci_token_leak — GitLab CI token in response
    if body_lower.contains("ci_job_token") || body_lower.contains("gitlab-ci-token") {
        features.insert("cloud:gitlab_ci_token_leak".into(), 1.0);
    }

    // cloud:aws_sqs_public — SQS unauthenticated ReceiveMessage
    if body_lower.contains("<receivemessageresponse")
        || body_lower.contains("sqs.amazonaws.com")
    {
        if ctx.response.status == 200 {
            features.insert("cloud:aws_sqs_public".into(), 1.0);
        }
    }

    // cloud:aws_sns_public — SNS unauthenticated requests
    if body_lower.contains("<listsubscriptionsresponse")
        || body_lower.contains("sns.amazonaws.com")
    {
        if ctx.response.status == 200 {
            features.insert("cloud:aws_sns_public".into(), 1.0);
        }
    }
}

/// Check for AWS access key pattern (AKIA followed by 16 uppercase alphanumeric chars)
fn has_aws_key_pattern(body: &str) -> bool {
    let bytes = body.as_bytes();
    for i in 0..bytes.len().saturating_sub(19) {
        if &bytes[i..i + 4] == b"AKIA" {
            let rest = &bytes[i + 4..i + 20];
            if rest
                .iter()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::super::tests::*;
    use super::*;

    #[test]
    fn test_s3_bucket_listing() {
        let response = make_response(
            "<?xml version=\"1.0\"?><ListBucketResult><Name>mybucket</Name></ListBucketResult>",
            200,
        );
        let mut ctx = make_ctx("ssrf", "http://s3.amazonaws.com/mybucket", response);
        ctx.request_url = "https://mybucket.s3.amazonaws.com/".to_string();
        let mut features = HashMap::new();
        extract_cloud_features(&ctx, &mut features);
        assert!(features.contains_key("cloud:s3_bucket_listing"));
        assert!(features.contains_key("cloud:s3_bucket_public_read"));
    }

    #[test]
    fn test_imds_accessible() {
        let response = make_response("ami-id\ninstance-id\ninstance-type", 200);
        let mut ctx = make_ctx("ssrf", "http://169.254.169.254/latest/meta-data", response);
        ctx.request_url = "http://169.254.169.254/latest/meta-data".to_string();
        let mut features = HashMap::new();
        extract_cloud_features(&ctx, &mut features);
        assert!(features.contains_key("cloud:imds_v1_accessible"));
    }

    #[test]
    fn test_iam_credentials_leaked() {
        let response = make_response(
            "{\"AccessKeyId\": \"AKIAIOSFODNN7EXAMPLE\", \"SecretAccessKey\": \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"}",
            200,
        );
        let ctx = make_ctx("ssrf", "http://169.254.169.254", response);
        let mut features = HashMap::new();
        extract_cloud_features(&ctx, &mut features);
        assert!(features.contains_key("cloud:iam_role_credentials_leaked"));
    }

    #[test]
    fn test_aws_key_pattern() {
        assert!(has_aws_key_pattern("key=AKIAIOSFODNN7EXAMPLE"));
        assert!(!has_aws_key_pattern("key=NOTANACCESSKEY123"));
        assert!(!has_aws_key_pattern("key=AKIAtooShort"));
    }

    #[test]
    fn test_terraform_state() {
        let response = make_response(
            "{\"version\": 4, \"terraform_version\": \"1.5.0\", \"serial\": 12}",
            200,
        );
        let ctx = make_ctx("traversal", "/terraform.tfstate", response);
        let mut features = HashMap::new();
        extract_cloud_features(&ctx, &mut features);
        assert!(features.contains_key("cloud:terraform_state_public"));
    }

    #[test]
    fn test_jenkins_unauthenticated() {
        let mut response = make_response(
            "<html><head><title>Dashboard [Jenkins]</title></head></html>",
            200,
        );
        response
            .headers
            .insert("x-jenkins".to_string(), "2.414.1".to_string());
        let ctx = make_ctx("traversal", "/", response);
        let mut features = HashMap::new();
        extract_cloud_features(&ctx, &mut features);
        assert!(features.contains_key("cloud:jenkins_unauthenticated"));
    }

    #[test]
    fn test_firebase_public() {
        let response = make_response("{\"users\": [{\"name\": \"admin\"}]}", 200);
        let mut ctx = make_ctx("ssrf", "https://myapp.firebaseio.com/.json", response);
        ctx.request_url = "https://myapp.firebaseio.com/.json".to_string();
        let mut features = HashMap::new();
        extract_cloud_features(&ctx, &mut features);
        assert!(features.contains_key("cloud:firebase_db_public"));
    }

    #[test]
    fn test_elasticsearch_unauthenticated() {
        let response = make_response(
            "{\"name\": \"node-1\", \"cluster_name\": \"production\", \"tagline\": \"You Know, for Search\"}",
            200,
        );
        let ctx = make_ctx("ssrf", "http://10.0.0.1:9200/", response);
        let mut features = HashMap::new();
        extract_cloud_features(&ctx, &mut features);
        assert!(features.contains_key("cloud:elasticsearch_unauthenticated"));
    }
}
