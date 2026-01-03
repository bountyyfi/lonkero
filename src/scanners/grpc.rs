// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use std::sync::Arc;
use tracing::{debug, info};

pub struct GrpcScanner {
    http_client: Arc<HttpClient>,
}

impl GrpcScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan URL for gRPC vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("[gRPC] Scanning: {}", url);

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Test 1: Detect gRPC endpoints
        tests_run += 1;
        let response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => {
                debug!("[NOTE] [gRPC] Could not fetch URL");
                return Ok((vulnerabilities, tests_run));
            }
        };

        let is_grpc = self.detect_grpc_endpoint(&response, url);
        if !is_grpc {
            debug!("[NOTE] [gRPC] Not a gRPC endpoint");
            return Ok((vulnerabilities, tests_run));
        }

        info!("[SUCCESS] [gRPC] gRPC endpoint detected");

        // Test 2: Check for gRPC reflection enabled
        tests_run += 1;
        self.check_grpc_reflection(&response, url, &mut vulnerabilities);

        // Test 3: Check for missing authentication
        tests_run += 1;
        self.check_authentication(&response, url, &mut vulnerabilities);

        // Test 4: Check for insecure transport (plaintext)
        tests_run += 1;
        self.check_insecure_transport(url, &mut vulnerabilities);

        // Test 5: Check for metadata injection
        tests_run += 1;
        self.check_metadata_security(&response, url, &mut vulnerabilities);

        // Test 6: Check for error disclosure
        tests_run += 1;
        self.check_error_disclosure(&response, url, &mut vulnerabilities);

        // Test 7: Check for missing authorization
        tests_run += 1;
        self.check_authorization(&response, url, &mut vulnerabilities);

        info!(
            "[SUCCESS] [gRPC] Completed {} tests, found {} issues",
            tests_run,
            vulnerabilities.len()
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Detect gRPC endpoint
    /// IMPORTANT: This must be STRICT to avoid false positives on normal web pages
    fn detect_grpc_endpoint(&self, response: &crate::http_client::HttpResponse, url: &str) -> bool {
        let url_lower = url.to_lowercase();

        // Check response headers for gRPC indicators - this is the DEFINITIVE check
        if let Some(content_type) = response.header("content-type") {
            if content_type.contains("application/grpc")
                || content_type.contains("application/grpc+proto")
            {
                return true;
            }
        }

        // Check for gRPC-specific headers that are ONLY present in actual gRPC responses
        if response.header("grpc-status").is_some()
            || response.header("grpc-message").is_some()
            || response.header("grpc-encoding").is_some()
        {
            return true;
        }

        // URL must explicitly contain gRPC port (very specific)
        if url_lower.contains(":50051") {
            return true;
        }

        // Do NOT detect based on body content alone!
        // Words like "grpc", "protobuf", "proto3" can appear in documentation,
        // Next.js pages, or any web page discussing these technologies.
        // This causes massive false positives on tech company websites.

        false
    }

    /// Check for gRPC reflection enabled
    fn check_grpc_reflection(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body_lower = response.body.to_lowercase();

        // Check for reflection service indicators
        if body_lower.contains("serverreflection")
            || body_lower.contains("reflection")
            || body_lower.contains("grpc.reflection")
        {
            vulnerabilities.push(self.create_vulnerability(
                "gRPC Server Reflection Enabled",
                url,
                Severity::Medium,
                Confidence::Medium,
                "gRPC server reflection is enabled - exposes service definitions",
                "Server reflection service detected in response".to_string(),
                5.3,
            ));
        }
    }

    /// Check authentication
    fn check_authentication(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body_lower = response.body.to_lowercase();

        // Check for authentication mechanisms
        let has_auth = body_lower.contains("authenticate")
            || body_lower.contains("authorization")
            || body_lower.contains("bearer")
            || body_lower.contains("jwt")
            || response.header("authorization").is_some()
            || response.header("www-authenticate").is_some();

        // If gRPC but no auth indicators
        if (body_lower.contains("grpc") || body_lower.contains("protobuf")) && !has_auth {
            vulnerabilities.push(self.create_vulnerability(
                "gRPC Missing Authentication",
                url,
                Severity::Medium,
                Confidence::Low,
                "gRPC service may lack authentication - verify manually",
                "No authentication mechanisms detected".to_string(),
                5.0,
            ));
        }
    }

    /// Check for insecure transport
    fn check_insecure_transport(&self, url: &str, vulnerabilities: &mut Vec<Vulnerability>) {
        // Check if using HTTP instead of HTTPS for gRPC
        if url.starts_with("http://") && !url.contains("localhost") && !url.contains("127.0.0.1") {
            vulnerabilities.push(self.create_vulnerability(
                "gRPC Using Insecure Transport",
                url,
                Severity::High,
                Confidence::High,
                "gRPC service uses plaintext HTTP - data transmitted unencrypted",
                "gRPC endpoint accessible over unencrypted HTTP".to_string(),
                7.4,
            ));
        }
    }

    /// Check metadata security
    ///
    /// NOTE: This check is ONLY meaningful for confirmed gRPC endpoints.
    /// We look for gRPC-specific metadata handling patterns, NOT generic words.
    fn check_metadata_security(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        // Only check if we have actual gRPC-specific headers in response
        // Generic words like "metadata" or "headers" appear on ANY website
        let has_grpc_metadata_header = response.header("grpc-metadata-bin").is_some()
            || response.header("grpc-metadata").is_some();

        // Check for gRPC-specific metadata patterns in body (must be in gRPC context)
        let body_lower = response.body.to_lowercase();

        // These are SPECIFIC gRPC metadata patterns, not generic words
        let grpc_metadata_patterns = [
            "grpc-metadata-",   // gRPC metadata header prefix
            "metadata.get(",    // gRPC metadata API call
            "metadata.set(",    // gRPC metadata API call
            "frommetadata",     // gRPC metadata extraction
            "incomingmetadata", // gRPC incoming metadata
            "outgoingmetadata", // gRPC outgoing metadata
            "grpc.metadata",    // gRPC metadata object
        ];

        let has_grpc_metadata_code = grpc_metadata_patterns
            .iter()
            .any(|p| body_lower.contains(p));

        // Only flag if we see actual gRPC metadata handling without validation
        if has_grpc_metadata_header || has_grpc_metadata_code {
            // Check for validation patterns
            let validates_metadata = body_lower.contains("validatemetadata")
                || body_lower.contains("metadata.validate")
                || body_lower.contains("sanitizemetadata");

            if !validates_metadata {
                vulnerabilities.push(self.create_vulnerability(
                    "gRPC Metadata Injection Risk",
                    url,
                    Severity::Medium,
                    Confidence::Low,
                    "gRPC metadata may not be validated - potential injection attacks",
                    "gRPC metadata handling detected without apparent validation".to_string(),
                    5.3,
                ));
            }
        }
    }

    /// Check error disclosure
    fn check_error_disclosure(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body_lower = response.body.to_lowercase();

        // Check for verbose error messages
        let error_indicators = vec![
            "stack trace",
            "at line",
            "exception",
            "database error",
            "sql",
            "internal error",
            "debug",
        ];

        let mut found_indicators = Vec::new();
        for indicator in &error_indicators {
            if body_lower.contains(indicator) {
                found_indicators.push(*indicator);
            }
        }

        if found_indicators.len() >= 2 {
            vulnerabilities.push(self.create_vulnerability(
                "gRPC Verbose Error Messages",
                url,
                Severity::Low,
                Confidence::Medium,
                "gRPC service returns verbose error messages - information disclosure",
                format!("Error indicators found: {:?}", found_indicators),
                3.7,
            ));
        }
    }

    /// Check authorization
    fn check_authorization(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body_lower = response.body.to_lowercase();

        // Check for authorization implementation
        let has_authz = body_lower.contains("authorize")
            || body_lower.contains("permission")
            || body_lower.contains("role")
            || body_lower.contains("policy");

        // If gRPC service but no authorization indicators
        if (body_lower.contains("grpc") || body_lower.contains("service"))
            && body_lower.contains("rpc")
            && !has_authz
        {
            vulnerabilities.push(self.create_vulnerability(
                "gRPC Missing Authorization",
                url,
                Severity::Medium,
                Confidence::Low,
                "gRPC service may lack fine-grained authorization - verify manually",
                "No authorization mechanisms detected in RPC methods".to_string(),
                5.3,
            ));
        }
    }

    /// Create vulnerability record
    fn create_vulnerability(
        &self,
        title: &str,
        url: &str,
        severity: Severity,
        confidence: Confidence,
        description: &str,
        evidence: String,
        cvss: f32,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("grpc_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: format!("gRPC Vulnerability - {}", title),
            severity,
            confidence,
            category: "API Security".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: String::new(),
            description: description.to_string(),
            evidence: Some(evidence),
            cwe: "CWE-285".to_string(), // Improper Authorization
            cvss,
            verified: true,
            false_positive: false,
            remediation: r#"IMMEDIATE ACTION REQUIRED:

1. **Disable Server Reflection in Production**
   ```go
   // Go gRPC server
   import "google.golang.org/grpc/reflection"

   s := grpc.NewServer()

   // WRONG - Don't enable reflection in production
   if os.Getenv("ENV") != "production" {
       reflection.Register(s)  // Only in dev/staging
   }
   ```

2. **Implement Strong Authentication**
   ```go
   // Token-based authentication
   import (
       "google.golang.org/grpc"
       "google.golang.org/grpc/metadata"
   )

   // Authentication interceptor
   func authInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
       md, ok := metadata.FromIncomingContext(ctx)
       if !ok {
           return nil, status.Error(codes.Unauthenticated, "missing metadata")
       }

       tokens := md["authorization"]
       if len(tokens) == 0 {
           return nil, status.Error(codes.Unauthenticated, "missing token")
       }

       // Validate JWT token
       claims, err := validateJWT(tokens[0])
       if err != nil {
           return nil, status.Error(codes.Unauthenticated, "invalid token")
       }

       // Add claims to context
       ctx = context.WithValue(ctx, "user", claims)
       return handler(ctx, req)
   }

   // Register interceptor
   s := grpc.NewServer(
       grpc.UnaryInterceptor(authInterceptor),
   )
   ```

3. **Always Use TLS (gRPC over HTTPS)**
   ```go
   // Load TLS credentials
   creds, err := credentials.NewServerTLSFromFile("cert.pem", "key.pem")
   if err != nil {
       log.Fatalf("Failed to load TLS keys: %v", err)
   }

   // Create server with TLS
   s := grpc.NewServer(grpc.Creds(creds))

   // Client connects with TLS
   creds, _ := credentials.NewClientTLSFromFile("ca.pem", "")
   conn, err := grpc.Dial("example.com:50051",
       grpc.WithTransportCredentials(creds),
   )
   ```

4. **Implement Method-Level Authorization**
   ```go
   // Authorization interceptor
   func authzInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
       user := ctx.Value("user").(Claims)

       // Check permissions for specific RPC method
       if !hasPermission(user, info.FullMethod) {
           return nil, status.Error(codes.PermissionDenied, "insufficient permissions")
       }

       return handler(ctx, req)
   }

   func hasPermission(user Claims, method string) bool {
       permissions := map[string][]string{
           "/api.UserService/DeleteUser": {"admin"},
           "/api.UserService/GetUser":     {"admin", "user"},
       }

       required, exists := permissions[method]
       if !exists {
           return false
       }

       for _, role := range required {
           if user.Role == role {
               return true
           }
       }
       return false
   }
   ```

5. **Validate and Sanitize Metadata**
   ```go
   func validateMetadata(ctx context.Context) error {
       md, ok := metadata.FromIncomingContext(ctx)
       if !ok {
           return nil
       }

       // Validate specific metadata keys
       if requestID := md["request-id"]; len(requestID) > 0 {
           if !isValidUUID(requestID[0]) {
               return status.Error(codes.InvalidArgument, "invalid request-id")
           }
       }

       // Prevent metadata injection
       for key := range md {
           if strings.Contains(key, "grpc-") {
               return status.Error(codes.InvalidArgument, "reserved metadata prefix")
           }
       }

       return nil
   }
   ```

6. **Implement Input Validation**
   ```go
   // Use Protocol Buffer validation
   import "github.com/envoyproxy/protoc-gen-validate/validate"

   // In .proto file
   message CreateUserRequest {
     string email = 1 [(validate.rules).string.email = true];
     string name = 2 [(validate.rules).string = {min_len: 1, max_len: 100}];
     int32 age = 3 [(validate.rules).int32 = {gte: 0, lte: 120}];
   }

   // Validation interceptor
   func validationInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
       if v, ok := req.(interface{ Validate() error }); ok {
           if err := v.Validate(); err != nil {
               return nil, status.Error(codes.InvalidArgument, err.Error())
           }
       }
       return handler(ctx, req)
   }
   ```

7. **Sanitize Error Messages**
   ```go
   // Error handling middleware
   func errorInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
       resp, err := handler(ctx, req)

       if err != nil {
           // Log full error internally
           log.Printf("RPC error: %v", err)

           // Return sanitized error to client
           if os.Getenv("ENV") == "production" {
               return nil, status.Error(codes.Internal, "Internal server error")
           }
           return nil, err
       }

       return resp, nil
   }
   ```

8. **Implement Rate Limiting**
   ```go
   import "golang.org/x/time/rate"

   // Per-user rate limiter
   var limiters = make(map[string]*rate.Limiter)

   func rateLimitInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
       user := ctx.Value("user").(Claims)

       limiter, exists := limiters[user.ID]
       if !exists {
           limiter = rate.NewLimiter(rate.Limit(100), 10)  // 100 req/s, burst 10
           limiters[user.ID] = limiter
       }

       if !limiter.Allow() {
           return nil, status.Error(codes.ResourceExhausted, "rate limit exceeded")
       }

       return handler(ctx, req)
   }
   ```

9. **Security Headers and Metadata**
   ```go
   // Add security headers
   func securityHeaderInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
       // Add security-related metadata to response
       header := metadata.Pairs(
           "x-content-type-options", "nosniff",
           "x-frame-options", "DENY",
       )
       grpc.SendHeader(ctx, header)

       return handler(ctx, req)
   }
   ```

10. **Security Checklist**
    - [ ] Server reflection disabled in production
    - [ ] All connections use TLS/HTTPS
    - [ ] Authentication required for all RPCs
    - [ ] Method-level authorization implemented
    - [ ] Input validation on all requests
    - [ ] Metadata validated and sanitized
    - [ ] Error messages sanitized
    - [ ] Rate limiting implemented
    - [ ] Comprehensive logging enabled
    - [ ] Dead-letter queue for failed requests
    - [ ] Health checks secured
    - [ ] Monitoring and alerting active

11. **Testing & Monitoring**
    - Use grpcurl for testing: `grpcurl -plaintext localhost:50051 list`
    - Test with BloomRPC or Postman
    - Monitor authentication failures
    - Alert on rate limit violations
    - Track RPC latency and errors

References:
- gRPC Security Guide: https://grpc.io/docs/guides/auth/
- gRPC Best Practices: https://grpc.io/docs/guides/performance/
- Protocol Buffers Validation: https://github.com/envoyproxy/protoc-gen-validate
"#.to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
        }
    }
}

// UUID generation helper
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
    use std::collections::HashMap;

    #[test]
    fn test_grpc_detection() {
        let scanner = GrpcScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let mut headers = HashMap::new();
        headers.insert(
            "content-type".to_string(),
            "application/grpc+proto".to_string(),
        );

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: String::new(),
            headers,
            duration_ms: 100,
        };

        assert!(scanner.detect_grpc_endpoint(&response, "https://api.example.com:50051"));
    }

    #[test]
    fn test_reflection_detection() {
        let scanner = GrpcScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: r#"{"services": ["grpc.reflection.v1alpha.ServerReflection"]}"#.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_grpc_reflection(&response, "https://api.example.com:50051", &mut vulns);

        assert_eq!(vulns.len(), 1, "Should detect enabled reflection");
        assert_eq!(vulns[0].severity, Severity::Medium);
    }

    #[test]
    fn test_insecure_transport() {
        let scanner = GrpcScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let mut vulns = Vec::new();
        scanner.check_insecure_transport("http://api.example.com:50051", &mut vulns);

        assert_eq!(vulns.len(), 1, "Should detect insecure HTTP");
        assert_eq!(vulns[0].severity, Severity::High);
    }

    #[test]
    fn test_localhost_exception() {
        let scanner = GrpcScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let mut vulns = Vec::new();
        scanner.check_insecure_transport("http://localhost:50051", &mut vulns);

        assert_eq!(vulns.len(), 0, "Should not flag localhost HTTP");
    }

    #[test]
    fn test_no_false_positive() {
        let scanner = GrpcScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: "<html><body>Normal page</body></html>".to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        assert!(!scanner.detect_grpc_endpoint(&response, "https://example.com"));
    }
}
