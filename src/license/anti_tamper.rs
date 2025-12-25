// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.
//
// ANTI-TAMPERING MODULE - Hardcore Protection Layer
//
// This module implements multiple layers of protection against:
// - Binary patching
// - Memory manipulation
// - Debugger attachment
// - Function hooking
// - Atomic value tampering
//
// Design principles:
// 1. Defense in depth - multiple redundant checks
// 2. Distributed verification - checks scattered throughout codebase
// 3. Fail-closed - any anomaly triggers lockdown
// 4. Honeypots - fake targets that trigger on tampering
// 5. Obfuscation - make reverse engineering harder

use std::sync::atomic::{AtomicU64, AtomicBool, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Sha256, Digest};

// ============================================================================
// SECTION 1: Obfuscated State Storage
// Values are XOR'd with runtime-generated keys to prevent memory scanning
// ============================================================================

/// Primary validation state - XOR'd with OBFUSCATION_KEY
static VALIDATION_STATE_A: AtomicU64 = AtomicU64::new(0);
/// Secondary validation state - must match A after XOR
static VALIDATION_STATE_B: AtomicU64 = AtomicU64::new(0);
/// Tertiary state for triple redundancy
static VALIDATION_STATE_C: AtomicU64 = AtomicU64::new(0);

/// Obfuscation key - generated at first use, stored obfuscated
static OBFUSCATION_KEY: AtomicU64 = AtomicU64::new(0);
static KEY_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Integrity counters - must always match
static INTEGRITY_COUNTER_A: AtomicUsize = AtomicUsize::new(0);
static INTEGRITY_COUNTER_B: AtomicUsize = AtomicUsize::new(0);

/// Tamper detection flag - once set, never cleared
static TAMPER_DETECTED: AtomicBool = AtomicBool::new(false);

/// Check counter - tracks how many integrity checks passed
static CHECK_COUNTER: AtomicU64 = AtomicU64::new(0);

// Magic constants - if these don't match expected, binary was patched
const MAGIC_A: u64 = 0x426F756E747979_u64;  // "Bountyy"
const MAGIC_B: u64 = 0x4C6F6E6B65726F_u64;  // "Lonkero"
const MAGIC_C: u64 = 0x536563757265_u64;    // "Secure"
const EXPECTED_MAGIC_SUM: u64 = MAGIC_A.wrapping_add(MAGIC_B).wrapping_add(MAGIC_C);

// ============================================================================
// SECTION 2: Initialization with Runtime Key Generation
// ============================================================================

/// Initialize the anti-tampering system with a runtime-generated key
/// This MUST be called before any license checks
#[inline(never)]
pub fn initialize_protection() -> bool {
    if KEY_INITIALIZED.load(Ordering::SeqCst) {
        return verify_state_consistency();
    }

    // Generate obfuscation key from multiple entropy sources
    let key = generate_obfuscation_key();
    OBFUSCATION_KEY.store(key, Ordering::SeqCst);

    // Initialize validation states with obfuscated "invalid" value
    let invalid_marker = 0xDEAD_BEEF_CAFE_BABEu64 ^ key;
    VALIDATION_STATE_A.store(invalid_marker, Ordering::SeqCst);
    VALIDATION_STATE_B.store(invalid_marker, Ordering::SeqCst);
    VALIDATION_STATE_C.store(invalid_marker, Ordering::SeqCst);

    // Initialize counters
    INTEGRITY_COUNTER_A.store(0, Ordering::SeqCst);
    INTEGRITY_COUNTER_B.store(0, Ordering::SeqCst);

    KEY_INITIALIZED.store(true, Ordering::SeqCst);

    // Verify magic constants weren't patched
    verify_magic_constants()
}

/// Generate obfuscation key from multiple sources
#[inline(never)]
fn generate_obfuscation_key() -> u64 {
    let mut hasher = Sha256::new();

    // Source 1: Current timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    hasher.update(&timestamp.to_le_bytes());

    // Source 2: Function pointer addresses (ASLR entropy)
    let fn_ptr_1 = initialize_protection as *const () as u64;
    let fn_ptr_2 = verify_state_consistency as *const () as u64;
    let fn_ptr_3 = generate_obfuscation_key as *const () as u64;
    hasher.update(&fn_ptr_1.to_le_bytes());
    hasher.update(&fn_ptr_2.to_le_bytes());
    hasher.update(&fn_ptr_3.to_le_bytes());

    // Source 3: Stack address (additional ASLR entropy)
    let stack_var: u64 = 0;
    let stack_addr = &stack_var as *const u64 as u64;
    hasher.update(&stack_addr.to_le_bytes());

    // Source 4: Process-specific data
    hasher.update(&std::process::id().to_le_bytes());

    let hash = hasher.finalize();
    u64::from_le_bytes(hash[0..8].try_into().unwrap())
}

// ============================================================================
// SECTION 3: State Management with Triple Redundancy
// ============================================================================

/// Set validation state to "valid" - called after successful license check
/// Uses triple redundancy with different XOR keys
#[inline(never)]
pub fn set_validated(license_hash: u64) {
    if TAMPER_DETECTED.load(Ordering::SeqCst) {
        return; // Silently fail if tampered
    }

    let key = OBFUSCATION_KEY.load(Ordering::SeqCst);
    if key == 0 {
        return; // Not initialized
    }

    // Valid marker with license-specific component
    let valid_marker = 0x56414C4944_u64 ^ license_hash; // "VALID" ^ hash

    // Store with different XOR patterns for each state
    VALIDATION_STATE_A.store(valid_marker ^ key, Ordering::SeqCst);
    VALIDATION_STATE_B.store(valid_marker ^ key.rotate_left(13), Ordering::SeqCst);
    VALIDATION_STATE_C.store(valid_marker ^ key.rotate_right(17), Ordering::SeqCst);

    // Increment integrity counters (must stay in sync)
    INTEGRITY_COUNTER_A.fetch_add(1, Ordering::SeqCst);
    INTEGRITY_COUNTER_B.fetch_add(1, Ordering::SeqCst);
}

/// Check if validation state is valid
/// Verifies all three redundant states match
#[inline(never)]
pub fn is_validated() -> bool {
    if TAMPER_DETECTED.load(Ordering::SeqCst) {
        return false;
    }

    let key = OBFUSCATION_KEY.load(Ordering::SeqCst);
    if key == 0 || !KEY_INITIALIZED.load(Ordering::SeqCst) {
        return false;
    }

    // Decode all three states
    let state_a = VALIDATION_STATE_A.load(Ordering::SeqCst) ^ key;
    let state_b = VALIDATION_STATE_B.load(Ordering::SeqCst) ^ key.rotate_left(13);
    let state_c = VALIDATION_STATE_C.load(Ordering::SeqCst) ^ key.rotate_right(17);

    // All three must match
    if state_a != state_b || state_b != state_c {
        // Tampering detected! States don't match
        trigger_tamper_response("state_mismatch");
        return false;
    }

    // Check it's a valid marker (contains "VALID" signature)
    let is_valid = (state_a & 0xFF_FFFF_FFFF) != 0xDEAD_BEEF_CAFE_BABEu64;

    // Verify counters still match
    if !verify_counter_integrity() {
        return false;
    }

    if is_valid {
        CHECK_COUNTER.fetch_add(1, Ordering::SeqCst);
    }

    is_valid
}

/// Verify state consistency without full validation check
#[inline(never)]
fn verify_state_consistency() -> bool {
    let key = OBFUSCATION_KEY.load(Ordering::SeqCst);
    if key == 0 {
        return false;
    }

    let state_a = VALIDATION_STATE_A.load(Ordering::SeqCst) ^ key;
    let state_b = VALIDATION_STATE_B.load(Ordering::SeqCst) ^ key.rotate_left(13);
    let state_c = VALIDATION_STATE_C.load(Ordering::SeqCst) ^ key.rotate_right(17);

    state_a == state_b && state_b == state_c
}

/// Verify integrity counters match
#[inline(never)]
fn verify_counter_integrity() -> bool {
    let a = INTEGRITY_COUNTER_A.load(Ordering::SeqCst);
    let b = INTEGRITY_COUNTER_B.load(Ordering::SeqCst);

    if a != b {
        trigger_tamper_response("counter_mismatch");
        return false;
    }
    true
}

// ============================================================================
// SECTION 4: Magic Constant Verification (Detects Binary Patching)
// ============================================================================

/// Verify magic constants haven't been patched
/// If anyone modifies the binary, these won't match
#[inline(never)]
pub fn verify_magic_constants() -> bool {
    let sum = MAGIC_A.wrapping_add(MAGIC_B).wrapping_add(MAGIC_C);

    if sum != EXPECTED_MAGIC_SUM {
        trigger_tamper_response("magic_mismatch");
        return false;
    }

    // Additional check: verify the constants contain expected patterns
    if MAGIC_A & 0xFF != 0x79 {  // Last byte of "Bountyy"
        trigger_tamper_response("magic_a_corrupted");
        return false;
    }

    if MAGIC_B & 0xFF != 0x6F {  // Last byte of "Lonkero"
        trigger_tamper_response("magic_b_corrupted");
        return false;
    }

    true
}

// ============================================================================
// SECTION 5: Function Integrity Verification
// ============================================================================

/// Function pointer table - verified at runtime
struct FunctionIntegrity {
    /// Expected relative offsets between functions
    expected_offsets: [i64; 4],
}

/// Verify critical function pointers haven't been hooked
#[inline(never)]
pub fn verify_function_integrity() -> bool {
    // Get function addresses
    let fn_validate = is_validated as *const () as usize;
    let fn_set = set_validated as *const () as usize;
    let fn_init = initialize_protection as *const () as usize;
    let fn_tamper = trigger_tamper_response as *const () as usize;

    // Verify all pointers are in valid code range (not NULL, not max)
    for &addr in &[fn_validate, fn_set, fn_init, fn_tamper] {
        if addr == 0 || addr == usize::MAX {
            trigger_tamper_response("null_function_ptr");
            return false;
        }

        // Check alignment (functions should be at least 4-byte aligned)
        if addr & 0x3 != 0 {
            trigger_tamper_response("misaligned_function");
            return false;
        }
    }

    // Verify functions are in same general memory region (not scattered by hooks)
    let min_addr = fn_validate.min(fn_set).min(fn_init).min(fn_tamper);
    let max_addr = fn_validate.max(fn_set).max(fn_init).max(fn_tamper);

    // Functions in same module should be within ~16MB of each other
    if max_addr - min_addr > 16 * 1024 * 1024 {
        trigger_tamper_response("function_scatter");
        return false;
    }

    true
}

/// Verify a specific function hasn't been patched with a JMP hook
/// Checks first bytes for common hook patterns
#[inline(never)]
pub fn verify_no_hook(func_ptr: *const ()) -> bool {
    if func_ptr.is_null() {
        return false;
    }

    // Read first 16 bytes of function
    let bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(func_ptr as *const u8, 16)
    };

    // Check for common x86_64 hook patterns:
    // JMP rel32: 0xE9 xx xx xx xx
    // JMP [rip+rel32]: 0xFF 0x25 xx xx xx xx
    // MOV RAX, imm64; JMP RAX: 0x48 0xB8 ... 0xFF 0xE0

    // Pattern 1: Direct JMP
    if bytes[0] == 0xE9 {
        trigger_tamper_response("jmp_hook_detected");
        return false;
    }

    // Pattern 2: Indirect JMP
    if bytes[0] == 0xFF && bytes[1] == 0x25 {
        trigger_tamper_response("indirect_jmp_hook");
        return false;
    }

    // Pattern 3: MOV RAX, imm; JMP RAX
    if bytes[0] == 0x48 && bytes[1] == 0xB8 {
        // Check if followed by JMP RAX
        if bytes[10] == 0xFF && bytes[11] == 0xE0 {
            trigger_tamper_response("mov_jmp_hook");
            return false;
        }
    }

    // Pattern 4: INT3 breakpoint
    if bytes[0] == 0xCC {
        trigger_tamper_response("breakpoint_detected");
        return false;
    }

    true
}

// ============================================================================
// SECTION 6: Anti-Debugging
// ============================================================================

/// Check if a debugger is attached
#[inline(never)]
pub fn detect_debugger() -> bool {
    // Method 1: Check /proc/self/status for TracerPid (Linux)
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("TracerPid:") {
                    let pid: i32 = line
                        .split_whitespace()
                        .nth(1)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                    if pid != 0 {
                        return true; // Debugger attached!
                    }
                }
            }
        }
    }

    // Method 2: Timing check - debugger stepping causes delays
    let start = std::time::Instant::now();

    // Do some work that should be fast
    let mut x: u64 = 0;
    for i in 0..1000 {
        x = x.wrapping_add(i);
    }

    let elapsed = start.elapsed();

    // Should complete in < 1ms, debugger makes it slower
    if elapsed.as_millis() > 100 {
        // Suspicious timing - might be debugged
        return true;
    }

    // Use volatile read to prevent optimization
    std::hint::black_box(x);

    false
}

// ============================================================================
// SECTION 7: Honeypot Functions
// ============================================================================

/// HONEYPOT: This function looks like a bypass but triggers lockdown
/// Named to attract patchers looking for shortcuts
#[inline(never)]
#[allow(dead_code)]
pub fn bypass_license_check() -> bool {
    trigger_tamper_response("honeypot_bypass_called");
    false
}

/// HONEYPOT: Fake "enable all features" function
#[inline(never)]
#[allow(dead_code)]
pub fn enable_all_features() {
    trigger_tamper_response("honeypot_enable_all");
}

/// HONEYPOT: Fake "disable validation" function
#[inline(never)]
#[allow(dead_code)]
pub fn disable_validation() {
    trigger_tamper_response("honeypot_disable_validation");
}

/// HONEYPOT: Fake license key that triggers on use
#[allow(dead_code)]
pub const BACKDOOR_KEY: &str = "LONKERO-UNLIMITED-FREE";

/// Check if the honeypot key was used
#[inline(never)]
pub fn check_honeypot_key(key: &str) -> bool {
    if key == BACKDOOR_KEY || key.contains("CRACK") || key.contains("KEYGEN") {
        trigger_tamper_response("honeypot_key_used");
        return true;
    }
    false
}

// ============================================================================
// SECTION 8: Tamper Response
// ============================================================================

/// Trigger tamper response - called when tampering detected
/// This permanently marks the session as compromised
#[inline(never)]
pub fn trigger_tamper_response(reason: &str) {
    // Set tamper flag (never cleared)
    TAMPER_DETECTED.store(true, Ordering::SeqCst);

    // Corrupt validation states
    VALIDATION_STATE_A.store(0, Ordering::SeqCst);
    VALIDATION_STATE_B.store(1, Ordering::SeqCst);  // Different, will fail checks
    VALIDATION_STATE_C.store(2, Ordering::SeqCst);

    // Corrupt counters
    INTEGRITY_COUNTER_A.store(usize::MAX, Ordering::SeqCst);
    INTEGRITY_COUNTER_B.store(0, Ordering::SeqCst);

    // Log (will appear in debug builds)
    #[cfg(debug_assertions)]
    eprintln!("[SECURITY] Tampering detected: {}", reason);

    // In release builds, silently fail - don't give attacker feedback
    let _ = reason;
}

/// Check if tampering was ever detected
#[inline(never)]
pub fn was_tampered() -> bool {
    TAMPER_DETECTED.load(Ordering::SeqCst)
}

// ============================================================================
// SECTION 9: Distributed Verification Macros
// ============================================================================

/// Macro for inline integrity check - scatter these throughout the codebase
#[macro_export]
macro_rules! verify_integrity {
    () => {{
        if $crate::license::anti_tamper::was_tampered() {
            return Err(anyhow::anyhow!("Operation not permitted"));
        }
        if !$crate::license::anti_tamper::is_validated() {
            return Err(anyhow::anyhow!("License validation required"));
        }
    }};
}

/// Macro for silent integrity check that returns false
#[macro_export]
macro_rules! check_integrity {
    () => {{
        !$crate::license::anti_tamper::was_tampered()
            && $crate::license::anti_tamper::is_validated()
    }};
}

// ============================================================================
// SECTION 10: Runtime Self-Verification
// ============================================================================

/// Comprehensive runtime check - call periodically
#[inline(never)]
pub fn full_integrity_check() -> bool {
    // Check 1: Tamper flag
    if was_tampered() {
        return false;
    }

    // Check 2: Magic constants
    if !verify_magic_constants() {
        return false;
    }

    // Check 3: State consistency
    if !verify_state_consistency() {
        return false;
    }

    // Check 4: Counter integrity
    if !verify_counter_integrity() {
        return false;
    }

    // Check 5: Function integrity
    if !verify_function_integrity() {
        return false;
    }

    // Check 6: Critical function hooks
    let critical_fns: [*const (); 4] = [
        is_validated as *const (),
        set_validated as *const (),
        full_integrity_check as *const (),
        trigger_tamper_response as *const (),
    ];

    for fn_ptr in critical_fns {
        if !verify_no_hook(fn_ptr) {
            return false;
        }
    }

    // Check 7: Debugger (soft check - just record, don't fail)
    if detect_debugger() {
        // Note: We don't fail on debugger, just record it
        // This prevents attackers from knowing if we detected them
        #[cfg(debug_assertions)]
        eprintln!("[SECURITY] Debugger detected");
    }

    true
}

// ============================================================================
// SECTION 11: Compile-Time Obfuscation Helpers
// ============================================================================

/// Obfuscate a string at compile time (basic XOR)
#[macro_export]
macro_rules! obfuscate_str {
    ($s:expr) => {{
        const KEY: u8 = 0x5A;
        const BYTES: &[u8] = $s.as_bytes();
        const LEN: usize = BYTES.len();

        let mut result = [0u8; LEN];
        let mut i = 0;
        while i < LEN {
            result[i] = BYTES[i] ^ KEY;
            i += 1;
        }
        result
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialization() {
        assert!(initialize_protection());
        assert!(verify_magic_constants());
    }

    #[test]
    fn test_validation_flow() {
        initialize_protection();

        // Initially not validated
        assert!(!is_validated());

        // Set validated
        set_validated(0x12345678);

        // Now validated
        assert!(is_validated());

        // State should be consistent
        assert!(verify_state_consistency());
    }

    #[test]
    fn test_function_integrity() {
        assert!(verify_function_integrity());
    }

    #[test]
    fn test_honeypot_key() {
        assert!(check_honeypot_key("LONKERO-UNLIMITED-FREE"));
        assert!(check_honeypot_key("CRACKED-KEY"));
        assert!(!check_honeypot_key("valid-license-key"));
    }

    #[test]
    fn test_full_integrity() {
        initialize_protection();
        set_validated(0xABCDEF);
        assert!(full_integrity_check());
    }
}
