# Scan Modes Analysis: Is `-ultra` Needed?

**Date**: 2025-12-15
**Reviewer**: Security Architecture Review

---

## Current Design

### Scan Modes (Enum)
Controls **payload intensity** for injection testing:

| Mode | Payloads | Use Case |
|------|----------|----------|
| **Fast** | 50 | Quick smoke test, CI/CD |
| **Normal** | 500 | Standard security scan (default CLI) |
| **Thorough** | 5,000 | Comprehensive pen-test |
| **Insane** | All (~10,000+) | Maximum coverage, slow |

### Ultra Mode (Boolean Flag)
Controls **which scanners run**:
- **Default**: `true` (enabled by default)
- **Controls**:
  1. Subdomain enumeration thoroughness (`subdomain_enum_thorough`)
  2. **Phase 8**: Cloud & Container Security
     - Cloud Storage scanner
     - Container Security scanner
     - API Gateway scanner
     - Cloud Security scanner

---

## Scan Phase Structure

```
Phase 0: Reconnaissance (web crawling, tech detection)
Phase 1: Parameter injection testing
Phase 2: Security configuration testing
Phase 3: Authentication testing
Phase 4: API security testing
Phase 5: Advanced injection testing
Phase 6: Protocol testing
Phase 7: Business logic testing
Phase 8: Cloud & Container ← ONLY if ultra=true
```

---

## Problems with Current Design

### 🔴 Problem 1: Confusing Naming
```bash
# What's the difference?
lonkero scan https://example.com --mode insane
lonkero scan https://example.com --mode normal --ultra
```

**Issue**: "Ultra" suggests it's more thorough than "Insane", but they control different things:
- `--mode insane` = Most payloads for injection testing
- `--ultra` = Enables cloud/container phase

Users expect: `Fast < Normal < Thorough < Insane < Ultra`
Reality: `Ultra` is orthogonal to scan modes

---

### 🟠 Problem 2: Surprising Default
```rust
fn default_ultra() -> bool {
    true  // ← Ultra enabled by default!
}
```

**Issue**: By default, even "fast" mode runs cloud scanning:
```bash
lonkero scan https://example.com --mode fast
# Actually runs: Fast mode + Cloud scanning (Phase 8)
```

This is **counterintuitive** - users expect "fast" to be fast.

---

### 🟠 Problem 3: Mixed Concerns
Ultra mode controls TWO unrelated things:
1. **Subdomain enumeration** thoroughness (100 vs 1000+ subdomains)
2. **Cloud/container** security phase (4 additional scanners)

These should potentially be separate flags.

---

### 🟡 Problem 4: Lack of Granularity
Users cannot:
- Run thorough injection testing WITHOUT cloud scanning
- Run ONLY cloud scanning without injection tests
- Enable/disable specific cloud scanners

Current options are binary: all cloud or no cloud.

---

## Usage Analysis

### CLI Flag Definition
```rust
// src/cli/main.rs:151-153
/// Enable ultra mode (more thorough, slower)
#[arg(short, long)]
ultra: bool,
```

**Documentation is vague**: "more thorough, slower" doesn't explain:
- What specifically becomes thorough?
- How much slower?
- What features are enabled?

---

## Recommendations

### ✅ Option 1: Remove Ultra, Extend Scan Modes (RECOMMENDED)

Make scan modes more granular:

```rust
pub enum ScanMode {
    Fast,        // 50 payloads, no cloud, basic subdomain
    Normal,      // 500 payloads, no cloud, basic subdomain
    Thorough,    // 5000 payloads, basic cloud, extended subdomain
    Insane,      // All payloads, full cloud, full subdomain
}
```

**Benefits**:
- ✅ Simpler mental model
- ✅ Linear progression
- ✅ One flag to control everything
- ✅ No confusing defaults

**Drawbacks**:
- ❌ Less flexible (can't do "thorough injection, no cloud")
- ❌ Breaking change for existing users

---

### ✅ Option 2: Rename & Clarify Ultra (PRACTICAL)

```rust
pub struct ScanConfig {
    pub scan_mode: ScanMode,  // Controls payload count
    pub enable_cloud_scanning: bool,  // Controls Phase 8
    pub subdomain_thoroughness: SubdomainMode,  // Separate control
}

pub enum SubdomainMode {
    Basic,     // 100 common subdomains
    Extended,  // 1000+ subdomains
}
```

**CLI**:
```bash
lonkero scan https://example.com \
  --mode thorough \
  --enable-cloud \
  --subdomain-mode extended
```

**Benefits**:
- ✅ Clear, self-documenting
- ✅ Flexible combinations
- ✅ Gradual migration path

**Drawbacks**:
- ❌ More flags to manage
- ❌ Still a breaking change

---

### ✅ Option 3: Phase Selection (ADVANCED)

```bash
lonkero scan https://example.com \
  --mode normal \
  --phases 0-7  # Skip cloud phase

lonkero scan https://example.com \
  --mode fast \
  --phases 8  # ONLY cloud scanning

lonkero scan https://example.com \
  --mode thorough \
  --phases all  # Everything
```

**Benefits**:
- ✅ Maximum flexibility
- ✅ Power users can fine-tune
- ✅ Can skip slow phases

**Drawbacks**:
- ❌ Complex for beginners
- ❌ Need to document phase numbers
- ❌ More implementation work

---

## Comparison Matrix

| Approach | Simplicity | Flexibility | Breaking Change | Migration Effort |
|----------|-----------|-------------|-----------------|------------------|
| **Current (ultra)** | ⭐⭐ | ⭐⭐ | N/A | N/A |
| **Option 1: Extend modes** | ⭐⭐⭐⭐⭐ | ⭐⭐ | Yes | Medium |
| **Option 2: Rename ultra** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | Yes | Low |
| **Option 3: Phase selection** | ⭐⭐ | ⭐⭐⭐⭐⭐ | Yes | High |

---

## Recommended Action: **Option 2 (Rename & Clarify)**

### Implementation Steps

**Step 1: Deprecate `ultra`, add new flags**
```rust
pub struct ScanConfig {
    pub scan_mode: ScanMode,

    #[deprecated(since = "1.1.0", note = "Use enable_cloud_scanning instead")]
    pub ultra: bool,

    /// Enable cloud & container security testing (Phase 8)
    #[serde(default = "default_false")]
    pub enable_cloud_scanning: bool,

    /// Extended subdomain enumeration (1000+ subdomains vs 100)
    #[serde(default = "default_false")]
    pub subdomain_extended: bool,
}
```

**Step 2: Update CLI**
```rust
/// Enable cloud & container security scanning
#[arg(long, alias = "ultra")]
enable_cloud: bool,

/// Use extended subdomain list (1000+ subdomains)
#[arg(long)]
subdomain_extended: bool,
```

**Step 3: Backward compatibility**
```rust
// Map old ultra flag to new flags
if args.ultra {
    config.enable_cloud_scanning = true;
    config.subdomain_extended = true;
}
```

**Step 4: Update defaults**
```rust
fn default_false() -> bool {
    false  // Don't enable cloud by default
}
```

**Step 5: Update documentation**
```markdown
# Scan Modes

## Payload Intensity
- `--mode fast`: 50 payloads (CI/CD)
- `--mode normal`: 500 payloads (default)
- `--mode thorough`: 5,000 payloads (pen-test)
- `--mode insane`: All payloads (maximum coverage)

## Additional Features
- `--enable-cloud`: Add cloud & container security tests (slower)
- `--subdomain-extended`: Use 1000+ subdomains instead of 100
```

---

## Migration Plan

### Phase 1 (v1.1.0) - Deprecation
- Add new flags with `--ultra` as alias
- Show deprecation warning when `--ultra` is used
- Update documentation

### Phase 2 (v1.2.0) - Transition
- Make `--ultra` print warning but still work
- Update all examples to use new flags

### Phase 3 (v2.0.0) - Removal
- Remove `--ultra` flag entirely
- Clean up deprecated code

---

## Impact Analysis

### Users Affected
```bash
# Current usage patterns (from examples)
lonkero scan https://example.com --mode normal --ultra
# → Update to:
lonkero scan https://example.com --mode normal --enable-cloud

lonkero scan https://example.com --mode fast
# → No change (fast is still fast, no cloud by default)

lonkero scan https://example.com --mode insane --ultra
# → Update to:
lonkero scan https://example.com --mode insane --enable-cloud
```

### API/Library Users
```rust
// Old
ScanConfig {
    scan_mode: ScanMode::Normal,
    ultra: true,
    ..Default::default()
}

// New (backward compatible during transition)
ScanConfig {
    scan_mode: ScanMode::Normal,
    enable_cloud_scanning: true,
    subdomain_extended: true,
    ..Default::default()
}
```

---

## Conclusion

**YES, `-ultra` should be replaced** with clearer, more specific flags:
- `--enable-cloud` for cloud/container security
- `--subdomain-extended` for thorough subdomain enumeration

This improves:
1. **Clarity**: Users understand exactly what each flag does
2. **Flexibility**: Can enable cloud without extended subdomains (or vice versa)
3. **Defaults**: Fast mode is actually fast (no cloud by default)
4. **Documentation**: Self-documenting flag names

**Effort**: Low (aliasing + deprecation path)
**Risk**: Low (backward compatible during transition)
**Benefit**: High (much clearer UX)

---

## Next Steps

1. Create issue: "Deprecate --ultra flag, add --enable-cloud and --subdomain-extended"
2. Implement Option 2 with backward compatibility
3. Update documentation and examples
4. Add deprecation warnings
5. Plan removal for v2.0.0

---

**Status**: Proposal for review
**Priority**: Medium (UX improvement, not a bug)
**Timeline**: 3 releases (deprecate → warn → remove)
