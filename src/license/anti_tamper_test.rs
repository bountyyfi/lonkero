// Copyright (c) 2025 Bountyy Oy. All rights reserved.

#[cfg(test)]
mod tests {
    use crate::license::anti_tamper::*;

    #[test]
    fn test_initialization() {
        assert!(initialize_protection());
        assert!(!was_tampered());
    }

    #[test]
    fn test_validation_flow() {
        initialize_protection();
        assert!(!is_validated());
        set_validated(0x12345678ABCDEF00);
        assert!(is_validated());
    }

    #[test]
    fn test_full_integrity() {
        initialize_protection();
        set_validated(0xCAFEBABE);
        assert!(full_integrity_check());
    }

    #[test]
    fn test_magic_constants() {
        assert!(verify_magic_constants());
    }

    #[test]
    fn test_honeypot_keys() {
        initialize_protection();
        assert!(check_honeypot_key("LONKERO-UNLIMITED-FREE"));
        assert!(check_honeypot_key("CRACKED-VERSION"));
        assert!(check_honeypot_key("KEYGEN-OUTPUT"));
        assert!(check_honeypot_key("PATCHED-KEY"));
        assert!(!check_honeypot_key("valid-license-key-here"));
    }

    #[test]
    fn test_honeypot_functions_trigger_lockdown() {
        initialize_protection();
        set_validated(0xABCD);
        assert!(is_validated());

        let _ = bypass_license_check();

        assert!(was_tampered());
        assert!(!is_validated());
    }

    #[test]
    fn test_hook_detection() {
        let fn_ptr = initialize_protection as *const ();
        assert!(verify_no_hook(fn_ptr));
    }
}
