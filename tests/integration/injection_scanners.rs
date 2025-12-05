// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Integration Test Suite Runner for All Injection Scanners
 * Centralized module to run all injection scanner tests
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

// Re-export all test modules
pub mod sqli_tests;
pub mod xss_tests;
pub mod command_injection_tests;
pub mod nosql_tests;
pub mod ldap_tests;
// XXE, CRLF, Template, Path Traversal, and SSRF tests will be added
