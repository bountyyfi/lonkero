// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Integration Tests Module
 * Organizes all integration test modules for scanners
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

// Authentication scanner tests (if they exist)
#[cfg(test)]
#[allow(dead_code)]
pub mod auth_scanners;
#[cfg(test)]
#[allow(dead_code)]
pub mod jwt_tests;
#[cfg(test)]
#[allow(dead_code)]
pub mod oauth_tests;

// API scanner tests (if they exist)
#[cfg(test)]
#[allow(dead_code)]
pub mod api_scanners;
#[cfg(test)]
#[allow(dead_code)]
pub mod graphql_tests;

// Injection scanner tests
pub mod sqli_tests;
pub mod xss_tests;
pub mod command_injection_tests;
pub mod nosql_tests;
pub mod ldap_tests;
pub mod xxe_tests;
pub mod crlf_tests;
pub mod template_injection_tests;
pub mod path_traversal_tests;
pub mod ssrf_tests;
