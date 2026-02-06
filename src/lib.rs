// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Scanner Library
 * Exposes scanner modules for testing
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */
pub mod adaptive_concurrency;
pub mod auth_context;
pub mod cdn_detector;
pub mod circuit_breaker;
pub mod config;
pub mod crawler;
pub mod database;
pub mod detection_helpers;
pub mod dns_cache;
pub mod framework_detector;
pub mod headless_crawler;
pub mod multi_role;
pub mod oob_detector;
pub mod payloads;
pub mod payloads_comprehensive;
pub mod payloads_optimized;
pub mod queue;
pub mod rate_limiter;
pub mod reporting;
pub mod request_batcher;
pub mod subdomain_enum;
pub mod types;
pub mod vulnerability;

// Probabilistic inference engine for side-channel vulnerability detection
pub mod inference;

// Cloud security infrastructure
pub mod cloud;

// Scanner modules
pub mod http_client;
pub mod scanners;

// Production error handling and resilience modules
pub mod errors;
pub mod metrics;
pub mod retry;

// Validation modules
pub mod validation;

// Registry modules
pub mod registry;

// Rule engine module
pub mod engine;

// Real-time scanning module
pub mod realtime;

// Vulnerability retesting module
pub mod retest;

// Nuclei custom template management
pub mod nuclei;

// Analysis module
pub mod analysis;

// Discovery module
pub mod discovery;

// License verification and killswitch module
pub mod license;

// Quantum-safe signing and scan authorization module
pub mod signing;

// Module IDs for server-side authorization
pub mod modules;

// Machine Learning module (model-based detection, GDPR-compliant)
pub mod ml;

// Feature extraction layer for model-based vulnerability scoring
pub mod features;

// Model scorer for vulnerability detection
pub mod scorer;

// Probe payload library
pub mod probes;

// GraphQL introspection and schema parsing
pub mod graphql_introspection;

// State-aware crawling module
pub mod state_tracker;

// Form replay system for security testing
pub mod form_replay;

// Session recording for browser session capture and replay
pub mod session_recording;

// Parasite Mode - route requests through real browser TLS (legacy name)
pub mod parasite;

// Browser-Assist Mode - legitimate browser-assisted security scanning
// This is the proper, enterprise-ready approach: transparent, auditable, user-controlled
pub mod browser_assist;
