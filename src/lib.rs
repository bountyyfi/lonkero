// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Scanner Library
 * Exposes scanner modules for testing
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

pub mod adaptive_concurrency;
pub mod cdn_detector;
pub mod circuit_breaker;
pub mod config;
pub mod crawler;
pub mod headless_crawler;
pub mod auth_context;
pub mod database;
pub mod dns_cache;
pub mod framework_detector;
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

// Cloud security infrastructure
pub mod cloud;

// Scanner modules
pub mod scanners;
pub mod http_client;

// Production error handling and resilience modules
pub mod errors;
pub mod retry;
pub mod metrics;
pub mod health;

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

// Distributed worker module
pub mod worker;

// Internal network agent
pub mod agent;

// Analysis module
pub mod analysis;

// Discovery module
pub mod discovery;

// N-API exports for Node.js integration
pub mod napi_bridge;

// License verification and killswitch module
pub mod license;

// Quantum-safe signing and scan authorization module
pub mod signing;

// Module IDs for server-side authorization
pub mod modules;
