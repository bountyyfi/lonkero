// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Discovery Module
 * Asset discovery functionality (subdomains, ports, endpoints, etc.)
 *
 * © 2025 Bountyy Oy
 */

pub mod subdomain_discovery;

pub use subdomain_discovery::{SubdomainDiscovery, DiscoveryConfig, SubdomainInfo};
