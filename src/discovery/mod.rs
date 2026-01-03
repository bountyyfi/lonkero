// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

pub mod endpoint_discovery;
/**
 * Discovery Module
 * Asset discovery functionality (subdomains, ports, endpoints, etc.)
 *
 * © 2026 Bountyy Oy
 */
pub mod subdomain_discovery;

pub use endpoint_discovery::{DiscoveredEndpoint, EndpointCategory, EndpointDiscovery};
pub use subdomain_discovery::{DiscoveryConfig, SubdomainDiscovery, SubdomainInfo};
