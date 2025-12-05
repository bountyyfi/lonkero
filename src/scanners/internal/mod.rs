// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Internal Scanning Modules
 * © 2025 Bountyy Oy
 */

pub mod authenticated_scanner;
pub mod network_discovery;

pub use authenticated_scanner::{
    AuthenticatedScanner, AuthenticatedScanResult, ScanCredential,
    PatchInfo, ConfigurationItem, ServiceInfo, VulnerabilityInfo,
};

pub use network_discovery::{
    NetworkDiscoveryScanner, NetworkDiscoveryResult, DiscoveryOptions,
    PortInfo, NetworkInterface,
};
