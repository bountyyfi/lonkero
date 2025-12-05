// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Registry Module
 * Scanner registry and metadata management
 * © 2025 Bountyy Oy
 */

pub mod scanner_registry;

pub use scanner_registry::{
    ScannerRegistry, ScannerMetadata, ScannerCategory, RiskLevel,
    ScannerCapability, ScannerConfigSchema, ConfigProperty, SCANNER_REGISTRY
};
