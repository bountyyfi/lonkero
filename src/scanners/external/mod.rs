// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

// External Scanning Modules
// Production-grade external scanning for internet-facing assets
// © 2025 Bountyy Oy

pub mod port_scanner;
pub mod ssl_scanner;
pub mod dns_scanner;

pub use port_scanner::{
    ExternalPortScanner, PortScanConfig, PortScanResult, PortScanSummary,
    PortState, ScanTechnique,
};

pub use ssl_scanner::{
    SslScanner, SslScanConfig, SslScanResult, SslGrade,
    CertificateInfo, CipherSuite, ProtocolSupport, SslIssue, SslVulnerability,
};

pub use dns_scanner::{
    DnsScanner, DnsScanConfig, DnsScanResult,
    SpfRecord, DkimRecord, DmarcRecord, CaaRecord, DnssecInfo, SubdomainTakeover,
};
