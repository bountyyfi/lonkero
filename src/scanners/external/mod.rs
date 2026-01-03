// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

// External Scanning Modules
// Production-grade external scanning for internet-facing assets
// © 2026 Bountyy Oy

pub mod dns_scanner;
pub mod port_scanner;
pub mod ssl_scanner;

pub use port_scanner::{
    ExternalPortScanner, PortScanConfig, PortScanResult, PortScanSummary, PortState, ScanTechnique,
};

pub use ssl_scanner::{
    CertificateInfo, CipherSuite, ProtocolSupport, SslGrade, SslIssue, SslScanConfig,
    SslScanResult, SslScanner, SslVulnerability,
};

pub use dns_scanner::{
    CaaRecord, DkimRecord, DmarcRecord, DnsScanConfig, DnsScanResult, DnsScanner, DnssecInfo,
    SpfRecord, SubdomainTakeover,
};
