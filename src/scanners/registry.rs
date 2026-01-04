// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! # Scanner Registry Module
//!
//! This module provides intelligent scanner routing based on detected technology stack.
//! It ensures that only relevant scanners are executed for each target, improving both
//! scan efficiency and accuracy.
//!
//! ## Features
//!
//! - Technology-based scanner selection
//! - Priority-based scanner ordering
//! - Smart skip logic for irrelevant combinations
//! - Universal scanners that run on all targets
//!
//! ## Example
//!
//! ```rust
//! use crate::scanners::registry::{ScannerRegistry, TechCategory, ScannerType};
//!
//! let registry = ScannerRegistry::new();
//! let tech_stack = vec![TechCategory::JavaScript(JsFramework::React), TechCategory::GraphQL];
//! let scanners = registry.get_scanners_for_tech(&tech_stack);
//! ```
//!
//! @copyright 2026 Bountyy Oy
//! @license Proprietary

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// ============================================================================
// Technology Category Definitions
// ============================================================================

/// JavaScript framework/runtime variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JsFramework {
    /// Node.js runtime
    Node,
    /// React frontend framework
    React,
    /// Vue.js frontend framework
    Vue,
    /// Angular frontend framework
    Angular,
    /// Next.js full-stack framework
    NextJs,
    /// Nuxt.js full-stack framework
    Nuxt,
    /// Express.js backend framework
    Express,
    /// SvelteKit framework
    SvelteKit,
    /// Remix framework
    Remix,
    /// Gatsby static site generator
    Gatsby,
    /// Electron desktop apps
    Electron,
    /// Deno runtime
    Deno,
    /// Generic JavaScript
    Generic,
}

/// PHP framework/CMS variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PhpFramework {
    /// WordPress CMS
    WordPress,
    /// Laravel framework
    Laravel,
    /// Drupal CMS
    Drupal,
    /// Magento e-commerce
    Magento,
    /// Symfony framework
    Symfony,
    /// Joomla CMS
    Joomla,
    /// WooCommerce (WordPress)
    WooCommerce,
    /// PrestaShop
    PrestaShop,
    /// CodeIgniter framework
    CodeIgniter,
    /// Yii framework
    Yii,
    /// CakePHP framework
    CakePHP,
    /// Generic PHP
    Generic,
}

/// Python framework variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PythonFramework {
    /// Django framework
    Django,
    /// Flask micro-framework
    Flask,
    /// FastAPI async framework
    FastAPI,
    /// Jinja2 templating
    Jinja2,
    /// Tornado async framework
    Tornado,
    /// Pyramid framework
    Pyramid,
    /// Starlette ASGI framework
    Starlette,
    /// Generic Python
    Generic,
}

/// Java framework variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JavaFramework {
    /// Spring framework
    Spring,
    /// Apache Tomcat server
    Tomcat,
    /// Apache Struts framework
    Struts,
    /// JavaServer Pages
    Jsp,
    /// Java EE/Jakarta EE
    JavaEE,
    /// Play framework
    Play,
    /// Dropwizard framework
    Dropwizard,
    /// Micronaut framework
    Micronaut,
    /// Quarkus framework
    Quarkus,
    /// Liferay portal
    Liferay,
    /// Generic Java
    Generic,
}

/// .NET framework variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DotNetFramework {
    /// ASP.NET Core/Classic
    AspNet,
    /// Blazor WebAssembly/Server
    Blazor,
    /// ASP.NET MVC
    Mvc,
    /// ASP.NET Web API
    WebApi,
    /// SignalR real-time
    SignalR,
    /// .NET Core
    Core,
    /// Generic .NET
    Generic,
}

/// Ruby framework variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RubyFramework {
    /// Ruby on Rails
    Rails,
    /// Sinatra micro-framework
    Sinatra,
    /// Hanami framework
    Hanami,
    /// Padrino framework
    Padrino,
    /// Generic Ruby
    Generic,
}

/// Go framework variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GoFramework {
    /// Gin web framework
    Gin,
    /// Echo framework
    Echo,
    /// Fiber framework
    Fiber,
    /// Chi router
    Chi,
    /// Gorilla toolkit
    Gorilla,
    /// Generic Go
    Generic,
}

/// Rust framework variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RustFramework {
    /// Actix Web
    Actix,
    /// Rocket framework
    Rocket,
    /// Axum framework
    Axum,
    /// Warp framework
    Warp,
    /// Generic Rust
    Generic,
}

/// Static site hosting platforms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StaticPlatform {
    /// Cloudflare Pages
    CloudflarePages,
    /// Vercel
    Vercel,
    /// Netlify
    Netlify,
    /// GitHub Pages
    GitHubPages,
    /// GitLab Pages
    GitLabPages,
    /// AWS Amplify
    AwsAmplify,
    /// Azure Static Web Apps
    AzureStaticWebApps,
    /// Firebase Hosting
    FirebaseHosting,
    /// Surge.sh
    Surge,
    /// Generic static
    Generic,
}

/// Cloud provider variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CloudProvider {
    /// Amazon Web Services
    Aws,
    /// Microsoft Azure
    Azure,
    /// Google Cloud Platform
    Gcp,
    /// Firebase services
    Firebase,
    /// DigitalOcean
    DigitalOcean,
    /// Heroku
    Heroku,
    /// Alibaba Cloud
    Alibaba,
}

/// Technology category with framework variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TechCategory {
    /// JavaScript/Node.js ecosystem
    JavaScript(JsFramework),
    /// PHP ecosystem
    Php(PhpFramework),
    /// Python ecosystem
    Python(PythonFramework),
    /// Java ecosystem
    Java(JavaFramework),
    /// .NET ecosystem
    DotNet(DotNetFramework),
    /// Ruby ecosystem
    Ruby(RubyFramework),
    /// Go ecosystem
    Go(GoFramework),
    /// Rust ecosystem
    Rust(RustFramework),
    /// Static site platforms
    StaticSite(StaticPlatform),
    /// Cloud providers
    Cloud(CloudProvider),
    /// GraphQL API
    GraphQL,
    /// gRPC API
    GrpC,
    /// WebSocket
    WebSocket,
    /// Unknown/undetected technology
    Unknown,
}

impl TechCategory {
    /// Get the base technology name
    pub fn base_name(&self) -> &'static str {
        match self {
            TechCategory::JavaScript(_) => "JavaScript",
            TechCategory::Php(_) => "PHP",
            TechCategory::Python(_) => "Python",
            TechCategory::Java(_) => "Java",
            TechCategory::DotNet(_) => ".NET",
            TechCategory::Ruby(_) => "Ruby",
            TechCategory::Go(_) => "Go",
            TechCategory::Rust(_) => "Rust",
            TechCategory::StaticSite(_) => "StaticSite",
            TechCategory::Cloud(_) => "Cloud",
            TechCategory::GraphQL => "GraphQL",
            TechCategory::GrpC => "gRPC",
            TechCategory::WebSocket => "WebSocket",
            TechCategory::Unknown => "Unknown",
        }
    }

    /// Check if this is a backend technology
    pub fn is_backend(&self) -> bool {
        matches!(
            self,
            TechCategory::JavaScript(
                JsFramework::Node | JsFramework::Express | JsFramework::NextJs | JsFramework::Nuxt
            ) | TechCategory::Php(_)
                | TechCategory::Python(_)
                | TechCategory::Java(_)
                | TechCategory::DotNet(_)
                | TechCategory::Ruby(_)
                | TechCategory::Go(_)
                | TechCategory::Rust(_)
        )
    }

    /// Check if this is a frontend-only technology
    pub fn is_frontend_only(&self) -> bool {
        matches!(
            self,
            TechCategory::JavaScript(JsFramework::React | JsFramework::Vue | JsFramework::Angular)
                | TechCategory::StaticSite(_)
        )
    }

    /// Check if this is a CMS
    pub fn is_cms(&self) -> bool {
        matches!(
            self,
            TechCategory::Php(
                PhpFramework::WordPress
                    | PhpFramework::Drupal
                    | PhpFramework::Joomla
                    | PhpFramework::Magento
            )
        )
    }

    /// Convert from framework detector's DetectedTechnology to registry TechCategory.
    /// Maps technology names to specific framework variants where possible.
    pub fn from_detected_technology(name: &str, category: &str) -> Self {
        let name_lower = name.to_lowercase();

        // JavaScript/Node.js frameworks
        if category == "JavaScript" || name_lower.contains("node") || name_lower.contains("npm") {
            if name_lower.contains("react") {
                return TechCategory::JavaScript(JsFramework::React);
            } else if name_lower.contains("vue") {
                return TechCategory::JavaScript(JsFramework::Vue);
            } else if name_lower.contains("angular") {
                return TechCategory::JavaScript(JsFramework::Angular);
            } else if name_lower.contains("next") {
                return TechCategory::JavaScript(JsFramework::NextJs);
            } else if name_lower.contains("nuxt") {
                return TechCategory::JavaScript(JsFramework::Nuxt);
            } else if name_lower.contains("express") {
                return TechCategory::JavaScript(JsFramework::Express);
            } else if name_lower.contains("svelte") {
                return TechCategory::JavaScript(JsFramework::SvelteKit);
            } else if name_lower.contains("node") {
                return TechCategory::JavaScript(JsFramework::Node);
            }
            return TechCategory::JavaScript(JsFramework::Generic);
        }

        // PHP frameworks
        if category == "Language" && name_lower.contains("php")
            || name_lower.contains("wordpress")
            || name_lower.contains("laravel")
            || name_lower.contains("drupal")
        {
            if name_lower.contains("wordpress") {
                return TechCategory::Php(PhpFramework::WordPress);
            } else if name_lower.contains("laravel") {
                return TechCategory::Php(PhpFramework::Laravel);
            } else if name_lower.contains("drupal") {
                return TechCategory::Php(PhpFramework::Drupal);
            } else if name_lower.contains("symfony") {
                return TechCategory::Php(PhpFramework::Symfony);
            } else if name_lower.contains("magento") {
                return TechCategory::Php(PhpFramework::Magento);
            } else if name_lower.contains("joomla") {
                return TechCategory::Php(PhpFramework::Joomla);
            }
            return TechCategory::Php(PhpFramework::Generic);
        }

        // Python frameworks
        if name_lower.contains("python")
            || name_lower.contains("django")
            || name_lower.contains("flask")
            || name_lower.contains("fastapi")
        {
            if name_lower.contains("django") {
                return TechCategory::Python(PythonFramework::Django);
            } else if name_lower.contains("flask") {
                return TechCategory::Python(PythonFramework::Flask);
            } else if name_lower.contains("fastapi") {
                return TechCategory::Python(PythonFramework::FastAPI);
            }
            return TechCategory::Python(PythonFramework::Generic);
        }

        // Java frameworks
        if name_lower.contains("java")
            || name_lower.contains("spring")
            || name_lower.contains("tomcat")
        {
            if name_lower.contains("spring") {
                return TechCategory::Java(JavaFramework::Spring);
            } else if name_lower.contains("struts") {
                return TechCategory::Java(JavaFramework::Struts);
            }
            return TechCategory::Java(JavaFramework::Generic);
        }

        // .NET frameworks
        if name_lower.contains("asp.net")
            || name_lower.contains("dotnet")
            || name_lower.contains(".net")
        {
            if name_lower.contains("core") {
                return TechCategory::DotNet(DotNetFramework::Core);
            }
            return TechCategory::DotNet(DotNetFramework::AspNet);
        }

        // Ruby frameworks
        if name_lower.contains("ruby") || name_lower.contains("rails") {
            if name_lower.contains("rails") {
                return TechCategory::Ruby(RubyFramework::Rails);
            } else if name_lower.contains("sinatra") {
                return TechCategory::Ruby(RubyFramework::Sinatra);
            }
            return TechCategory::Ruby(RubyFramework::Generic);
        }

        // Go frameworks
        if name_lower.contains("go") || name_lower.contains("gin") || name_lower.contains("echo") {
            if name_lower.contains("gin") {
                return TechCategory::Go(GoFramework::Gin);
            } else if name_lower.contains("echo") {
                return TechCategory::Go(GoFramework::Echo);
            }
            return TechCategory::Go(GoFramework::Generic);
        }

        // GraphQL
        if name_lower.contains("graphql") {
            return TechCategory::GraphQL;
        }

        // Cloud providers
        if category == "CloudProvider"
            || name_lower.contains("aws")
            || name_lower.contains("azure")
            || name_lower.contains("gcp")
            || name_lower.contains("google cloud")
        {
            if name_lower.contains("aws") || name_lower.contains("amazon") {
                return TechCategory::Cloud(CloudProvider::Aws);
            } else if name_lower.contains("azure") {
                return TechCategory::Cloud(CloudProvider::Azure);
            } else if name_lower.contains("gcp") || name_lower.contains("google") {
                return TechCategory::Cloud(CloudProvider::Gcp);
            } else if name_lower.contains("firebase") {
                return TechCategory::Cloud(CloudProvider::Firebase);
            }
        }

        // Static site platforms
        if name_lower.contains("vercel")
            || name_lower.contains("netlify")
            || name_lower.contains("cloudflare pages")
            || name_lower.contains("github pages")
        {
            if name_lower.contains("vercel") {
                return TechCategory::StaticSite(StaticPlatform::Vercel);
            } else if name_lower.contains("netlify") {
                return TechCategory::StaticSite(StaticPlatform::Netlify);
            } else if name_lower.contains("cloudflare") {
                return TechCategory::StaticSite(StaticPlatform::CloudflarePages);
            } else if name_lower.contains("github") {
                return TechCategory::StaticSite(StaticPlatform::GitHubPages);
            }
            return TechCategory::StaticSite(StaticPlatform::Generic);
        }

        // Default to Unknown
        TechCategory::Unknown
    }
}

// ============================================================================
// Scanner Type Definitions
// ============================================================================

/// All available scanner types categorized by functionality
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScannerType {
    // === Injection Scanners ===
    /// Cross-Site Scripting detection
    Xss,
    /// SQL Injection detection
    SqlI,
    /// NoSQL Injection detection
    NoSqlI,
    /// Command Injection detection
    CommandInjection,
    /// Server-Side Template Injection
    Ssti,
    /// LDAP Injection detection
    LdapInjection,
    /// XPath Injection detection
    XPathInjection,
    /// Code Injection detection
    CodeInjection,
    /// XML External Entity injection
    Xxe,
    /// XML Injection detection
    XmlInjection,
    /// CRLF Injection detection
    CrlfInjection,
    /// Email Header Injection detection
    EmailHeaderInjection,
    /// HTML Injection detection
    HtmlInjection,
    /// Host Header Injection detection
    HostHeaderInjection,
    /// HTTP Parameter Pollution
    HttpParameterPollution,
    /// Server-Side Includes Injection
    SsiInjection,
    /// Path Traversal detection
    PathTraversal,
    /// Log4j/Log4Shell vulnerability
    Log4j,
    /// Second-Order Injection detection
    SecondOrderInjection,

    // === Authentication Scanners ===
    /// JWT vulnerability detection
    Jwt,
    /// JWT specific vulnerabilities (algorithm confusion, etc.)
    JwtVulnerabilities,
    /// OAuth vulnerability detection
    OAuth,
    /// SAML vulnerability detection
    Saml,
    /// Session management analysis
    SessionAnalyzer,
    /// Authentication bypass detection
    AuthBypass,
    /// Rate limiting detection
    RateLimiting,
    /// MFA bypass detection
    Mfa,
    /// Advanced authentication testing
    AdvancedAuth,
    /// WebAuthn/FIDO2 testing
    WebAuthn,
    /// AWS Cognito user enumeration
    CognitoEnum,

    // === Authorization Scanners ===
    /// Insecure Direct Object Reference
    Idor,
    /// Broken Object Level Authorization
    Bola,
    /// Mass Assignment vulnerability
    MassAssignment,

    // === Configuration Scanners ===
    /// CORS misconfiguration detection
    Cors,
    /// Security headers analysis
    SecurityHeaders,
    /// Clickjacking vulnerability
    Clickjacking,
    /// Web cache poisoning
    CachePoisoning,
    /// Tomcat misconfiguration
    TomcatMisconfig,
    /// Varnish misconfiguration
    VarnishMisconfig,
    /// Open redirect detection
    OpenRedirect,

    // === CMS-Specific Scanners ===
    /// WordPress security scanner
    WordPress,
    /// Django security scanner
    Django,
    /// Next.js security scanner
    NextJs,
    /// Express.js security scanner
    Express,
    /// React security scanner
    React,
    /// Laravel security scanner
    Laravel,
    /// Drupal security scanner
    Drupal,
    /// SvelteKit security scanner
    SvelteKit,
    /// Liferay security scanner
    Liferay,
    /// Framework vulnerability scanner
    FrameworkVulnerabilities,

    // === API-Specific Scanners ===
    /// GraphQL security scanner
    GraphQL,
    /// GraphQL security advanced
    GraphQLSecurity,
    /// REST API security scanner
    RestApi,
    /// gRPC security scanner
    GrpC,
    /// API fuzzing scanner
    ApiFuzzer,
    /// API gateway scanner
    ApiGateway,

    // === Cloud Scanners ===
    /// AWS security scanner
    Aws,
    /// Azure security scanner
    Azure,
    /// Azure API Management scanner
    AzureApim,
    /// GCP security scanner
    Gcp,
    /// Firebase security scanner
    Firebase,
    /// S3 bucket scanner
    S3,
    /// Cloud storage scanner
    CloudStorage,
    /// Container security scanner
    ContainerSecurity,
    /// Cloud security scanner
    CloudSecurity,

    // === Cryptography Scanners ===
    /// SSL/TLS configuration scanner
    Ssl,
    /// Certificate validation scanner
    Certificates,

    // === Protocol Scanners ===
    /// HTTP/2 security scanner
    Http2,
    /// HTTP/3 security scanner
    Http3,
    /// WebSocket security scanner
    WebSocket,
    /// HTTP request smuggling
    HttpSmuggling,

    // === Information Disclosure ===
    /// Sensitive data exposure
    SensitiveData,
    /// Source map exposure
    SourceMap,
    /// Information disclosure
    InformationDisclosure,
    /// JavaScript sensitive info
    JsSensitiveInfo,
    /// Google dorking
    GoogleDorking,
    /// Favicon hash analysis
    FaviconHash,

    // === Business Logic ===
    /// Race condition detection
    RaceCondition,
    /// Business logic flaws
    BusinessLogic,
    /// CSRF detection
    Csrf,

    // === File Operations ===
    /// File upload vulnerability
    FileUpload,
    /// File upload advanced
    FileUploadVulnerabilities,

    // === Serialization ===
    /// Deserialization vulnerability
    Deserialization,

    // === Request Manipulation ===
    /// SSRF detection
    Ssrf,
    /// Blind SSRF detection
    SsrfBlind,
    /// ReDoS detection
    ReDoS,

    // === Client-Side ===
    /// Prototype pollution
    PrototypePollution,
    /// Client route auth bypass
    ClientRouteAuthBypass,
    /// JS Miner (endpoint discovery)
    JsMiner,

    // === WAF/Security ===
    /// WAF bypass techniques
    WafBypass,

    // === CVE Specific ===
    /// CVE-2025-55182 scanner
    Cve202555182,
    /// CVE-2025-55183 scanner
    Cve202555183,
    /// CVE-2025-55184 scanner
    Cve202555184,

    // === Advanced ===
    /// Advanced SSTI scanner
    SstiAdvanced,
    /// Merlin exploit scanner
    Merlin,
}

impl ScannerType {
    /// Get the scanner's display name
    pub fn display_name(&self) -> &'static str {
        match self {
            ScannerType::Xss => "XSS Scanner",
            ScannerType::SqlI => "SQL Injection Scanner",
            ScannerType::NoSqlI => "NoSQL Injection Scanner",
            ScannerType::CommandInjection => "Command Injection Scanner",
            ScannerType::Ssti => "SSTI Scanner",
            ScannerType::LdapInjection => "LDAP Injection Scanner",
            ScannerType::XPathInjection => "XPath Injection Scanner",
            ScannerType::CodeInjection => "Code Injection Scanner",
            ScannerType::Xxe => "XXE Scanner",
            ScannerType::XmlInjection => "XML Injection Scanner",
            ScannerType::CrlfInjection => "CRLF Injection Scanner",
            ScannerType::EmailHeaderInjection => "Email Header Injection Scanner",
            ScannerType::HtmlInjection => "HTML Injection Scanner",
            ScannerType::HostHeaderInjection => "Host Header Injection Scanner",
            ScannerType::HttpParameterPollution => "HPP Scanner",
            ScannerType::SsiInjection => "SSI Injection Scanner",
            ScannerType::PathTraversal => "Path Traversal Scanner",
            ScannerType::Log4j => "Log4j Scanner",
            ScannerType::SecondOrderInjection => "Second-Order Injection Scanner",
            ScannerType::Jwt => "JWT Scanner",
            ScannerType::JwtVulnerabilities => "JWT Vulnerabilities Scanner",
            ScannerType::OAuth => "OAuth Scanner",
            ScannerType::Saml => "SAML Scanner",
            ScannerType::SessionAnalyzer => "Session Analyzer",
            ScannerType::AuthBypass => "Auth Bypass Scanner",
            ScannerType::RateLimiting => "Rate Limiting Scanner",
            ScannerType::Mfa => "MFA Scanner",
            ScannerType::AdvancedAuth => "Advanced Auth Scanner",
            ScannerType::WebAuthn => "WebAuthn Scanner",
            ScannerType::CognitoEnum => "Cognito Enumeration Scanner",
            ScannerType::Idor => "IDOR Scanner",
            ScannerType::Bola => "BOLA Scanner",
            ScannerType::MassAssignment => "Mass Assignment Scanner",
            ScannerType::Cors => "CORS Scanner",
            ScannerType::SecurityHeaders => "Security Headers Scanner",
            ScannerType::Clickjacking => "Clickjacking Scanner",
            ScannerType::CachePoisoning => "Cache Poisoning Scanner",
            ScannerType::TomcatMisconfig => "Tomcat Misconfig Scanner",
            ScannerType::VarnishMisconfig => "Varnish Misconfig Scanner",
            ScannerType::OpenRedirect => "Open Redirect Scanner",
            ScannerType::WordPress => "WordPress Security Scanner",
            ScannerType::Django => "Django Security Scanner",
            ScannerType::NextJs => "Next.js Security Scanner",
            ScannerType::Express => "Express Security Scanner",
            ScannerType::React => "React Security Scanner",
            ScannerType::Laravel => "Laravel Security Scanner",
            ScannerType::Drupal => "Drupal Security Scanner",
            ScannerType::SvelteKit => "SvelteKit Security Scanner",
            ScannerType::Liferay => "Liferay Security Scanner",
            ScannerType::FrameworkVulnerabilities => "Framework Vulnerabilities Scanner",
            ScannerType::GraphQL => "GraphQL Scanner",
            ScannerType::GraphQLSecurity => "GraphQL Security Scanner",
            ScannerType::RestApi => "REST API Scanner",
            ScannerType::GrpC => "gRPC Scanner",
            ScannerType::ApiFuzzer => "API Fuzzer",
            ScannerType::ApiGateway => "API Gateway Scanner",
            ScannerType::Aws => "AWS Scanner",
            ScannerType::Azure => "Azure Scanner",
            ScannerType::AzureApim => "Azure APIM Scanner",
            ScannerType::Gcp => "GCP Scanner",
            ScannerType::Firebase => "Firebase Scanner",
            ScannerType::S3 => "S3 Scanner",
            ScannerType::CloudStorage => "Cloud Storage Scanner",
            ScannerType::ContainerSecurity => "Container Security Scanner",
            ScannerType::CloudSecurity => "Cloud Security Scanner",
            ScannerType::Ssl => "SSL/TLS Scanner",
            ScannerType::Certificates => "Certificate Scanner",
            ScannerType::Http2 => "HTTP/2 Scanner",
            ScannerType::Http3 => "HTTP/3 Scanner",
            ScannerType::WebSocket => "WebSocket Scanner",
            ScannerType::HttpSmuggling => "HTTP Smuggling Scanner",
            ScannerType::SensitiveData => "Sensitive Data Scanner",
            ScannerType::SourceMap => "Source Map Scanner",
            ScannerType::InformationDisclosure => "Information Disclosure Scanner",
            ScannerType::JsSensitiveInfo => "JS Sensitive Info Scanner",
            ScannerType::GoogleDorking => "Google Dorking Scanner",
            ScannerType::FaviconHash => "Favicon Hash Scanner",
            ScannerType::RaceCondition => "Race Condition Scanner",
            ScannerType::BusinessLogic => "Business Logic Scanner",
            ScannerType::Csrf => "CSRF Scanner",
            ScannerType::FileUpload => "File Upload Scanner",
            ScannerType::FileUploadVulnerabilities => "File Upload Vulnerabilities Scanner",
            ScannerType::Deserialization => "Deserialization Scanner",
            ScannerType::Ssrf => "SSRF Scanner",
            ScannerType::SsrfBlind => "Blind SSRF Scanner",
            ScannerType::ReDoS => "ReDoS Scanner",
            ScannerType::PrototypePollution => "Prototype Pollution Scanner",
            ScannerType::ClientRouteAuthBypass => "Client Route Auth Bypass Scanner",
            ScannerType::JsMiner => "JS Miner Scanner",
            ScannerType::WafBypass => "WAF Bypass Scanner",
            ScannerType::Cve202555182 => "CVE-2025-55182 Scanner",
            ScannerType::Cve202555183 => "CVE-2025-55183 Scanner",
            ScannerType::Cve202555184 => "CVE-2025-55184 Scanner",
            ScannerType::SstiAdvanced => "Advanced SSTI Scanner",
            ScannerType::Merlin => "Merlin Scanner",
        }
    }

    /// Check if this is an injection scanner
    pub fn is_injection(&self) -> bool {
        matches!(
            self,
            ScannerType::Xss
                | ScannerType::SqlI
                | ScannerType::NoSqlI
                | ScannerType::CommandInjection
                | ScannerType::Ssti
                | ScannerType::SstiAdvanced
                | ScannerType::LdapInjection
                | ScannerType::XPathInjection
                | ScannerType::CodeInjection
                | ScannerType::Xxe
                | ScannerType::XmlInjection
                | ScannerType::CrlfInjection
                | ScannerType::EmailHeaderInjection
                | ScannerType::HtmlInjection
                | ScannerType::HostHeaderInjection
                | ScannerType::SsiInjection
                | ScannerType::PathTraversal
        )
    }

    /// Check if this is a configuration scanner
    pub fn is_configuration(&self) -> bool {
        matches!(
            self,
            ScannerType::Cors
                | ScannerType::SecurityHeaders
                | ScannerType::Clickjacking
                | ScannerType::CachePoisoning
                | ScannerType::TomcatMisconfig
                | ScannerType::VarnishMisconfig
        )
    }
}

// ============================================================================
// Scanner Registry Implementation
// ============================================================================

/// Priority and skip information for a scanner-technology combination
#[derive(Debug, Clone)]
pub struct ScannerTechMapping {
    /// Priority level (1-10, higher = run first)
    pub priority: u8,
    /// Whether to skip this combination entirely
    pub skip: bool,
    /// Reason for skipping (if applicable)
    pub skip_reason: Option<String>,
}

impl Default for ScannerTechMapping {
    fn default() -> Self {
        Self {
            priority: 5,
            skip: false,
            skip_reason: None,
        }
    }
}

/// Payload intensity level - determines how many payloads to use
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PayloadIntensity {
    /// Minimal payloads - quick validation (50 payloads)
    Minimal,
    /// Standard payloads - balanced coverage (500 payloads)
    Standard,
    /// Extended payloads - thorough testing (5000 payloads)
    Extended,
    /// Maximum payloads - all available payloads
    Maximum,
}

impl PayloadIntensity {
    /// Get the payload count limit for this intensity
    pub fn payload_limit(&self) -> usize {
        match self {
            PayloadIntensity::Minimal => 50,
            PayloadIntensity::Standard => 500,
            PayloadIntensity::Extended => 5000,
            PayloadIntensity::Maximum => usize::MAX,
        }
    }

    /// Determine intensity based on parameter risk score (0-100)
    pub fn from_risk_score(score: u32) -> Self {
        match score {
            0..=25 => PayloadIntensity::Minimal,
            26..=50 => PayloadIntensity::Standard,
            51..=75 => PayloadIntensity::Extended,
            _ => PayloadIntensity::Maximum,
        }
    }
}

/// Scanner Registry for technology-based scanner routing
///
/// This registry maintains mappings between technology stacks and appropriate
/// security scanners, enabling efficient and targeted vulnerability testing.
pub struct ScannerRegistry {
    /// Technology to scanner mappings with priorities
    tech_scanner_map: HashMap<TechCategory, Vec<(ScannerType, ScannerTechMapping)>>,
    /// Scanner skip rules (tech -> scanner -> should_skip)
    skip_rules: HashMap<(TechCategory, ScannerType), ScannerTechMapping>,
    /// Universal scanners that run on all targets
    universal_scanners: Vec<ScannerType>,
    /// Core vulnerability scanners that ALWAYS run (deduplicated)
    core_scanners: Vec<ScannerType>,
    /// Fallback scanners for Unknown tech (expanded coverage)
    fallback_scanners: Vec<ScannerType>,
    /// Default scanner priorities
    default_priorities: HashMap<ScannerType, u8>,
}

impl Default for ScannerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ScannerRegistry {
    /// Create a new scanner registry with default mappings
    pub fn new() -> Self {
        let mut registry = Self {
            tech_scanner_map: HashMap::new(),
            skip_rules: HashMap::new(),
            universal_scanners: Vec::new(),
            core_scanners: Vec::new(),
            fallback_scanners: Vec::new(),
            default_priorities: HashMap::new(),
        };
        registry.initialize_mappings();
        registry
    }

    /// Get all scanners relevant for the given technology stack
    ///
    /// # Arguments
    ///
    /// * `tech_categories` - Slice of detected technology categories
    ///
    /// # Returns
    ///
    /// Vector of scanner types sorted by priority (highest first)
    pub fn get_scanners_for_tech(&self, tech_categories: &[TechCategory]) -> Vec<ScannerType> {
        let mut scanners: HashSet<ScannerType> = HashSet::new();
        let mut scanner_priorities: HashMap<ScannerType, u8> = HashMap::new();

        // Always include universal scanners
        for scanner in &self.universal_scanners {
            scanners.insert(*scanner);
            scanner_priorities.insert(*scanner, self.get_priority(scanner, &TechCategory::Unknown));
        }

        // Add scanners for each detected technology
        for tech in tech_categories {
            if let Some(tech_scanners) = self.tech_scanner_map.get(tech) {
                for (scanner, mapping) in tech_scanners {
                    if !mapping.skip && !self.should_skip(scanner, tech) {
                        scanners.insert(*scanner);
                        let priority = mapping
                            .priority
                            .max(*scanner_priorities.get(scanner).unwrap_or(&0));
                        scanner_priorities.insert(*scanner, priority);
                    }
                }
            }

            // Also add scanners based on base technology
            self.add_base_tech_scanners(tech, &mut scanners, &mut scanner_priorities);
        }

        // Sort by priority (descending)
        let mut result: Vec<ScannerType> = scanners.into_iter().collect();
        result.sort_by(|a, b| {
            let pri_a = scanner_priorities.get(a).unwrap_or(&5);
            let pri_b = scanner_priorities.get(b).unwrap_or(&5);
            pri_b.cmp(pri_a)
        });

        result
    }

    /// Get the priority for a scanner-technology combination
    ///
    /// # Arguments
    ///
    /// * `scanner` - The scanner type
    /// * `tech` - The technology category
    ///
    /// # Returns
    ///
    /// Priority level from 1-10 (higher = run first)
    pub fn get_priority(&self, scanner: &ScannerType, tech: &TechCategory) -> u8 {
        // Check for specific mapping
        if let Some(mapping) = self.skip_rules.get(&(*tech, *scanner)) {
            return mapping.priority;
        }

        // Check tech-specific mappings
        if let Some(tech_scanners) = self.tech_scanner_map.get(tech) {
            for (s, mapping) in tech_scanners {
                if s == scanner {
                    return mapping.priority;
                }
            }
        }

        // Return default priority
        *self.default_priorities.get(scanner).unwrap_or(&5)
    }

    /// Check if a scanner should be skipped for a given technology
    ///
    /// # Arguments
    ///
    /// * `scanner` - The scanner type
    /// * `tech` - The technology category
    ///
    /// # Returns
    ///
    /// True if the scanner should be skipped
    pub fn should_skip(&self, scanner: &ScannerType, tech: &TechCategory) -> bool {
        // Check explicit skip rules
        if let Some(mapping) = self.skip_rules.get(&(*tech, *scanner)) {
            return mapping.skip;
        }

        // Apply smart skip logic
        self.apply_smart_skip_logic(scanner, tech)
    }

    /// Get the list of universal scanners
    pub fn get_universal_scanners(&self) -> &[ScannerType] {
        &self.universal_scanners
    }

    /// Get the list of core vulnerability scanners (ALWAYS run, but deduplicated)
    pub fn get_core_scanners(&self) -> &[ScannerType] {
        &self.core_scanners
    }

    /// Get the list of fallback scanners (run when tech=Unknown for expanded coverage)
    pub fn get_fallback_scanners(&self) -> &[ScannerType] {
        &self.fallback_scanners
    }

    /// Check if a scanner is universal (runs on all targets)
    pub fn is_universal(&self, scanner: &ScannerType) -> bool {
        self.universal_scanners.contains(scanner)
    }

    /// Check if a scanner is a core vulnerability scanner
    pub fn is_core(&self, scanner: &ScannerType) -> bool {
        self.core_scanners.contains(scanner)
    }

    /// Get all registered technology categories
    pub fn get_all_tech_categories(&self) -> Vec<TechCategory> {
        self.tech_scanner_map.keys().cloned().collect()
    }

    /// Get intelligent scan configuration for a target
    ///
    /// This method provides context-aware scanner and payload selection:
    /// - Always includes universal scanners (CORS, headers, etc.)
    /// - Always includes core vulnerability scanners (XSS, SQLi, etc.)
    /// - Adds tech-specific scanners when technology is detected
    /// - Adds fallback scanners when tech is Unknown (more coverage, not less)
    ///
    /// # Arguments
    ///
    /// * `tech_categories` - Detected technology categories
    /// * `parameter_risk_score` - Risk score for the parameter being tested (0-100)
    ///
    /// # Returns
    ///
    /// Tuple of (scanners to run, payload intensity)
    pub fn get_intelligent_scan_config(
        &self,
        tech_categories: &[TechCategory],
        parameter_risk_score: u32,
    ) -> (Vec<ScannerType>, PayloadIntensity) {
        let mut scanners: HashSet<ScannerType> = HashSet::new();
        let mut scanner_priorities: HashMap<ScannerType, u8> = HashMap::new();

        // LAYER 1: Universal scanners - ALWAYS run
        for scanner in &self.universal_scanners {
            scanners.insert(*scanner);
            scanner_priorities.insert(*scanner, self.get_priority(scanner, &TechCategory::Unknown));
        }

        // LAYER 2: Core vulnerability scanners - ALWAYS run (but will be deduplicated)
        for scanner in &self.core_scanners {
            scanners.insert(*scanner);
            let priority = self.default_priorities.get(scanner).unwrap_or(&8);
            scanner_priorities.insert(*scanner, *priority);
        }

        // Check if we have any known technology
        let has_known_tech = tech_categories
            .iter()
            .any(|t| !matches!(t, TechCategory::Unknown));

        if has_known_tech {
            // LAYER 3: Tech-specific scanners - run when tech is detected
            for tech in tech_categories {
                if let Some(tech_scanners) = self.tech_scanner_map.get(tech) {
                    for (scanner, mapping) in tech_scanners {
                        if !mapping.skip && !self.should_skip(scanner, tech) {
                            scanners.insert(*scanner);
                            let priority = mapping
                                .priority
                                .max(*scanner_priorities.get(scanner).unwrap_or(&0));
                            scanner_priorities.insert(*scanner, priority);
                        }
                    }
                }
                // Add base tech scanners
                self.add_base_tech_scanners(tech, &mut scanners, &mut scanner_priorities);
            }
        } else {
            // LAYER 4: Fallback scanners - run MORE tests when tech is Unknown
            // This ensures we don't miss vulnerabilities due to failed detection
            for scanner in &self.fallback_scanners {
                scanners.insert(*scanner);
                let priority = self.default_priorities.get(scanner).unwrap_or(&6);
                scanner_priorities.insert(*scanner, *priority);
            }
        }

        // Sort by priority
        let mut result: Vec<ScannerType> = scanners.into_iter().collect();
        result.sort_by(|a, b| {
            let pri_a = scanner_priorities.get(a).unwrap_or(&5);
            let pri_b = scanner_priorities.get(b).unwrap_or(&5);
            pri_b.cmp(pri_a)
        });

        // Determine payload intensity based on parameter risk
        let intensity = PayloadIntensity::from_risk_score(parameter_risk_score);

        (result, intensity)
    }

    /// Get skip reason for a scanner-tech combination
    pub fn get_skip_reason(&self, scanner: &ScannerType, tech: &TechCategory) -> Option<String> {
        if let Some(mapping) = self.skip_rules.get(&(*tech, *scanner)) {
            return mapping.skip_reason.clone();
        }

        if self.apply_smart_skip_logic(scanner, tech) {
            return Some(format!(
                "{} is not applicable to {} technology",
                scanner.display_name(),
                tech.base_name()
            ));
        }

        None
    }

    // ========================================================================
    // Private Implementation
    // ========================================================================

    /// Initialize all default mappings
    fn initialize_mappings(&mut self) {
        self.initialize_universal_scanners();
        self.initialize_core_scanners();
        self.initialize_fallback_scanners();
        self.initialize_default_priorities();
        self.initialize_javascript_mappings();
        self.initialize_php_mappings();
        self.initialize_python_mappings();
        self.initialize_java_mappings();
        self.initialize_dotnet_mappings();
        self.initialize_ruby_mappings();
        self.initialize_go_mappings();
        self.initialize_rust_mappings();
        self.initialize_static_site_mappings();
        self.initialize_graphql_mappings();
        self.initialize_cloud_mappings();
        self.initialize_skip_rules();
    }

    /// Initialize universal scanners that run on all targets
    fn initialize_universal_scanners(&mut self) {
        self.universal_scanners = vec![
            // Configuration scanners - always relevant
            ScannerType::Cors,
            ScannerType::SecurityHeaders,
            ScannerType::Clickjacking,
            ScannerType::InformationDisclosure,
            // SSL/TLS - always relevant for HTTPS targets
            ScannerType::Ssl,
            // Open redirect - can occur anywhere
            ScannerType::OpenRedirect,
            // HTTP smuggling - protocol level
            ScannerType::HttpSmuggling,
            // Host header injection - universal
            ScannerType::HostHeaderInjection,
        ];
    }

    /// Initialize core vulnerability scanners that ALWAYS run
    /// These are the critical vulnerability classes that should be tested
    /// regardless of technology stack (but endpoints will be deduplicated)
    fn initialize_core_scanners(&mut self) {
        self.core_scanners = vec![
            // Critical injection vulnerabilities - ALWAYS test
            ScannerType::Xss,
            ScannerType::SqlI,
            ScannerType::CommandInjection,
            ScannerType::Ssrf,
            ScannerType::SsrfBlind,
            ScannerType::PathTraversal,
            ScannerType::SecondOrderInjection,
            // Authentication/Authorization - ALWAYS test
            ScannerType::Idor,
            ScannerType::Bola,
            ScannerType::Jwt,
            ScannerType::AuthBypass,
            // Business logic - ALWAYS test
            ScannerType::Csrf,
            ScannerType::RaceCondition,
            // Other high-impact
            ScannerType::FileUpload,
            ScannerType::Ssti,
        ];
    }

    /// Initialize fallback scanners for Unknown technology
    /// When tech detection fails, we run MORE tests, not fewer
    /// This ensures we don't miss vulnerabilities due to detection failures
    fn initialize_fallback_scanners(&mut self) {
        self.fallback_scanners = vec![
            // All injection types - cast a wide net
            ScannerType::NoSqlI,
            ScannerType::Xxe,
            ScannerType::XmlInjection,
            ScannerType::LdapInjection,
            ScannerType::XPathInjection,
            ScannerType::CodeInjection,
            ScannerType::CrlfInjection,
            ScannerType::HtmlInjection,
            ScannerType::EmailHeaderInjection,
            ScannerType::HttpParameterPollution,
            ScannerType::SsiInjection,
            ScannerType::SstiAdvanced,
            // Deserialization - common across many platforms
            ScannerType::Deserialization,
            // Mass assignment - common in many frameworks
            ScannerType::MassAssignment,
            // Client-side attacks
            ScannerType::PrototypePollution,
            ScannerType::ClientRouteAuthBypass,
            // Advanced auth testing
            ScannerType::OAuth,
            ScannerType::Saml,
            ScannerType::JwtVulnerabilities,
            ScannerType::SessionAnalyzer,
            ScannerType::RateLimiting,
            ScannerType::Mfa,
            // Cache and protocol attacks
            ScannerType::CachePoisoning,
            ScannerType::Http2,
            // Information gathering
            ScannerType::JsMiner,
            ScannerType::JsSensitiveInfo,
            ScannerType::SourceMap,
            ScannerType::SensitiveData,
            ScannerType::GoogleDorking,
            // API testing
            ScannerType::ApiFuzzer,
            ScannerType::RestApi,
            // Business logic
            ScannerType::BusinessLogic,
            ScannerType::FileUploadVulnerabilities,
            // CVE-specific
            ScannerType::Log4j,
            // WAF testing
            ScannerType::WafBypass,
            ScannerType::ReDoS,
            // Advanced exploitation
            ScannerType::Merlin,
            // Cloud-specific
            ScannerType::CognitoEnum,
            // WebSocket
            ScannerType::WebSocket,
            // GraphQL
            ScannerType::GraphQL,
            ScannerType::GraphQLSecurity,
            // HTTP/3
            ScannerType::Http3,
            // gRPC
            ScannerType::GrpC,
            // API Gateway
            ScannerType::ApiGateway,
            // Favicon analysis
            ScannerType::FaviconHash,
        ];
    }

    /// Initialize default scanner priorities
    fn initialize_default_priorities(&mut self) {
        // Critical injection scanners - highest priority
        self.default_priorities.insert(ScannerType::SqlI, 10);
        self.default_priorities
            .insert(ScannerType::CommandInjection, 10);
        self.default_priorities.insert(ScannerType::Ssrf, 9);
        self.default_priorities.insert(ScannerType::SsrfBlind, 9);
        self.default_priorities
            .insert(ScannerType::PathTraversal, 9);
        self.default_priorities.insert(ScannerType::Log4j, 10);
        self.default_priorities
            .insert(ScannerType::SecondOrderInjection, 9);

        // XSS and other injection
        self.default_priorities.insert(ScannerType::Xss, 8);
        self.default_priorities.insert(ScannerType::Ssti, 8);
        self.default_priorities.insert(ScannerType::SstiAdvanced, 8);
        self.default_priorities.insert(ScannerType::Xxe, 8);
        self.default_priorities.insert(ScannerType::NoSqlI, 8);

        // Authentication - high priority
        self.default_priorities.insert(ScannerType::Jwt, 8);
        self.default_priorities
            .insert(ScannerType::JwtVulnerabilities, 8);
        self.default_priorities.insert(ScannerType::AuthBypass, 8);
        self.default_priorities.insert(ScannerType::OAuth, 7);
        self.default_priorities.insert(ScannerType::Saml, 7);

        // Authorization
        self.default_priorities.insert(ScannerType::Idor, 7);
        self.default_priorities.insert(ScannerType::Bola, 7);

        // Configuration - medium-high priority
        self.default_priorities.insert(ScannerType::Cors, 6);
        self.default_priorities
            .insert(ScannerType::SecurityHeaders, 6);
        self.default_priorities.insert(ScannerType::Clickjacking, 6);

        // Framework-specific - medium priority
        self.default_priorities.insert(ScannerType::WordPress, 7);
        self.default_priorities.insert(ScannerType::Django, 7);
        self.default_priorities.insert(ScannerType::Laravel, 7);
        self.default_priorities.insert(ScannerType::NextJs, 7);
        self.default_priorities.insert(ScannerType::Express, 7);

        // API scanners
        self.default_priorities.insert(ScannerType::GraphQL, 7);
        self.default_priorities
            .insert(ScannerType::GraphQLSecurity, 7);
        self.default_priorities.insert(ScannerType::GrpC, 6);

        // Cloud scanners
        self.default_priorities.insert(ScannerType::Firebase, 7);
        self.default_priorities.insert(ScannerType::S3, 7);
        self.default_priorities.insert(ScannerType::CloudStorage, 6);
        self.default_priorities.insert(ScannerType::CognitoEnum, 7);

        // Advanced exploitation scanners
        self.default_priorities.insert(ScannerType::Merlin, 8);
        self.default_priorities.insert(ScannerType::Http3, 6);
        self.default_priorities.insert(ScannerType::WebSocket, 6);
        self.default_priorities.insert(ScannerType::ApiGateway, 6);
        self.default_priorities.insert(ScannerType::FaviconHash, 4);

        // Default for unspecified
        self.default_priorities
            .insert(ScannerType::InformationDisclosure, 5);
    }

    /// Initialize JavaScript/Node.js technology mappings
    fn initialize_javascript_mappings(&mut self) {
        // Node.js/Express specific scanners
        let node_scanners = vec![
            (
                ScannerType::PrototypePollution,
                ScannerTechMapping {
                    priority: 9,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::NoSqlI,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Xss,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::CommandInjection,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Ssrf,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Express,
                ScannerTechMapping {
                    priority: 9,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::JsMiner,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::JsSensitiveInfo,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::ReDoS,
                ScannerTechMapping {
                    priority: 6,
                    skip: false,
                    skip_reason: None,
                },
            ),
        ];
        self.tech_scanner_map.insert(
            TechCategory::JavaScript(JsFramework::Node),
            node_scanners.clone(),
        );
        self.tech_scanner_map.insert(
            TechCategory::JavaScript(JsFramework::Express),
            node_scanners,
        );

        // React specific
        let react_scanners = vec![
            (
                ScannerType::PrototypePollution,
                ScannerTechMapping {
                    priority: 9,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Xss,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::React,
                ScannerTechMapping {
                    priority: 9,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::ClientRouteAuthBypass,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::JsMiner,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::JsSensitiveInfo,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::SourceMap,
                ScannerTechMapping {
                    priority: 6,
                    skip: false,
                    skip_reason: None,
                },
            ),
        ];
        self.tech_scanner_map
            .insert(TechCategory::JavaScript(JsFramework::React), react_scanners);

        // Next.js specific
        let nextjs_scanners = vec![
            (
                ScannerType::NextJs,
                ScannerTechMapping {
                    priority: 10,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::PrototypePollution,
                ScannerTechMapping {
                    priority: 9,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Xss,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Ssrf,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::ClientRouteAuthBypass,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::JsMiner,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::JsSensitiveInfo,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::SourceMap,
                ScannerTechMapping {
                    priority: 6,
                    skip: false,
                    skip_reason: None,
                },
            ),
        ];
        self.tech_scanner_map.insert(
            TechCategory::JavaScript(JsFramework::NextJs),
            nextjs_scanners,
        );

        // SvelteKit specific
        let sveltekit_scanners = vec![
            (
                ScannerType::SvelteKit,
                ScannerTechMapping {
                    priority: 10,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::PrototypePollution,
                ScannerTechMapping {
                    priority: 9,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Xss,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::ClientRouteAuthBypass,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::JsMiner,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
        ];
        self.tech_scanner_map.insert(
            TechCategory::JavaScript(JsFramework::SvelteKit),
            sveltekit_scanners,
        );
    }

    /// Initialize PHP technology mappings
    fn initialize_php_mappings(&mut self) {
        // WordPress specific scanners
        let wordpress_scanners = vec![
            (
                ScannerType::WordPress,
                ScannerTechMapping {
                    priority: 10,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::SqlI,
                ScannerTechMapping {
                    priority: 9,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Xss,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::FileUpload,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::FileUploadVulnerabilities,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::PathTraversal,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Xxe,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Deserialization,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Csrf,
                ScannerTechMapping {
                    priority: 6,
                    skip: false,
                    skip_reason: None,
                },
            ),
        ];
        self.tech_scanner_map.insert(
            TechCategory::Php(PhpFramework::WordPress),
            wordpress_scanners,
        );

        // Laravel specific scanners
        let laravel_scanners = vec![
            (
                ScannerType::Laravel,
                ScannerTechMapping {
                    priority: 10,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::SqlI,
                ScannerTechMapping {
                    priority: 9,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Xss,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::MassAssignment,
                ScannerTechMapping {
                    priority: 9,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Deserialization,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Ssti,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::FileUpload,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Csrf,
                ScannerTechMapping {
                    priority: 6,
                    skip: false,
                    skip_reason: None,
                },
            ),
        ];
        self.tech_scanner_map
            .insert(TechCategory::Php(PhpFramework::Laravel), laravel_scanners);

        // Drupal specific scanners
        let drupal_scanners = vec![
            (
                ScannerType::Drupal,
                ScannerTechMapping {
                    priority: 10,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::SqlI,
                ScannerTechMapping {
                    priority: 9,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Xss,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::FileUpload,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Deserialization,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::PathTraversal,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
        ];
        self.tech_scanner_map
            .insert(TechCategory::Php(PhpFramework::Drupal), drupal_scanners);

        // Generic PHP scanners
        let php_generic_scanners = vec![
            (
                ScannerType::SqlI,
                ScannerTechMapping {
                    priority: 9,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Xss,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::CommandInjection,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::FileUpload,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::PathTraversal,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Xxe,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Deserialization,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::LdapInjection,
                ScannerTechMapping {
                    priority: 6,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Ssti,
                ScannerTechMapping {
                    priority: 6,
                    skip: false,
                    skip_reason: None,
                },
            ),
        ];
        self.tech_scanner_map.insert(
            TechCategory::Php(PhpFramework::Generic),
            php_generic_scanners,
        );
    }

    /// Initialize Python technology mappings
    fn initialize_python_mappings(&mut self) {
        // Django specific scanners
        let django_scanners = vec![
            (
                ScannerType::Django,
                ScannerTechMapping {
                    priority: 10,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::SqlI,
                ScannerTechMapping {
                    priority: 9,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Xss,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Ssti,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::SstiAdvanced,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Deserialization,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Csrf,
                ScannerTechMapping {
                    priority: 6,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::MassAssignment,
                ScannerTechMapping {
                    priority: 6,
                    skip: false,
                    skip_reason: None,
                },
            ),
        ];
        self.tech_scanner_map.insert(
            TechCategory::Python(PythonFramework::Django),
            django_scanners,
        );

        // Flask specific scanners
        let flask_scanners = vec![
            (
                ScannerType::Ssti,
                ScannerTechMapping {
                    priority: 10,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::SstiAdvanced,
                ScannerTechMapping {
                    priority: 10,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::SqlI,
                ScannerTechMapping {
                    priority: 9,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Xss,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::CommandInjection,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Deserialization,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
        ];
        self.tech_scanner_map
            .insert(TechCategory::Python(PythonFramework::Flask), flask_scanners);

        // FastAPI specific scanners
        let fastapi_scanners = vec![
            (
                ScannerType::SqlI,
                ScannerTechMapping {
                    priority: 9,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Xss,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::ApiFuzzer,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Idor,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Bola,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::MassAssignment,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
        ];
        self.tech_scanner_map.insert(
            TechCategory::Python(PythonFramework::FastAPI),
            fastapi_scanners,
        );

        // Jinja2 specific (SSTI is critical)
        let jinja2_scanners = vec![
            (
                ScannerType::Ssti,
                ScannerTechMapping {
                    priority: 10,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::SstiAdvanced,
                ScannerTechMapping {
                    priority: 10,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Xss,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
        ];
        self.tech_scanner_map.insert(
            TechCategory::Python(PythonFramework::Jinja2),
            jinja2_scanners,
        );
    }

    /// Initialize Java technology mappings
    fn initialize_java_mappings(&mut self) {
        // Spring specific scanners
        let spring_scanners = vec![
            (
                ScannerType::Log4j,
                ScannerTechMapping {
                    priority: 10,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Deserialization,
                ScannerTechMapping {
                    priority: 10,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::SqlI,
                ScannerTechMapping {
                    priority: 9,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Xss,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Xxe,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::XmlInjection,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::LdapInjection,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Ssti,
                ScannerTechMapping {
                    priority: 6,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::MassAssignment,
                ScannerTechMapping {
                    priority: 6,
                    skip: false,
                    skip_reason: None,
                },
            ),
        ];
        self.tech_scanner_map
            .insert(TechCategory::Java(JavaFramework::Spring), spring_scanners);

        // Tomcat specific scanners
        let tomcat_scanners = vec![
            (
                ScannerType::TomcatMisconfig,
                ScannerTechMapping {
                    priority: 10,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Log4j,
                ScannerTechMapping {
                    priority: 10,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Deserialization,
                ScannerTechMapping {
                    priority: 9,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::PathTraversal,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Xxe,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
        ];
        self.tech_scanner_map
            .insert(TechCategory::Java(JavaFramework::Tomcat), tomcat_scanners);

        // Struts specific scanners
        let struts_scanners = vec![
            (
                ScannerType::Deserialization,
                ScannerTechMapping {
                    priority: 10,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Log4j,
                ScannerTechMapping {
                    priority: 10,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::CommandInjection,
                ScannerTechMapping {
                    priority: 9,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Xxe,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::SqlI,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
        ];
        self.tech_scanner_map
            .insert(TechCategory::Java(JavaFramework::Struts), struts_scanners);

        // Liferay specific
        let liferay_scanners = vec![
            (
                ScannerType::Liferay,
                ScannerTechMapping {
                    priority: 10,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Deserialization,
                ScannerTechMapping {
                    priority: 9,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Log4j,
                ScannerTechMapping {
                    priority: 9,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Xss,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::SqlI,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
        ];
        self.tech_scanner_map
            .insert(TechCategory::Java(JavaFramework::Liferay), liferay_scanners);
    }

    /// Initialize .NET technology mappings
    fn initialize_dotnet_mappings(&mut self) {
        // ASP.NET specific scanners
        let aspnet_scanners = vec![
            (
                ScannerType::Deserialization,
                ScannerTechMapping {
                    priority: 10,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::SqlI,
                ScannerTechMapping {
                    priority: 9,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Xss,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Xxe,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::PathTraversal,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::XmlInjection,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::MassAssignment,
                ScannerTechMapping {
                    priority: 6,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Csrf,
                ScannerTechMapping {
                    priority: 6,
                    skip: false,
                    skip_reason: None,
                },
            ),
        ];
        self.tech_scanner_map.insert(
            TechCategory::DotNet(DotNetFramework::AspNet),
            aspnet_scanners,
        );

        // Blazor specific scanners
        let blazor_scanners = vec![
            (
                ScannerType::Xss,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::ClientRouteAuthBypass,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Deserialization,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::WebSocket,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
        ];
        self.tech_scanner_map.insert(
            TechCategory::DotNet(DotNetFramework::Blazor),
            blazor_scanners,
        );
    }

    /// Initialize Ruby technology mappings
    fn initialize_ruby_mappings(&mut self) {
        // Rails specific scanners
        let rails_scanners = vec![
            (
                ScannerType::Deserialization,
                ScannerTechMapping {
                    priority: 10,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::SqlI,
                ScannerTechMapping {
                    priority: 9,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Xss,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::MassAssignment,
                ScannerTechMapping {
                    priority: 9,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Ssti,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::CommandInjection,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Csrf,
                ScannerTechMapping {
                    priority: 6,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::FileUpload,
                ScannerTechMapping {
                    priority: 6,
                    skip: false,
                    skip_reason: None,
                },
            ),
        ];
        self.tech_scanner_map
            .insert(TechCategory::Ruby(RubyFramework::Rails), rails_scanners);

        // Sinatra specific scanners
        let sinatra_scanners = vec![
            (
                ScannerType::SqlI,
                ScannerTechMapping {
                    priority: 9,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Xss,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Ssti,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::CommandInjection,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
        ];
        self.tech_scanner_map
            .insert(TechCategory::Ruby(RubyFramework::Sinatra), sinatra_scanners);
    }

    /// Initialize Go technology mappings
    fn initialize_go_mappings(&mut self) {
        let go_scanners = vec![
            (
                ScannerType::SqlI,
                ScannerTechMapping {
                    priority: 9,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Xss,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::CommandInjection,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Ssrf,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::PathTraversal,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Ssti,
                ScannerTechMapping {
                    priority: 6,
                    skip: false,
                    skip_reason: None,
                },
            ),
        ];

        for framework in [
            GoFramework::Gin,
            GoFramework::Echo,
            GoFramework::Fiber,
            GoFramework::Chi,
            GoFramework::Gorilla,
            GoFramework::Generic,
        ] {
            self.tech_scanner_map
                .insert(TechCategory::Go(framework), go_scanners.clone());
        }
    }

    /// Initialize Rust technology mappings
    fn initialize_rust_mappings(&mut self) {
        // Rust is generally memory-safe, focus on logic bugs
        let rust_scanners = vec![
            (
                ScannerType::SqlI,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Xss,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Ssrf,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::PathTraversal,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Idor,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Bola,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
        ];

        for framework in [
            RustFramework::Actix,
            RustFramework::Rocket,
            RustFramework::Axum,
            RustFramework::Warp,
            RustFramework::Generic,
        ] {
            self.tech_scanner_map
                .insert(TechCategory::Rust(framework), rust_scanners.clone());
        }
    }

    /// Initialize static site platform mappings
    fn initialize_static_site_mappings(&mut self) {
        // Static sites have limited attack surface
        let static_scanners = vec![
            // XSS can still occur in client-side JavaScript
            (
                ScannerType::Xss,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
            // Source maps might be exposed
            (
                ScannerType::SourceMap,
                ScannerTechMapping {
                    priority: 6,
                    skip: false,
                    skip_reason: None,
                },
            ),
            // JS secrets might be exposed
            (
                ScannerType::JsSensitiveInfo,
                ScannerTechMapping {
                    priority: 6,
                    skip: false,
                    skip_reason: None,
                },
            ),
            // Configuration issues
            (
                ScannerType::InformationDisclosure,
                ScannerTechMapping {
                    priority: 5,
                    skip: false,
                    skip_reason: None,
                },
            ),
        ];

        for platform in [
            StaticPlatform::CloudflarePages,
            StaticPlatform::Vercel,
            StaticPlatform::Netlify,
            StaticPlatform::GitHubPages,
            StaticPlatform::GitLabPages,
            StaticPlatform::AwsAmplify,
            StaticPlatform::AzureStaticWebApps,
            StaticPlatform::FirebaseHosting,
            StaticPlatform::Surge,
            StaticPlatform::Generic,
        ] {
            self.tech_scanner_map
                .insert(TechCategory::StaticSite(platform), static_scanners.clone());
        }
    }

    /// Initialize GraphQL-specific mappings
    fn initialize_graphql_mappings(&mut self) {
        let graphql_scanners = vec![
            (
                ScannerType::GraphQL,
                ScannerTechMapping {
                    priority: 10,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::GraphQLSecurity,
                ScannerTechMapping {
                    priority: 10,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Idor,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Bola,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::InformationDisclosure,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::RateLimiting,
                ScannerTechMapping {
                    priority: 6,
                    skip: false,
                    skip_reason: None,
                },
            ),
        ];
        self.tech_scanner_map
            .insert(TechCategory::GraphQL, graphql_scanners);
    }

    /// Initialize cloud provider mappings
    fn initialize_cloud_mappings(&mut self) {
        // AWS specific
        let aws_scanners = vec![
            (
                ScannerType::Aws,
                ScannerTechMapping {
                    priority: 9,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::S3,
                ScannerTechMapping {
                    priority: 9,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::CloudStorage,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::CognitoEnum,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Ssrf,
                ScannerTechMapping {
                    priority: 9,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::CloudSecurity,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
        ];
        self.tech_scanner_map
            .insert(TechCategory::Cloud(CloudProvider::Aws), aws_scanners);

        // Azure specific
        let azure_scanners = vec![
            (
                ScannerType::Azure,
                ScannerTechMapping {
                    priority: 9,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::AzureApim,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::CloudStorage,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Ssrf,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::CloudSecurity,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
        ];
        self.tech_scanner_map
            .insert(TechCategory::Cloud(CloudProvider::Azure), azure_scanners);

        // GCP specific
        let gcp_scanners = vec![
            (
                ScannerType::Gcp,
                ScannerTechMapping {
                    priority: 9,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::CloudStorage,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Ssrf,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::CloudSecurity,
                ScannerTechMapping {
                    priority: 7,
                    skip: false,
                    skip_reason: None,
                },
            ),
        ];
        self.tech_scanner_map
            .insert(TechCategory::Cloud(CloudProvider::Gcp), gcp_scanners);

        // Firebase specific
        let firebase_scanners = vec![
            (
                ScannerType::Firebase,
                ScannerTechMapping {
                    priority: 10,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::NoSqlI,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::Idor,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
            (
                ScannerType::AuthBypass,
                ScannerTechMapping {
                    priority: 8,
                    skip: false,
                    skip_reason: None,
                },
            ),
        ];
        self.tech_scanner_map.insert(
            TechCategory::Cloud(CloudProvider::Firebase),
            firebase_scanners,
        );
    }

    /// Initialize explicit skip rules for incompatible combinations
    fn initialize_skip_rules(&mut self) {
        // Skip PHP-specific scanners for non-PHP technologies
        for js_framework in [
            JsFramework::Node,
            JsFramework::React,
            JsFramework::Vue,
            JsFramework::Angular,
            JsFramework::NextJs,
            JsFramework::Express,
        ] {
            self.skip_rules.insert(
                (
                    TechCategory::JavaScript(js_framework),
                    ScannerType::WordPress,
                ),
                ScannerTechMapping {
                    priority: 0,
                    skip: true,
                    skip_reason: Some("WordPress scanner not applicable to JavaScript".into()),
                },
            );
            self.skip_rules.insert(
                (TechCategory::JavaScript(js_framework), ScannerType::Laravel),
                ScannerTechMapping {
                    priority: 0,
                    skip: true,
                    skip_reason: Some("Laravel scanner not applicable to JavaScript".into()),
                },
            );
            self.skip_rules.insert(
                (TechCategory::JavaScript(js_framework), ScannerType::Drupal),
                ScannerTechMapping {
                    priority: 0,
                    skip: true,
                    skip_reason: Some("Drupal scanner not applicable to JavaScript".into()),
                },
            );
        }

        // Skip Java-specific scanners for non-Java technologies
        for php_framework in [
            PhpFramework::WordPress,
            PhpFramework::Laravel,
            PhpFramework::Drupal,
            PhpFramework::Generic,
        ] {
            self.skip_rules.insert(
                (
                    TechCategory::Php(php_framework),
                    ScannerType::TomcatMisconfig,
                ),
                ScannerTechMapping {
                    priority: 0,
                    skip: true,
                    skip_reason: Some("Tomcat scanner not applicable to PHP".into()),
                },
            );
            self.skip_rules.insert(
                (TechCategory::Php(php_framework), ScannerType::Log4j),
                ScannerTechMapping {
                    priority: 0,
                    skip: true,
                    skip_reason: Some("Log4j scanner not applicable to PHP".into()),
                },
            );
            self.skip_rules.insert(
                (TechCategory::Php(php_framework), ScannerType::Liferay),
                ScannerTechMapping {
                    priority: 0,
                    skip: true,
                    skip_reason: Some("Liferay scanner not applicable to PHP".into()),
                },
            );
        }

        // Skip Node.js specific scanners for non-JS technologies
        for java_framework in [
            JavaFramework::Spring,
            JavaFramework::Tomcat,
            JavaFramework::Struts,
            JavaFramework::Generic,
        ] {
            self.skip_rules.insert(
                (
                    TechCategory::Java(java_framework),
                    ScannerType::PrototypePollution,
                ),
                ScannerTechMapping {
                    priority: 0,
                    skip: true,
                    skip_reason: Some("Prototype pollution not applicable to Java".into()),
                },
            );
            self.skip_rules.insert(
                (TechCategory::Java(java_framework), ScannerType::Express),
                ScannerTechMapping {
                    priority: 0,
                    skip: true,
                    skip_reason: Some("Express scanner not applicable to Java".into()),
                },
            );
            self.skip_rules.insert(
                (TechCategory::Java(java_framework), ScannerType::NextJs),
                ScannerTechMapping {
                    priority: 0,
                    skip: true,
                    skip_reason: Some("Next.js scanner not applicable to Java".into()),
                },
            );
        }

        // CRITICAL FIX: DO NOT skip injection scanners for "static" platforms
        // Cloudflare Pages runs Workers (dynamic), Vercel runs Functions (dynamic)
        // Netlify runs Functions (dynamic) - all can have SQLi, NoSQLi, etc.
        // This skip logic was causing 0% detection rate on modern deployments
        // DISABLED - Always run injection tests regardless of hosting platform
        /*
        for platform in [
            StaticPlatform::CloudflarePages,
            StaticPlatform::Vercel,
            StaticPlatform::Netlify,
            StaticPlatform::GitHubPages,
            StaticPlatform::Generic,
        ] {
            for scanner in [
                ScannerType::SqlI,
                ScannerType::NoSqlI,
                ScannerType::CommandInjection,
                ScannerType::Ssti,
                ScannerType::LdapInjection,
                ScannerType::Deserialization,
                ScannerType::FileUpload,
            ] {
                self.skip_rules.insert(
                    (TechCategory::StaticSite(platform), scanner),
                    ScannerTechMapping {
                        priority: 0,
                        skip: true,
                        skip_reason: Some(
                            "Server-side scanner not applicable to static sites".into(),
                        ),
                    },
                );
            }
        }
        */

        // Skip form-based injection tests for GraphQL
        self.skip_rules.insert(
            (TechCategory::GraphQL, ScannerType::Csrf),
            ScannerTechMapping {
                priority: 0,
                skip: true,
                skip_reason: Some("CSRF testing not applicable to GraphQL APIs".into()),
            },
        );
    }

    /// Add scanners based on base technology (fallback logic)
    fn add_base_tech_scanners(
        &self,
        tech: &TechCategory,
        scanners: &mut HashSet<ScannerType>,
        priorities: &mut HashMap<ScannerType, u8>,
    ) {
        match tech {
            TechCategory::JavaScript(_) => {
                // All JS gets prototype pollution and JS-specific scanners
                if !self.should_skip(&ScannerType::PrototypePollution, tech) {
                    scanners.insert(ScannerType::PrototypePollution);
                    priorities
                        .entry(ScannerType::PrototypePollution)
                        .or_insert(8);
                }
                scanners.insert(ScannerType::JsMiner);
                priorities.entry(ScannerType::JsMiner).or_insert(6);
            }
            TechCategory::Java(_) => {
                // All Java gets deserialization and Log4j
                scanners.insert(ScannerType::Deserialization);
                priorities.entry(ScannerType::Deserialization).or_insert(9);
                scanners.insert(ScannerType::Log4j);
                priorities.entry(ScannerType::Log4j).or_insert(10);
            }
            TechCategory::Python(_) => {
                // All Python gets SSTI
                scanners.insert(ScannerType::Ssti);
                priorities.entry(ScannerType::Ssti).or_insert(8);
                scanners.insert(ScannerType::SstiAdvanced);
                priorities.entry(ScannerType::SstiAdvanced).or_insert(8);
            }
            TechCategory::Php(_) => {
                // All PHP gets deserialization and file upload
                scanners.insert(ScannerType::Deserialization);
                priorities.entry(ScannerType::Deserialization).or_insert(7);
                scanners.insert(ScannerType::FileUpload);
                priorities.entry(ScannerType::FileUpload).or_insert(7);
            }
            TechCategory::Ruby(_) => {
                // All Ruby gets deserialization and mass assignment
                scanners.insert(ScannerType::Deserialization);
                priorities.entry(ScannerType::Deserialization).or_insert(9);
                scanners.insert(ScannerType::MassAssignment);
                priorities.entry(ScannerType::MassAssignment).or_insert(8);
            }
            _ => {}
        }
    }

    /// Apply smart skip logic for technology-scanner combinations
    fn apply_smart_skip_logic(&self, scanner: &ScannerType, tech: &TechCategory) -> bool {
        match (scanner, tech) {
            // Skip PHP CMS scanners for non-PHP
            (ScannerType::WordPress | ScannerType::Drupal | ScannerType::Laravel, tech)
                if !matches!(tech, TechCategory::Php(_)) =>
            {
                true
            }

            // Skip Java-specific scanners for non-Java
            (ScannerType::TomcatMisconfig | ScannerType::Log4j | ScannerType::Liferay, tech)
                if !matches!(tech, TechCategory::Java(_)) =>
            {
                true
            }

            // Skip Node.js specific for non-JS
            (
                ScannerType::PrototypePollution
                | ScannerType::Express
                | ScannerType::NextJs
                | ScannerType::React,
                tech,
            ) if !matches!(tech, TechCategory::JavaScript(_)) => true,

            // Skip Django for non-Python
            (ScannerType::Django, tech) if !matches!(tech, TechCategory::Python(_)) => true,

            // CRITICAL FIX: DO NOT skip injection for "static" sites
            // Cloudflare/Vercel/Netlify can run dynamic code
            // DISABLED to ensure all sites are tested for injection
            // (scanner, TechCategory::StaticSite(_))
            //     if scanner.is_injection()
            //         && !matches!(scanner, ScannerType::Xss | ScannerType::HtmlInjection) =>
            // {
            //     true
            // }

            // Skip GraphQL scanners for non-GraphQL
            (ScannerType::GraphQL | ScannerType::GraphQLSecurity, tech)
                if !matches!(tech, TechCategory::GraphQL) =>
            {
                true
            }

            // Skip gRPC scanner for non-gRPC
            (ScannerType::GrpC, tech) if !matches!(tech, TechCategory::GrpC) => true,

            // Skip WebSocket scanner for non-WebSocket
            (ScannerType::WebSocket, tech) if !matches!(tech, TechCategory::WebSocket) => true,

            _ => false,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_initialization() {
        let registry = ScannerRegistry::new();
        assert!(!registry.universal_scanners.is_empty());
        assert!(!registry.tech_scanner_map.is_empty());
    }

    #[test]
    fn test_universal_scanners_included() {
        let registry = ScannerRegistry::new();
        let scanners = registry.get_scanners_for_tech(&[TechCategory::Unknown]);

        assert!(scanners.contains(&ScannerType::Cors));
        assert!(scanners.contains(&ScannerType::SecurityHeaders));
        assert!(scanners.contains(&ScannerType::Clickjacking));
    }

    #[test]
    fn test_wordpress_scanners() {
        let registry = ScannerRegistry::new();
        let tech = vec![TechCategory::Php(PhpFramework::WordPress)];
        let scanners = registry.get_scanners_for_tech(&tech);

        assert!(scanners.contains(&ScannerType::WordPress));
        assert!(scanners.contains(&ScannerType::SqlI));
        assert!(!scanners.contains(&ScannerType::PrototypePollution));
    }

    #[test]
    fn test_static_site_skips_injection() {
        let registry = ScannerRegistry::new();
        let tech = vec![TechCategory::StaticSite(StaticPlatform::Vercel)];
        let scanners = registry.get_scanners_for_tech(&tech);

        // Should have XSS
        assert!(scanners.contains(&ScannerType::Xss));
        // Should NOT have SQLi
        assert!(!scanners.contains(&ScannerType::SqlI));
        // Should NOT have CommandInjection
        assert!(!scanners.contains(&ScannerType::CommandInjection));
    }

    #[test]
    fn test_graphql_scanners() {
        let registry = ScannerRegistry::new();
        let tech = vec![TechCategory::GraphQL];
        let scanners = registry.get_scanners_for_tech(&tech);

        assert!(scanners.contains(&ScannerType::GraphQL));
        assert!(scanners.contains(&ScannerType::GraphQLSecurity));
    }

    #[test]
    fn test_javascript_prototype_pollution() {
        let registry = ScannerRegistry::new();
        let tech = vec![TechCategory::JavaScript(JsFramework::Node)];
        let scanners = registry.get_scanners_for_tech(&tech);

        assert!(scanners.contains(&ScannerType::PrototypePollution));
    }

    #[test]
    fn test_java_deserialization() {
        let registry = ScannerRegistry::new();
        let tech = vec![TechCategory::Java(JavaFramework::Spring)];
        let scanners = registry.get_scanners_for_tech(&tech);

        assert!(scanners.contains(&ScannerType::Deserialization));
        assert!(scanners.contains(&ScannerType::Log4j));
    }

    #[test]
    fn test_priority_ordering() {
        let registry = ScannerRegistry::new();
        let tech = vec![TechCategory::Php(PhpFramework::WordPress)];
        let scanners = registry.get_scanners_for_tech(&tech);

        // WordPress scanner should be first (priority 10)
        assert_eq!(scanners[0], ScannerType::WordPress);
    }

    #[test]
    fn test_should_skip() {
        let registry = ScannerRegistry::new();

        // WordPress scanner should be skipped for JavaScript
        assert!(registry.should_skip(
            &ScannerType::WordPress,
            &TechCategory::JavaScript(JsFramework::Node)
        ));

        // WordPress scanner should NOT be skipped for WordPress
        assert!(!registry.should_skip(
            &ScannerType::WordPress,
            &TechCategory::Php(PhpFramework::WordPress)
        ));
    }

    #[test]
    fn test_tech_category_base_name() {
        assert_eq!(
            TechCategory::JavaScript(JsFramework::React).base_name(),
            "JavaScript"
        );
        assert_eq!(
            TechCategory::Php(PhpFramework::WordPress).base_name(),
            "PHP"
        );
        assert_eq!(
            TechCategory::Python(PythonFramework::Django).base_name(),
            "Python"
        );
    }

    #[test]
    fn test_tech_category_is_backend() {
        assert!(TechCategory::JavaScript(JsFramework::Express).is_backend());
        assert!(TechCategory::Python(PythonFramework::Django).is_backend());
        assert!(!TechCategory::JavaScript(JsFramework::React).is_backend());
        assert!(!TechCategory::StaticSite(StaticPlatform::Vercel).is_backend());
    }

    #[test]
    fn test_scanner_type_display_name() {
        assert_eq!(ScannerType::Xss.display_name(), "XSS Scanner");
        assert_eq!(ScannerType::SqlI.display_name(), "SQL Injection Scanner");
        assert_eq!(
            ScannerType::WordPress.display_name(),
            "WordPress Security Scanner"
        );
    }

    #[test]
    fn test_is_universal() {
        let registry = ScannerRegistry::new();

        assert!(registry.is_universal(&ScannerType::Cors));
        assert!(registry.is_universal(&ScannerType::SecurityHeaders));
        assert!(!registry.is_universal(&ScannerType::WordPress));
    }

    #[test]
    fn test_multiple_tech_categories() {
        let registry = ScannerRegistry::new();
        let tech = vec![
            TechCategory::JavaScript(JsFramework::React),
            TechCategory::GraphQL,
        ];
        let scanners = registry.get_scanners_for_tech(&tech);

        // Should have both React and GraphQL scanners
        assert!(scanners.contains(&ScannerType::React));
        assert!(scanners.contains(&ScannerType::GraphQL));
        assert!(scanners.contains(&ScannerType::PrototypePollution));
    }

    #[test]
    fn test_core_scanners_initialized() {
        let registry = ScannerRegistry::new();
        let core = registry.get_core_scanners();

        // Core scanners should include critical vulnerability types
        assert!(core.contains(&ScannerType::Xss));
        assert!(core.contains(&ScannerType::SqlI));
        assert!(core.contains(&ScannerType::Ssrf));
        assert!(core.contains(&ScannerType::Idor));
        assert!(core.contains(&ScannerType::Bola));
    }

    #[test]
    fn test_fallback_scanners_initialized() {
        let registry = ScannerRegistry::new();
        let fallback = registry.get_fallback_scanners();

        // Fallback should include extended coverage
        assert!(fallback.contains(&ScannerType::NoSqlI));
        assert!(fallback.contains(&ScannerType::Xxe));
        assert!(fallback.contains(&ScannerType::Deserialization));
        assert!(fallback.contains(&ScannerType::Log4j));
        assert!(!fallback.is_empty());
    }

    #[test]
    fn test_intelligent_scan_config_with_known_tech() {
        let registry = ScannerRegistry::new();
        let tech = vec![TechCategory::Python(PythonFramework::Flask)];
        let (scanners, intensity) = registry.get_intelligent_scan_config(&tech, 50);

        // Should include universal scanners
        assert!(scanners.contains(&ScannerType::Cors));
        // Should include core scanners
        assert!(scanners.contains(&ScannerType::Xss));
        assert!(scanners.contains(&ScannerType::SqlI));
        // Should include Python-specific (SSTI for Flask)
        assert!(scanners.contains(&ScannerType::Ssti));
        // Risk score 50 = Standard intensity
        assert_eq!(intensity, PayloadIntensity::Standard);
    }

    #[test]
    fn test_intelligent_scan_config_with_unknown_tech() {
        let registry = ScannerRegistry::new();
        let tech = vec![TechCategory::Unknown];
        let (scanners, intensity) = registry.get_intelligent_scan_config(&tech, 80);

        // Should include universal scanners
        assert!(scanners.contains(&ScannerType::Cors));
        // Should include core scanners
        assert!(scanners.contains(&ScannerType::Xss));
        // Should include fallback scanners for broader coverage
        assert!(scanners.contains(&ScannerType::NoSqlI));
        assert!(scanners.contains(&ScannerType::Deserialization));
        // Risk score 80 = Maximum intensity
        assert_eq!(intensity, PayloadIntensity::Maximum);
    }

    #[test]
    fn test_payload_intensity_from_risk_score() {
        assert_eq!(
            PayloadIntensity::from_risk_score(10),
            PayloadIntensity::Minimal
        );
        assert_eq!(
            PayloadIntensity::from_risk_score(25),
            PayloadIntensity::Minimal
        );
        assert_eq!(
            PayloadIntensity::from_risk_score(30),
            PayloadIntensity::Standard
        );
        assert_eq!(
            PayloadIntensity::from_risk_score(50),
            PayloadIntensity::Standard
        );
        assert_eq!(
            PayloadIntensity::from_risk_score(60),
            PayloadIntensity::Extended
        );
        assert_eq!(
            PayloadIntensity::from_risk_score(75),
            PayloadIntensity::Extended
        );
        assert_eq!(
            PayloadIntensity::from_risk_score(80),
            PayloadIntensity::Maximum
        );
        assert_eq!(
            PayloadIntensity::from_risk_score(100),
            PayloadIntensity::Maximum
        );
    }

    #[test]
    fn test_payload_intensity_limits() {
        assert_eq!(PayloadIntensity::Minimal.payload_limit(), 50);
        assert_eq!(PayloadIntensity::Standard.payload_limit(), 500);
        assert_eq!(PayloadIntensity::Extended.payload_limit(), 5000);
        assert_eq!(PayloadIntensity::Maximum.payload_limit(), usize::MAX);
    }

    #[test]
    fn test_is_core_scanner() {
        let registry = ScannerRegistry::new();

        assert!(registry.is_core(&ScannerType::Xss));
        assert!(registry.is_core(&ScannerType::SqlI));
        assert!(!registry.is_core(&ScannerType::WordPress)); // Framework-specific, not core
    }

    #[test]
    fn test_unknown_tech_gets_more_scanners_than_specific() {
        let registry = ScannerRegistry::new();

        // Unknown tech should get fallback expansion
        let (unknown_scanners, _) =
            registry.get_intelligent_scan_config(&[TechCategory::Unknown], 50);

        // Static site should get minimal scanners (skip server-side)
        let (static_scanners, _) = registry
            .get_intelligent_scan_config(&[TechCategory::StaticSite(StaticPlatform::Vercel)], 50);

        // Unknown should have more scanners due to fallback expansion
        assert!(unknown_scanners.len() > static_scanners.len());
    }
}
