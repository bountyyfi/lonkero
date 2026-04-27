// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use futures::stream::{self, StreamExt};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// Subdomain takeover service fingerprint
#[derive(Debug, Clone)]
struct ServiceFingerprint {
    /// Service/provider name
    name: &'static str,
    /// CNAME patterns that indicate this service
    cname_patterns: &'static [&'static str],
    /// HTTP response body patterns indicating vulnerability
    http_signatures: &'static [&'static str],
    /// HTTP headers that confirm the service
    header_patterns: &'static [(&'static str, &'static str)],
    /// Whether an NXDOMAIN response indicates vulnerability
    nxdomain_vulnerable: bool,
    /// Base severity when vulnerable
    severity: Severity,
    /// CVSS score
    cvss: f32,
    /// Whether takeover is confirmed exploitable
    confirmed_exploitable: bool,
    /// Remediation advice
    remediation: &'static str,
}

/// All supported service fingerprints
const SERVICE_FINGERPRINTS: &[ServiceFingerprint] = &[
    // AWS S3
    ServiceFingerprint {
        name: "AWS S3",
        cname_patterns: &[".s3.amazonaws.com", ".s3-website", "s3.amazonaws.com"],
        http_signatures: &[
            "NoSuchBucket",
            "The specified bucket does not exist",
            "BucketNotFound",
        ],
        header_patterns: &[("x-amz-request-id", ""), ("server", "AmazonS3")],
        nxdomain_vulnerable: false,
        severity: Severity::Critical,
        cvss: 9.0,
        confirmed_exploitable: true,
        remediation: "Remove the DNS CNAME record pointing to the non-existent S3 bucket, or recreate the bucket with the same name to claim it before an attacker does.",
    },
    // AWS CloudFront
    ServiceFingerprint {
        name: "AWS CloudFront",
        cname_patterns: &[".cloudfront.net"],
        http_signatures: &[
            "The request could not be satisfied",
            "Bad request",
            "ERROR: The request could not be satisfied",
        ],
        header_patterns: &[("server", "CloudFront"), ("x-amz-cf-pop", "")],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.5,
        confirmed_exploitable: true,
        remediation: "Remove the DNS CNAME record pointing to CloudFront, or configure a new CloudFront distribution with this alternate domain name.",
    },
    // Azure Web Apps
    ServiceFingerprint {
        name: "Azure Web Apps",
        cname_patterns: &[".azurewebsites.net", ".azure-mobile.net"],
        http_signatures: &[
            "404 Web Site not found",
            "Azure Error",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: true,
        severity: Severity::Critical,
        cvss: 9.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record pointing to Azure, or create a new Azure Web App with the matching hostname.",
    },
    // Azure Cloud Apps
    ServiceFingerprint {
        name: "Azure Cloud Apps",
        cname_patterns: &[".cloudapp.azure.com", ".cloudapp.net"],
        http_signatures: &[],
        header_patterns: &[],
        nxdomain_vulnerable: true,
        severity: Severity::Critical,
        cvss: 9.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or claim the Azure Cloud Service resource.",
    },
    // Azure Traffic Manager
    ServiceFingerprint {
        name: "Azure Traffic Manager",
        cname_patterns: &[".trafficmanager.net"],
        http_signatures: &[],
        header_patterns: &[],
        nxdomain_vulnerable: true,
        severity: Severity::High,
        cvss: 8.5,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or create a new Traffic Manager profile with the matching DNS name.",
    },
    // GitHub Pages
    ServiceFingerprint {
        name: "GitHub Pages",
        cname_patterns: &[".github.io", "github.map.fastly.net"],
        http_signatures: &[
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ],
        header_patterns: &[("server", "GitHub.com")],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record pointing to GitHub Pages, or configure a GitHub repository with this custom domain.",
    },
    // Heroku
    ServiceFingerprint {
        name: "Heroku",
        cname_patterns: &[".herokuapp.com", ".herokucdn.com", ".herokudns.com"],
        http_signatures: &[
            "No such app",
            "herokucdn.com/error-pages/",
            "There's nothing here, yet",
        ],
        header_patterns: &[("server", "Cowboy")],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record pointing to Heroku, or create a new Heroku app with the matching domain configuration.",
    },
    // Shopify
    ServiceFingerprint {
        name: "Shopify",
        cname_patterns: &[".myshopify.com", "shops.myshopify.com"],
        http_signatures: &[
            "Sorry, this shop is currently unavailable",
            "Only one step left",
        ],
        header_patterns: &[("x-shopify-stage", "")],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain in a Shopify store's settings.",
    },
    // Fastly
    ServiceFingerprint {
        name: "Fastly",
        cname_patterns: &[".fastly.net", ".fastlylb.net", ".map.fastly.net"],
        http_signatures: &[
            "Fastly error: unknown domain",
            "Fastly error:",
        ],
        header_patterns: &[("server", "Varnish"), ("via", "varnish")],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain in a Fastly service.",
    },
    // Pantheon
    ServiceFingerprint {
        name: "Pantheon",
        cname_patterns: &[".pantheonsite.io", ".pantheon.io"],
        http_signatures: &[
            "The gods are wise, but do not know of the site",
            "404 Unknown Site",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain in Pantheon.",
    },
    // Tumblr
    ServiceFingerprint {
        name: "Tumblr",
        cname_patterns: &[".tumblr.com", "domains.tumblr.com"],
        http_signatures: &[
            "There's nothing here",
            "Whatever you were looking for doesn't currently exist",
        ],
        header_patterns: &[("x-tumblr-user", "")],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 7.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain on a Tumblr blog.",
    },
    // Zendesk
    ServiceFingerprint {
        name: "Zendesk",
        cname_patterns: &[".zendesk.com", "zendesk.com"],
        http_signatures: &[
            "Help Center Closed",
            "This help center no longer exists",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain in Zendesk.",
    },
    // Netlify
    ServiceFingerprint {
        name: "Netlify",
        cname_patterns: &[".netlify.app", ".netlify.com", ".bitballoon.com"],
        http_signatures: &[
            "Not Found - Request ID:",
            "Page Not Found",
        ],
        header_patterns: &[("server", "Netlify")],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain on a Netlify site.",
    },
    // Ghost
    ServiceFingerprint {
        name: "Ghost",
        cname_patterns: &[".ghost.io", ".ghost.org"],
        http_signatures: &[
            "The thing you were looking for is no longer here",
            "Ghost site not found",
        ],
        header_patterns: &[("x-powered-by", "Ghost")],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain in Ghost.",
    },
    // Surge.sh
    ServiceFingerprint {
        name: "Surge.sh",
        cname_patterns: &[".surge.sh", "na-west1.surge.sh"],
        http_signatures: &[
            "project not found",
        ],
        header_patterns: &[("server", "SurgeSH")],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or deploy a project to Surge.sh with this domain.",
    },
    // Bitbucket
    ServiceFingerprint {
        name: "Bitbucket",
        cname_patterns: &[".bitbucket.io", ".bitbucket.org"],
        http_signatures: &[
            "Repository not found",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure Bitbucket Cloud repository to use this domain.",
    },
    // Cargo (crates.io documentation)
    ServiceFingerprint {
        name: "Cargo/crates.io",
        cname_patterns: &[".crates.io", ".docs.rs"],
        http_signatures: &[
            "404: This page could not be found",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 6.5,
        confirmed_exploitable: false,
        remediation: "Remove the CNAME record pointing to Cargo/crates.io.",
    },
    // Fly.io
    ServiceFingerprint {
        name: "Fly.io",
        cname_patterns: &[".fly.dev", ".fly.io"],
        http_signatures: &[
            "404 Not Found",
        ],
        header_patterns: &[("server", "Fly/"), ("fly-request-id", "")],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain in a Fly.io application.",
    },
    // Vercel
    ServiceFingerprint {
        name: "Vercel",
        cname_patterns: &[".vercel.app", ".now.sh", ".vercel.com"],
        http_signatures: &[
            "DEPLOYMENT_NOT_FOUND",
            "The deployment could not be found",
        ],
        header_patterns: &[("server", "Vercel"), ("x-vercel-id", "")],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain in a Vercel project.",
    },
    // WordPress.com
    ServiceFingerprint {
        name: "WordPress.com",
        cname_patterns: &[".wordpress.com", "lb.wordpress.com"],
        http_signatures: &[
            "Do you want to register",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 7.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain in WordPress.com.",
    },
    // Tilda
    ServiceFingerprint {
        name: "Tilda",
        cname_patterns: &[".tilda.ws", ".tildacdn.com"],
        http_signatures: &[
            "Please renew your subscription",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 7.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain in Tilda.",
    },
    // Agile CRM
    ServiceFingerprint {
        name: "Agile CRM",
        cname_patterns: &[".agilecrm.com"],
        http_signatures: &[
            "Sorry, this page is no longer available",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 7.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain in Agile CRM.",
    },
    // UserVoice
    ServiceFingerprint {
        name: "UserVoice",
        cname_patterns: &[".uservoice.com"],
        http_signatures: &[
            "This UserVoice subdomain is currently available",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain in UserVoice.",
    },
    // Cargo Collective
    ServiceFingerprint {
        name: "Cargo Collective",
        cname_patterns: &[".cargocollective.com", "subdomain.cargocollective.com"],
        http_signatures: &[
            "404 Not Found",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 6.5,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain in Cargo Collective.",
    },
    // Help Scout
    ServiceFingerprint {
        name: "Help Scout",
        cname_patterns: &[".helpscoutdocs.com", "secure.helpscout.net"],
        http_signatures: &[
            "No settings were found for this company",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 7.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain in Help Scout.",
    },
    // Acquia
    ServiceFingerprint {
        name: "Acquia",
        cname_patterns: &[".acquia-sites.com", ".acquia-test.co", ".acquia-dev.com"],
        http_signatures: &[
            "The site you are looking for could not be found",
            "Web Site Not Found",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or claim the domain in Acquia Cloud.",
    },
    // AWS Elastic Beanstalk
    ServiceFingerprint {
        name: "AWS Elastic Beanstalk",
        cname_patterns: &[".elasticbeanstalk.com"],
        http_signatures: &[],
        header_patterns: &[],
        nxdomain_vulnerable: true,
        severity: Severity::Critical,
        cvss: 9.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or recreate the Elastic Beanstalk environment with the matching name.",
    },
    // Read the Docs
    ServiceFingerprint {
        name: "Read the Docs",
        cname_patterns: &[".readthedocs.io", ".readthedocs.com", "readthedocs.org"],
        http_signatures: &[
            "unknown to Read the Docs",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 6.5,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or claim the project on Read the Docs.",
    },
    // Webflow
    ServiceFingerprint {
        name: "Webflow",
        cname_patterns: &["proxy.webflow.com", "proxy-ssl.webflow.com", ".webflow.io"],
        http_signatures: &[
            "The page you are looking for doesn't exist or has been moved",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or add the custom domain in your Webflow site settings.",
    },
    // Brightcove
    ServiceFingerprint {
        name: "Brightcove",
        cname_patterns: &[".bcvp0rtal.com", ".brightcovegallery.com", ".gallery.video"],
        http_signatures: &[
            "<p class=\"bc-gallery-error-code\">Error Code: 404</p>",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 7.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or claim the gallery in Brightcove.",
    },
    // Big Cartel
    ServiceFingerprint {
        name: "Big Cartel",
        cname_patterns: &[".bigcartel.com"],
        http_signatures: &[
            "<h1>Oops! We couldn&#8217;t find that page.</h1>",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or claim the store on Big Cartel.",
    },
    // Campaign Monitor
    ServiceFingerprint {
        name: "Campaign Monitor",
        cname_patterns: &[".createsend.com"],
        http_signatures: &[
            "Double check the URL or <a href=\"mailto:help@createsend.com",
            "Trying to access your account?",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain in Campaign Monitor.",
    },
    // Aha!
    ServiceFingerprint {
        name: "Aha!",
        cname_patterns: &[".aha.io"],
        http_signatures: &[
            "There is no portal here ... sending you back to Aha!",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 7.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the portal in Aha!.",
    },
    // Intercom
    ServiceFingerprint {
        name: "Intercom",
        cname_patterns: &["custom.intercom.help"],
        http_signatures: &[
            "This page is reserved for artistic dogs.",
            "Uh oh. That page doesn&#8217;t exist.",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the help center custom domain in Intercom.",
    },
    // Hatena Blog
    ServiceFingerprint {
        name: "Hatena Blog",
        cname_patterns: &["hatenablog.com"],
        http_signatures: &[
            "404 Blog is not found",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 7.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or claim the blog on Hatena.",
    },
    // LaunchRock
    ServiceFingerprint {
        name: "LaunchRock",
        cname_patterns: &[".launchrock.com"],
        http_signatures: &[
            "It looks like you may have taken a wrong turn somewhere",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 7.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain in LaunchRock.",
    },
    // Pingdom
    ServiceFingerprint {
        name: "Pingdom",
        cname_patterns: &["stats.pingdom.com"],
        http_signatures: &[
            "Sorry, couldn&#8217;t find the status page",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 6.5,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or claim the public status page in Pingdom.",
    },
    // Readme.io
    ServiceFingerprint {
        name: "Readme.io",
        cname_patterns: &[".readme.io"],
        http_signatures: &[
            "Project doesnt exist... yet!",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 7.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or claim the project on Readme.io.",
    },
    // Tave
    ServiceFingerprint {
        name: "Tave",
        cname_patterns: &[".tave.com"],
        http_signatures: &[
            "<h1>Error 404: Page Not Found</h1>",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 6.5,
        confirmed_exploitable: false,
        remediation: "Remove the CNAME record pointing to Tave.",
    },
    // Teamwork
    ServiceFingerprint {
        name: "Teamwork",
        cname_patterns: &[".teamwork.com"],
        http_signatures: &[
            "Oops - We didn&#8217;t find your site.",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 7.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the workspace domain in Teamwork.",
    },
    // Unbounce
    ServiceFingerprint {
        name: "Unbounce",
        cname_patterns: &[".unbouncepages.com"],
        http_signatures: &[
            "The requested URL was not found on this server",
            "<title>404 Not Found</title>",
        ],
        header_patterns: &[],
        // Body text "404 Not Found" alone would be too broad on its own,
        // but the .unbouncepages.com CNAME constraint anchors the match.
        nxdomain_vulnerable: true,
        severity: Severity::High,
        cvss: 7.5,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or add the custom domain in Unbounce.",
    },
    // Wishpond
    ServiceFingerprint {
        name: "Wishpond",
        cname_patterns: &[".wishpond.com"],
        http_signatures: &[
            "https://www.wishpond.com/404?campaign=true",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 7.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the campaign in Wishpond.",
    },
    // Aftership
    ServiceFingerprint {
        name: "Aftership",
        cname_patterns: &[".aftership.com"],
        http_signatures: &[
            "Oops.... Looks like you got lost",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 7.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the tracking domain in AfterShip.",
    },
    // GitBook
    ServiceFingerprint {
        name: "GitBook",
        cname_patterns: &["hosting.gitbook.io", "hosting.gitbook.com", ".gitbook.io"],
        http_signatures: &[
            "If you need urgent help, please contact our support team",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the custom domain in GitBook.",
    },
    // HubSpot
    ServiceFingerprint {
        name: "HubSpot",
        cname_patterns: &[
            "sites.hscoscdn00.net",
            "sites.hscoscdn10.net",
            "sites.hscoscdn20.net",
            "sites.hscoscdn30.net",
            "sites.hscoscdn40.net",
        ],
        http_signatures: &[
            "domain is not configured to redirect",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the custom domain in HubSpot CMS.",
    },
    // Kajabi
    ServiceFingerprint {
        name: "Kajabi",
        cname_patterns: &["endpoint.mykajabi.com"],
        http_signatures: &[
            "<h1>The page you were looking for doesn&#8217;t exist.</h1>",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 6.5,
        confirmed_exploitable: false,
        remediation: "Remove the CNAME record pointing to Kajabi.",
    },
    // Helpjuice
    ServiceFingerprint {
        name: "Helpjuice",
        cname_patterns: &[".helpjuice.com"],
        http_signatures: &[
            "We could not find what you&#39;re looking for.",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 7.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the help center domain in Helpjuice.",
    },
    // Anima (S3-backed uploads)
    ServiceFingerprint {
        name: "Anima",
        cname_patterns: &["anima-uploads.s3.amazonaws.com"],
        http_signatures: &[
            "<Code>NoSuchKey</Code>",
            "<Code>NoSuchBucket</Code>",
        ],
        header_patterns: &[("server", "AmazonS3")],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or reconfigure the Anima project.",
    },
    // Smartling
    ServiceFingerprint {
        name: "Smartling",
        cname_patterns: &["sites.smartling.com"],
        http_signatures: &[
            "Domain is not configured",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 7.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain in Smartling Global Delivery Network.",
    },
    // Strikingly
    ServiceFingerprint {
        name: "Strikingly",
        cname_patterns: &[".s.strikinglydns.com", ".strikinglydns.com"],
        http_signatures: &[
            "But if you&#39;re looking to build your own website",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 7.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or claim the domain in Strikingly.",
    },
    // Cargo Collective (proper signature)
    ServiceFingerprint {
        name: "Worksites.net",
        cname_patterns: &[".worksites.net"],
        http_signatures: &[
            "Hello! Sorry, but the website you&#8217;re looking for doesn&#8217;t exist.",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 7.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the worksite.",
    },
    // Thinkific
    ServiceFingerprint {
        name: "Thinkific",
        cname_patterns: &[".thinkific.com"],
        http_signatures: &[
            "We couldn&#39;t find what you&#39;re looking for.",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 6.5,
        confirmed_exploitable: false,
        remediation: "Remove the CNAME record or claim the domain on Thinkific.",
    },
    // Uberflip
    ServiceFingerprint {
        name: "Uberflip",
        cname_patterns: &[".uberflip.com"],
        http_signatures: &[
            "The URL you&#39;ve accessed does not provide a hub.",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 7.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the hub on Uberflip.",
    },
    // Mashery / TIBCO
    ServiceFingerprint {
        name: "Mashery",
        cname_patterns: &[".mashery.com"],
        http_signatures: &[
            "Unrecognized domain <strong>",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 7.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the API portal in Mashery.",
    },
    // Worksuite (Pulse / Tilda variants) - skip if too generic
    // Cloudfront S3 redirector / S3 Website endpoint
    ServiceFingerprint {
        name: "AWS S3 Website",
        cname_patterns: &[
            "s3-website-us-east-1.amazonaws.com",
            "s3-website-us-east-2.amazonaws.com",
            "s3-website-us-west-1.amazonaws.com",
            "s3-website-us-west-2.amazonaws.com",
            "s3-website-eu-west-1.amazonaws.com",
            "s3-website-eu-central-1.amazonaws.com",
            "s3-website.eu-west-2.amazonaws.com",
            "s3-website.eu-west-3.amazonaws.com",
            "s3-website.ap-south-1.amazonaws.com",
            "s3-website.ap-northeast-1.amazonaws.com",
            "s3-website.ap-southeast-1.amazonaws.com",
            "s3-website.ap-southeast-2.amazonaws.com",
            "s3-website.eu-north-1.amazonaws.com",
            "s3-website.ca-central-1.amazonaws.com",
            "s3-website.sa-east-1.amazonaws.com",
        ],
        http_signatures: &[
            "NoSuchBucket",
            "The specified bucket does not exist",
        ],
        header_patterns: &[("server", "AmazonS3")],
        nxdomain_vulnerable: false,
        severity: Severity::Critical,
        cvss: 9.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record pointing to the missing S3 website bucket, or recreate the bucket with the same name in the same region.",
    },
    // Azure Blob Storage
    ServiceFingerprint {
        name: "Azure Blob Storage",
        cname_patterns: &[".blob.core.windows.net"],
        http_signatures: &[
            "<Code>BlobNotFound</Code>",
            "The specified blob does not exist",
            "<Code>InvalidUri</Code>",
        ],
        header_patterns: &[("server", "Microsoft-HTTPAPI")],
        nxdomain_vulnerable: true,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or recreate the Azure storage account with the matching name.",
    },
    // Azure CDN (msecnd / azureedge)
    ServiceFingerprint {
        name: "Azure CDN",
        cname_patterns: &[".azureedge.net", ".vo.msecnd.net"],
        http_signatures: &[],
        header_patterns: &[],
        nxdomain_vulnerable: true,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or claim the Azure CDN endpoint with the matching name.",
    },
    // Google Cloud Storage
    ServiceFingerprint {
        name: "Google Cloud Storage",
        cname_patterns: &["c.storage.googleapis.com", "storage.googleapis.com"],
        http_signatures: &[
            "<Code>NoSuchBucket</Code>",
            "The specified bucket does not exist.",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or recreate the GCS bucket with the same name.",
    },
    // Firebase Hosting
    ServiceFingerprint {
        name: "Firebase Hosting",
        cname_patterns: &[".web.app", ".firebaseapp.com"],
        http_signatures: &[
            "Site Not Found",
            "Why am I seeing this?",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: true,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or claim the Firebase Hosting site name.",
    },
    // DigitalOcean App Platform
    ServiceFingerprint {
        name: "DigitalOcean App Platform",
        cname_patterns: &[".ondigitalocean.app"],
        http_signatures: &[
            "Domain Not Found",
            "We could not find an application matching this hostname",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: true,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the custom domain in DigitalOcean App Platform.",
    },
    // Render.com
    ServiceFingerprint {
        name: "Render",
        cname_patterns: &[".onrender.com"],
        http_signatures: &[],
        header_patterns: &[("x-render-routing", "no-server")],
        nxdomain_vulnerable: true,
        severity: Severity::High,
        cvss: 7.5,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or claim the service name on Render.",
    },
    // Railway
    ServiceFingerprint {
        name: "Railway",
        cname_patterns: &[".railway.app", ".up.railway.app"],
        http_signatures: &[
            "Application not found",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: true,
        severity: Severity::High,
        cvss: 7.5,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or deploy a Railway service with the matching subdomain.",
    },
    // Pages.dev (Cloudflare Pages) - NXDOMAIN-only signal to avoid FPs;
    // body-based 404 detection is too noisy on Cloudflare-served sites.
    ServiceFingerprint {
        name: "Cloudflare Pages",
        cname_patterns: &[".pages.dev"],
        http_signatures: &[],
        header_patterns: &[],
        nxdomain_vulnerable: true,
        severity: Severity::Medium,
        cvss: 6.5,
        confirmed_exploitable: false,
        remediation: "Remove the CNAME record or claim the Cloudflare Pages project name.",
    },
    // Workers.dev (Cloudflare Workers)
    ServiceFingerprint {
        name: "Cloudflare Workers",
        cname_patterns: &[".workers.dev"],
        http_signatures: &[],
        header_patterns: &[],
        nxdomain_vulnerable: true,
        severity: Severity::Medium,
        cvss: 6.5,
        confirmed_exploitable: false,
        remediation: "Remove the CNAME record or claim the Cloudflare Workers script name.",
    },
    // GitLab Pages
    ServiceFingerprint {
        name: "GitLab Pages",
        cname_patterns: &[".gitlab.io"],
        http_signatures: &[
            "The page you&#39;re looking for could not be found",
            "<title>The page you're looking for could not be found",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 6.5,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the custom domain in GitLab Pages.",
    },
    // Squarespace
    ServiceFingerprint {
        name: "Squarespace",
        cname_patterns: &["ext-cust.squarespace.com", "ext-sq.squarespace.com"],
        http_signatures: &[
            "No Such Account",
            "Website Expired",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 7.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or attach the domain to a Squarespace site.",
    },
    // Statuspage (PagerDuty)
    ServiceFingerprint {
        name: "Statuspage",
        cname_patterns: &["statuspage.io"],
        http_signatures: &[
            "You are being <a href=\"https://www.statuspage.io\">redirected",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 6.0,
        confirmed_exploitable: false,
        remediation: "Remove the CNAME record or configure the page in Statuspage.",
    },
];

/// DNS resolution result for a subdomain
#[derive(Debug, Clone)]
struct DnsResult {
    subdomain: String,
    cname_records: Vec<String>,
    a_records: Vec<String>,
    is_nxdomain: bool,
    matched_service: Option<String>,
}

/// Subdomain takeover scanner
pub struct SubdomainTakeoverScanner {
    http_client: Arc<HttpClient>,
}

impl SubdomainTakeoverScanner {
    /// Create a new subdomain takeover scanner
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan a target URL for subdomain takeover vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // License check
        if !crate::license::verify_scan_authorized() {
            return Ok((Vec::new(), 0));
        }

        info!("[SubdomainTakeover] Starting scan for: {}", url);

        let vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Get baseline response for context awareness
        tests_run += 1;
        let _baseline_response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(e) => {
                debug!("[SubdomainTakeover] Failed to get baseline: {}", e);
                return Ok((vulnerabilities, tests_run));
            }
        };

        // Extract domain from URL
        let domain = match self.extract_domain(url) {
            Some(d) => d,
            None => {
                info!("[SubdomainTakeover] Could not extract domain from URL");
                return Ok((vulnerabilities, tests_run));
            }
        };

        info!("[SubdomainTakeover] Scanning domain: {}", domain);

        // Check if subdomain enumeration is enabled or if we should enumerate
        let subdomains = if config.enum_subdomains || config.subdomain_extended() {
            // Use comprehensive subdomain enumeration
            self.enumerate_subdomains(&domain, config.subdomain_extended())
                .await
        } else {
            // Just check the main domain and www
            vec![domain.clone(), format!("www.{}", domain)]
        };

        if subdomains.is_empty() {
            info!("[SubdomainTakeover] No subdomains to check");
            return Ok((vulnerabilities, tests_run));
        }

        info!(
            "[SubdomainTakeover] Checking {} subdomains for takeover vulnerabilities",
            subdomains.len()
        );

        // DNS resolver setup
        let resolver = match self.create_resolver().await {
            Ok(r) => r,
            Err(e) => {
                warn!("[SubdomainTakeover] Failed to create DNS resolver: {}", e);
                return Ok((vulnerabilities, tests_run));
            }
        };

        // Scan all subdomains in parallel
        let tests_completed = Arc::new(AtomicUsize::new(0));
        let vulns = Arc::new(Mutex::new(Vec::new()));
        let resolver = Arc::new(resolver);

        // High concurrency for DNS lookups
        let concurrent_requests = 50;

        stream::iter(subdomains)
            .for_each_concurrent(concurrent_requests, |subdomain| {
                let resolver = Arc::clone(&resolver);
                let client = Arc::clone(&self.http_client);
                let tests_completed = Arc::clone(&tests_completed);
                let vulns = Arc::clone(&vulns);

                async move {
                    // DNS resolution
                    tests_completed.fetch_add(1, Ordering::Relaxed);

                    let dns_result = Self::resolve_subdomain(&resolver, &subdomain).await;

                    if let Some(result) = dns_result {
                        // Check for NXDOMAIN vulnerabilities
                        if result.is_nxdomain {
                            if let Some(vuln) = Self::check_nxdomain_vulnerability(&result).await {
                                let mut v = vulns.lock().await;
                                v.push(vuln);
                                return;
                            }
                        }

                        // Check for CNAME-based vulnerabilities
                        if !result.cname_records.is_empty() {
                            for cname in &result.cname_records {
                                if let Some(fingerprint) = Self::match_cname_to_service(cname) {
                                    // HTTP verification
                                    tests_completed.fetch_add(1, Ordering::Relaxed);

                                    if let Some(vuln) = Self::verify_http_vulnerability(
                                        &client,
                                        &result.subdomain,
                                        cname,
                                        fingerprint,
                                    )
                                    .await
                                    {
                                        info!(
                                            "[ALERT] Subdomain takeover found: {} -> {} ({})",
                                            result.subdomain, cname, fingerprint.name
                                        );
                                        let mut v = vulns.lock().await;
                                        v.push(vuln);
                                    }
                                }
                            }
                        }
                    }
                }
            })
            .await;

        // Extract results
        let final_vulns = match Arc::try_unwrap(vulns) {
            Ok(mutex) => mutex.into_inner(),
            Err(arc) => {
                let guard = arc.lock().await;
                guard.clone()
            }
        };

        tests_run += tests_completed.load(Ordering::Relaxed);

        info!(
            "[SUCCESS] [SubdomainTakeover] Completed {} tests, found {} vulnerabilities",
            tests_run,
            final_vulns.len()
        );

        Ok((final_vulns, tests_run))
    }

    /// Extract the domain from a URL
    fn extract_domain(&self, url: &str) -> Option<String> {
        url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
    }

    /// Create a DNS resolver
    async fn create_resolver(&self) -> Result<TokioResolver> {
        let resolver = TokioResolver::builder(TokioConnectionProvider::default())
            .map_err(|e| anyhow::anyhow!("Failed to create resolver: {}", e))?
            .build();
        Ok(resolver)
    }

    /// Enumerate subdomains for a domain
    async fn enumerate_subdomains(&self, domain: &str, thorough: bool) -> Vec<String> {
        let mut subdomains = Vec::new();

        // Common subdomain prefixes
        let common_prefixes = vec![
            "www",
            "api",
            "admin",
            "dev",
            "staging",
            "test",
            "qa",
            "uat",
            "mail",
            "smtp",
            "ftp",
            "vpn",
            "remote",
            "blog",
            "shop",
            "store",
            "cdn",
            "static",
            "assets",
            "media",
            "m",
            "mobile",
            "app",
            "portal",
            "dashboard",
            "panel",
            "beta",
            "alpha",
            "demo",
            "git",
            "gitlab",
            "jenkins",
            "ci",
            "jira",
            "confluence",
            "wiki",
            "status",
            "monitor",
            "db",
            "mysql",
            "postgres",
            "redis",
            "backup",
            "old",
            "new",
            "legacy",
            "v1",
            "v2",
            "ws",
            "graphql",
            "docs",
            "help",
            "support",
            "secure",
            "login",
            "auth",
            "oauth",
            "payment",
            "internal",
            "corp",
            "intranet",
            // Frequently dangling: marketing/campaign hosts
            "go",
            "promo",
            "campaign",
            "campaigns",
            "offers",
            "deals",
            "newsletter",
            "events",
            "event",
            "webinar",
            "landing",
            "lp",
            "tracker",
            "track",
            "links",
            "share",
            // Frequently dangling: support/help portals
            "kb",
            "knowledge",
            "knowledgebase",
            "answers",
            "community",
            "feedback",
            "ideas",
            // Frequently dangling: dev/staging variants used once and forgotten
            "preview",
            "review",
            "ephemeral",
            "feature",
            "experiment",
            "lab",
            "labs",
            "playground",
            "sandbox",
            // Frequently dangling: internal status / monitoring
            "uptime",
            "incident",
            "incidents",
            "stats",
            "grafana",
            "kibana",
            "prometheus",
            "alertmanager",
        ];

        // Extended prefixes for thorough scanning
        let extended_prefixes = vec![
            "autodiscover",
            "autoconfig",
            "cpanel",
            "whm",
            "plesk",
            "webdisk",
            "webmail",
            "email",
            "mx",
            "ns1",
            "ns2",
            "ftp2",
            "files",
            "download",
            "upload",
            "ssl",
            "tls",
            "test1",
            "test2",
            "dev1",
            "dev2",
            "stage",
            "staging1",
            "staging2",
            "prod",
            "production",
            "lb",
            "loadbalancer",
            "proxy",
            "gateway",
            "cdn1",
            "cdn2",
            "static1",
            "static2",
            "img",
            "images",
            "video",
            "stream",
            "chat",
            "crm",
            "erp",
            "hr",
            "finance",
            "reports",
            "analytics",
            "stats",
            "logging",
            "logs",
        ];

        let prefixes: Vec<&str> = if thorough {
            common_prefixes
                .iter()
                .chain(extended_prefixes.iter())
                .cloned()
                .collect()
        } else {
            common_prefixes
        };

        // Generate subdomains
        for prefix in prefixes {
            subdomains.push(format!("{}.{}", prefix, domain));
        }

        // Add the base domain
        subdomains.push(domain.to_string());

        subdomains
    }

    /// Resolve a subdomain's DNS records
    async fn resolve_subdomain(resolver: &TokioResolver, subdomain: &str) -> Option<DnsResult> {
        let mut result = DnsResult {
            subdomain: subdomain.to_string(),
            cname_records: Vec::new(),
            a_records: Vec::new(),
            is_nxdomain: false,
            matched_service: None,
        };

        // Query CNAME records
        match resolver
            .lookup(subdomain, hickory_resolver::proto::rr::RecordType::CNAME)
            .await
        {
            Ok(response) => {
                for record in response.iter() {
                    if let Some(cname) = record.as_cname() {
                        result.cname_records.push(cname.0.to_string());
                    }
                }
            }
            Err(e) => {
                let error_str = e.to_string().to_lowercase();
                if error_str.contains("nxdomain") || error_str.contains("no name") {
                    result.is_nxdomain = true;
                }
            }
        }

        // Query A records
        match resolver.lookup_ip(subdomain).await {
            Ok(response) => {
                for ip in response.iter() {
                    result.a_records.push(ip.to_string());
                }
            }
            Err(e) => {
                let error_str = e.to_string().to_lowercase();
                if error_str.contains("nxdomain") || error_str.contains("no name") {
                    result.is_nxdomain = true;
                }
            }
        }

        // Only return if we have results or NXDOMAIN
        if result.is_nxdomain || !result.cname_records.is_empty() || !result.a_records.is_empty() {
            Some(result)
        } else {
            None
        }
    }

    /// Match a CNAME record to a known vulnerable service
    fn match_cname_to_service(cname: &str) -> Option<&'static ServiceFingerprint> {
        let cname_lower = cname.to_lowercase();

        for fingerprint in SERVICE_FINGERPRINTS {
            for pattern in fingerprint.cname_patterns {
                if cname_lower.contains(pattern) {
                    return Some(fingerprint);
                }
            }
        }

        None
    }

    /// Check for NXDOMAIN-based vulnerabilities
    async fn check_nxdomain_vulnerability(dns_result: &DnsResult) -> Option<Vulnerability> {
        // Check if any known service is vulnerable to NXDOMAIN takeover
        for cname in &dns_result.cname_records {
            if let Some(fingerprint) = Self::match_cname_to_service(cname) {
                if fingerprint.nxdomain_vulnerable {
                    return Some(Self::create_vulnerability(
                        &dns_result.subdomain,
                        cname,
                        fingerprint,
                        "NXDOMAIN response indicates the underlying service has been decommissioned",
                        Confidence::High,
                    ));
                }
            }
        }

        None
    }

    /// Verify vulnerability via HTTP response
    async fn verify_http_vulnerability(
        client: &HttpClient,
        subdomain: &str,
        cname: &str,
        fingerprint: &'static ServiceFingerprint,
    ) -> Option<Vulnerability> {
        // Try both HTTP and HTTPS
        for scheme in &["https", "http"] {
            let url = format!("{}://{}", scheme, subdomain);

            match client.get(&url).await {
                Ok(response) => {
                    // Check HTTP signatures
                    let body_lower = response.body.to_lowercase();

                    for signature in fingerprint.http_signatures {
                        if body_lower.contains(&signature.to_lowercase()) {
                            let evidence = format!(
                                "HTTP response contains takeover signature: '{}'. CNAME: {} -> {}",
                                signature, subdomain, cname
                            );

                            return Some(Self::create_vulnerability(
                                subdomain,
                                cname,
                                fingerprint,
                                &evidence,
                                Confidence::High,
                            ));
                        }
                    }

                    // Check header patterns
                    for (header_name, expected_value) in fingerprint.header_patterns {
                        if let Some(header_value) = response.header(header_name) {
                            if expected_value.is_empty() || header_value.contains(expected_value) {
                                // Header matches - do additional body check for Fly.io
                                if fingerprint.name == "Fly.io" {
                                    // Fly.io needs specific 404 pattern
                                    if body_lower.contains("404 not found")
                                        && !body_lower.contains("your app")
                                    {
                                        let evidence = format!(
                                            "Fly.io 404 response with fly-request-id header. CNAME: {} -> {}",
                                            subdomain, cname
                                        );
                                        return Some(Self::create_vulnerability(
                                            subdomain,
                                            cname,
                                            fingerprint,
                                            &evidence,
                                            Confidence::Medium,
                                        ));
                                    }
                                }
                                // Render: x-render-routing: no-server only appears
                                // when no service is bound to the hostname.
                                if fingerprint.name == "Render"
                                    && header_name.eq_ignore_ascii_case("x-render-routing")
                                    && header_value.to_lowercase().contains("no-server")
                                {
                                    let evidence = format!(
                                        "Render 'x-render-routing: no-server' indicates no service is bound. CNAME: {} -> {}",
                                        subdomain, cname
                                    );
                                    return Some(Self::create_vulnerability(
                                        subdomain,
                                        cname,
                                        fingerprint,
                                        &evidence,
                                        Confidence::High,
                                    ));
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("[SubdomainTakeover] HTTP request failed for {}: {}", url, e);
                    // Connection errors to known services might also indicate vulnerability
                    let error_str = e.to_string().to_lowercase();
                    if error_str.contains("connection refused")
                        || error_str.contains("no route to host")
                    {
                        // Could indicate the service is down/decommissioned
                        debug!(
                            "[SubdomainTakeover] Connection error may indicate vulnerability: {}",
                            subdomain
                        );
                    }
                }
            }
        }

        None
    }

    /// Create a vulnerability report
    fn create_vulnerability(
        subdomain: &str,
        cname: &str,
        fingerprint: &'static ServiceFingerprint,
        evidence: &str,
        confidence: Confidence,
    ) -> Vulnerability {
        let description = format!(
            "Subdomain {} is vulnerable to takeover. The CNAME record points to {} ({}) \
            which appears to be unclaimed or decommissioned. An attacker could register this \
            resource on the {} platform and serve malicious content on your domain, potentially \
            enabling phishing attacks, cookie theft, and reputation damage.",
            subdomain, cname, fingerprint.name, fingerprint.name
        );

        let remediation = format!(
            "IMMEDIATE ACTION REQUIRED:\n\n\
            1. **Primary Fix**: {}\n\n\
            2. **Verify the Fix**:\n\
               - After making DNS changes, wait for TTL expiration (check current TTL)\n\
               - Verify with: `dig {} CNAME +short`\n\
               - Confirm the CNAME no longer points to {}\n\n\
            3. **Prevent Future Occurrences**:\n\
               - Implement a process to review DNS records when decommissioning services\n\
               - Use DNS monitoring to detect dangling records\n\
               - Document all external service dependencies\n\n\
            4. **If Already Exploited**:\n\
               - Check if attacker has claimed the resource\n\
               - Review access logs for suspicious activity\n\
               - Consider notifying affected users if cookies/sessions were at risk\n\n\
            References:\n\
            - OWASP: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover\n\
            - CWE-284: https://cwe.mitre.org/data/definitions/284.html",
            fingerprint.remediation,
            subdomain,
            fingerprint.name
        );

        Vulnerability {
            id: format!("subdomain_takeover_{:x}", rand::random::<u32>()),
            vuln_type: format!("Subdomain Takeover - {}", fingerprint.name),
            severity: fingerprint.severity.clone(),
            confidence,
            category: "DNS Security".to_string(),
            url: format!("https://{}", subdomain),
            parameter: Some("CNAME".to_string()),
            payload: cname.to_string(),
            description,
            evidence: Some(evidence.to_string()),
            cwe: "CWE-284".to_string(), // Improper Access Control
            cvss: fingerprint.cvss,
            verified: fingerprint.confirmed_exploitable,
            false_positive: false,
            remediation,
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }
}

/// Scan a target for subdomain takeover vulnerabilities
/// Convenience function for use by the scanner registry
pub async fn scan_subdomain_takeover(
    http_client: Arc<HttpClient>,
    url: &str,
    config: &ScanConfig,
) -> Result<(Vec<Vulnerability>, usize)> {
    let scanner = SubdomainTakeoverScanner::new(http_client);
    scanner.scan(url, config).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cname_matching() {
        // Test AWS S3
        assert!(
            SubdomainTakeoverScanner::match_cname_to_service("mybucket.s3.amazonaws.com").is_some()
        );

        // Test GitHub Pages
        assert!(SubdomainTakeoverScanner::match_cname_to_service("myorg.github.io").is_some());

        // Test Azure
        assert!(
            SubdomainTakeoverScanner::match_cname_to_service("myapp.azurewebsites.net").is_some()
        );

        // Test Heroku
        assert!(SubdomainTakeoverScanner::match_cname_to_service("myapp.herokuapp.com").is_some());

        // New providers
        assert!(SubdomainTakeoverScanner::match_cname_to_service("example.acquia-sites.com").is_some());
        assert!(
            SubdomainTakeoverScanner::match_cname_to_service("env.us-east-1.elasticbeanstalk.com")
                .is_some()
        );
        assert!(SubdomainTakeoverScanner::match_cname_to_service("docs.readthedocs.io").is_some());
        assert!(SubdomainTakeoverScanner::match_cname_to_service("proxy-ssl.webflow.com").is_some());
        assert!(SubdomainTakeoverScanner::match_cname_to_service("custom.intercom.help").is_some());
        assert!(
            SubdomainTakeoverScanner::match_cname_to_service("acct.sites.hscoscdn10.net").is_some()
        );
        assert!(SubdomainTakeoverScanner::match_cname_to_service("user.gitbook.io").is_some());
        assert!(
            SubdomainTakeoverScanner::match_cname_to_service("storage.blob.core.windows.net")
                .is_some()
        );
        assert!(SubdomainTakeoverScanner::match_cname_to_service("svc.onrender.com").is_some());
        assert!(SubdomainTakeoverScanner::match_cname_to_service("app.up.railway.app").is_some());
        assert!(
            SubdomainTakeoverScanner::match_cname_to_service("ext-cust.squarespace.com").is_some()
        );
        assert!(SubdomainTakeoverScanner::match_cname_to_service("user.gitlab.io").is_some());
        assert!(SubdomainTakeoverScanner::match_cname_to_service("site.web.app").is_some());
        assert!(SubdomainTakeoverScanner::match_cname_to_service("foo.azureedge.net").is_some());
        assert!(
            SubdomainTakeoverScanner::match_cname_to_service("anima-uploads.s3.amazonaws.com")
                .is_some()
        );

        // Test unknown service
        assert!(SubdomainTakeoverScanner::match_cname_to_service("unknown.example.com").is_none());
    }

    #[test]
    fn test_fingerprint_coverage() {
        // Ensure we have all the required services
        let service_names: Vec<&str> = SERVICE_FINGERPRINTS.iter().map(|f| f.name).collect();

        assert!(service_names.contains(&"AWS S3"));
        assert!(service_names.contains(&"AWS CloudFront"));
        assert!(service_names.contains(&"Azure Web Apps"));
        assert!(service_names.contains(&"GitHub Pages"));
        assert!(service_names.contains(&"Heroku"));
        assert!(service_names.contains(&"Shopify"));
        assert!(service_names.contains(&"Fastly"));
        assert!(service_names.contains(&"Pantheon"));
        assert!(service_names.contains(&"Tumblr"));
        assert!(service_names.contains(&"Zendesk"));
        assert!(service_names.contains(&"Netlify"));
        assert!(service_names.contains(&"Ghost"));
        assert!(service_names.contains(&"Surge.sh"));
        assert!(service_names.contains(&"Bitbucket"));
        assert!(service_names.contains(&"Fly.io"));
        assert!(service_names.contains(&"Vercel"));
        // Newly added high-fidelity fingerprints
        assert!(service_names.contains(&"Acquia"));
        assert!(service_names.contains(&"AWS Elastic Beanstalk"));
        assert!(service_names.contains(&"AWS S3 Website"));
        assert!(service_names.contains(&"Azure Blob Storage"));
        assert!(service_names.contains(&"Azure CDN"));
        assert!(service_names.contains(&"Google Cloud Storage"));
        assert!(service_names.contains(&"Firebase Hosting"));
        assert!(service_names.contains(&"DigitalOcean App Platform"));
        assert!(service_names.contains(&"Render"));
        assert!(service_names.contains(&"Railway"));
        assert!(service_names.contains(&"Cloudflare Pages"));
        assert!(service_names.contains(&"GitLab Pages"));
        assert!(service_names.contains(&"Squarespace"));
        assert!(service_names.contains(&"Intercom"));
        assert!(service_names.contains(&"HubSpot"));
        assert!(service_names.contains(&"GitBook"));
        assert!(service_names.contains(&"Read the Docs"));
        assert!(service_names.contains(&"Webflow"));
        assert!(service_names.contains(&"Brightcove"));
        assert!(service_names.contains(&"Big Cartel"));
        assert!(service_names.contains(&"Campaign Monitor"));
        assert!(service_names.contains(&"Aha!"));
        assert!(service_names.contains(&"Hatena Blog"));
        assert!(service_names.contains(&"LaunchRock"));
        assert!(service_names.contains(&"Pingdom"));
        assert!(service_names.contains(&"Readme.io"));
        assert!(service_names.contains(&"Tave"));
        assert!(service_names.contains(&"Teamwork"));
        assert!(service_names.contains(&"Unbounce"));
        assert!(service_names.contains(&"Wishpond"));
        assert!(service_names.contains(&"Aftership"));
        assert!(service_names.contains(&"Kajabi"));
        assert!(service_names.contains(&"Helpjuice"));
        assert!(service_names.contains(&"Anima"));
        assert!(service_names.contains(&"Smartling"));
        assert!(service_names.contains(&"Strikingly"));
        assert!(service_names.contains(&"Worksites.net"));
        assert!(service_names.contains(&"Thinkific"));
        assert!(service_names.contains(&"Uberflip"));
        assert!(service_names.contains(&"Mashery"));
        assert!(service_names.contains(&"Statuspage"));
    }

    #[test]
    fn test_severity_levels() {
        for fingerprint in SERVICE_FINGERPRINTS {
            // All services should have High or Critical severity
            assert!(
                matches!(
                    fingerprint.severity,
                    Severity::High | Severity::Critical | Severity::Medium
                ),
                "Service {} has unexpected severity",
                fingerprint.name
            );

            // CVSS should be reasonable
            assert!(
                fingerprint.cvss >= 6.0 && fingerprint.cvss <= 10.0,
                "Service {} has unreasonable CVSS score",
                fingerprint.name
            );
        }
    }
}
