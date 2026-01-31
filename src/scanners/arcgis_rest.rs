// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - ArcGIS REST Services Data Exposure Scanner
 * Detects misconfigured ArcGIS REST Services exposing sensitive data
 *
 * Based on real-world finding: Municipalities exposing PII through
 * unauthenticated ArcGIS query capabilities.
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Common ArcGIS REST endpoint paths to probe
const ARCGIS_PATHS: &[&str] = &[
    "/arcgis/rest/services",
    "/server/rest/services",
    "/gis/rest/services",
    "/portal/sharing/rest",
    "/hosting/rest/services",
    "/geoportal/rest/services",
];

/// Service types that can expose queryable data
const QUERYABLE_SERVICE_TYPES: &[&str] = &["MapServer", "FeatureServer", "ImageServer"];

/// PII type classification
#[derive(Debug, Clone, PartialEq)]
pub enum PiiType {
    // Nordic
    SwedishPersonnummer,
    FinnishHetu,
    NorwegianFnr,
    DanishCpr,
    // North America
    UsSsn,
    CanadianSin,
    // UK/Ireland
    UkNin,
    IrishPps,
    // Europe
    GermanSteuerid,
    FrenchNir,
    SpanishNie,
    ItalianCodiceFiscale,
    DutchBsn,
    BelgianNrn,
    // Asia Pacific
    AustralianTfn,
    NewZealandIrd,
    SingaporeNric,
    // Common
    Email,
    Phone,
    Address,
    Name,
    DateOfBirth,
    FinancialData,
    BankAccount,
    CreditCard,
    PassportNumber,
    DriversLicense,
    MedicalId,
}

impl std::fmt::Display for PiiType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Nordic
            PiiType::SwedishPersonnummer => write!(f, "Swedish Personnummer"),
            PiiType::FinnishHetu => write!(f, "Finnish Henkilötunnus"),
            PiiType::NorwegianFnr => write!(f, "Norwegian Fødselsnummer"),
            PiiType::DanishCpr => write!(f, "Danish CPR Number"),
            // North America
            PiiType::UsSsn => write!(f, "US Social Security Number"),
            PiiType::CanadianSin => write!(f, "Canadian Social Insurance Number"),
            // UK/Ireland
            PiiType::UkNin => write!(f, "UK National Insurance Number"),
            PiiType::IrishPps => write!(f, "Irish PPS Number"),
            // Europe
            PiiType::GermanSteuerid => write!(f, "German Steuer-ID"),
            PiiType::FrenchNir => write!(f, "French NIR (Numéro de Sécurité Sociale)"),
            PiiType::SpanishNie => write!(f, "Spanish NIE/NIF"),
            PiiType::ItalianCodiceFiscale => write!(f, "Italian Codice Fiscale"),
            PiiType::DutchBsn => write!(f, "Dutch BSN (Burgerservicenummer)"),
            PiiType::BelgianNrn => write!(f, "Belgian National Register Number"),
            // Asia Pacific
            PiiType::AustralianTfn => write!(f, "Australian Tax File Number"),
            PiiType::NewZealandIrd => write!(f, "New Zealand IRD Number"),
            PiiType::SingaporeNric => write!(f, "Singapore NRIC"),
            // Common
            PiiType::Email => write!(f, "Email Address"),
            PiiType::Phone => write!(f, "Phone Number"),
            PiiType::Address => write!(f, "Physical Address"),
            PiiType::Name => write!(f, "Personal Name"),
            PiiType::DateOfBirth => write!(f, "Date of Birth"),
            PiiType::FinancialData => write!(f, "Financial Data"),
            PiiType::BankAccount => write!(f, "Bank Account"),
            PiiType::CreditCard => write!(f, "Credit Card"),
            PiiType::PassportNumber => write!(f, "Passport Number"),
            PiiType::DriversLicense => write!(f, "Driver's License"),
            PiiType::MedicalId => write!(f, "Medical/Health ID"),
        }
    }
}

/// Discovered ArcGIS service
#[derive(Debug, Clone)]
struct ArcGISService {
    name: String,
    service_type: String,
    url: String,
}

/// Discovered layer within a service
#[derive(Debug, Clone)]
struct LayerInfo {
    id: u32,
    name: String,
    capabilities: Vec<String>,
    field_names: Vec<String>,
}

/// Detailed finding for a vulnerable layer
#[derive(Debug)]
struct LayerFinding {
    service_name: String,
    layer_id: u32,
    layer_name: String,
    capabilities: Vec<String>,
    record_count: Option<u64>,
    sample_fields: Vec<String>,
    pii_detected: Vec<PiiType>,
    is_writable: bool,
    sensitive_field_names: Vec<String>,
    query_url: String,
}

/// ArcGIS services list response
#[derive(Debug, Deserialize)]
struct ServicesResponse {
    #[serde(default)]
    folders: Vec<String>,
    #[serde(default)]
    services: Vec<ServiceInfo>,
    #[serde(rename = "currentVersion")]
    current_version: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct ServiceInfo {
    name: String,
    #[serde(rename = "type")]
    service_type: String,
}

/// Service details response
#[derive(Debug, Deserialize)]
struct ServiceDetailsResponse {
    #[serde(default)]
    layers: Vec<LayerBasicInfo>,
    #[serde(default)]
    capabilities: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LayerBasicInfo {
    id: u32,
    name: String,
}

/// Layer details response
#[derive(Debug, Deserialize)]
struct LayerDetailsResponse {
    #[serde(default)]
    fields: Vec<FieldInfo>,
    #[serde(default)]
    capabilities: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FieldInfo {
    name: String,
    #[serde(rename = "type")]
    field_type: Option<String>,
    alias: Option<String>,
}

/// Query response
#[derive(Debug, Deserialize)]
struct QueryResponse {
    #[serde(default)]
    features: Vec<Feature>,
    #[serde(default)]
    count: Option<u64>,
    #[serde(default)]
    error: Option<ErrorInfo>,
}

#[derive(Debug, Deserialize)]
struct Feature {
    #[serde(default)]
    attributes: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct ErrorInfo {
    code: Option<i32>,
    message: Option<String>,
}

/// Count response
#[derive(Debug, Deserialize)]
struct CountResponse {
    count: Option<u64>,
    #[serde(default)]
    error: Option<ErrorInfo>,
}

pub struct ArcGISRestScanner {
    http_client: Arc<HttpClient>,
    // Nordic PII patterns
    swedish_pnr: Regex,
    finnish_hetu: Regex,
    norwegian_fnr: Regex,
    danish_cpr: Regex,
    // North American patterns
    us_ssn: Regex,
    canadian_sin: Regex,
    // UK/Ireland patterns
    uk_nin: Regex,
    irish_pps: Regex,
    // European patterns
    german_steuerid: Regex,
    french_nir: Regex,
    spanish_nie: Regex,
    italian_cf: Regex,
    dutch_bsn: Regex,
    belgian_nrn: Regex,
    // Asia Pacific patterns
    australian_tfn: Regex,
    nz_ird: Regex,
    singapore_nric: Regex,
    // Common patterns
    email_pattern: Regex,
    phone_pattern: Regex,
    iban_pattern: Regex,
    credit_card_pattern: Regex,
    dob_pattern: Regex,
}

impl ArcGISRestScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self {
            http_client,
            // Nordic patterns
            // Swedish personnummer: YYYYMMDD-XXXX or YYYYMMDDXXXX
            swedish_pnr: Regex::new(r"\b(19|20)\d{6}[-]?\d{4}\b").unwrap(),
            // Finnish henkilötunnus: DDMMYY[-+A]XXXC
            finnish_hetu: Regex::new(r"\b\d{6}[-+A]\d{3}[A-Z0-9]\b").unwrap(),
            // Norwegian fødselsnummer: 11 digits
            norwegian_fnr: Regex::new(r"\b\d{11}\b").unwrap(),
            // Danish CPR: DDMMYY-XXXX
            danish_cpr: Regex::new(r"\b\d{6}-\d{4}\b").unwrap(),

            // North American patterns
            // US SSN: XXX-XX-XXXX or XXXXXXXXX
            us_ssn: Regex::new(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b").unwrap(),
            // Canadian SIN: XXX-XXX-XXX or XXXXXXXXX
            canadian_sin: Regex::new(r"\b\d{3}[-\s]?\d{3}[-\s]?\d{3}\b").unwrap(),

            // UK/Ireland patterns
            // UK NIN: AB123456C (2 letters, 6 digits, 1 letter)
            uk_nin: Regex::new(r"\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b").unwrap(),
            // Irish PPS: 7 digits + 1-2 letters
            irish_pps: Regex::new(r"\b\d{7}[A-Z]{1,2}\b").unwrap(),

            // European patterns
            // German Steuer-ID: 11 digits
            german_steuerid: Regex::new(r"\b\d{11}\b").unwrap(),
            // French NIR: 13 or 15 digits
            french_nir: Regex::new(r"\b[12]\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}(\s?\d{2})?\b").unwrap(),
            // Spanish NIE: X/Y/Z + 7 digits + letter, or NIF: 8 digits + letter
            spanish_nie: Regex::new(r"\b[XYZ]\d{7}[A-Z]\b|\b\d{8}[A-Z]\b").unwrap(),
            // Italian Codice Fiscale: 16 alphanumeric chars
            italian_cf: Regex::new(r"\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b").unwrap(),
            // Dutch BSN: 9 digits
            dutch_bsn: Regex::new(r"\b\d{9}\b").unwrap(),
            // Belgian National Register Number: YY.MM.DD-XXX.XX
            belgian_nrn: Regex::new(r"\b\d{2}\.\d{2}\.\d{2}[-]\d{3}\.\d{2}\b").unwrap(),

            // Asia Pacific patterns
            // Australian TFN: 8 or 9 digits
            australian_tfn: Regex::new(r"\b\d{3}\s?\d{3}\s?\d{2,3}\b").unwrap(),
            // NZ IRD: 8 or 9 digits
            nz_ird: Regex::new(r"\b\d{2,3}[-\s]?\d{3}[-\s]?\d{3}\b").unwrap(),
            // Singapore NRIC: S/T/F/G + 7 digits + letter
            singapore_nric: Regex::new(r"\b[STFG]\d{7}[A-Z]\b").unwrap(),

            // Common patterns
            // Email
            email_pattern: Regex::new(r"(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
                .unwrap(),
            // Phone (international formats)
            phone_pattern: Regex::new(
                r"\b(\+?[0-9]{1,4}[\s-]?)?[0-9]{2,4}[\s-]?[0-9]{3,4}[\s-]?[0-9]{3,4}\b",
            )
            .unwrap(),
            // IBAN
            iban_pattern: Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b").unwrap(),
            // Credit card (basic pattern)
            credit_card_pattern: Regex::new(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b").unwrap(),
            // Date of birth patterns (various formats)
            dob_pattern: Regex::new(r"\b(0?[1-9]|1[0-2])[-/](0?[1-9]|[12]\d|3[01])[-/](19|20)\d{2}\b|\b(19|20)\d{2}[-/](0?[1-9]|1[0-2])[-/](0?[1-9]|[12]\d|3[01])\b").unwrap(),
        }
    }

    /// Main scan entry point
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("[ArcGIS] Scanning: {}", url);

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Extract base URL
        let base_url = self.extract_base_url(url);

        // Phase 1: Detect ArcGIS REST Services
        let mut arcgis_base: Option<String> = None;
        for path in ARCGIS_PATHS {
            tests_run += 1;
            let probe_url = format!("{}{}?f=json", base_url, path);

            match self.http_client.get(&probe_url).await {
                Ok(response) => {
                    if response.status_code == 200 && self.is_arcgis_response(&response.body) {
                        info!("[ArcGIS] Found ArcGIS REST Services at: {}{}", base_url, path);
                        arcgis_base = Some(format!("{}{}", base_url, path));
                        break;
                    }
                }
                Err(e) => {
                    debug!("[ArcGIS] Probe failed for {}: {}", probe_url, e);
                }
            }
        }

        let arcgis_base = match arcgis_base {
            Some(base) => base,
            None => {
                debug!("[ArcGIS] No ArcGIS REST Services detected at {}", url);
                return Ok((vulnerabilities, tests_run));
            }
        };

        // Phase 2: Enumerate services
        let services = self
            .enumerate_services(&arcgis_base, &mut tests_run)
            .await;
        if services.is_empty() {
            debug!("[ArcGIS] No queryable services found");
            return Ok((vulnerabilities, tests_run));
        }

        info!("[ArcGIS] Found {} services to analyze", services.len());

        // Phase 3: Check each service for data exposure
        for service in services.iter().take(50) {
            // Limit to prevent excessive requests
            let findings = self
                .analyze_service(service, &mut tests_run, &mut vulnerabilities)
                .await;

            for finding in findings {
                self.create_vulnerability_from_finding(&finding, &mut vulnerabilities);
            }
        }

        info!(
            "[SUCCESS] [ArcGIS] Completed {} tests, found {} issues",
            tests_run,
            vulnerabilities.len()
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Extract base URL from input
    fn extract_base_url(&self, url: &str) -> String {
        if let Ok(parsed) = url::Url::parse(url) {
            format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""))
        } else {
            url.to_string()
        }
    }

    /// Check if response indicates ArcGIS REST Services
    fn is_arcgis_response(&self, body: &str) -> bool {
        // Check for ArcGIS-specific response patterns
        body.contains("currentVersion")
            || body.contains("\"folders\"")
            || body.contains("\"services\"")
            || body.contains("MapServer")
            || body.contains("FeatureServer")
    }

    /// Enumerate all services including those in folders
    async fn enumerate_services(
        &self,
        base_url: &str,
        tests_run: &mut usize,
    ) -> Vec<ArcGISService> {
        let mut services = Vec::new();
        let mut visited_folders: HashSet<String> = HashSet::new();
        let mut folders_to_visit = vec![String::new()]; // Start with root

        while let Some(folder) = folders_to_visit.pop() {
            if visited_folders.contains(&folder) {
                continue;
            }
            visited_folders.insert(folder.clone());

            // Limit folder depth to prevent infinite loops
            if visited_folders.len() > 20 {
                warn!("[ArcGIS] Folder enumeration limit reached");
                break;
            }

            *tests_run += 1;
            let services_url = if folder.is_empty() {
                format!("{}?f=json", base_url)
            } else {
                format!("{}/{}?f=json", base_url, folder)
            };

            match self.http_client.get(&services_url).await {
                Ok(response) => {
                    if response.status_code == 200 {
                        if let Ok(parsed) =
                            serde_json::from_str::<ServicesResponse>(&response.body)
                        {
                            // Add discovered folders
                            for f in parsed.folders {
                                let full_folder = if folder.is_empty() {
                                    f
                                } else {
                                    format!("{}/{}", folder, f)
                                };
                                folders_to_visit.push(full_folder);
                            }

                            // Add discovered services
                            for svc in parsed.services {
                                if QUERYABLE_SERVICE_TYPES.contains(&svc.service_type.as_str()) {
                                    let service_name = if folder.is_empty() {
                                        svc.name.clone()
                                    } else {
                                        format!("{}/{}", folder, svc.name)
                                    };
                                    services.push(ArcGISService {
                                        name: service_name.clone(),
                                        service_type: svc.service_type.clone(),
                                        url: format!(
                                            "{}/{}/{}",
                                            base_url, service_name, svc.service_type
                                        ),
                                    });
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("[ArcGIS] Failed to enumerate folder {}: {}", folder, e);
                }
            }
        }

        services
    }

    /// Analyze a service for data exposure vulnerabilities
    async fn analyze_service(
        &self,
        service: &ArcGISService,
        tests_run: &mut usize,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) -> Vec<LayerFinding> {
        let mut findings = Vec::new();

        // Get service details
        *tests_run += 1;
        let details_url = format!("{}?f=json", service.url);

        let service_details = match self.http_client.get(&details_url).await {
            Ok(response) => {
                if response.status_code == 200 {
                    serde_json::from_str::<ServiceDetailsResponse>(&response.body).ok()
                } else {
                    None
                }
            }
            Err(_) => None,
        };

        let service_details = match service_details {
            Some(d) => d,
            None => return findings,
        };

        // Parse service-level capabilities
        let service_capabilities: Vec<String> = service_details
            .capabilities
            .as_ref()
            .map(|c| c.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default();

        let has_query = service_capabilities
            .iter()
            .any(|c| c.eq_ignore_ascii_case("Query"));

        if !has_query {
            debug!(
                "[ArcGIS] Service {} does not have Query capability",
                service.name
            );
            return findings;
        }

        // Check for write capabilities (FeatureServer)
        let is_writable = service_capabilities.iter().any(|c| {
            c.eq_ignore_ascii_case("Create")
                || c.eq_ignore_ascii_case("Update")
                || c.eq_ignore_ascii_case("Delete")
                || c.eq_ignore_ascii_case("Editing")
        });

        if is_writable {
            // Create vulnerability for writable service even without PII
            vulnerabilities.push(self.create_vulnerability(
                "ArcGIS Unauthenticated Write Access",
                &service.url,
                Severity::High,
                Confidence::High,
                &format!(
                    "ArcGIS FeatureServer '{}' allows unauthenticated write operations. \
                    An attacker could create, update, or delete records without authentication. \
                    Capabilities: {}",
                    service.name,
                    service_capabilities.join(", ")
                ),
                format!("Service URL: {}\nCapabilities: {:?}", service.url, service_capabilities),
                8.1,
                "CWE-306",
            ));
        }

        // Analyze each layer
        for layer in service_details.layers.iter().take(20) {
            // Limit layers per service
            if let Some(finding) = self
                .analyze_layer(service, layer, &service_capabilities, is_writable, tests_run)
                .await
            {
                findings.push(finding);
            }
        }

        findings
    }

    /// Analyze a single layer for data exposure
    async fn analyze_layer(
        &self,
        service: &ArcGISService,
        layer: &LayerBasicInfo,
        service_capabilities: &[String],
        is_writable: bool,
        tests_run: &mut usize,
    ) -> Option<LayerFinding> {
        // Get layer details (fields)
        *tests_run += 1;
        let layer_url = format!("{}/{}?f=json", service.url, layer.id);

        let layer_details = match self.http_client.get(&layer_url).await {
            Ok(response) => {
                if response.status_code == 200 {
                    serde_json::from_str::<LayerDetailsResponse>(&response.body).ok()
                } else {
                    None
                }
            }
            Err(_) => None,
        };

        let layer_details = layer_details?;

        // Extract field names
        let field_names: Vec<String> = layer_details
            .fields
            .iter()
            .map(|f| f.name.clone())
            .collect();

        // Check for sensitive field names
        let sensitive_fields = self.detect_sensitive_field_names(&field_names);

        // If no sensitive fields detected by name, skip further analysis
        if sensitive_fields.is_empty() && !is_writable {
            return None;
        }

        // Attempt sample query (limited to 5 records for responsible disclosure)
        *tests_run += 1;
        let query_url = format!(
            "{}/{}/query?where=1=1&outFields=*&f=json&resultRecordCount=5",
            service.url, layer.id
        );

        let (sample_data, pii_detected) = match self.http_client.get(&query_url).await {
            Ok(response) => {
                if response.status_code == 200 {
                    if let Ok(query_result) =
                        serde_json::from_str::<QueryResponse>(&response.body)
                    {
                        // Check for auth errors
                        if let Some(error) = query_result.error {
                            if matches!(error.code, Some(499) | Some(498) | Some(403)) {
                                debug!(
                                    "[ArcGIS] Layer {} requires authentication",
                                    layer.name
                                );
                                return None;
                            }
                        }

                        // Detect PII in response
                        let pii = self.detect_pii_in_response(&response.body);
                        (Some(query_result.features), pii)
                    } else {
                        (None, Vec::new())
                    }
                } else {
                    (None, Vec::new())
                }
            }
            Err(_) => (None, Vec::new()),
        };

        // If no PII detected and no sensitive field names, skip
        if pii_detected.is_empty() && sensitive_fields.is_empty() && !is_writable {
            return None;
        }

        // Get record count for impact assessment
        *tests_run += 1;
        let count_url = format!(
            "{}/{}/query?where=1=1&returnCountOnly=true&f=json",
            service.url, layer.id
        );

        let record_count = match self.http_client.get(&count_url).await {
            Ok(response) => {
                if response.status_code == 200 {
                    serde_json::from_str::<CountResponse>(&response.body)
                        .ok()
                        .and_then(|c| c.count)
                } else {
                    None
                }
            }
            Err(_) => None,
        };

        Some(LayerFinding {
            service_name: service.name.clone(),
            layer_id: layer.id,
            layer_name: layer.name.clone(),
            capabilities: service_capabilities.to_vec(),
            record_count,
            sample_fields: field_names,
            pii_detected,
            is_writable,
            sensitive_field_names: sensitive_fields,
            query_url,
        })
    }

    /// Detect sensitive field names
    fn detect_sensitive_field_names(&self, field_names: &[String]) -> Vec<String> {
        let sensitive_patterns = [
            // National IDs - Nordic
            "personnummer", "personorganisationnr", "persorgnr", "hetu", "cpr", "fnr",
            // National IDs - North America
            "ssn", "social_security", "socialsecurity", "sin", "socialinsurance",
            // National IDs - UK/Ireland
            "nin", "national_insurance", "nationalinsurance", "pps", "ppsn",
            // National IDs - Europe
            "steuerid", "steuernummer", "nir", "securite_sociale", "nie", "nif",
            "codice_fiscale", "codicefiscale", "bsn", "burgerservicenummer",
            // National IDs - Asia Pacific
            "tfn", "taxfilenumber", "ird", "nric", "fin",
            // Birth dates
            "dob", "dateofbirth", "date_of_birth", "birthdate", "birth_date",
            "fodelsedatum", "syntymaaika", "geburtsdatum", "fecha_nacimiento",
            // Names - English
            "firstname", "lastname", "fullname", "givenname", "surname", "middlename",
            "first_name", "last_name", "full_name", "given_name", "middle_name",
            // Names - Nordic
            "namn", "fornamn", "efternamn", "fnamn", "enamn", "nimi", "etunimi", "sukunimi",
            // Names - German/French/Spanish
            "vorname", "nachname", "prenom", "nom", "nombre", "apellido",
            // Address - English
            "address", "street", "city", "state", "zipcode", "zip", "postcode",
            "addr", "street_address", "home_address", "mailing_address",
            // Address - Nordic
            "adress", "gatuadress", "osoite", "katuosoite", "hemort",
            "postnummer", "postnr", "postinumero",
            // Address - Other languages
            "strasse", "adresse", "rue", "direccion", "calle", "indirizzo", "via",
            // Contact - Phone
            "phone", "telephone", "tel", "mobile", "mobil", "cell", "cellphone",
            "telefon", "puhelin", "telefono", "handynummer",
            // Contact - Email
            "email", "e_mail", "mail", "epost", "sahkoposti", "correo",
            // Financial
            "salary", "income", "wage", "pay", "compensation", "earnings",
            "palkka", "lon", "gehalt", "salaire", "stipendio",
            "bank", "account", "konto", "iban", "routing", "bic", "swift",
            "credit_card", "creditcard", "card_number", "cardnumber",
            // Property/Real Estate
            "property", "parcel", "lot", "deed", "title", "owner", "ownership",
            "fastighet", "agare", "omistaja", "eigentuemer", "proprietaire",
            // Medical/Health
            "patient", "medical", "health", "diagnosis", "medicare", "medicaid",
            "insurance_id", "member_id", "policy", "prescription",
            // Identification
            "passport", "license", "licence", "dl", "driver", "id_number", "idnumber",
            // Sensitive categories
            "race", "ethnicity", "religion", "political", "sexual", "gender",
            "disability", "veteran", "criminal", "arrest",
        ];

        field_names
            .iter()
            .filter(|name| {
                let lower = name.to_lowercase();
                sensitive_patterns
                    .iter()
                    .any(|p| lower.contains(p))
            })
            .cloned()
            .collect()
    }

    /// Detect PII in response data
    fn detect_pii_in_response(&self, body: &str) -> Vec<PiiType> {
        let mut detected = Vec::new();
        let body_lower = body.to_lowercase();

        // === NORDIC NATIONAL IDs ===

        // Swedish personnummer (with Luhn validation)
        if self.swedish_pnr.is_match(body) {
            for cap in self.swedish_pnr.captures_iter(body) {
                if let Some(m) = cap.get(0) {
                    let digits: String = m.as_str().chars().filter(|c| c.is_ascii_digit()).collect();
                    if digits.len() >= 10 && self.validate_swedish_pnr(&digits) {
                        if !detected.contains(&PiiType::SwedishPersonnummer) {
                            detected.push(PiiType::SwedishPersonnummer);
                        }
                        break;
                    }
                }
            }
        }

        // Finnish henkilötunnus
        if self.finnish_hetu.is_match(body) && !detected.contains(&PiiType::FinnishHetu) {
            detected.push(PiiType::FinnishHetu);
        }

        // Norwegian fødselsnummer (context-aware - 11 digits is common)
        if self.norwegian_fnr.is_match(body) {
            if body_lower.contains("fodselsnummer") || body_lower.contains("fnr")
                || body_lower.contains("personnr") || body_lower.contains("norwegian") {
                if !detected.contains(&PiiType::NorwegianFnr) {
                    detected.push(PiiType::NorwegianFnr);
                }
            }
        }

        // Danish CPR
        if self.danish_cpr.is_match(body) {
            if body_lower.contains("cpr") || body_lower.contains("personnummer")
                || body_lower.contains("danish") || body_lower.contains("denmark") {
                if !detected.contains(&PiiType::DanishCpr) {
                    detected.push(PiiType::DanishCpr);
                }
            }
        }

        // === NORTH AMERICAN IDs ===

        // US Social Security Number (context-aware)
        if self.us_ssn.is_match(body) {
            // SSN pattern matches many things, so require context
            if body_lower.contains("ssn") || body_lower.contains("social_security")
                || body_lower.contains("socialsecurity") || body_lower.contains("social security") {
                if !detected.contains(&PiiType::UsSsn) {
                    detected.push(PiiType::UsSsn);
                }
            }
        }

        // Canadian SIN (context-aware)
        if self.canadian_sin.is_match(body) {
            if body_lower.contains("sin") || body_lower.contains("social_insurance")
                || body_lower.contains("canadian") || body_lower.contains("canada") {
                if !detected.contains(&PiiType::CanadianSin) {
                    detected.push(PiiType::CanadianSin);
                }
            }
        }

        // === UK/IRELAND IDs ===

        // UK National Insurance Number
        if self.uk_nin.is_match(body) && !detected.contains(&PiiType::UkNin) {
            detected.push(PiiType::UkNin);
        }

        // Irish PPS Number
        if self.irish_pps.is_match(body) {
            if body_lower.contains("pps") || body_lower.contains("irish") || body_lower.contains("ireland") {
                if !detected.contains(&PiiType::IrishPps) {
                    detected.push(PiiType::IrishPps);
                }
            }
        }

        // === EUROPEAN IDs ===

        // German Steuer-ID (context-aware - 11 digits is common)
        if self.german_steuerid.is_match(body) {
            if body_lower.contains("steuer") || body_lower.contains("german")
                || body_lower.contains("deutschland") {
                if !detected.contains(&PiiType::GermanSteuerid) {
                    detected.push(PiiType::GermanSteuerid);
                }
            }
        }

        // French NIR (context-aware)
        if self.french_nir.is_match(body) {
            if body_lower.contains("nir") || body_lower.contains("securite_sociale")
                || body_lower.contains("french") || body_lower.contains("france") {
                if !detected.contains(&PiiType::FrenchNir) {
                    detected.push(PiiType::FrenchNir);
                }
            }
        }

        // Spanish NIE/NIF
        if self.spanish_nie.is_match(body) && !detected.contains(&PiiType::SpanishNie) {
            detected.push(PiiType::SpanishNie);
        }

        // Italian Codice Fiscale
        if self.italian_cf.is_match(body) && !detected.contains(&PiiType::ItalianCodiceFiscale) {
            detected.push(PiiType::ItalianCodiceFiscale);
        }

        // Dutch BSN (context-aware - 9 digits is common)
        if self.dutch_bsn.is_match(body) {
            if body_lower.contains("bsn") || body_lower.contains("burgerservicenummer")
                || body_lower.contains("dutch") || body_lower.contains("netherlands") {
                if !detected.contains(&PiiType::DutchBsn) {
                    detected.push(PiiType::DutchBsn);
                }
            }
        }

        // Belgian NRN
        if self.belgian_nrn.is_match(body) && !detected.contains(&PiiType::BelgianNrn) {
            detected.push(PiiType::BelgianNrn);
        }

        // === ASIA PACIFIC IDs ===

        // Australian TFN (context-aware)
        if self.australian_tfn.is_match(body) {
            if body_lower.contains("tfn") || body_lower.contains("tax_file")
                || body_lower.contains("taxfile") || body_lower.contains("australian")
                || body_lower.contains("australia") {
                if !detected.contains(&PiiType::AustralianTfn) {
                    detected.push(PiiType::AustralianTfn);
                }
            }
        }

        // New Zealand IRD (context-aware)
        if self.nz_ird.is_match(body) {
            if body_lower.contains("ird") || body_lower.contains("new_zealand")
                || body_lower.contains("newzealand") || body_lower.contains("nz") {
                if !detected.contains(&PiiType::NewZealandIrd) {
                    detected.push(PiiType::NewZealandIrd);
                }
            }
        }

        // Singapore NRIC
        if self.singapore_nric.is_match(body) && !detected.contains(&PiiType::SingaporeNric) {
            detected.push(PiiType::SingaporeNric);
        }

        // === COMMON PII ===

        // Email
        if self.email_pattern.is_match(body) && !detected.contains(&PiiType::Email) {
            detected.push(PiiType::Email);
        }

        // Phone (context-aware)
        if self.phone_pattern.is_match(body) {
            if body_lower.contains("phone") || body_lower.contains("telefon")
                || body_lower.contains("mobil") || body_lower.contains("cell")
                || body_lower.contains("tel") || body_lower.contains("puhelin")
                || body_lower.contains("telephone") {
                if !detected.contains(&PiiType::Phone) {
                    detected.push(PiiType::Phone);
                }
            }
        }

        // Date of Birth
        if self.dob_pattern.is_match(body) {
            if body_lower.contains("dob") || body_lower.contains("birth")
                || body_lower.contains("born") || body_lower.contains("geburt")
                || body_lower.contains("fodelse") || body_lower.contains("syntyma") {
                if !detected.contains(&PiiType::DateOfBirth) {
                    detected.push(PiiType::DateOfBirth);
                }
            }
        }

        // IBAN
        if self.iban_pattern.is_match(body) && !detected.contains(&PiiType::BankAccount) {
            detected.push(PiiType::BankAccount);
        }

        // Credit card
        if self.credit_card_pattern.is_match(body) && !detected.contains(&PiiType::CreditCard) {
            detected.push(PiiType::CreditCard);
        }

        // Name fields (field name detection)
        let name_indicators = [
            "\"name\"", "\"namn\"", "\"firstname\"", "\"lastname\"", "\"fullname\"",
            "\"first_name\"", "\"last_name\"", "\"full_name\"", "\"fornamn\"", "\"efternamn\"",
            "\"givenname\"", "\"surname\"", "\"vorname\"", "\"nachname\"", "\"prenom\"",
            "\"nom\"", "\"nombre\"", "\"apellido\"", "\"nimi\"", "\"etunimi\"", "\"sukunimi\""
        ];
        if name_indicators.iter().any(|n| body_lower.contains(n)) && !detected.contains(&PiiType::Name) {
            detected.push(PiiType::Name);
        }

        // Address fields
        let address_indicators = [
            "\"address\"", "\"adress\"", "\"street\"", "\"gatuadress\"", "\"osoite\"",
            "\"strasse\"", "\"rue\"", "\"direccion\"", "\"calle\"", "\"indirizzo\"",
            "\"home_address\"", "\"mailing_address\"", "\"street_address\""
        ];
        if address_indicators.iter().any(|a| body_lower.contains(a)) && !detected.contains(&PiiType::Address) {
            detected.push(PiiType::Address);
        }

        // Financial data
        let financial_indicators = [
            "\"salary\"", "\"income\"", "\"wage\"", "\"pay\"", "\"earnings\"",
            "\"palkka\"", "\"lon\"", "\"gehalt\"", "\"salaire\"", "\"compensation\""
        ];
        if financial_indicators.iter().any(|f| body_lower.contains(f)) && !detected.contains(&PiiType::FinancialData) {
            detected.push(PiiType::FinancialData);
        }

        // Medical ID indicators
        let medical_indicators = [
            "\"patient\"", "\"medical\"", "\"diagnosis\"", "\"medicare\"", "\"medicaid\"",
            "\"health_id\"", "\"member_id\"", "\"insurance_id\""
        ];
        if medical_indicators.iter().any(|m| body_lower.contains(m)) && !detected.contains(&PiiType::MedicalId) {
            detected.push(PiiType::MedicalId);
        }

        // Passport/License indicators
        let id_indicators = [
            "\"passport\"", "\"license\"", "\"licence\"", "\"driver\"", "\"dl_number\"",
            "\"id_number\"", "\"identification\""
        ];
        if id_indicators.iter().any(|i| body_lower.contains(i)) {
            if body_lower.contains("passport") && !detected.contains(&PiiType::PassportNumber) {
                detected.push(PiiType::PassportNumber);
            }
            if (body_lower.contains("license") || body_lower.contains("licence") || body_lower.contains("driver"))
                && !detected.contains(&PiiType::DriversLicense) {
                detected.push(PiiType::DriversLicense);
            }
        }

        detected
    }

    /// Validate Swedish personnummer using Luhn algorithm
    fn validate_swedish_pnr(&self, digits: &str) -> bool {
        if digits.len() < 10 {
            return false;
        }

        // Take last 10 digits
        let check_digits = if digits.len() == 12 {
            &digits[2..]
        } else {
            digits
        };

        if check_digits.len() != 10 {
            return false;
        }

        // Luhn algorithm
        let mut sum = 0;
        for (i, c) in check_digits.chars().enumerate() {
            let digit = c.to_digit(10).unwrap_or(0) as u32;
            let multiplied = if i % 2 == 0 { digit * 2 } else { digit };
            sum += if multiplied > 9 {
                multiplied - 9
            } else {
                multiplied
            };
        }

        sum % 10 == 0
    }

    /// Create vulnerability from layer finding
    fn create_vulnerability_from_finding(
        &self,
        finding: &LayerFinding,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let has_pii = !finding.pii_detected.is_empty();
        let has_sensitive_fields = !finding.sensitive_field_names.is_empty();

        // Determine severity based on findings
        let (severity, cvss) = if has_pii {
            // Critical: National IDs (any country)
            let has_national_id = finding.pii_detected.iter().any(|p| matches!(p,
                PiiType::SwedishPersonnummer | PiiType::FinnishHetu |
                PiiType::NorwegianFnr | PiiType::DanishCpr |
                PiiType::UsSsn | PiiType::CanadianSin |
                PiiType::UkNin | PiiType::IrishPps |
                PiiType::GermanSteuerid | PiiType::FrenchNir |
                PiiType::SpanishNie | PiiType::ItalianCodiceFiscale |
                PiiType::DutchBsn | PiiType::BelgianNrn |
                PiiType::AustralianTfn | PiiType::NewZealandIrd |
                PiiType::SingaporeNric
            ));

            // Critical: Financial/Payment data
            let has_financial = finding.pii_detected.iter().any(|p| matches!(p,
                PiiType::BankAccount | PiiType::CreditCard | PiiType::FinancialData
            ));

            // Critical: Medical data
            let has_medical = finding.pii_detected.contains(&PiiType::MedicalId);

            // High: Identity documents
            let has_identity_docs = finding.pii_detected.iter().any(|p| matches!(p,
                PiiType::PassportNumber | PiiType::DriversLicense
            ));

            if has_national_id {
                (Severity::Critical, 9.1) // National ID exposure - highest impact
            } else if has_medical {
                (Severity::Critical, 9.0) // Medical data - HIPAA, GDPR Art 9
            } else if has_financial {
                (Severity::Critical, 8.8) // Financial data - PCI DSS
            } else if has_identity_docs {
                (Severity::High, 8.0) // Identity documents
            } else {
                (Severity::High, 7.5) // Other PII (email, phone, address, DOB)
            }
        } else if has_sensitive_fields {
            (Severity::High, 7.5) // Potentially sensitive data
        } else if finding.is_writable {
            (Severity::High, 8.1) // Write access
        } else {
            (Severity::Medium, 5.3) // Data exposure without confirmed PII
        };

        let pii_list: Vec<String> = finding.pii_detected.iter().map(|p| p.to_string()).collect();
        let record_count_str = finding
            .record_count
            .map(|c| format!("{} records", c))
            .unwrap_or_else(|| "unknown count".to_string());

        let description = format!(
            "ArcGIS REST Services layer '{}' in service '{}' exposes data without authentication. \
            {} are accessible via unauthenticated query API. {}{}{}",
            finding.layer_name,
            finding.service_name,
            record_count_str,
            if has_pii {
                format!("\n\nDetected PII types: {}", pii_list.join(", "))
            } else {
                String::new()
            },
            if has_sensitive_fields {
                format!(
                    "\n\nSensitive field names: {}",
                    finding.sensitive_field_names.join(", ")
                )
            } else {
                String::new()
            },
            if finding.is_writable {
                "\n\nWARNING: This layer also allows unauthenticated write operations!"
            } else {
                ""
            }
        );

        let evidence = format!(
            "Query URL: {}\n\nCapabilities: {}\n\nExposed Fields: {}\n\nRecord Count: {}",
            finding.query_url,
            finding.capabilities.join(", "),
            finding.sample_fields.join(", "),
            finding
                .record_count
                .map(|c| c.to_string())
                .unwrap_or_else(|| "N/A".to_string())
        );

        vulnerabilities.push(self.create_vulnerability(
            "ArcGIS REST Services Data Exposure",
            &finding.query_url,
            severity,
            if has_pii {
                Confidence::High
            } else {
                Confidence::Medium
            },
            &description,
            evidence,
            cvss,
            if has_pii { "CWE-359" } else { "CWE-200" },
        ));
    }

    /// Create a vulnerability finding
    fn create_vulnerability(
        &self,
        title: &str,
        url: &str,
        severity: Severity,
        confidence: Confidence,
        description: &str,
        evidence: String,
        cvss: f32,
        cwe: &str,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("arcgis_{}", uuid::Uuid::new_v4()),
            vuln_type: format!("ArcGIS Misconfiguration - {}", title),
            severity,
            confidence,
            category: "Data Exposure".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: String::new(),
            description: description.to_string(),
            evidence: Some(evidence),
            cwe: cwe.to_string(),
            cvss,
            verified: true,
            false_positive: false,
            remediation: r#"## Remediation

1. **Disable Query Capability** on layers containing sensitive data:
   - In ArcGIS Server Manager, edit the service properties
   - Under "Capabilities", uncheck "Query" for sensitive layers

2. **Implement Authentication**:
   - Enable token-based authentication on the ArcGIS Server
   - Configure the service to require authentication
   - Use ArcGIS Server security model with proper roles

3. **Review Data Classification**:
   - Audit all published services for sensitive data
   - Move PII data to internal-only services
   - Consider data masking for public-facing layers

4. **Network Segmentation**:
   - Place ArcGIS servers with sensitive data behind VPN
   - Use firewall rules to restrict access to authorized IPs

5. **For FeatureServer with Write Access**:
   - Disable Create/Update/Delete capabilities unless required
   - Implement field-level permissions
   - Enable editor tracking for audit trails

## References
- ESRI Security Best Practices: https://enterprise.arcgis.com/en/server/latest/administer/windows/best-practices-for-arcgis-server-security.htm
- OWASP: Sensitive Data Exposure
"#
            .to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
            ml_data: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_swedish_pnr_validation() {
        let scanner = ArcGISRestScanner::new(Arc::new(
            HttpClient::with_config(30, 3, false, false, 100, 10).unwrap(),
        ));

        // Valid personnummer (example)
        assert!(scanner.validate_swedish_pnr("8507099805"));
        // Invalid checksum
        assert!(!scanner.validate_swedish_pnr("8507099800"));
    }

    #[test]
    fn test_sensitive_field_detection() {
        let scanner = ArcGISRestScanner::new(Arc::new(
            HttpClient::with_config(30, 3, false, false, 100, 10).unwrap(),
        ));

        let fields = vec![
            "OBJECTID".to_string(),
            "Shape".to_string(),
            "personnummer".to_string(),
            "namn".to_string(),
            "adress".to_string(),
            "GlobalID".to_string(),
        ];

        let sensitive = scanner.detect_sensitive_field_names(&fields);
        assert_eq!(sensitive.len(), 3);
        assert!(sensitive.contains(&"personnummer".to_string()));
        assert!(sensitive.contains(&"namn".to_string()));
        assert!(sensitive.contains(&"adress".to_string()));
    }

    #[test]
    fn test_pii_detection_patterns() {
        let scanner = ArcGISRestScanner::new(Arc::new(
            HttpClient::with_config(30, 3, false, false, 100, 10).unwrap(),
        ));

        // Test email detection
        let body_with_email = r#"{"email": "test@example.com"}"#;
        let pii = scanner.detect_pii_in_response(body_with_email);
        assert!(pii.contains(&PiiType::Email));

        // Test Swedish personnummer
        let body_with_pnr = r#"{"personnummer": "19850709-9805"}"#;
        let pii = scanner.detect_pii_in_response(body_with_pnr);
        assert!(pii.contains(&PiiType::SwedishPersonnummer));
    }
}
