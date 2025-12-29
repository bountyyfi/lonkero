/// Smart parameter filtering to avoid testing framework internals
/// and focus on actual user input fields

use tracing::debug;

pub struct ParameterFilter;

impl ParameterFilter {
    /// Returns true if parameter should be SKIPPED (not worth testing)
    pub fn should_skip_parameter(param_name: &str, scanner_type: ScannerType) -> bool {
        let param_lower = param_name.to_lowercase();

        // ALWAYS skip these (framework internals) - uses substring matching
        let framework_internals_substring = [
            // Apollo/GraphQL internals (all variations)
            "_apollo", "apollodata", "apolloprovider", "apollopromise", "apolloutil",
            "__typename", "__schema", "__type", "_meta", "_debug", "_trace",
            "graphql", "operationname", "variables", "extensions",
            // Vue/Nuxt/React internals
            "vnode", "vuesignature", "ssrcontext", "prefetch", "watchloading",
            "_previousdata", "forceupdate", "checkoutparams",
            "getmetahtml", "handleerror", "scopedslots",
            // Sentry tracking
            "_sentryrootspan", "_sentryspans", "_times",
            // Service/DI patterns
            "service",
            // Internal framework flags
            "skipall", "skipallqueries", "skipallsubscriptions",
            // Crypto libraries
            "ed25519", "elliptic", "secp256k1",
        ];

        for internal in &framework_internals_substring {
            if param_lower.contains(internal) {
                debug!("[ParameterFilter] Skipping framework internal (substring): {}", param_name);
                return true; // SKIP
            }
        }

        // Exact match only (to avoid false positives like "locality" matching "local")
        let framework_internals_exact = [
            "apollo", "wrapper", "mount", "morph", "tune", "spectrum", "palette",
            "loadingkey", "maxdepth", "maxheight", "row", "offset", "after",
            "i18n", "locale", "live", "normal", "alarm", "archived", "info",
            "_key", "_sub", "q", "col", "app", "type", "sort", "sortby",
            "hasnormal", "vnode", "wrapper",
        ];

        for internal in &framework_internals_exact {
            if param_lower == *internal {
                debug!("[ParameterFilter] Skipping framework internal (exact): {}", param_name);
                return true; // SKIP
            }
        }

        // Skip obvious test/debug parameters
        if param_lower.starts_with("test_") ||
           param_lower.starts_with("debug_") ||
           param_lower.starts_with("_internal") {
            debug!("[ParameterFilter] Skipping test/debug parameter: {}", param_name);
            return true;
        }

        // Skip form builder auto-generated field IDs (UUID-style: f_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
        if (param_lower.starts_with("f_") || param_lower.starts_with("field_")) &&
           param_name.chars().filter(|c| *c == '-').count() >= 3 &&
           param_name.len() > 30 {
            debug!("[ParameterFilter] Skipping form builder UUID field: {}", param_name);
            return true;
        }

        // Skip auto-generated form field names like checkbox_field_0, radio_field_1, etc.
        if (param_lower.starts_with("checkbox_field_") ||
            param_lower.starts_with("radio_field_") ||
            param_lower.starts_with("input_field_") ||
            param_lower.starts_with("text_field_") ||
            param_lower.starts_with("select_field_") ||
            param_lower.starts_with("button_field_")) &&
           param_name.chars().last().map_or(false, |c| c.is_numeric()) {
            debug!("[ParameterFilter] Skipping auto-generated form field: {}", param_name);
            return true;
        }

        // Scanner-specific skipping
        match scanner_type {
            ScannerType::XXE | ScannerType::XML => {
                // XXE only works on XML-processing endpoints
                // Skip if no XML content-type and parameter doesn't suggest XML
                let skip = !param_lower.contains("xml") &&
                           !param_lower.contains("soap") &&
                           !param_lower.contains("document");
                if skip {
                    debug!("[ParameterFilter] Skipping non-XML parameter for XXE: {}", param_name);
                }
                skip
            }
            ScannerType::SQLi => {
                // Skip obvious non-database params
                let skip = param_lower.starts_with("is") || // isSubcontracting, isDayjs
                           param_lower.starts_with("skip") || // skipAll
                           param_lower.starts_with("has") || // hasPermission
                           param_lower.starts_with("enable") || // enableFeature
                           param_lower.starts_with("show"); // showDetails
                if skip {
                    debug!("[ParameterFilter] Skipping boolean-like parameter for SQLi: {}", param_name);
                }
                skip
            }
            ScannerType::XSS => {
                // XSS needs string fields that get rendered
                // Skip numeric/boolean params
                let numeric_suffixes = ["id", "count", "weight", "height", "depth", "price", "size", "width", "length"];
                let skip = numeric_suffixes.iter().any(|s| param_lower.ends_with(s)) &&
                           !param_lower.contains("name") && // "product_id_name" should not be skipped
                           !param_lower.contains("description");
                if skip {
                    debug!("[ParameterFilter] Skipping numeric parameter for XSS: {}", param_name);
                }
                skip
            }
            ScannerType::NoSQL => {
                // NoSQL injection targets database query parameters
                // Skip parameters that are clearly not used in database queries

                // Skip boolean flags
                if param_lower.starts_with("is") ||
                   param_lower.starts_with("has") ||
                   param_lower.starts_with("enable") ||
                   param_lower.starts_with("disable") ||
                   param_lower.starts_with("show") ||
                   param_lower.starts_with("hide") {
                    debug!("[ParameterFilter] Skipping boolean-like parameter for NoSQL: {}", param_name);
                    return true;
                }

                // Skip address/location fields - these are display/form data, not queries
                let address_fields = [
                    "street", "street2", "address", "locality", "city", "postcode",
                    "zipcode", "zip", "country", "state", "province", "region",
                    "phone", "mobile", "puhelin", "telephone", "fax",
                    "contactname", "contactemail", "contactphone",
                    "pickupcountry", "destinationcountry", "countryfilter",
                    "postcodefilter", "licenseplate", "licenseplat"
                ];
                if address_fields.iter().any(|f| param_lower == *f || param_lower.replace("_", "") == *f) {
                    debug!("[ParameterFilter] Skipping address/location field for NoSQL: {}", param_name);
                    return true;
                }

                // Skip invoice/billing display fields (not query fields)
                let invoice_fields = [
                    "einvoicename", "einvoiceaddress", "einvoicebroker", "einvoicebrokerid",
                    "emailinvoicename", "emailinvoiceaddress",
                    "price", "priceafterfirst", "pricingtype"
                ];
                if invoice_fields.iter().any(|f| param_lower == *f || param_lower.replace("_", "") == *f) {
                    debug!("[ParameterFilter] Skipping invoice/billing field for NoSQL: {}", param_name);
                    return true;
                }

                // Skip UI/form fields
                let ui_fields = [
                    "sortdirection", "pagination", "before", "after", "range",
                    "defaultdepth", "defaultweight", "day", "offset", "limit"
                ];
                if ui_fields.iter().any(|f| param_lower == *f || param_lower.replace("_", "") == *f) {
                    debug!("[ParameterFilter] Skipping UI/pagination field for NoSQL: {}", param_name);
                    return true;
                }

                false
            }
            ScannerType::CommandInjection => {
                // Command injection typically targets file/path/command parameters
                // NOT password fields, checkboxes, or login forms

                // Skip authentication/login fields - these are NEVER command injection targets
                let auth_fields = [
                    "password", "passwd", "pwd", "pass", "secret", "token",
                    "username", "user", "login", "log", "email", "mail",
                    "rememberme", "remember", "remember_me", "keeploggedin",
                    "csrf", "csrftoken", "_token", "authenticity_token",
                    "captcha", "recaptcha", "g-recaptcha-response",
                ];
                if auth_fields.iter().any(|f| param_lower == *f || param_lower.replace("_", "") == *f) {
                    debug!("[ParameterFilter] Skipping auth/login field for Command Injection: {}", param_name);
                    return true;
                }

                // Skip boolean/checkbox fields
                if param_lower.starts_with("is") ||
                   param_lower.starts_with("has") ||
                   param_lower.starts_with("enable") ||
                   param_lower.starts_with("disable") ||
                   param_lower.starts_with("show") ||
                   param_lower.starts_with("hide") ||
                   param_lower.ends_with("_flag") ||
                   param_lower.ends_with("_checkbox") {
                    debug!("[ParameterFilter] Skipping boolean parameter for Command Injection: {}", param_name);
                    return true;
                }

                // Skip pagination/UI fields
                if param_lower == "count" ||
                   param_lower == "limit" ||
                   param_lower == "offset" ||
                   param_lower == "page" ||
                   param_lower == "size" ||
                   param_lower == "sort" ||
                   param_lower == "order" {
                    debug!("[ParameterFilter] Skipping pagination field for Command Injection: {}", param_name);
                    return true;
                }

                // Only test parameters that suggest command/file operations
                let cmd_indicators = [
                    "cmd", "command", "exec", "execute", "run", "shell",
                    "file", "filename", "filepath", "path", "dir", "directory",
                    "script", "process", "program", "bin", "binary",
                    "host", "hostname", "ip", "address", "ping", "target",
                    "action", "operation", "func", "function", "method",
                    "template", "include", "require", "load", "import",
                ];
                let has_cmd_indicator = cmd_indicators.iter().any(|ind| param_lower.contains(ind));

                if !has_cmd_indicator {
                    debug!("[ParameterFilter] Skipping non-command parameter for Command Injection: {} (no cmd indicators)", param_name);
                    return true;
                }

                false
            }
            ScannerType::PathTraversal => {
                // Path traversal needs file/path-related parameters
                // NOT password fields, checkboxes, or login forms

                // Skip authentication/login fields - these are NEVER path traversal targets
                let auth_fields = [
                    "password", "passwd", "pwd", "pass", "secret", "token",
                    "username", "user", "login", "log", "email", "mail",
                    "rememberme", "remember", "remember_me", "keeploggedin",
                    "csrf", "csrftoken", "_token", "authenticity_token",
                    "captcha", "recaptcha", "g-recaptcha-response",
                ];
                if auth_fields.iter().any(|f| param_lower == *f || param_lower.replace("_", "") == *f) {
                    debug!("[ParameterFilter] Skipping auth/login field for Path Traversal: {}", param_name);
                    return true;
                }

                // Skip boolean fields
                if param_lower.starts_with("is") ||
                   param_lower.starts_with("has") ||
                   param_lower.starts_with("enable") ||
                   param_lower.starts_with("disable") {
                    debug!("[ParameterFilter] Skipping boolean parameter for Path Traversal: {}", param_name);
                    return true;
                }

                // Only test parameters that suggest file/path operations
                let path_indicators = [
                    "file", "filename", "filepath", "path", "dir", "directory",
                    "folder", "document", "upload", "download", "attachment",
                    "include", "require", "load", "import", "template", "view",
                    "src", "source", "dest", "destination", "target",
                    "config", "conf", "logfile", "logpath", "backup", "image", "img", "asset",
                ];
                let has_path_indicator = path_indicators.iter().any(|ind| param_lower.contains(ind));

                if !has_path_indicator {
                    debug!("[ParameterFilter] Skipping non-path parameter for Path Traversal: {} (no path indicators)", param_name);
                    return true;
                }

                false
            }
            ScannerType::SSRF => {
                // SSRF needs URL/URI/host parameters
                let url_indicators = ["url", "uri", "host", "domain", "link", "href", "callback", "webhook", "redirect"];
                let skip = !url_indicators.iter().any(|ind| param_lower.contains(ind)) &&
                           (param_lower.starts_with("is") || param_lower.starts_with("has"));
                if skip {
                    debug!("[ParameterFilter] Skipping non-URL parameter for SSRF: {}", param_name);
                }
                skip
            }
            ScannerType::ReDoS => {
                // ReDoS only matters for regex-validated inputs like email, phone, URL patterns
                // Skip boolean flags and params unlikely to have regex validation
                if param_lower.starts_with("is") ||
                   param_lower.starts_with("has") ||
                   param_lower.starts_with("enable") ||
                   param_lower.starts_with("disable") ||
                   param_lower.starts_with("skip") ||
                   param_lower.ends_with("count") {
                    debug!("[ParameterFilter] Skipping boolean/numeric parameter for ReDoS: {}", param_name);
                    return true;
                }

                // Skip address/location display fields - unlikely to have regex
                let skip_fields = [
                    "street", "street2", "address", "locality", "city",
                    "state", "province", "region", "country",
                    "pickupcountry", "destinationcountry", "countryfilter",
                    "contactname", "contactphone", "licenseplate",
                    "einvoicename", "einvoiceaddress", "einvoicebroker",
                    "emailinvoicename", "emailinvoiceaddress",
                    "price", "priceafterfirst", "pricingtype",
                    "sortdirection", "pagination", "before", "after",
                    "defaultdepth", "defaultweight", "day", "range",
                    "product", "productid", "subcontractorproduct",
                    "routename", "workshiftid", "companyid", "office",
                    "client", "login", "data", "mobile", "puhelin"
                ];
                if skip_fields.iter().any(|f| param_lower == *f || param_lower.replace("_", "") == *f) {
                    debug!("[ParameterFilter] Skipping display field for ReDoS: {}", param_name);
                    return true;
                }

                // Only test params likely to have regex validation
                let regex_likely = [
                    "email", "mail", "phone", "url", "uri", "pattern",
                    "postcode", "zipcode", "zip", "ssn", "username",
                    "search", "query", "filter", "input", "text", "name"
                ];
                if !regex_likely.iter().any(|f| param_lower.contains(f)) {
                    // If not a common regex-validated field and ends with id, skip
                    if param_lower.ends_with("id") {
                        debug!("[ParameterFilter] Skipping ID field for ReDoS: {}", param_name);
                        return true;
                    }
                }

                false
            }
            ScannerType::Other => false, // Other scanners test everything
        }
    }

    /// Returns priority score (1-10) for parameter
    /// Higher score = test first (likely vulnerable)
    pub fn get_parameter_priority(param_name: &str) -> u8 {
        let param_lower = param_name.to_lowercase();

        // CRITICAL PRIORITY (score 10): Direct security-sensitive fields
        let critical_priority = [
            "password", "passwd", "pwd", "token", "secret", "key", "auth",
            "credential", "apikey", "api_key"
        ];
        for field in &critical_priority {
            if param_lower.contains(field) {
                return 10;
            }
        }

        // HIGH PRIORITY (score 9): User input fields
        let high_priority = [
            "email", "username", "user", "message", "comment", "feedback",
            "description", "search", "query", "input", "text", "content"
        ];
        for field in &high_priority {
            if param_lower.contains(field) {
                return 9;
            }
        }

        // MEDIUM-HIGH PRIORITY (score 7): File and URL operations
        let medium_high_priority = [
            "file", "path", "url", "uri", "link", "redirect", "callback",
            "upload", "download", "attachment"
        ];
        for field in &medium_high_priority {
            if param_lower.contains(field) {
                return 7;
            }
        }

        // MEDIUM PRIORITY (score 5): Business data
        let medium_priority = [
            "name", "address", "phone", "company", "business", "product",
            "price", "city", "country", "title", "subject"
        ];
        for field in &medium_priority {
            if param_lower.contains(field) {
                return 5;
            }
        }

        // LOW PRIORITY (score 3): ID fields (often numeric)
        if param_lower.ends_with("id") || param_lower.ends_with("_id") {
            return 3;
        }

        // LOWEST PRIORITY (score 1): Everything else
        1
    }

    /// Check if parameter value suggests it's worth testing
    /// Returns (should_test, confidence_score)
    pub fn should_test_value(value: &str) -> (bool, u8) {
        // Empty values - low priority
        if value.is_empty() {
            return (true, 1);
        }

        // Very long values might be encoded data - medium priority
        if value.len() > 500 {
            return (true, 4);
        }

        // Pure numeric - low priority for injection attacks
        if value.chars().all(|c| c.is_numeric() || c == '.' || c == '-') {
            return (true, 2);
        }

        // Boolean values - very low priority
        if value == "true" || value == "false" || value == "0" || value == "1" {
            return (true, 1);
        }

        // Contains special characters - HIGH PRIORITY (might already be exploited)
        let special_chars = ['<', '>', '\'', '"', '`', ';', '|', '&', '$'];
        if special_chars.iter().any(|c| value.contains(*c)) {
            return (true, 9);
        }

        // Regular text - normal priority
        (true, 5)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScannerType {
    SQLi,
    XSS,
    XXE,
    XML,
    NoSQL,
    CommandInjection,
    PathTraversal,
    SSRF,
    ReDoS,
    Other,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_framework_internals_skipped() {
        assert!(ParameterFilter::should_skip_parameter("_apolloInitData", ScannerType::XSS));
        assert!(ParameterFilter::should_skip_parameter("vueSignature", ScannerType::SQLi));
        assert!(ParameterFilter::should_skip_parameter("__typename", ScannerType::Other));
    }

    #[test]
    fn test_scanner_specific_filtering() {
        // XXE should skip non-XML params
        assert!(ParameterFilter::should_skip_parameter("username", ScannerType::XXE));
        assert!(!ParameterFilter::should_skip_parameter("xmlData", ScannerType::XXE));

        // SQLi should skip boolean-like params
        assert!(ParameterFilter::should_skip_parameter("isActive", ScannerType::SQLi));
        assert!(!ParameterFilter::should_skip_parameter("username", ScannerType::SQLi));

        // XSS should skip numeric params
        assert!(ParameterFilter::should_skip_parameter("user_id", ScannerType::XSS));
        assert!(!ParameterFilter::should_skip_parameter("username", ScannerType::XSS));
    }

    #[test]
    fn test_parameter_priority() {
        assert_eq!(ParameterFilter::get_parameter_priority("password"), 10);
        assert_eq!(ParameterFilter::get_parameter_priority("email"), 9);
        assert_eq!(ParameterFilter::get_parameter_priority("filepath"), 7);
        assert_eq!(ParameterFilter::get_parameter_priority("username"), 9);
        assert_eq!(ParameterFilter::get_parameter_priority("user_id"), 3);
        assert_eq!(ParameterFilter::get_parameter_priority("random_field"), 1);
    }

    #[test]
    fn test_value_analysis() {
        assert_eq!(ParameterFilter::should_test_value(""), (true, 1));
        assert_eq!(ParameterFilter::should_test_value("123"), (true, 2));
        assert_eq!(ParameterFilter::should_test_value("true"), (true, 1));
        assert_eq!(ParameterFilter::should_test_value("<script>"), (true, 9));
        assert_eq!(ParameterFilter::should_test_value("normal text"), (true, 5));
    }
}
