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
            "_apollo",
            "apollodata",
            "apolloprovider",
            "apollopromise",
            "apolloutil",
            "__typename",
            "__schema",
            "__type",
            "_meta",
            "_debug",
            "_trace",
            "graphql",
            "operationname",
            "variables",
            "extensions",
            // Vue/Nuxt/React internals
            "vnode",
            "vuesignature",
            "ssrcontext",
            "prefetch",
            "watchloading",
            "_previousdata",
            "forceupdate",
            "checkoutparams",
            "getmetahtml",
            "handleerror",
            "scopedslots",
            // Sentry tracking
            "_sentryrootspan",
            "_sentryspans",
            "_times",
            // Service/DI patterns
            "service",
            // Internal framework flags
            "skipall",
            "skipallqueries",
            "skipallsubscriptions",
            // Crypto libraries
            "ed25519",
            "elliptic",
            "secp256k1",
        ];

        for internal in &framework_internals_substring {
            if param_lower.contains(internal) {
                debug!(
                    "[ParameterFilter] Skipping framework internal (substring): {}",
                    param_name
                );
                return true; // SKIP
            }
        }

        // Exact match only (to avoid false positives like "locality" matching "local")
        let framework_internals_exact = [
            "apollo",
            "wrapper",
            "mount",
            "morph",
            "tune",
            "spectrum",
            "palette",
            "loadingkey",
            "maxdepth",
            "maxheight",
            "row",
            "offset",
            "after",
            "i18n",
            "locale",
            "live",
            "normal",
            "alarm",
            "archived",
            "info",
            "_key",
            "_sub",
            "q",
            "col",
            "app",
            "type",
            "sort",
            "sortby",
            "hasnormal",
            "vnode",
            "wrapper",
        ];

        for internal in &framework_internals_exact {
            if param_lower == *internal {
                debug!(
                    "[ParameterFilter] Skipping framework internal (exact): {}",
                    param_name
                );
                return true; // SKIP
            }
        }

        // Skip HTML placeholder text being extracted as parameter names
        // These are not real parameters: "Search articles...", "Enter coupon code (e.g., SAVE50)"
        if param_name.contains("...")
            || param_name.contains("e.g.")
            || param_name.contains("(e.g.,")
            || param_name.contains("Enter ")
            || param_name.contains("Search ")
            || param_name.contains("Type ")
            || param_name.contains("Select ")
            || param_name.contains("Choose ")
            || param_name.contains("Click ")
            || param_name.len() > 50  // Real param names are rarely this long
            || param_name.contains(' ') && param_name.len() > 20  // "Search in Drive" etc.
        {
            debug!(
                "[ParameterFilter] Skipping placeholder text as parameter: {}",
                param_name
            );
            return true;
        }

        // Skip obvious test/debug parameters
        if param_lower.starts_with("test_")
            || param_lower.starts_with("debug_")
            || param_lower.starts_with("_internal")
        {
            debug!(
                "[ParameterFilter] Skipping test/debug parameter: {}",
                param_name
            );
            return true;
        }

        // Skip form builder auto-generated field IDs (UUID-style: f_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
        if (param_lower.starts_with("f_") || param_lower.starts_with("field_"))
            && param_name.chars().filter(|c| *c == '-').count() >= 3
            && param_name.len() > 30
        {
            debug!(
                "[ParameterFilter] Skipping form builder UUID field: {}",
                param_name
            );
            return true;
        }

        // Skip auto-generated form field names like checkbox_field_0, radio_field_1, etc.
        if (param_lower.starts_with("checkbox_field_")
            || param_lower.starts_with("radio_field_")
            || param_lower.starts_with("input_field_")
            || param_lower.starts_with("text_field_")
            || param_lower.starts_with("select_field_")
            || param_lower.starts_with("button_field_"))
            && param_name.chars().last().map_or(false, |c| c.is_numeric())
        {
            debug!(
                "[ParameterFilter] Skipping auto-generated form field: {}",
                param_name
            );
            return true;
        }

        // Scanner-specific skipping
        match scanner_type {
            ScannerType::XXE | ScannerType::XML => {
                // XXE can occur in ANY parameter that accepts structured data
                // Many XML injection points use generic names like "data", "payload", "content", "body"
                // Only skip obvious non-XML parameters like boolean flags

                // Skip boolean/flag parameters - these can't be XXE vectors
                if param_lower.starts_with("is")
                    || param_lower.starts_with("has")
                    || param_lower.starts_with("enable")
                    || param_lower.starts_with("disable")
                    || param_lower.starts_with("show")
                    || param_lower.starts_with("hide")
                    || param_lower == "remember"
                    || param_lower == "rememberme"
                    || param_lower == "remember_me"
                {
                    debug!(
                        "[ParameterFilter] Skipping boolean parameter for XXE: {}",
                        param_name
                    );
                    return true;
                }

                // Skip CSRF tokens and auth tokens - not XXE vectors
                if param_lower.contains("csrf")
                    || param_lower.contains("token")
                    || param_lower == "_token"
                    || param_lower.contains("authenticity")
                {
                    debug!(
                        "[ParameterFilter] Skipping security token for XXE: {}",
                        param_name
                    );
                    return true;
                }

                // Skip pagination/sort fields
                if param_lower == "page"
                    || param_lower == "limit"
                    || param_lower == "offset"
                    || param_lower == "sort"
                    || param_lower == "order"
                {
                    debug!(
                        "[ParameterFilter] Skipping pagination field for XXE: {}",
                        param_name
                    );
                    return true;
                }

                // Test ALL other parameters - XXE can be in unexpected places
                false
            }
            ScannerType::SQLi => {
                // Skip boolean-like parameters (Quote Cancellation false positives)
                if param_lower.starts_with("is") // isSubcontracting, isDayjs
                    || param_lower.starts_with("skip") // skipAll
                    || param_lower.starts_with("has") // hasPermission
                    || param_lower.starts_with("enable") // enableFeature
                    || param_lower.starts_with("show") // showDetails
                    || param_lower.starts_with("hide")
                    || param_lower.starts_with("disable")
                {
                    debug!(
                        "[ParameterFilter] Skipping boolean-like parameter for SQLi: {}",
                        param_name
                    );
                    return true;
                }

                // Skip file input parameters (Quote Cancellation false positives)
                // Files are binary data, not SQL string contexts
                if param_lower.contains("file")
                    && (param_lower.contains("input")
                        || param_lower.contains("upload")
                        || param_lower.contains("avatar")
                        || param_lower.contains("image")
                        || param_lower.contains("document")
                        || param_lower.contains("attachment"))
                {
                    debug!(
                        "[ParameterFilter] Skipping file input parameter for SQLi: {}",
                        param_name
                    );
                    return true;
                }

                // Skip checkbox/toggle parameters - these are boolean values, not SQL injectable
                if param_lower == "remember"
                    || param_lower == "rememberme"
                    || param_lower == "remember_me"
                    || param_lower == "keeploggedin"
                    || param_lower == "keep_logged_in"
                    || param_lower == "stayloggedin"
                    || param_lower == "terms"
                    || param_lower == "agree"
                    || param_lower == "consent"
                    || param_lower == "subscribe"
                    || param_lower == "newsletter"
                    || param_lower.ends_with("_checkbox")
                    || param_lower.ends_with("_check")
                    || param_lower.ends_with("_toggle")
                {
                    debug!(
                        "[ParameterFilter] Skipping checkbox/toggle parameter for SQLi: {}",
                        param_name
                    );
                    return true;
                }

                // Skip CSRF tokens - not SQL injectable
                if param_lower.contains("csrf")
                    || param_lower.contains("_token")
                    || param_lower.contains("authenticity")
                {
                    debug!(
                        "[ParameterFilter] Skipping security token for SQLi: {}",
                        param_name
                    );
                    return true;
                }

                false
            }
            ScannerType::XSS => {
                // XSS can occur in many unexpected places - be less restrictive
                // Only skip obvious non-injectable contexts

                // Skip CSRF tokens - not displayed to users
                if param_lower.contains("csrf")
                    || param_lower.contains("_token")
                    || param_lower.contains("authenticity")
                {
                    debug!(
                        "[ParameterFilter] Skipping security token for XSS: {}",
                        param_name
                    );
                    return true;
                }

                // Skip pure pagination (these are typically numeric only)
                if param_lower == "page"
                    || param_lower == "limit"
                    || param_lower == "offset"
                    || param_lower == "count"
                {
                    debug!(
                        "[ParameterFilter] Skipping pagination field for XSS: {}",
                        param_name
                    );
                    return true;
                }

                // Skip boolean flags
                if param_lower.starts_with("is")
                    || param_lower.starts_with("has")
                    || param_lower.starts_with("enable")
                    || param_lower.starts_with("disable")
                {
                    debug!(
                        "[ParameterFilter] Skipping boolean parameter for XSS: {}",
                        param_name
                    );
                    return true;
                }

                // Test ALL other parameters - XSS can be in IDs, names, any reflected value
                false
            }
            ScannerType::NoSQL => {
                // NoSQL injection targets database query parameters
                // Skip parameters that are clearly not used in database queries

                // Skip boolean flags
                if param_lower.starts_with("is")
                    || param_lower.starts_with("has")
                    || param_lower.starts_with("enable")
                    || param_lower.starts_with("disable")
                    || param_lower.starts_with("show")
                    || param_lower.starts_with("hide")
                {
                    debug!(
                        "[ParameterFilter] Skipping boolean-like parameter for NoSQL: {}",
                        param_name
                    );
                    return true;
                }

                // Skip address/location fields - these are display/form data, not queries
                let address_fields = [
                    "street",
                    "street2",
                    "address",
                    "locality",
                    "city",
                    "postcode",
                    "zipcode",
                    "zip",
                    "country",
                    "state",
                    "province",
                    "region",
                    "phone",
                    "mobile",
                    "puhelin",
                    "telephone",
                    "fax",
                    "contactname",
                    "contactemail",
                    "contactphone",
                    "pickupcountry",
                    "destinationcountry",
                    "countryfilter",
                    "postcodefilter",
                    "licenseplate",
                    "licenseplat",
                ];
                if address_fields
                    .iter()
                    .any(|f| param_lower == *f || param_lower.replace("_", "") == *f)
                {
                    debug!(
                        "[ParameterFilter] Skipping address/location field for NoSQL: {}",
                        param_name
                    );
                    return true;
                }

                // Skip invoice/billing display fields (not query fields)
                let invoice_fields = [
                    "einvoicename",
                    "einvoiceaddress",
                    "einvoicebroker",
                    "einvoicebrokerid",
                    "emailinvoicename",
                    "emailinvoiceaddress",
                    "price",
                    "priceafterfirst",
                    "pricingtype",
                ];
                if invoice_fields
                    .iter()
                    .any(|f| param_lower == *f || param_lower.replace("_", "") == *f)
                {
                    debug!(
                        "[ParameterFilter] Skipping invoice/billing field for NoSQL: {}",
                        param_name
                    );
                    return true;
                }

                // Skip UI/form fields
                let ui_fields = [
                    "sortdirection",
                    "pagination",
                    "before",
                    "after",
                    "range",
                    "defaultdepth",
                    "defaultweight",
                    "day",
                    "offset",
                    "limit",
                ];
                if ui_fields
                    .iter()
                    .any(|f| param_lower == *f || param_lower.replace("_", "") == *f)
                {
                    debug!(
                        "[ParameterFilter] Skipping UI/pagination field for NoSQL: {}",
                        param_name
                    );
                    return true;
                }

                false
            }
            ScannerType::CommandInjection => {
                // Command injection can occur in many parameter types, not just "cmd" named fields
                // Only skip obvious non-targets: auth fields, boolean flags, and pure pagination

                // Skip authentication/login fields - these are processed differently
                let auth_fields = [
                    "password",
                    "passwd",
                    "pwd",
                    "pass",
                    "secret",
                    "username",
                    "user",
                    "login",
                    "email",
                    "mail",
                    "rememberme",
                    "remember",
                    "remember_me",
                    "keeploggedin",
                    "csrf",
                    "csrftoken",
                    "_token",
                    "authenticity_token",
                    "captcha",
                    "recaptcha",
                    "g-recaptcha-response",
                ];
                if auth_fields
                    .iter()
                    .any(|f| param_lower == *f || param_lower.replace("_", "") == *f)
                {
                    debug!(
                        "[ParameterFilter] Skipping auth/login field for Command Injection: {}",
                        param_name
                    );
                    return true;
                }

                // Skip pure boolean/checkbox fields
                if param_lower.starts_with("is")
                    || param_lower.starts_with("has")
                    || param_lower.starts_with("enable")
                    || param_lower.starts_with("disable")
                    || param_lower.ends_with("_flag")
                    || param_lower.ends_with("_checkbox")
                {
                    debug!(
                        "[ParameterFilter] Skipping boolean parameter for Command Injection: {}",
                        param_name
                    );
                    return true;
                }

                // Skip pure pagination fields (these are typically numeric)
                if param_lower == "count"
                    || param_lower == "limit"
                    || param_lower == "offset"
                    || param_lower == "page"
                    || param_lower == "size"
                {
                    debug!(
                        "[ParameterFilter] Skipping pagination field for Command Injection: {}",
                        param_name
                    );
                    return true;
                }

                // Test ALL other parameters - command injection can be in unexpected places
                // Parameters like "query", "search", "name", "data", "input", "value" are all valid targets
                false
            }
            ScannerType::PathTraversal => {
                // Path traversal can occur in many parameter types
                // Only skip obvious non-targets: auth fields and boolean flags

                // Skip authentication/login fields
                let auth_fields = [
                    "password",
                    "passwd",
                    "pwd",
                    "pass",
                    "secret",
                    "username",
                    "user",
                    "login",
                    "email",
                    "mail",
                    "rememberme",
                    "remember",
                    "remember_me",
                    "keeploggedin",
                    "csrf",
                    "csrftoken",
                    "_token",
                    "authenticity_token",
                    "captcha",
                    "recaptcha",
                    "g-recaptcha-response",
                ];
                if auth_fields
                    .iter()
                    .any(|f| param_lower == *f || param_lower.replace("_", "") == *f)
                {
                    debug!(
                        "[ParameterFilter] Skipping auth/login field for Path Traversal: {}",
                        param_name
                    );
                    return true;
                }

                // Skip boolean fields
                if param_lower.starts_with("is")
                    || param_lower.starts_with("has")
                    || param_lower.starts_with("enable")
                    || param_lower.starts_with("disable")
                {
                    debug!(
                        "[ParameterFilter] Skipping boolean parameter for Path Traversal: {}",
                        param_name
                    );
                    return true;
                }

                // Skip pure pagination fields
                if param_lower == "count"
                    || param_lower == "limit"
                    || param_lower == "offset"
                    || param_lower == "page"
                    || param_lower == "size"
                    || param_lower == "sort"
                    || param_lower == "order"
                {
                    debug!(
                        "[ParameterFilter] Skipping pagination field for Path Traversal: {}",
                        param_name
                    );
                    return true;
                }

                // Test ALL other parameters - path traversal can be in unexpected places
                // Parameters like "name", "data", "input", "value", "id" are all valid targets
                false
            }
            ScannerType::SSRF => {
                // SSRF needs URL/URI/host parameters - common in webhooks, PDF generators, image processors
                let url_indicators = [
                    "url", "uri", "host", "domain", "link", "href", "callback", "webhook",
                    "redirect", "src", "source", "next", "return", "returnurl", "return_url",
                    "image", "imageurl", "img", "file", "fileurl", "template", "templateurl",
                    "template_url", "endpoint", "target", "targeturl", "proxy", "fetch",
                ];
                let skip = !url_indicators.iter().any(|ind| param_lower.contains(ind))
                    && (param_lower.starts_with("is") || param_lower.starts_with("has"));
                if skip {
                    debug!(
                        "[ParameterFilter] Skipping non-URL parameter for SSRF: {}",
                        param_name
                    );
                }
                skip
            }
            ScannerType::ReDoS => {
                // ReDoS only matters for regex-validated inputs like email, phone, URL patterns
                // Skip boolean flags and params unlikely to have regex validation
                if param_lower.starts_with("is")
                    || param_lower.starts_with("has")
                    || param_lower.starts_with("enable")
                    || param_lower.starts_with("disable")
                    || param_lower.starts_with("skip")
                    || param_lower.ends_with("count")
                {
                    debug!(
                        "[ParameterFilter] Skipping boolean/numeric parameter for ReDoS: {}",
                        param_name
                    );
                    return true;
                }

                // Skip address/location display fields - unlikely to have regex
                let skip_fields = [
                    "street",
                    "street2",
                    "address",
                    "locality",
                    "city",
                    "state",
                    "province",
                    "region",
                    "country",
                    "pickupcountry",
                    "destinationcountry",
                    "countryfilter",
                    "contactname",
                    "contactphone",
                    "licenseplate",
                    "einvoicename",
                    "einvoiceaddress",
                    "einvoicebroker",
                    "emailinvoicename",
                    "emailinvoiceaddress",
                    "price",
                    "priceafterfirst",
                    "pricingtype",
                    "sortdirection",
                    "pagination",
                    "before",
                    "after",
                    "defaultdepth",
                    "defaultweight",
                    "day",
                    "range",
                    "product",
                    "productid",
                    "subcontractorproduct",
                    "routename",
                    "workshiftid",
                    "companyid",
                    "office",
                    "client",
                    "login",
                    "data",
                    "mobile",
                    "puhelin",
                ];
                if skip_fields
                    .iter()
                    .any(|f| param_lower == *f || param_lower.replace("_", "") == *f)
                {
                    debug!(
                        "[ParameterFilter] Skipping display field for ReDoS: {}",
                        param_name
                    );
                    return true;
                }

                // Only test params likely to have regex validation
                let regex_likely = [
                    "email", "mail", "phone", "url", "uri", "pattern", "postcode", "zipcode",
                    "zip", "ssn", "username", "search", "query", "filter", "input", "text", "name",
                ];
                if !regex_likely.iter().any(|f| param_lower.contains(f)) {
                    // If not a common regex-validated field and ends with id, skip
                    if param_lower.ends_with("id") {
                        debug!(
                            "[ParameterFilter] Skipping ID field for ReDoS: {}",
                            param_name
                        );
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
            "password",
            "passwd",
            "pwd",
            "token",
            "secret",
            "key",
            "auth",
            "credential",
            "apikey",
            "api_key",
        ];
        for field in &critical_priority {
            if param_lower.contains(field) {
                return 10;
            }
        }

        // HIGH PRIORITY (score 9): User input fields
        let high_priority = [
            "email",
            "username",
            "user",
            "message",
            "comment",
            "feedback",
            "description",
            "search",
            "query",
            "input",
            "text",
            "content",
        ];
        for field in &high_priority {
            if param_lower.contains(field) {
                return 9;
            }
        }

        // MEDIUM-HIGH PRIORITY (score 7): File and URL operations
        let medium_high_priority = [
            "file",
            "path",
            "url",
            "uri",
            "link",
            "redirect",
            "callback",
            "upload",
            "download",
            "attachment",
        ];
        for field in &medium_high_priority {
            if param_lower.contains(field) {
                return 7;
            }
        }

        // MEDIUM PRIORITY (score 5): Business data
        let medium_priority = [
            "name", "address", "phone", "company", "business", "product", "price", "city",
            "country", "title", "subject",
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
        if value
            .chars()
            .all(|c| c.is_numeric() || c == '.' || c == '-')
        {
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
        assert!(ParameterFilter::should_skip_parameter(
            "_apolloInitData",
            ScannerType::XSS
        ));
        assert!(ParameterFilter::should_skip_parameter(
            "vueSignature",
            ScannerType::SQLi
        ));
        assert!(ParameterFilter::should_skip_parameter(
            "__typename",
            ScannerType::Other
        ));
    }

    #[test]
    fn test_scanner_specific_filtering() {
        // XXE should test most params now (loosened filter)
        // Only skip boolean flags, tokens, and pagination
        assert!(ParameterFilter::should_skip_parameter(
            "isActive",
            ScannerType::XXE
        ));
        assert!(ParameterFilter::should_skip_parameter(
            "csrfToken",
            ScannerType::XXE
        ));
        assert!(!ParameterFilter::should_skip_parameter(
            "username",
            ScannerType::XXE
        )); // Now tested!
        assert!(!ParameterFilter::should_skip_parameter(
            "xmlData",
            ScannerType::XXE
        ));
        assert!(!ParameterFilter::should_skip_parameter(
            "data",
            ScannerType::XXE
        )); // Generic param - now tested

        // SQLi should skip boolean-like params
        assert!(ParameterFilter::should_skip_parameter(
            "isActive",
            ScannerType::SQLi
        ));
        assert!(!ParameterFilter::should_skip_parameter(
            "username",
            ScannerType::SQLi
        ));

        // XSS should skip tokens and booleans, but test most params including IDs
        assert!(ParameterFilter::should_skip_parameter(
            "csrf_token",
            ScannerType::XSS
        ));
        assert!(ParameterFilter::should_skip_parameter(
            "isEnabled",
            ScannerType::XSS
        ));
        assert!(!ParameterFilter::should_skip_parameter(
            "user_id",  // Now tested - IDs can be reflected in XSS contexts
            ScannerType::XSS
        ));
        assert!(!ParameterFilter::should_skip_parameter(
            "username",
            ScannerType::XSS
        ));
        assert!(!ParameterFilter::should_skip_parameter(
            "search",
            ScannerType::XSS
        ));

        // Command Injection tests most params now (loosened filter)
        assert!(ParameterFilter::should_skip_parameter(
            "password",
            ScannerType::CommandInjection
        ));
        assert!(ParameterFilter::should_skip_parameter(
            "isEnabled",
            ScannerType::CommandInjection
        ));
        assert!(!ParameterFilter::should_skip_parameter(
            "query",
            ScannerType::CommandInjection
        )); // Generic param - now tested
        assert!(!ParameterFilter::should_skip_parameter(
            "name",
            ScannerType::CommandInjection
        )); // Generic param - now tested

        // Path Traversal tests most params now (loosened filter)
        assert!(ParameterFilter::should_skip_parameter(
            "password",
            ScannerType::PathTraversal
        ));
        assert!(ParameterFilter::should_skip_parameter(
            "hasPermission",
            ScannerType::PathTraversal
        ));
        assert!(!ParameterFilter::should_skip_parameter(
            "filename",
            ScannerType::PathTraversal
        ));
        assert!(!ParameterFilter::should_skip_parameter(
            "data",
            ScannerType::PathTraversal
        )); // Generic param - now tested
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

    #[test]
    fn test_placeholder_text_filtered() {
        // Placeholder text extracted as parameter names should be skipped
        assert!(ParameterFilter::should_skip_parameter(
            "Search articles...",
            ScannerType::SQLi
        ));
        assert!(ParameterFilter::should_skip_parameter(
            "Enter coupon code (e.g., SAVE50)",
            ScannerType::SQLi
        ));
        assert!(ParameterFilter::should_skip_parameter(
            "Search in Drive",
            ScannerType::SQLi
        ));
        assert!(ParameterFilter::should_skip_parameter(
            "Type your message here...",
            ScannerType::XSS
        ));
        // Very long parameter names should be skipped
        assert!(ParameterFilter::should_skip_parameter(
            "this_is_a_very_long_parameter_name_that_is_probably_not_real_and_should_be_filtered",
            ScannerType::SQLi
        ));
    }

    #[test]
    fn test_sqli_false_positive_filters() {
        // File input parameters should be skipped for SQLi
        assert!(ParameterFilter::should_skip_parameter(
            "avatarFileInput",
            ScannerType::SQLi
        ));
        assert!(ParameterFilter::should_skip_parameter(
            "documentFileUpload",
            ScannerType::SQLi
        ));
        assert!(ParameterFilter::should_skip_parameter(
            "imageFileInput",
            ScannerType::SQLi
        ));

        // Checkbox/toggle parameters should be skipped for SQLi
        assert!(ParameterFilter::should_skip_parameter(
            "remember",
            ScannerType::SQLi
        ));
        assert!(ParameterFilter::should_skip_parameter(
            "rememberme",
            ScannerType::SQLi
        ));
        assert!(ParameterFilter::should_skip_parameter(
            "terms",
            ScannerType::SQLi
        ));
        assert!(ParameterFilter::should_skip_parameter(
            "newsletter",
            ScannerType::SQLi
        ));
        assert!(ParameterFilter::should_skip_parameter(
            "agree_checkbox",
            ScannerType::SQLi
        ));

        // CSRF tokens should be skipped for SQLi
        assert!(ParameterFilter::should_skip_parameter(
            "csrf_token",
            ScannerType::SQLi
        ));
        assert!(ParameterFilter::should_skip_parameter(
            "authenticity_token",
            ScannerType::SQLi
        ));

        // Normal params should NOT be skipped
        assert!(!ParameterFilter::should_skip_parameter(
            "username",
            ScannerType::SQLi
        ));
        assert!(!ParameterFilter::should_skip_parameter(
            "search",
            ScannerType::SQLi
        ));
        assert!(!ParameterFilter::should_skip_parameter(
            "id",
            ScannerType::SQLi
        ));
    }
}
