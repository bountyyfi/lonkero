// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Endpoint Discovery Scanner
 * Discovers hidden endpoints, admin panels, and sensitive paths
 *
 * Features:
 * - Multilingual wordlist (Finnish, English, Swedish, German, French, Spanish, etc.)
 * - Smart response analysis (status codes, redirects, content)
 * - Adaptive rate limiting
 * - False positive filtering
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */
use crate::http_client::HttpClient;
use anyhow::Result;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, info};

/// Discovered endpoint
#[derive(Debug, Clone)]
pub struct DiscoveredEndpoint {
    pub url: String,
    pub status_code: u16,
    pub content_length: usize,
    pub redirect_location: Option<String>,
    pub category: EndpointCategory,
}

/// Category of discovered endpoint
#[derive(Debug, Clone, PartialEq)]
pub enum EndpointCategory {
    Admin,
    Authentication,
    Api,
    Backup,
    Config,
    Debug,
    Documentation,
    FileUpload,
    Database,
    Monitoring,
    Other,
}

pub struct EndpointDiscovery {
    http_client: Arc<HttpClient>,
}

impl EndpointDiscovery {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Discover endpoints on target
    pub async fn discover(&self, base_url: &str) -> Result<Vec<DiscoveredEndpoint>> {
        info!(
            "[EndpointDiscovery] Starting endpoint discovery on {}",
            base_url
        );

        let mut discovered = Vec::new();
        let mut checked = HashSet::new();
        let base_url = base_url.trim_end_matches('/');

        // Get baseline response for comparison
        let baseline = self.get_baseline_response(base_url).await;

        for path in Self::get_wordlist() {
            let url = format!("{}{}", base_url, path);

            if checked.contains(&url) {
                continue;
            }
            checked.insert(url.clone());

            match self.http_client.get(&url).await {
                Ok(response) => {
                    // Skip if matches baseline (likely custom 404)
                    if self.is_false_positive(&response, &baseline) {
                        continue;
                    }

                    // Interesting status codes
                    if self.is_interesting_response(response.status_code) {
                        let category = Self::categorize_path(path);
                        let redirect = response.header("location").map(|s| s.to_string());

                        debug!(
                            "[EndpointDiscovery] Found: {} ({})",
                            url, response.status_code
                        );

                        discovered.push(DiscoveredEndpoint {
                            url,
                            status_code: response.status_code,
                            content_length: response.body.len(),
                            redirect_location: redirect,
                            category,
                        });
                    }
                }
                Err(_) => continue,
            }
        }

        info!(
            "[EndpointDiscovery] Discovered {} endpoints",
            discovered.len()
        );

        Ok(discovered)
    }

    /// Get baseline response for false positive detection
    async fn get_baseline_response(&self, base_url: &str) -> Option<(u16, usize, String)> {
        // Request a random non-existent path to detect custom 404 pages
        let random_path = format!(
            "{}/lonkero_random_404_test_{}",
            base_url,
            uuid::Uuid::new_v4()
        );

        match self.http_client.get(&random_path).await {
            Ok(response) => Some((
                response.status_code,
                response.body.len(),
                // First 500 chars for comparison
                response.body.chars().take(500).collect(),
            )),
            Err(_) => None,
        }
    }

    /// Check if response is likely a false positive (custom 404)
    fn is_false_positive(
        &self,
        response: &crate::http_client::HttpResponse,
        baseline: &Option<(u16, usize, String)>,
    ) -> bool {
        if let Some((baseline_status, baseline_len, baseline_content)) = baseline {
            // Same status code and similar content length = likely custom 404
            if response.status_code == *baseline_status {
                let len_diff = (response.body.len() as i64 - *baseline_len as i64).abs();
                if len_diff < 100 {
                    return true;
                }

                // Similar content = false positive
                let response_start: String = response.body.chars().take(500).collect();
                if response_start == *baseline_content {
                    return true;
                }
            }
        }
        false
    }

    /// Check if status code indicates interesting endpoint
    fn is_interesting_response(&self, status: u16) -> bool {
        matches!(
            status,
            200 | 201 | 204 | 301 | 302 | 307 | 308 | 401 | 403 | 405 | 500
        )
    }

    /// Categorize path based on keywords.
    ///
    /// High-impact, narrowly-named patterns (VCS leaks, credential files,
    /// diagnostic endpoints) are checked first so a hit on `/.git/config` is
    /// labelled `Config` rather than the generic substring match against
    /// `config` further down — same final variant here, but matching the
    /// specific pattern first lets future additions split into their own
    /// category without re-ordering.
    fn categorize_path(path: &str) -> EndpointCategory {
        let path_lower = path.to_lowercase();

        // VCS, dotfile, and credential-file leaks. Each substring is unique
        // enough that a match is almost always a real sensitive resource.
        const SENSITIVE_CONFIG_SUBSTRINGS: &[&str] = &[
            ".git",
            ".svn",
            ".hg/",
            "id_rsa",
            "id_ed25519",
            "id_ecdsa",
            "/.ssh",
            "/.aws",
            "/.kube",
            "/.docker",
            ".htpasswd",
            ".htaccess",
            ".netrc",
            ".npmrc",
            ".pypirc",
            "credentials.json",
            "service-account",
            ".tfstate",
            ".tfvars",
            "private.key",
            "private.pem",
            "master.key",
            "wp-config",
            "secrets.yml",
            "database.yml",
            "credentials.yml.enc",
            "parameters.yml",
        ];
        if SENSITIVE_CONFIG_SUBSTRINGS
            .iter()
            .any(|s| path_lower.contains(s))
        {
            return EndpointCategory::Config;
        }

        // Diagnostic / profiling endpoints that frequently leak env vars,
        // heap dumps, request bodies, or session data when exposed.
        const DEBUG_DISCLOSURE_SUBSTRINGS: &[&str] = &[
            "actuator",
            "/jolokia",
            "heapdump",
            "threaddump",
            "_profiler",
            "trace.axd",
            "elmah.axd",
            "glimpse.axd",
            "_ignition",
            "_debugbar",
            "/_wdt",
            "telescope",
            "/horizon",
            "phpinfo",
            "/info.php",
            "xdebug",
            "/pprof",
            "/debug/vars",
        ];
        if DEBUG_DISCLOSURE_SUBSTRINGS
            .iter()
            .any(|s| path_lower.contains(s))
        {
            return EndpointCategory::Debug;
        }

        // Admin paths
        if path_lower.contains("admin")
            || path_lower.contains("hallinta")
            || path_lower.contains("yllapito")
            || path_lower.contains("administrator")
            || path_lower.contains("verwaltung")
            || path_lower.contains("gestion")
            || path_lower.contains("administrador")
        {
            return EndpointCategory::Admin;
        }

        // Authentication paths
        if path_lower.contains("login")
            || path_lower.contains("kirjaudu")
            || path_lower.contains("sisaan")
            || path_lower.contains("register")
            || path_lower.contains("rekister")
            || path_lower.contains("signup")
            || path_lower.contains("auth")
            || path_lower.contains("signin")
            || path_lower.contains("logga")
            || path_lower.contains("anmelden")
            || path_lower.contains("connexion")
            || path_lower.contains("iniciar")
        {
            return EndpointCategory::Authentication;
        }

        // API paths
        if path_lower.contains("api")
            || path_lower.contains("graphql")
            || path_lower.contains("rest")
            || path_lower.contains("v1")
            || path_lower.contains("v2")
        {
            return EndpointCategory::Api;
        }

        // Backup paths — archive/dump extensions and editor swap files belong
        // here because a hit on the real path means a packaged copy of the
        // source tree or database is publicly served.
        if path_lower.contains("backup")
            || path_lower.contains("varmuuskopio")
            || path_lower.contains("bak")
            || path_lower.contains("old")
            || path_lower.contains("copy")
            || path_lower.contains("archive")
            || path_lower.ends_with(".tar")
            || path_lower.ends_with(".tar.gz")
            || path_lower.ends_with(".tgz")
            || path_lower.ends_with(".tar.bz2")
            || path_lower.ends_with(".zip")
            || path_lower.ends_with(".7z")
            || path_lower.ends_with(".rar")
            || path_lower.ends_with(".gz")
            || path_lower.ends_with(".bz2")
            || path_lower.ends_with(".dump")
            || path_lower.ends_with(".swp")
            || path_lower.ends_with(".save")
            || path_lower.ends_with(".orig")
            || path_lower.ends_with("~")
        {
            return EndpointCategory::Backup;
        }

        // Config paths
        if path_lower.contains("config")
            || path_lower.contains("asetukset")
            || path_lower.contains("settings")
            || path_lower.contains("env")
        {
            return EndpointCategory::Config;
        }

        // Debug paths
        if path_lower.contains("debug")
            || path_lower.contains("test")
            || path_lower.contains("dev")
            || path_lower.contains("staging")
        {
            return EndpointCategory::Debug;
        }

        // Documentation
        if path_lower.contains("doc")
            || path_lower.contains("swagger")
            || path_lower.contains("openapi")
            || path_lower.contains("readme")
        {
            return EndpointCategory::Documentation;
        }

        // File upload
        if path_lower.contains("upload")
            || path_lower.contains("lataa")
            || path_lower.contains("file")
            || path_lower.contains("tiedosto")
        {
            return EndpointCategory::FileUpload;
        }

        // Database admin tools and direct cluster APIs.
        if path_lower.contains("phpmyadmin")
            || path_lower.contains("adminer")
            || path_lower.contains("database")
            || path_lower.contains("db")
            || path_lower.contains("sql")
            || path_lower.contains("couchdb")
            || path_lower.contains("_cat/")
            || path_lower.contains("_cluster")
            || path_lower.contains("redis-commander")
            || path_lower.contains("rediscommander")
            || path_lower.contains("/flower")
            || path_lower.contains("kafdrop")
            || path_lower.contains("/cmak")
            || path_lower.contains("/akhq")
            || path_lower.contains("rabbitmq")
            || path_lower.contains("/minio")
            || path_lower.contains("mongoexpress")
            || path_lower.contains("/_all_dbs")
        {
            return EndpointCategory::Database;
        }

        // Monitoring / observability dashboards and metric scrapers.
        if path_lower.contains("health")
            || path_lower.contains("status")
            || path_lower.contains("metrics")
            || path_lower.contains("monitor")
            || path_lower.contains("grafana")
            || path_lower.contains("kibana")
            || path_lower.contains("prometheus")
            || path_lower.contains("alertmanager")
            || path_lower.contains("/loki")
            || path_lower.contains("/tempo")
            || path_lower.contains("/jaeger")
            || path_lower.contains("/zipkin")
            || path_lower.contains("/sentry")
        {
            return EndpointCategory::Monitoring;
        }

        EndpointCategory::Other
    }

    /// Get multilingual wordlist
    fn get_wordlist() -> Vec<&'static str> {
        vec![
            // ========================================
            // FINNISH (Suomi)
            // ========================================
            // Authentication
            "/kirjaudu",
            "/kirjaudu-sisaan",
            "/kirjautuminen",
            "/sisaankirjautuminen",
            "/rekisteroidy",
            "/rekisteroityminen",
            "/rekisteröidy",
            "/rekisteröityminen",
            "/luo-tili",
            "/unohditko-salasanan",
            "/salasana",
            "/uusi-salasana",
            "/vaihda-salasana",
            "/kirjaudu-ulos",
            "/uloskirjautuminen",
            // Admin
            "/hallinta",
            "/hallintapaneeli",
            "/yllapito",
            "/ylläpito",
            "/admin",
            "/paakayttaja",
            "/pääkäyttäjä",
            "/kayttajahallinta",
            "/käyttäjähallinta",
            "/asetukset",
            "/jarjestelma",
            "/järjestelmä",
            // User
            "/kayttaja",
            "/käyttäjä",
            "/profiili",
            "/oma-tili",
            "/omat-tiedot",
            "/tili",
            "/tilaus",
            "/tilaukset",
            // Content
            "/sisalto",
            "/sisältö",
            "/sivut",
            "/artikkelit",
            "/uutiset",
            "/blogi",
            "/media",
            "/kuvat",
            "/tiedostot",
            "/lataukset",
            "/lataa",
            // E-commerce Finnish
            "/ostoskori",
            "/kassa",
            "/maksu",
            "/tilaa",
            "/tuotteet",
            "/tuote",
            "/kauppa",
            "/verkkokauppa",
            "/hinnasto",
            // Other Finnish
            "/haku",
            "/etsi",
            "/yhteystiedot",
            "/ota-yhteytta",
            "/tietoa-meista",
            "/palvelut",
            "/tuki",
            "/ohje",
            "/apua",
            "/ukk",
            "/usein-kysytyt",
            "/tietosuoja",
            "/evasteet",
            "/kayttoehdot",
            "/käyttöehdot",
            // ========================================
            // SWEDISH (Svenska)
            // ========================================
            "/logga-in",
            "/inloggning",
            "/registrera",
            "/registrering",
            "/skapa-konto",
            "/glomt-losenord",
            "/logga-ut",
            "/anvandare",
            "/användare",
            "/profil",
            "/mitt-konto",
            "/installningar",
            "/inställningar",
            "/admin",
            "/administration",
            "/forvaltning",
            "/förvaltning",
            "/sok",
            "/sök",
            "/kontakt",
            "/om-oss",
            "/tjanster",
            "/tjänster",
            "/hjalp",
            "/hjälp",
            "/varukorg",
            "/kassa",
            "/betalning",
            "/produkter",
            "/butik",
            // ========================================
            // GERMAN (Deutsch)
            // ========================================
            "/anmelden",
            "/einloggen",
            "/login",
            "/registrieren",
            "/registrierung",
            "/konto-erstellen",
            "/passwort-vergessen",
            "/abmelden",
            "/ausloggen",
            "/benutzer",
            "/profil",
            "/mein-konto",
            "/einstellungen",
            "/verwaltung",
            "/administration",
            "/admin",
            "/suche",
            "/suchen",
            "/kontakt",
            "/impressum",
            "/uber-uns",
            "/über-uns",
            "/dienste",
            "/dienstleistungen",
            "/hilfe",
            "/warenkorb",
            "/kasse",
            "/bezahlung",
            "/zahlung",
            "/produkte",
            "/shop",
            "/datenschutz",
            "/agb",
            // ========================================
            // FRENCH (Français)
            // ========================================
            "/connexion",
            "/se-connecter",
            "/inscription",
            "/enregistrement",
            "/creer-compte",
            "/créer-compte",
            "/mot-de-passe-oublie",
            "/mot-de-passe-oublié",
            "/deconnexion",
            "/déconnexion",
            "/utilisateur",
            "/profil",
            "/mon-compte",
            "/parametres",
            "/paramètres",
            "/gestion",
            "/administration",
            "/admin",
            "/recherche",
            "/chercher",
            "/contact",
            "/a-propos",
            "/à-propos",
            "/services",
            "/aide",
            "/panier",
            "/caisse",
            "/paiement",
            "/produits",
            "/boutique",
            "/mentions-legales",
            "/mentions-légales",
            "/confidentialite",
            "/confidentialité",
            // ========================================
            // SPANISH (Español)
            // ========================================
            "/iniciar-sesion",
            "/ingresar",
            "/acceder",
            "/registrarse",
            "/registro",
            "/crear-cuenta",
            "/olvide-contrasena",
            "/olvidé-contraseña",
            "/cerrar-sesion",
            "/cerrar-sesión",
            "/usuario",
            "/perfil",
            "/mi-cuenta",
            "/configuracion",
            "/configuración",
            "/ajustes",
            "/gestion",
            "/gestión",
            "/administracion",
            "/administración",
            "/admin",
            "/buscar",
            "/busqueda",
            "/búsqueda",
            "/contacto",
            "/sobre-nosotros",
            "/acerca-de",
            "/servicios",
            "/ayuda",
            "/carrito",
            "/caja",
            "/pago",
            "/productos",
            "/tienda",
            "/aviso-legal",
            "/privacidad",
            "/terminos",
            "/términos",
            // ========================================
            // PORTUGUESE (Português)
            // ========================================
            "/entrar",
            "/login",
            "/cadastrar",
            "/cadastro",
            "/registrar",
            "/registro",
            "/criar-conta",
            "/esqueci-senha",
            "/sair",
            "/usuario",
            "/usuário",
            "/perfil",
            "/minha-conta",
            "/configuracoes",
            "/configurações",
            "/gestao",
            "/gestão",
            "/administracao",
            "/administração",
            "/admin",
            "/buscar",
            "/pesquisar",
            "/contato",
            "/sobre-nos",
            "/servicos",
            "/serviços",
            "/ajuda",
            "/carrinho",
            "/checkout",
            "/pagamento",
            "/produtos",
            "/loja",
            // ========================================
            // ITALIAN (Italiano)
            // ========================================
            "/accedi",
            "/login",
            "/registrati",
            "/registrazione",
            "/crea-account",
            "/password-dimenticata",
            "/esci",
            "/utente",
            "/profilo",
            "/mio-account",
            "/impostazioni",
            "/gestione",
            "/amministrazione",
            "/admin",
            "/cerca",
            "/ricerca",
            "/contatti",
            "/contatto",
            "/chi-siamo",
            "/servizi",
            "/aiuto",
            "/carrello",
            "/cassa",
            "/pagamento",
            "/prodotti",
            "/negozio",
            // ========================================
            // DUTCH (Nederlands)
            // ========================================
            "/inloggen",
            "/aanmelden",
            "/registreren",
            "/account-aanmaken",
            "/wachtwoord-vergeten",
            "/uitloggen",
            "/afmelden",
            "/gebruiker",
            "/profiel",
            "/mijn-account",
            "/instellingen",
            "/beheer",
            "/administratie",
            "/admin",
            "/zoeken",
            "/contact",
            "/over-ons",
            "/diensten",
            "/hulp",
            "/winkelwagen",
            "/afrekenen",
            "/betaling",
            "/producten",
            "/winkel",
            // ========================================
            // POLISH (Polski)
            // ========================================
            "/zaloguj",
            "/logowanie",
            "/rejestracja",
            "/zarejestruj",
            "/utworz-konto",
            "/zapomnialem-hasla",
            "/wyloguj",
            "/uzytkownik",
            "/profil",
            "/moje-konto",
            "/ustawienia",
            "/zarzadzanie",
            "/administracja",
            "/admin",
            "/szukaj",
            "/wyszukiwanie",
            "/kontakt",
            "/o-nas",
            "/uslugi",
            "/pomoc",
            "/koszyk",
            "/kasa",
            "/platnosc",
            "/produkty",
            "/sklep",
            // ========================================
            // RUSSIAN (Русский - transliterated)
            // ========================================
            "/vhod",
            "/vxod",
            "/login",
            "/registracija",
            "/registratsiya",
            "/sozdat-akkaunt",
            "/zabyl-parol",
            "/vyhod",
            "/vyxod",
            "/polzovatel",
            "/profil",
            "/moj-akkaunt",
            "/nastrojki",
            "/upravlenie",
            "/administratsiya",
            "/admin",
            "/poisk",
            "/kontakty",
            "/o-nas",
            "/uslugi",
            "/pomosch",
            "/korzina",
            "/kassa",
            "/oplata",
            "/produkty",
            "/magazin",
            // ========================================
            // ENGLISH (Common)
            // ========================================
            // Authentication
            "/login",
            "/signin",
            "/sign-in",
            "/logon",
            "/log-on",
            "/register",
            "/signup",
            "/sign-up",
            "/create-account",
            "/forgot-password",
            "/reset-password",
            "/change-password",
            "/logout",
            "/signout",
            "/sign-out",
            "/log-out",
            "/auth",
            "/authenticate",
            "/oauth",
            "/oauth2",
            "/sso",
            "/saml",
            "/callback",
            "/authorize",
            "/token",
            "/refresh-token",
            "/2fa",
            "/mfa",
            "/verify",
            "/verify-email",
            "/confirm",
            "/activate",
            // Admin
            "/admin",
            "/administrator",
            "/administration",
            "/admin-panel",
            "/adminpanel",
            "/control-panel",
            "/controlpanel",
            "/cpanel",
            "/dashboard",
            "/backend",
            "/backoffice",
            "/back-office",
            "/management",
            "/manager",
            "/console",
            "/portal",
            "/cms",
            "/system",
            "/sys",
            "/sysadmin",
            "/superadmin",
            "/super-admin",
            "/root",
            "/master",
            "/webmaster",
            "/moderator",
            "/mod",
            "/staff",
            // User/Account
            "/user",
            "/users",
            "/account",
            "/accounts",
            "/profile",
            "/profiles",
            "/my-account",
            "/myaccount",
            "/me",
            "/self",
            "/member",
            "/members",
            "/membership",
            "/settings",
            "/preferences",
            "/options",
            // API
            "/api",
            "/api/v1",
            "/api/v2",
            "/api/v3",
            "/rest",
            "/restapi",
            "/rest-api",
            "/graphql",
            "/graphiql",
            "/playground",
            "/explorer",
            "/swagger",
            "/swagger-ui",
            "/openapi",
            "/openapi.json",
            "/openapi.yaml",
            "/api-docs",
            "/docs",
            "/documentation",
            "/redoc",
            "/api/docs",
            "/api/swagger",
            "/api/health",
            "/api/status",
            "/api/version",
            "/api/info",
            "/api/ping",
            // Config/Environment
            "/config",
            "/configuration",
            "/conf",
            "/env",
            "/environment",
            "/.env",
            "/.env.local",
            "/.env.production",
            "/.env.development",
            "/config.json",
            "/config.yml",
            "/config.yaml",
            "/config.xml",
            "/settings.json",
            "/app.config",
            "/web.config",
            "/application.yml",
            "/application.properties",
            // Debug/Development
            "/debug",
            "/debugging",
            "/dev",
            "/development",
            "/test",
            "/testing",
            "/tests",
            "/qa",
            "/staging",
            "/stage",
            "/sandbox",
            "/demo",
            "/preview",
            "/beta",
            "/alpha",
            "/trace",
            "/traces",
            "/logs",
            "/log",
            "/logging",
            "/error",
            "/errors",
            "/exception",
            "/exceptions",
            "/stack",
            "/stacktrace",
            "/dump",
            "/memory",
            "/heap",
            "/profiler",
            "/profiling",
            "/xdebug",
            "/phpinfo",
            "/phpinfo.php",
            "/info.php",
            "/test.php",
            "/info",
            "/server-info",
            "/server-status",
            "/status",
            "/health",
            "/healthz",
            "/healthcheck",
            "/health-check",
            "/ready",
            "/readiness",
            "/liveness",
            "/alive",
            "/ping",
            "/pong",
            "/version",
            "/versions",
            "/build",
            "/build-info",
            "/metrics",
            "/prometheus",
            "/actuator",
            "/actuator/health",
            "/actuator/info",
            "/actuator/metrics",
            "/actuator/env",
            "/actuator/beans",
            "/actuator/mappings",
            "/actuator/configprops",
            "/actuator/trace",
            "/actuator/heapdump",
            "/actuator/threaddump",
            // Backup/Old files
            "/backup",
            "/backups",
            "/bak",
            "/old",
            "/archive",
            "/archives",
            "/temp",
            "/tmp",
            "/cache",
            "/cached",
            "/copy",
            "/backup.sql",
            "/backup.zip",
            "/backup.tar.gz",
            "/db.sql",
            "/database.sql",
            "/dump.sql",
            "/data.sql",
            "/export.sql",
            // Database
            "/phpmyadmin",
            "/pma",
            "/mysql",
            "/mysqladmin",
            "/adminer",
            "/adminer.php",
            "/database",
            "/databases",
            "/db",
            "/dbadmin",
            "/sql",
            "/sqladmin",
            "/pgadmin",
            "/postgres",
            "/postgresql",
            "/mongodb",
            "/mongo",
            "/redis",
            "/elasticsearch",
            "/kibana",
            "/grafana",
            // File management
            "/upload",
            "/uploads",
            "/file",
            "/files",
            "/download",
            "/downloads",
            "/media",
            "/images",
            "/image",
            "/img",
            "/assets",
            "/static",
            "/public",
            "/storage",
            "/data",
            "/resources",
            "/resource",
            "/content",
            "/contents",
            "/attachment",
            "/attachments",
            "/documents",
            "/document",
            "/docs",
            "/doc",
            "/pdf",
            "/pdfs",
            // E-commerce
            "/cart",
            "/basket",
            "/checkout",
            "/order",
            "/orders",
            "/payment",
            "/payments",
            "/pay",
            "/billing",
            "/invoice",
            "/invoices",
            "/shop",
            "/store",
            "/product",
            "/products",
            "/catalog",
            "/catalogue",
            "/category",
            "/categories",
            "/wishlist",
            "/favorites",
            "/compare",
            "/review",
            "/reviews",
            // Search
            "/search",
            "/find",
            "/query",
            "/lookup",
            "/autocomplete",
            "/suggest",
            "/suggestions",
            // XSS/Injection-prone endpoints (reflection, JSONP, templates)
            "/echo",
            "/reflect",
            "/mirror",
            "/test",
            "/debug",
            "/callback",
            "/jsonp",
            "/embed",
            "/preview",
            "/render",
            "/template",
            "/view",
            "/display",
            "/show",
            "/print",
            "/pdf",
            "/qr",
            "/barcode",
            "/snippet",
            "/code",
            "/output",
            "/response",
            "/result",
            "/name",
            "/user",
            "/error",
            "/redirect",
            "/goto",
            "/next",
            "/return",
            "/url",
            "/link",
            "/forward",
            "/stats",
            "/api/callback",
            "/api/echo",
            "/api/stats",
            "/api/jsonp",
            // Communication
            "/contact",
            "/contact-us",
            "/contactus",
            "/feedback",
            "/support",
            "/help",
            "/faq",
            "/faqs",
            "/ticket",
            "/tickets",
            "/chat",
            "/livechat",
            "/live-chat",
            "/message",
            "/messages",
            "/inbox",
            "/mail",
            "/email",
            "/newsletter",
            "/subscribe",
            "/unsubscribe",
            // Legal/Info
            "/about",
            "/about-us",
            "/aboutus",
            "/privacy",
            "/privacy-policy",
            "/terms",
            "/terms-of-service",
            "/tos",
            "/legal",
            "/disclaimer",
            "/cookies",
            "/cookie-policy",
            "/gdpr",
            "/imprint",
            "/sitemap",
            "/sitemap.xml",
            "/robots.txt",
            "/humans.txt",
            "/security.txt",
            "/.well-known/security.txt",
            // RSS/Atom Feeds (potential XML XSS vectors)
            "/feed",
            "/feed.xml",
            "/rss",
            "/rss.xml",
            "/atom",
            "/atom.xml",
            "/blog/feed",
            "/blog/rss",
            "/news/feed",
            "/news/rss",
            "/feeds/posts/default",
            // Git/Source
            "/.git",
            "/.git/config",
            "/.git/HEAD",
            "/.gitignore",
            "/.svn",
            "/.svn/entries",
            "/.hg",
            "/.bzr",
            "/CVS",
            "/.DS_Store",
            "/Thumbs.db",
            // Package managers
            "/package.json",
            "/package-lock.json",
            "/yarn.lock",
            "/composer.json",
            "/composer.lock",
            "/Gemfile",
            "/Gemfile.lock",
            "/requirements.txt",
            "/Pipfile",
            "/Pipfile.lock",
            "/pom.xml",
            "/build.gradle",
            "/Cargo.toml",
            "/go.mod",
            "/go.sum",
            // Server/Infrastructure
            "/server",
            "/wp-admin",
            "/wp-login.php",
            "/wp-config.php",
            "/wp-content",
            "/wp-includes",
            "/wordpress",
            "/joomla",
            "/drupal",
            "/magento",
            "/prestashop",
            "/shopify",
            "/woocommerce",
            "/typo3",
            "/umbraco",
            "/sitecore",
            "/kentico",
            "/sitefinity",
            // Jenkins/CI
            "/jenkins",
            "/jenkins/login",
            "/jenkins/script",
            "/ci",
            "/build",
            "/builds",
            "/job",
            "/jobs",
            "/pipeline",
            "/pipelines",
            // Monitoring
            "/monitor",
            "/monitoring",
            "/apm",
            "/analytics",
            "/stats",
            "/statistics",
            "/reports",
            "/report",
            "/reporting",
            "/audit",
            "/auditing",
            // WebSocket
            "/ws",
            "/wss",
            "/websocket",
            "/socket",
            "/socket.io",
            "/sockjs",
            // Mobile
            "/mobile",
            "/app",
            "/ios",
            "/android",
            "/api/mobile",
            // Internal/Hidden
            "/internal",
            "/private",
            "/secret",
            "/secrets",
            "/hidden",
            "/secure",
            "/protected",
            "/restricted",
            "/confidential",
            "/_",
            "/__",
            "/~",
            // Common vulnerabilities
            "/cgi-bin",
            "/cgi-bin/test-cgi",
            "/cgi-sys",
            "/scripts",
            "/bin",
            "/exec",
            "/execute",
            "/run",
            "/cmd",
            "/command",
            "/shell",
            "/terminal",
            "/console",
            // Next.js specific
            "/_next",
            "/_next/static",
            "/api/auth",
            "/api/auth/signin",
            "/api/auth/signout",
            "/api/auth/session",
            "/api/auth/providers",
            // Common framework paths
            "/laravel",
            "/telescope",
            "/horizon",
            "/nova",
            "/vapor",
            "/django",
            "/django-admin",
            "/rails",
            "/express",
            "/flask",
            "/fastapi",
            "/spring",
            "/struts",
            // ========================================
            // SSRF-PRONE ENDPOINTS (HIGH PRIORITY)
            // ========================================
            "/proxy",
            "/proxy/fetch",
            "/fetch",
            "/fetch/url",
            "/url/fetch",
            "/get-url",
            "/geturl",
            "/preview",
            "/preview/url",
            "/render",
            "/render/url",
            "/screenshot",
            "/screenshot/url",
            "/pdf",
            "/pdf/generate",
            "/export/pdf",
            "/convert",
            "/convert/url",
            "/webhook",
            "/webhook/test",
            "/webhook/callback",
            "/callback",
            "/redirect",
            "/goto",
            "/redir",
            "/link",
            "/external",
            "/out",
            "/click",
            "/track",
            "/image-proxy",
            "/img-proxy",
            "/media-proxy",
            // ========================================
            // API DISCOVERY (COMPREHENSIVE)
            // ========================================
            // Common API endpoints
            "/api/users",
            "/api/user",
            "/api/search",
            "/api/data",
            "/api/config",
            "/api/settings",
            "/api/admin",
            "/api/login",
            "/api/logout",
            "/api/register",
            "/api/profile",
            "/api/account",
            "/api/me",
            "/api/upload",
            "/api/download",
            "/api/export",
            "/api/import",
            "/api/reports",
            "/api/analytics",
            "/api/logs",
            "/api/debug",
            "/api/test",
            "/api/internal",
            "/api/private",
            "/api/public",
            // Versioned API endpoints
            "/api/v1/users",
            "/api/v1/search",
            "/api/v1/data",
            "/api/v1/config",
            "/api/v1/admin",
            "/api/v2/users",
            "/api/v2/search",
            "/api/v2/data",
            "/api/v2/config",
            "/api/v2/admin",
            "/api/v3/users",
            "/api/v3/search",
            "/api/v3/data",
            "/v1/users",
            "/v1/api",
            "/v1/search",
            "/v1/data",
            "/v2/users",
            "/v2/api",
            "/v2/search",
            "/v2/data",
            "/v3/users",
            "/v3/api",
            // REST endpoints
            "/rest/users",
            "/rest/data",
            "/rest/api",
            "/restapi/users",
            "/restapi/data",
            // ========================================
            // ADMIN PANEL DISCOVERY (EXPANDED)
            // ========================================
            "/admin/login",
            "/admin/dashboard",
            "/admin/panel",
            "/admin/console",
            "/admin/settings",
            "/admin/config",
            "/admin/users",
            "/admin/logs",
            "/admin/debug",
            "/admin/test",
            "/admin/tools",
            "/admin/backup",
            "/admin/export",
            "/admin/import",
            "/admin/reports",
            "/admin/analytics",
            "/admin/api",
            "/dashboard/admin",
            "/dashboard/login",
            "/dashboard/home",
            "/management/login",
            "/management/admin",
            "/manage/admin",
            "/manage/users",
            "/manage/settings",
            // ========================================
            // DEBUG & DEVELOPMENT ENDPOINTS
            // ========================================
            "/debug/vars",
            "/debug/info",
            "/debug/config",
            "/debug/env",
            "/debug/routes",
            "/debug/settings",
            "/debug/status",
            "/debug/pprof",
            "/debug/metrics",
            "/debug/sql",
            "/debug/queries",
            "/internal/debug",
            "/internal/status",
            "/internal/health",
            "/internal/metrics",
            "/internal/api",
            // ========================================
            // TOOLS & UTILITIES (COMMAND INJECTION)
            // ========================================
            "/tools",
            "/tools/ping",
            "/tools/nslookup",
            "/tools/dig",
            "/tools/whois",
            "/tools/traceroute",
            "/tools/dns",
            "/tools/network",
            "/tools/test",
            "/tools/diagnostics",
            "/utils",
            "/utils/ping",
            "/utils/test",
            "/utils/convert",
            "/helpers",
            "/helpers/ping",
            "/helpers/test",
            "/diagnostics",
            "/diagnostics/ping",
            "/diagnostics/network",
            "/network-tools",
            "/network/ping",
            "/network/test",
            // ========================================
            // FILE OPERATIONS
            // ========================================
            "/backup/download",
            "/backup/export",
            "/backup/list",
            "/export/users",
            "/export/data",
            "/export/csv",
            "/export/json",
            "/export/xml",
            "/download/backup",
            "/download/file",
            "/download/export",
            "/download/logs",
            "/download/report",
            // ========================================
            // HIDDEN/INTERNAL FEATURES
            // ========================================
            "/hidden",
            "/hidden/admin",
            "/hidden/api",
            "/secret",
            "/secret/admin",
            "/secret/api",
            "/test/api",
            "/test/admin",
            "/test/upload",
            "/test/execute",
            "/dev/api",
            "/dev/admin",
            "/dev/test",
            "/staging/api",
            "/staging/admin",
            "/beta/api",
            "/beta/admin",
            // ========================================
            // GRAPHQL & MODERN API PATTERNS
            // ========================================
            "/graphql/admin",
            "/graphql/internal",
            "/graphiql/admin",
            "/graphql-explorer",
            "/api/graphql",
            "/v1/graphql",
            "/v2/graphql",
            // ========================================
            // SERVERLESS FUNCTIONS
            // ========================================
            "/functions",
            "/functions/api",
            "/.netlify/functions",
            "/.vercel/functions",
            "/api/serverless",
            "/lambda",
            "/functions/users",
            "/functions/admin",
            // ========================================
            // CLOUD METADATA ENDPOINTS
            // ========================================
            "/metadata",
            "/cloud-metadata",
            "/instance-metadata",
            "/compute-metadata",
            // ========================================
            // RATE LIMIT TESTING
            // ========================================
            "/rate-limit",
            "/ratelimit",
            "/throttle",
            // ========================================
            // SPRING BOOT ACTUATOR (DEEP + LEGACY)
            // Each path is a confirmed Spring Boot endpoint; a 200/JSON
            // response is an information disclosure, and `env`/`heapdump`/
            // `jolokia` reach RCE on common configurations.
            // ========================================
            "/actuator/env/PATH",
            "/actuator/env/SPRING_DATASOURCE_PASSWORD",
            "/actuator/loggers",
            "/actuator/loggers/ROOT",
            "/actuator/auditevents",
            "/actuator/sessions",
            "/actuator/caches",
            "/actuator/scheduledtasks",
            "/actuator/conditions",
            "/actuator/refresh",
            "/actuator/restart",
            "/actuator/shutdown",
            "/actuator/jolokia",
            "/actuator/jolokia/list",
            "/actuator/prometheus",
            "/actuator/httptrace",
            "/actuator/httpexchanges",
            "/actuator/flyway",
            "/actuator/liquibase",
            "/actuator/integrationgraph",
            "/actuator/quartz",
            "/actuator/sbom",
            "/actuator/gateway/routes",
            "/actuator/gateway/globalfilters",
            // Spring Boot 1.x legacy (no /actuator prefix)
            "/env",
            "/trace",
            "/heapdump",
            "/loggers",
            "/mappings",
            "/beans",
            "/autoconfig",
            "/jolokia",
            "/jolokia/list",
            "/manage/env",
            "/manage/health",
            "/manage/info",
            "/manage/heapdump",
            "/manage/actuator",
            // ========================================
            // JAVA APP SERVERS (TOMCAT / JBOSS / WEBLOGIC / SOLR)
            // ========================================
            "/manager/html",
            "/manager/text",
            "/manager/status",
            "/manager/jmxproxy",
            "/host-manager/html",
            "/host-manager/text",
            "/jmx-console",
            "/jmx-console/HtmlAdaptor",
            "/web-console",
            "/web-console/Invoker",
            "/invoker/JMXInvokerServlet",
            "/invoker/EJBInvokerServlet",
            "/jbossws",
            "/jbossws/services",
            "/console/login/LoginForm.jsp",
            "/wls-wsat/CoordinatorPortType",
            "/wls-wsat/ParticipantPortType",
            "/_async/AsyncResponseService",
            "/em/",
            "/em/console",
            "/solr/admin/cores",
            "/solr/admin/info/system",
            "/solr/admin/info/properties",
            "/solr/admin/info/threads",
            "/solr/admin/collections",
            // ========================================
            // HASHICORP VAULT / CONSUL / NOMAD
            // ========================================
            "/v1/sys/health",
            "/v1/sys/leader",
            "/v1/sys/init",
            "/v1/sys/seal-status",
            "/v1/sys/mounts",
            "/v1/sys/policies",
            "/v1/sys/auth",
            "/v1/sys/config/state",
            "/v1/auth/token/lookup-self",
            "/v1/secret/data",
            "/v1/secret/metadata",
            "/ui/vault",
            "/v1/agent/self",
            "/v1/agent/checks",
            "/v1/agent/services",
            "/v1/agent/members",
            "/v1/catalog/nodes",
            "/v1/catalog/services",
            "/v1/catalog/datacenters",
            "/v1/kv/?recurse",
            "/v1/agent/health",
            "/v1/jobs",
            "/v1/allocations",
            "/v1/nodes",
            "/v1/status/leader",
            // ========================================
            // KUBERNETES / KUBELET / DOCKER DAEMON
            // ========================================
            "/api/v1/namespaces",
            "/api/v1/namespaces/default/pods",
            "/api/v1/namespaces/default/secrets",
            "/api/v1/namespaces/kube-system/secrets",
            "/apis",
            "/openapi/v2",
            "/openapi/v3",
            "/healthz",
            "/livez",
            "/readyz",
            "/swagger-2.0.0.json",
            "/_ping",
            "/containers/json",
            "/images/json",
            "/runningpods",
            "/stats/summary",
            // ========================================
            // CI/CD CONTROL PLANES
            // ========================================
            "/argo",
            "/argo/api/v1/workflows",
            "/argocd",
            "/argocd/api/v1/applications",
            "/spinnaker",
            "/gate/",
            "/orca/",
            "/deck/",
            "/drone",
            "/drone/api/user",
            "/concourse",
            "/api/v1/info",
            "/teamcity",
            "/teamcity/login.html",
            "/bamboo",
            "/bamboo/admin",
            "/gocd",
            "/go/admin",
            "/tekton",
            "/jenkins/script",
            "/jenkins/manage",
            "/jenkins/asynchPeople/",
            "/jenkins/configure",
            "/jenkins/computer",
            "/jenkins/credentials",
            "/jenkins/jnlpJars/jenkins-cli.jar",
            "/securityRealm/user/admin",
            "/gitea/-/admin",
            "/gitlab/-/admin",
            "/gitlab/users/sign_in",
            "/gitlab/explore",
            "/bitbucket/admin",
            // ========================================
            // ARTIFACT / CONTAINER REGISTRIES
            // ========================================
            "/artifactory",
            "/artifactory/api/system/ping",
            "/artifactory/api/security/users",
            "/nexus",
            "/nexus/service/local/users",
            "/v2/_catalog",
            "/v2/",
            "/harbor",
            "/harbor/api/v2.0/users",
            "/portus",
            // ========================================
            // OBSERVABILITY STACKS
            // ========================================
            "/grafana",
            "/grafana/api/health",
            "/grafana/api/datasources",
            "/grafana/api/admin/users",
            "/grafana/login",
            "/kibana",
            "/kibana/api/status",
            "/kibana/app/kibana",
            "/alertmanager",
            "/alertmanager/api/v2/status",
            "/alertmanager/api/v2/alerts",
            "/prometheus/api/v1/status/config",
            "/prometheus/api/v1/status/flags",
            "/prometheus/api/v1/targets",
            "/prometheus/api/v1/rules",
            "/cortex/",
            "/loki/ready",
            "/tempo/",
            "/jaeger/api/services",
            "/zipkin/",
            "/sentry/api/0/",
            // ========================================
            // SERVICE MESH / API GATEWAY ADMIN
            // ========================================
            "/traefik/",
            "/traefik/dashboard/",
            "/api/rawdata",
            "/api/overview",
            "/kong/status",
            "/kong/",
            "/tyk/apis",
            "/tyk/",
            "/apisix/admin/routes",
            "/apisix/admin/services",
            "/apisix/admin/consumers",
            "/apisix/admin/plugins",
            "/server_info",
            "/config_dump",
            "/clusters",
            "/listeners",
            "/runtime",
            // ========================================
            // STORAGE / DATABASE BROWSERS
            // ========================================
            "/couchdb",
            "/_utils",
            "/_all_dbs",
            "/_membership",
            "/_session",
            "/influxdb/health",
            "/influxdb/api/v2",
            "/_cat",
            "/_cat/indices",
            "/_cluster/health",
            "/_cluster/state",
            "/_cluster/stats",
            "/_nodes",
            "/_search",
            "/_snapshot",
            "/minio/health/live",
            "/minio/health/ready",
            "/minio/login",
            "/minio-console",
            // ========================================
            // MESSAGING / QUEUES UI
            // ========================================
            "/rabbitmq/",
            "/rabbitmq/api/overview",
            "/rabbitmq/api/whoami",
            "/flower/",
            "/flower/api/workers",
            "/kafdrop/",
            "/kafka-manager/",
            "/cmak/",
            "/akhq/",
            "/redis-commander/",
            "/rediscommander/",
            // ========================================
            // DEVOPS UI
            // ========================================
            "/portainer/",
            "/portainer/api/status",
            "/portainer/api/endpoints",
            "/rancher/",
            "/rancher/v3/users",
            "/v3/users",
            "/v1-rancher",
            // ========================================
            // VCS / SOURCE LEAKS (PINPOINT FILES)
            // Each is a specific filename inside a versioned repo. A 200 here
            // is a confirmed source-tree disclosure.
            // ========================================
            "/.git/index",
            "/.git/packed-refs",
            "/.git/logs/HEAD",
            "/.git/logs/refs/heads/main",
            "/.git/logs/refs/heads/master",
            "/.git/refs/heads/main",
            "/.git/refs/heads/master",
            "/.git/info/exclude",
            "/.git/description",
            "/.git/COMMIT_EDITMSG",
            "/.git/ORIG_HEAD",
            "/.git/FETCH_HEAD",
            "/.git/hooks/pre-commit.sample",
            "/.gitlab-ci.yml",
            "/.gitea/",
            "/.svn/wc.db",
            "/.svn/format",
            "/.svn/pristine",
            "/.hg/store/00manifest.i",
            "/.hg/hgrc",
            "/.bzr/branch/branch.conf",
            "/CVS/Root",
            "/CVS/Entries",
            "/.idea/workspace.xml",
            "/.idea/dataSources.xml",
            "/.idea/WebServers.xml",
            "/.vscode/sftp.json",
            "/.vscode/settings.json",
            "/.history/",
            "/.bash_history",
            "/.zsh_history",
            "/.mysql_history",
            "/.psql_history",
            "/.python_history",
            "/.viminfo",
            // ========================================
            // CREDENTIAL / KEY FILES (DIRECT DISCLOSURE)
            // ========================================
            "/.netrc",
            "/.npmrc",
            "/.pypirc",
            "/.dockercfg",
            "/.docker/config.json",
            "/.aws/credentials",
            "/.aws/config",
            "/.kube/config",
            "/.ssh/id_rsa",
            "/.ssh/id_dsa",
            "/.ssh/id_ed25519",
            "/.ssh/id_ecdsa",
            "/.ssh/authorized_keys",
            "/.ssh/known_hosts",
            "/id_rsa",
            "/id_rsa.pub",
            "/id_ed25519",
            "/id_ecdsa",
            "/authorized_keys",
            "/.htpasswd",
            "/.htaccess",
            "/.boto",
            "/.pgpass",
            "/.s3cfg",
            "/.gitconfig",
            "/.terraform/terraform.tfstate",
            "/terraform.tfstate",
            "/terraform.tfstate.backup",
            "/terraform.tfvars",
            "/.terraformrc",
            "/.netlify/state.json",
            "/.firebaserc",
            "/firebase.json",
            "/credentials.json",
            "/service-account.json",
            "/service-account-key.json",
            "/firebase-adminsdk.json",
            "/gcp-credentials.json",
            "/aws-credentials.json",
            "/azure-credentials.json",
            "/oauth-private.key",
            "/private.pem",
            "/private.key",
            "/server.key",
            "/server.pem",
            "/key.pem",
            // ========================================
            // CLOUD / PLATFORM DEPLOY CONFIG
            // ========================================
            "/serverless.yml",
            "/serverless.yaml",
            "/now.json",
            "/vercel.json",
            "/app.yaml",
            "/Procfile",
            "/docker-compose.yml",
            "/docker-compose.yaml",
            "/docker-compose.override.yml",
            "/Dockerfile",
            "/Dockerfile.prod",
            "/Dockerfile.production",
            "/Makefile",
            "/.babelrc",
            "/.editorconfig",
            "/.eslintrc",
            "/.prettierrc",
            // ========================================
            // DOTENV / FRAMEWORK CONFIG LEAKS
            // ========================================
            "/.env.backup",
            "/.env.bak",
            "/.env.old",
            "/.env.staging",
            "/.env.test",
            "/.env.example",
            "/.env.sample",
            "/.env.dist",
            "/.env.dev",
            "/.env.docker",
            "/.env.prod",
            "/env.js",
            "/env.json",
            "/config.php",
            "/config.php.bak",
            "/configuration.php",
            "/wp-config.php.bak",
            "/wp-config.old",
            "/wp-config.php.swp",
            "/wp-config.php.save",
            "/wp-config.php~",
            "/wp-config.php.orig",
            "/sites/default/settings.php",
            "/sites/default/settings.php.bak",
            "/local.xml",
            "/app/etc/local.xml",
            "/app/etc/env.php",
            "/config/database.yml",
            "/config/secrets.yml",
            "/config/master.key",
            "/config/credentials.yml.enc",
            "/storage/oauth-private.key",
            "/storage/oauth-public.key",
            "/storage/logs/laravel.log",
            "/bootstrap/cache/config.php",
            "/instance/config.py",
            "/instance/application.cfg",
            "/settings.py",
            "/local_settings.py",
            // ========================================
            // LOG FILES (DIRECT DISCLOSURE)
            // ========================================
            "/access.log",
            "/access_log",
            "/error.log",
            "/error_log",
            "/app.log",
            "/application.log",
            "/debug.log",
            "/server.log",
            "/system.log",
            "/laravel.log",
            "/django.log",
            "/php_errors.log",
            "/php-fpm.log",
            "/nginx.log",
            "/apache.log",
            "/audit.log",
            "/logs/access.log",
            "/logs/error.log",
            "/logs/app.log",
            "/logs/debug.log",
            "/log/access.log",
            "/log/error.log",
            "/log/production.log",
            "/log/development.log",
            // ========================================
            // BACKUP ARCHIVE PATTERNS (COMMON FILENAMES)
            // ========================================
            "/backup.tar",
            "/backup.tar.gz",
            "/backup.tgz",
            "/backup.tar.bz2",
            "/backup.7z",
            "/backup.rar",
            "/backup.gz",
            "/backup.bz2",
            "/backup.sql.gz",
            "/backup.sql.bz2",
            "/db.sql.gz",
            "/db.tar.gz",
            "/db.zip",
            "/dump.tar.gz",
            "/dump.zip",
            "/website.zip",
            "/website.tar.gz",
            "/site.zip",
            "/site.tar.gz",
            "/www.zip",
            "/www.tar.gz",
            "/public_html.zip",
            "/public_html.tar.gz",
            "/htdocs.zip",
            "/htdocs.tar.gz",
            "/release.zip",
            "/release.tar.gz",
            "/build.zip",
            "/build.tar.gz",
            "/dist.zip",
            "/dist.tar.gz",
            // ========================================
            // CMS / FRAMEWORK SENSITIVE ENDPOINTS
            // ========================================
            "/wp-json/wp/v2/users",
            "/wp-json/wp/v2/users/1",
            "/wp-json/",
            "/xmlrpc.php",
            "/wp-cron.php",
            "/wp-content/debug.log",
            "/wp-content/uploads/wp-config.php",
            "/wp-content/backup-db/",
            "/wp-content/uploads/backup/",
            "/wp-admin/install.php",
            "/wp-admin/setup-config.php",
            "/wp-admin/admin-ajax.php",
            "/readme.html",
            "/license.txt",
            "/CHANGELOG.txt",
            "/INSTALL.txt",
            "/MAINTAINERS.txt",
            "/UPGRADE.txt",
            "/administrator/index.php",
            // ASP.NET
            "/trace.axd",
            "/elmah.axd",
            "/glimpse.axd",
            "/web.config.bak",
            "/web.config.old",
            "/Web.config",
            // ColdFusion
            "/CFIDE/administrator/",
            "/CFIDE/administrator/enter.cfm",
            "/CFIDE/scripts/",
            "/CFIDE/componentutils/",
            // PHP info variations
            "/i.php",
            "/phpinfo.php5",
            "/phpinfo.php7",
            "/p.php",
            "/x.php",
            // Symfony
            "/_profiler",
            "/_profiler/empty/search/results",
            "/_wdt",
            "/_fragment",
            "/app_dev.php",
            "/app/config/parameters.yml",
            // Laravel
            "/_ignition/execute-solution",
            "/telescope/requests",
            "/horizon/dashboard",
            "/horizon/api/stats",
            "/_debugbar",
            // ========================================
            // OPENID / OAUTH / IDENTITY DISCOVERY
            // ========================================
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
            "/.well-known/jwks.json",
            "/.well-known/webfinger",
            "/.well-known/host-meta",
            "/.well-known/host-meta.json",
            "/.well-known/change-password",
            "/.well-known/apple-app-site-association",
            "/apple-app-site-association",
            "/.well-known/assetlinks.json",
            "/.well-known/dnt-policy.txt",
            "/.well-known/matrix/server",
            "/.well-known/matrix/client",
            "/jwks",
            "/jwks.json",
            "/keys",
            // ========================================
            // CLOUD METADATA (REACHABLE VIA SSRF PROXY)
            // ========================================
            "/latest/meta-data/",
            "/latest/meta-data/iam/security-credentials/",
            "/latest/user-data",
            "/latest/dynamic/instance-identity/document",
            "/computeMetadata/v1/",
            "/metadata/instance",
            "/metadata/identity/oauth2/token",
            "/opc/v1/instance/",
            // ========================================
            // SSRF / WEBHOOK PROXIES (DEEPER PATTERNS)
            // ========================================
            "/api/proxy",
            "/api/fetch",
            "/api/url",
            "/api/render",
            "/api/screenshot",
            "/api/pdf",
            "/api/webhook",
            "/api/redirect",
            "/api/forward",
            "/api/import",
            "/api/integration",
            "/api/oembed",
            "/api/preview",
            "/proxy.php",
            "/proxy.aspx",
            "/proxy.jsp",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_categorize_admin_paths() {
        assert_eq!(
            EndpointDiscovery::categorize_path("/admin"),
            EndpointCategory::Admin
        );
        assert_eq!(
            EndpointDiscovery::categorize_path("/hallinta"),
            EndpointCategory::Admin
        );
        assert_eq!(
            EndpointDiscovery::categorize_path("/verwaltung"),
            EndpointCategory::Admin
        );
    }

    #[test]
    fn test_categorize_auth_paths() {
        assert_eq!(
            EndpointDiscovery::categorize_path("/login"),
            EndpointCategory::Authentication
        );
        assert_eq!(
            EndpointDiscovery::categorize_path("/kirjaudu"),
            EndpointCategory::Authentication
        );
        assert_eq!(
            EndpointDiscovery::categorize_path("/anmelden"),
            EndpointCategory::Authentication
        );
        assert_eq!(
            EndpointDiscovery::categorize_path("/connexion"),
            EndpointCategory::Authentication
        );
    }

    #[test]
    fn test_categorize_api_paths() {
        assert_eq!(
            EndpointDiscovery::categorize_path("/api/v1"),
            EndpointCategory::Api
        );
        assert_eq!(
            EndpointDiscovery::categorize_path("/graphql"),
            EndpointCategory::Api
        );
    }

    #[test]
    fn test_wordlist_has_finnish() {
        let wordlist = EndpointDiscovery::get_wordlist();
        assert!(wordlist.contains(&"/kirjaudu"));
        assert!(wordlist.contains(&"/hallinta"));
        assert!(wordlist.contains(&"/rekisteroidy"));
    }

    #[test]
    fn test_categorize_vcs_and_credential_leaks() {
        assert_eq!(
            EndpointDiscovery::categorize_path("/.git/index"),
            EndpointCategory::Config
        );
        assert_eq!(
            EndpointDiscovery::categorize_path("/.ssh/id_rsa"),
            EndpointCategory::Config
        );
        assert_eq!(
            EndpointDiscovery::categorize_path("/.aws/credentials"),
            EndpointCategory::Config
        );
        assert_eq!(
            EndpointDiscovery::categorize_path("/terraform.tfstate"),
            EndpointCategory::Config
        );
        assert_eq!(
            EndpointDiscovery::categorize_path("/wp-config.php.bak"),
            EndpointCategory::Config
        );
    }

    #[test]
    fn test_categorize_debug_disclosure() {
        assert_eq!(
            EndpointDiscovery::categorize_path("/actuator/heapdump"),
            EndpointCategory::Debug
        );
        assert_eq!(
            EndpointDiscovery::categorize_path("/jolokia/list"),
            EndpointCategory::Debug
        );
        assert_eq!(
            EndpointDiscovery::categorize_path("/trace.axd"),
            EndpointCategory::Debug
        );
        assert_eq!(
            EndpointDiscovery::categorize_path("/_ignition/execute-solution"),
            EndpointCategory::Debug
        );
        assert_eq!(
            EndpointDiscovery::categorize_path("/telescope/requests"),
            EndpointCategory::Debug
        );
    }

    #[test]
    fn test_categorize_backup_archives() {
        assert_eq!(
            EndpointDiscovery::categorize_path("/site.tar.gz"),
            EndpointCategory::Backup
        );
        assert_eq!(
            EndpointDiscovery::categorize_path("/dump.zip"),
            EndpointCategory::Backup
        );
        assert_eq!(
            EndpointDiscovery::categorize_path("/index.php~"),
            EndpointCategory::Backup
        );
    }

    #[test]
    fn test_wordlist_has_sensitive_paths() {
        let wordlist = EndpointDiscovery::get_wordlist();
        // Spring Boot
        assert!(wordlist.contains(&"/actuator/loggers"));
        assert!(wordlist.contains(&"/actuator/jolokia"));
        // VCS / credential leaks
        assert!(wordlist.contains(&"/.git/index"));
        assert!(wordlist.contains(&"/.ssh/id_rsa"));
        assert!(wordlist.contains(&"/.aws/credentials"));
        assert!(wordlist.contains(&"/terraform.tfstate"));
        // App server admin
        assert!(wordlist.contains(&"/manager/html"));
        // Observability
        assert!(wordlist.contains(&"/grafana/api/admin/users"));
        // OIDC discovery
        assert!(wordlist.contains(&"/.well-known/openid-configuration"));
    }
}
