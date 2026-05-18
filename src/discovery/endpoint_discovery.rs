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

    /// Categorize path based on keywords
    fn categorize_path(path: &str) -> EndpointCategory {
        let path_lower = path.to_lowercase();

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

        // Backup paths
        if path_lower.contains("backup")
            || path_lower.contains("varmuuskopio")
            || path_lower.contains("bak")
            || path_lower.contains("old")
            || path_lower.contains("copy")
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

        // Database
        if path_lower.contains("phpmyadmin")
            || path_lower.contains("adminer")
            || path_lower.contains("database")
            || path_lower.contains("db")
            || path_lower.contains("sql")
        {
            return EndpointCategory::Database;
        }

        // Monitoring
        if path_lower.contains("health")
            || path_lower.contains("status")
            || path_lower.contains("metrics")
            || path_lower.contains("monitor")
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
            // IaC / DEVOPS CONFIG FILES
            // High-confidence exposure: real credentials when accessible.
            // ========================================
            "/.aws/credentials",
            "/.aws/config",
            "/.azure/credentials",
            "/.azure/accessTokens.json",
            "/.gcloud/credentials.db",
            "/.gcloud/access_tokens.db",
            "/gcloud/application_default_credentials.json",
            "/.kube/config",
            "/kube-config",
            "/kubeconfig",
            "/.docker/config.json",
            "/.dockercfg",
            "/Dockerfile",
            "/docker-compose.yml",
            "/docker-compose.yaml",
            "/docker-compose.override.yml",
            "/docker-compose.prod.yml",
            "/terraform.tfstate",
            "/terraform.tfstate.backup",
            "/.terraform/terraform.tfstate",
            "/.terraform.lock.hcl",
            "/terraform.tfvars",
            "/Pulumi.yaml",
            "/serverless.yml",
            "/cloudbuild.yaml",
            "/buildspec.yml",
            "/appspec.yml",
            "/Procfile",
            "/Chart.yaml",
            "/values.yaml",
            "/skaffold.yaml",
            "/.gitlab-ci.yml",
            "/Jenkinsfile",
            "/jenkinsfile",
            "/.circleci/config.yml",
            "/.travis.yml",
            "/.drone.yml",
            "/.github/workflows/",
            "/.gitea/",
            "/azure-pipelines.yml",
            "/bitbucket-pipelines.yml",
            "/ansible.cfg",
            "/playbook.yml",
            "/inventory.ini",
            "/.npmrc",
            "/.yarnrc",
            "/.yarnrc.yml",
            "/.pypirc",
            "/.netrc",
            "/.htpasswd",
            "/.htaccess",
            "/.dockerignore",
            // ========================================
            // SHELL / TOOL HISTORY & DOTFILES
            // ========================================
            "/.bash_history",
            "/.zsh_history",
            "/.python_history",
            "/.mysql_history",
            "/.psql_history",
            "/.rediscli_history",
            "/.node_repl_history",
            "/.lesshst",
            "/.viminfo",
            "/.bashrc",
            "/.zshrc",
            "/.profile",
            "/.bash_profile",
            // ========================================
            // SSH / PRIVATE KEYS (catastrophic exposure)
            // ========================================
            "/.ssh/id_rsa",
            "/.ssh/id_dsa",
            "/.ssh/id_ecdsa",
            "/.ssh/id_ed25519",
            "/.ssh/authorized_keys",
            "/.ssh/known_hosts",
            "/.ssh/config",
            "/id_rsa",
            "/id_rsa.pub",
            "/server.key",
            "/server.crt",
            "/private.key",
            "/privkey.pem",
            "/cert.pem",
            // ========================================
            // SENSITIVE BACKUP VARIANTS
            // .bak / .old / ~ / .swp / .save on known config files
            // ========================================
            "/.env.bak",
            "/.env.old",
            "/.env~",
            "/.env.swp",
            "/.env.save",
            "/.env.backup",
            "/.env.prod",
            "/.env.staging",
            "/.env.test",
            "/.env.dist",
            "/.env.example",
            "/.env.sample",
            "/env.bak",
            "/env.backup",
            "/wp-config.php.bak",
            "/wp-config.php.old",
            "/wp-config.php~",
            "/wp-config.php.swp",
            "/wp-config.php.save",
            "/wp-config.php.txt",
            "/wp-config.bak",
            "/wp-config.old",
            "/wp-config-sample.php",
            "/config.php.bak",
            "/config.php.old",
            "/config.php~",
            "/config.php.swp",
            "/config.inc.php.bak",
            "/configuration.php.bak",
            "/configuration.php.old",
            "/database.yml.bak",
            "/secrets.yml.bak",
            "/settings.py.bak",
            "/local_settings.py",
            "/web.config.bak",
            "/web.config.old",
            "/application.properties.bak",
            "/application.yml.bak",
            "/credentials.bak",
            "/credentials.old",
            "/.env.json",
            // ========================================
            // DATABASE DUMPS (additional formats)
            // ========================================
            "/database.sql.gz",
            "/database.sql.bz2",
            "/database.sql.zip",
            "/db.dump",
            "/dump.gz",
            "/backup.sql.gz",
            "/backup.tar",
            "/backup.tgz",
            "/site.sql",
            "/users.sql",
            "/wordpress.sql",
            "/wp.sql",
            "/full_backup.sql",
            // ========================================
            // SPRING BOOT ACTUATOR (v2+)
            // ========================================
            "/actuator/loggers",
            "/actuator/scheduledtasks",
            "/actuator/auditevents",
            "/actuator/sessions",
            "/actuator/caches",
            "/actuator/conditions",
            "/actuator/refresh",
            "/actuator/restart",
            "/actuator/shutdown",
            "/actuator/pause",
            "/actuator/gateway/routes",
            "/actuator/gateway/refresh",
            "/actuator/httptrace",
            "/actuator/liquibase",
            "/actuator/flyway",
            "/actuator/integrationgraph",
            "/actuator/quartz",
            "/actuator/jolokia/",
            "/actuator/jolokia/list",
            "/management/health",
            "/management/env",
            "/management/configprops",
            "/management/info",
            "/management/metrics",
            "/management/beans",
            "/management/jolokia/list",
            "/jolokia/",
            "/jolokia/list",
            "/jolokia/version",
            "/jolokia/read/java.lang:type=Memory",
            // ========================================
            // JEE / SERVLET / APP SERVER LEAKS
            // ========================================
            "/WEB-INF/web.xml",
            "/WEB-INF/classes/",
            "/WEB-INF/lib/",
            "/WEB-INF/applicationContext.xml",
            "/META-INF/MANIFEST.MF",
            "/META-INF/context.xml",
            "/jmx-console/",
            "/jmx-console/HtmlAdaptor",
            "/web-console/",
            "/web-console/ServerInfo.jsp",
            "/invoker/JMXInvokerServlet",
            "/invoker/EJBInvokerServlet",
            "/manager/html",
            "/manager/status",
            "/manager/jmxproxy",
            "/manager/text/list",
            "/host-manager/html",
            "/console/",
            "/console/login/LoginForm.jsp",
            // ========================================
            // HASHICORP STACK (Vault / Consul / Nomad)
            // ========================================
            "/v1/sys/health",
            "/v1/sys/seal-status",
            "/v1/sys/init",
            "/v1/sys/leader",
            "/v1/sys/mounts",
            "/v1/sys/auth",
            "/v1/sys/policies",
            "/v1/sys/license/status",
            "/ui/vault/",
            "/v1/catalog/services",
            "/v1/catalog/nodes",
            "/v1/catalog/datacenters",
            "/v1/agent/self",
            "/v1/agent/checks",
            "/v1/agent/services",
            "/v1/status/leader",
            "/v1/status/peers",
            "/v1/acl/tokens",
            "/v1/kv/?recurse",
            "/ui/consul/",
            "/v1/jobs",
            "/v1/nodes",
            "/v1/agent/health",
            "/v1/agent/members",
            "/v1/operator/raft/configuration",
            // ========================================
            // ELASTICSEARCH / OPENSEARCH / SOLR
            // ========================================
            "/_cat/indices",
            "/_cat/indices?v",
            "/_cat/aliases",
            "/_cat/health",
            "/_cat/nodes",
            "/_cat/master",
            "/_cluster/health",
            "/_cluster/state",
            "/_cluster/stats",
            "/_cluster/settings",
            "/_nodes",
            "/_nodes/_all",
            "/_nodes/stats",
            "/_search",
            "/_all/_search",
            "/_security/user",
            "/_xpack",
            "/_snapshot",
            "/_template",
            "/solr/admin/",
            "/solr/admin/cores",
            "/solr/admin/info/system",
            "/solr/admin/configs",
            "/solr/admin/zookeeper",
            // ========================================
            // CONTAINER / ORCHESTRATOR APIs
            // ========================================
            "/api/v1/namespaces",
            "/api/v1/pods",
            "/api/v1/secrets",
            "/api/v1/nodes",
            "/api/v1/services",
            "/api/v1/configmaps",
            "/apis/apps/v1/deployments",
            "/version",
            "/openapi/v2",
            "/healthz",
            "/livez",
            "/readyz",
            "/varz",
            // ========================================
            // OBSERVABILITY / MONITORING (admin endpoints)
            // ========================================
            "/grafana/api/admin/users",
            "/grafana/api/datasources",
            "/grafana/api/org",
            "/grafana/login",
            "/grafana/public/img/grafana_icon.svg",
            "/kibana/api/status",
            "/kibana/api/saved_objects/_find?type=dashboard",
            "/api/console/proxy",
            "/api/saved_objects/_find",
            "/jaeger/",
            "/jaeger/api/services",
            "/zipkin/",
            "/zipkin/api/v2/services",
            "/prometheus/api/v1/status/config",
            "/prometheus/api/v1/status/flags",
            "/prometheus/api/v1/targets",
            "/prometheus/api/v1/rules",
            "/prometheus/api/v1/alerts",
            "/-/healthy",
            "/-/ready",
            "/-/reload",
            "/-/quitquitquit",
            "/loki/api/v1/labels",
            "/loki/api/v1/query",
            "/tempo/api/search",
            "/sentry/api/0/projects/",
            "/sentry/auth/login/",
            // ========================================
            // REVERSE PROXY / LB ADMIN
            // ========================================
            "/traefik/",
            "/traefik/dashboard/",
            "/api/rawdata",
            "/api/version",
            "/api/providers",
            "/api/http/routers",
            "/api/http/services",
            "/api/http/middlewares",
            "/haproxy?stats",
            "/haproxy_stats",
            "/haproxy-status",
            "/nginx_status",
            "/nginx-status",
            "/varnish/admin",
            "/envoy/stats",
            "/envoy/config_dump",
            "/envoy/clusters",
            "/envoy/listeners",
            "/envoy/server_info",
            "/envoy/ready",
            "/-/stats",
            // ========================================
            // VPN / NETWORK APPLIANCE LOGIN PAGES
            // (corporate attack surface, often CVE-prone)
            // ========================================
            "/vpn/index.html",
            "/vpn/tmindex.html",
            "/vpn/portal.html",
            "/citrix/StoreWeb/",
            "/Citrix/StoreWeb/",
            "/dana-na/auth/url_default/welcome.cgi",
            "/dana-cached/sc/sc.exe",
            "/dana-ws/namedusers",
            "/remote/login",
            "/remote/logincheck",
            "/remote/info",
            "/sslvpn/",
            "/sslvpn/Login/Login",
            "/+CSCOE+/logon.html",
            "/+CSCOU+/csco_logo.gif",
            "/global-protect/login.esp",
            "/global-protect/getconfig.esp",
            "/my.policy",
            "/tmui/login.jsp",
            "/mgmt/tm/util/bash",
            "/cgi-bin/welcome",
            "/level/15/exec/-/show/running-config",
            "/cgi-bin/luci/",
            "/luci",
            // ========================================
            // ATLASSIAN / JIRA / CONFLUENCE
            // ========================================
            "/rest/api/2/serverInfo",
            "/rest/api/latest/serverInfo",
            "/rest/api/2/dashboard",
            "/rest/api/2/myself",
            "/rest/applinks/1.0/listApplicationlinks",
            "/plugins/servlet/oauth/users/icon-uri",
            "/plugins/servlet/upm/requests",
            "/setup/setupadministrator.action",
            "/secure/AddPermission!default.jspa",
            "/s/cfx/_/;/WEB-INF/web.xml",
            // ========================================
            // MICROSOFT EXCHANGE / SHAREPOINT / OWA
            // ========================================
            "/owa/",
            "/owa/auth/logon.aspx",
            "/ecp/",
            "/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application",
            "/ews/exchange.asmx",
            "/autodiscover/autodiscover.xml",
            "/autodiscover/autodiscover.json",
            "/oab/",
            "/rpc/rpcproxy.dll",
            "/aspnet_client/",
            "/_layouts/15/",
            "/_layouts/15/start.aspx",
            "/_vti_bin/",
            "/_vti_bin/listdata.svc",
            "/_api/web/lists",
            // ========================================
            // OAUTH / OIDC / SAML DISCOVERY
            // ========================================
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
            "/.well-known/security.txt",
            "/.well-known/jwks.json",
            "/.well-known/assetlinks.json",
            "/.well-known/apple-app-site-association",
            "/.well-known/change-password",
            "/jwks.json",
            "/jwks",
            "/oauth/jwks",
            "/oauth2/jwks",
            "/auth/realms/master",
            "/auth/realms/master/.well-known/openid-configuration",
            "/realms/master",
            "/realms/master/protocol/openid-connect/certs",
            "/openam/",
            "/openam/json/realms/root/serverinfo/*",
            "/sso/",
            "/cas/login",
            "/cas/services",
            "/oxauth/.well-known/openid-configuration",
            "/idp/profile/SAML2/POST/SSO",
            "/idp/shibboleth",
            "/Shibboleth.sso/Metadata",
            "/saml/metadata",
            "/saml2/metadata",
            // ========================================
            // CI/CD ADMIN (additional)
            // ========================================
            "/jenkins/asynchPeople/",
            "/jenkins/people/",
            "/jenkins/computer/",
            "/jenkins/manage",
            "/jenkins/credentials/",
            "/jenkins/configureSecurity/",
            "/teamcity/",
            "/teamcity/admin/admin.html",
            "/teamcity/login.html",
            "/sonarqube/api/system/info",
            "/sonarqube/api/system/status",
            "/sonar/api/system/info",
            "/argo/api/v1/",
            "/argo/api/v1/applications",
            "/argocd/",
            "/argocd/api/v1/applications",
            "/spinnaker/",
            "/gocd/",
            "/gocd/go/admin/",
            "/woodpecker/",
            "/concourse/api/v1/info",
            // ========================================
            // DATABASE ADMIN GUIs (additional)
            // ========================================
            "/cloudbeaver",
            "/cloudbeaver/api",
            "/dbgate",
            "/sqlpad",
            "/sqlpad/login",
            "/clickhouse/play",
            "/play",
            "/?query=SHOW+DATABASES",
            "/superset/",
            "/superset/login/",
            "/superset/sqllab/",
            "/superset/dashboard/list/",
            "/metabase/",
            "/metabase/api/session",
            "/metabase/api/setup",
            "/redash/",
            "/redash/login",
            "/redash/api/data_sources",
            "/influxdb/",
            "/chronograf",
            "/chronograf/v1/sources",
            "/couchdb/_all_dbs",
            "/couchdb/_utils/",
            "/_utils/",
            "/_all_dbs",
            // ========================================
            // BIG DATA / NOTEBOOK
            // ========================================
            "/airflow/",
            "/airflow/admin/",
            "/airflow/api/v1/dags",
            "/airflow/login/",
            "/spark/",
            "/spark/jobs/",
            "/master/",
            "/master/jobs",
            "/hadoop/",
            "/cluster/",
            "/cluster/apps",
            "/ws/v1/cluster/apps",
            "/resourcemanager/",
            "/jupyter/",
            "/jupyter/tree",
            "/jupyter/api/sessions",
            "/notebook/tree",
            "/notebooks/",
            "/zeppelin/",
            "/zeppelin/api/notebook",
            "/flink/",
            "/flink/jobs",
            "/flink/overview",
            // ========================================
            // MESSAGE BROKERS / QUEUES
            // ========================================
            "/rabbitmq/",
            "/rabbitmq/api/overview",
            "/rabbitmq/api/connections",
            "/rabbitmq/api/queues",
            "/api/overview",
            "/api/connections",
            "/api/queues",
            "/api/vhosts",
            "/kafka-rest/",
            "/kafka-manager/",
            "/cmak/",
            "/akhq/",
            "/nats/varz",
            "/nats/connz",
            // ========================================
            // CONTAINER MANAGEMENT
            // ========================================
            "/portainer",
            "/portainer/api/",
            "/portainer/api/endpoints",
            "/portainer/api/status",
            "/rancher/",
            "/rancher/v3/",
            "/v3/settings",
            "/harbor/",
            "/harbor/api/v2.0/users",
            "/registry/v2/_catalog",
            "/v2/_catalog",
            "/v2/_catalog?n=1000",
            // ========================================
            // MAIL SERVER ADMIN
            // ========================================
            "/roundcube/",
            "/webmail/",
            "/mail/",
            "/squirrelmail/",
            "/mailcow/",
            "/zimbra/",
            "/zimbraAdmin/",
            "/iredmail/",
            "/iredadmin/",
            "/postfixadmin/",
            "/horde/",
            "/horde/login.php",
            "/SOGo/",
            "/SOGo/so/",
            // ========================================
            // MODERN FRAMEWORK ARTIFACTS
            // ========================================
            "/_next/data/",
            "/_next/image",
            "/_next/static/development/_buildManifest.js",
            "/_next/static/chunks/webpack.js",
            "/__nuxt/",
            "/_nuxt/",
            "/_nuxt/manifest.json",
            "/_astro/",
            "/.svelte-kit/",
            "/_app/version.json",
            "/_remix/",
            "/build/_assets/",
            "/_vercel/insights/",
            "/_vercel/speed-insights/",
            "/_vercel/",
            "/__/firebase/init.json",
            "/__/auth/handler",
            // ========================================
            // CRITICAL APP-SERVER CONSOLES
            // ========================================
            "/struts2-rest-showcase/",
            "/wls-wsat/",
            "/wls-wsat/CoordinatorPortType",
            "/_async/AsyncResponseService",
            "/jdbc/",
            "/jpa/",
            "/clientaccesspolicy.xml",
            "/crossdomain.xml",
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
}
