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
            // SENSITIVE FILE LEAKS (HIGH IMPACT, LOW FP)
            // ========================================
            // Extended .env variants (production credentials often leak via these)
            "/.env.staging",
            "/.env.stage",
            "/.env.test",
            "/.env.testing",
            "/.env.example",
            "/.env.sample",
            "/.env.backup",
            "/.env.bak",
            "/.env.old",
            "/.env.save",
            "/.env.swp",
            "/.env.swo",
            "/.env~",
            "/.env.dev",
            "/.env.prod",
            "/.env.dist",
            "/.env.default",
            "/.env.live",
            "/env.production",
            "/env.local",
            "/env.staging",
            // Extended .git exposure (full repo reconstruction)
            "/.git/index",
            "/.git/description",
            "/.git/packed-refs",
            "/.git/COMMIT_EDITMSG",
            "/.git/FETCH_HEAD",
            "/.git/ORIG_HEAD",
            "/.git/logs/HEAD",
            "/.git/logs/refs/heads/master",
            "/.git/logs/refs/heads/main",
            "/.git/logs/refs/heads/develop",
            "/.git/refs/heads/master",
            "/.git/refs/heads/main",
            "/.git/refs/heads/develop",
            "/.git/refs/heads/staging",
            "/.git/refs/heads/production",
            "/.git/refs/stash",
            "/.git/refs/remotes/origin/HEAD",
            "/.git/info/exclude",
            "/.git/hooks/pre-commit.sample",
            "/.git/objects/info/packs",
            "/.gitconfig",
            "/.gitmodules",
            "/.gitkeep",
            "/.gitattributes",
            "/.gitlab-ci.yml",
            "/.github/workflows/main.yml",
            "/.github/workflows/deploy.yml",
            "/.github/dependabot.yml",
            "/.circleci/config.yml",
            "/.travis.yml",
            "/.drone.yml",
            "/.azure-pipelines.yml",
            "/azure-pipelines.yml",
            "/bitbucket-pipelines.yml",
            // Source control - SVN/Mercurial/Bazaar/Fossil deep paths
            "/.svn/wc.db",
            "/.svn/pristine",
            "/.svn/format",
            "/.hg/store",
            "/.hg/hgrc",
            "/.hg/branch",
            "/.hg/dirstate",
            "/.bzr/branch-format",
            "/.bzr/checkout",
            "/.bzr/branch/last-revision",
            "/_darcs/inventory",
            "/.fslckout",
            // IDE / Editor leaks (credentials, internal infra)
            "/.vscode/settings.json",
            "/.vscode/launch.json",
            "/.vscode/sftp.json",
            "/.idea/workspace.xml",
            "/.idea/dataSources.xml",
            "/.idea/dataSources.local.xml",
            "/.idea/sshConfigs.xml",
            "/.idea/webServers.xml",
            "/.idea/modules.xml",
            "/.idea/deployment.xml",
            "/.idea/misc.xml",
            "/.idea/.name",
            "/.editorconfig",
            "/.project",
            "/.classpath",
            "/.settings/org.eclipse.jdt.core.prefs",
            "/nbproject/project.properties",
            "/nbproject/private/private.properties",
            // Shell history & local credentials
            "/.bash_history",
            "/.zsh_history",
            "/.sh_history",
            "/.history",
            "/.bashrc",
            "/.bash_profile",
            "/.profile",
            "/.zshrc",
            "/.viminfo",
            "/.lesshst",
            "/.mysql_history",
            "/.psql_history",
            "/.python_history",
            "/.node_repl_history",
            "/.rediscli_history",
            "/.irb_history",
            "/.sqlite_history",
            // Cloud & orchestration secrets
            "/.aws/credentials",
            "/.aws/config",
            "/.boto",
            "/.s3cfg",
            "/.kube/config",
            "/kube/config",
            "/kubeconfig",
            "/.docker/config.json",
            "/.gcloud/credentials.db",
            "/.azure/credentials",
            "/serverless.yml",
            "/serverless.yaml",
            "/.serverless/cloudformation-template-update-stack.json",
            "/firebase.json",
            "/.firebaserc",
            "/cloudbuild.yaml",
            "/cloudbuild.yml",
            "/app.yaml",
            "/Procfile",
            // Terraform state (contains secrets in plain text)
            "/terraform.tfstate",
            "/terraform.tfstate.backup",
            "/.terraform.lock.hcl",
            "/.terraform/terraform.tfstate",
            "/terraform.tfvars",
            "/terraform.tfvars.json",
            // SSH / GPG keys
            "/.ssh/id_rsa",
            "/.ssh/id_dsa",
            "/.ssh/id_ecdsa",
            "/.ssh/id_ed25519",
            "/.ssh/authorized_keys",
            "/.ssh/known_hosts",
            "/.ssh/config",
            "/id_rsa",
            "/id_rsa.pub",
            "/id_ed25519",
            "/server.key",
            "/server.pem",
            "/private.key",
            "/privatekey.pem",
            "/.gnupg/pubring.kbx",
            "/.gnupg/trustdb.gpg",
            // Database / mail / auth password files
            "/.htpasswd",
            "/.htaccess.bak",
            "/.htaccess.old",
            "/.htaccess.orig",
            "/.htaccess~",
            "/.htaccess.save",
            "/htaccess.txt",
            "/.npmrc",
            "/.yarnrc",
            "/.yarnrc.yml",
            "/.pypirc",
            "/.pgpass",
            "/.my.cnf",
            "/.mysql.cnf",
            "/.netrc",
            "/_netrc",
            "/.dockercfg",
            "/.cargo/credentials",
            "/.cargo/credentials.toml",
            // Backup file variants (rsync, vim swap, OS temp)
            "/backup.tar",
            "/backup.tgz",
            "/backup.tar.bz2",
            "/backup.7z",
            "/backup.rar",
            "/site.tar.gz",
            "/site.zip",
            "/www.zip",
            "/www.tar.gz",
            "/htdocs.zip",
            "/htdocs.tar.gz",
            "/public_html.zip",
            "/public_html.tar.gz",
            "/web.zip",
            "/web.tar.gz",
            "/wwwroot.zip",
            "/db.tar.gz",
            "/db.tgz",
            "/db.dump",
            "/dump.tar.gz",
            "/database.dump",
            "/database.tar.gz",
            "/mysql.sql",
            "/mysql.dump",
            "/postgres.dump",
            "/sqldump.sql",
            "/db_backup.sql",
            "/db-backup.sql",
            "/database-backup.sql",
            "/database_backup.sql",
            "/backup.sql.gz",
            "/dump.sql.gz",
            // WordPress credential / config leaks
            "/wp-config.php.bak",
            "/wp-config.php.old",
            "/wp-config.php.save",
            "/wp-config.php.swp",
            "/wp-config.php.swo",
            "/wp-config.php~",
            "/wp-config-sample.php",
            "/wp-config-backup.txt",
            "/wp-config.txt",
            "/wp-config.old",
            "/wp-config.bak",
            "/.wp-config.php.swp",
            "/wp-content/debug.log",
            "/wp-content/wp-cache-config.php",
            "/wp-content/uploads/dump.sql",
            "/wp-content/backup-db",
            "/wp-content/backups",
            "/wp-content/plugins/duplicator/installer.php",
            "/wp-content/plugins/duplicator/installer-backup.php",
            "/installer.php",
            "/install.php",
            "/setup-config.php",
            "/upgrade.php",
            "/xmlrpc.php",
            "/wp-cron.php",
            "/wp-load.php",
            "/wp-trackback.php",
            // Common framework secret / config exposures
            "/config/database.yml",
            "/config/secrets.yml",
            "/config/master.key",
            "/config/credentials.yml.enc",
            "/config/cable.yml",
            "/config/storage.yml",
            "/config/application.yml",
            "/config/application-prod.yml",
            "/config/application-dev.yml",
            "/config/application-staging.yml",
            "/config/secret.yaml",
            "/config/secrets.json",
            "/config/local.json",
            "/config/production.json",
            "/config/default.json",
            "/secrets.json",
            "/secrets.yaml",
            "/secrets.yml",
            "/credentials.json",
            "/credentials.yaml",
            "/credentials.yml",
            "/conf/secrets.yml",
            "/app/etc/local.xml",
            "/app/etc/env.php",
            "/app/etc/config.php",
            // Docker / container files
            "/Dockerfile",
            "/Dockerfile.prod",
            "/Dockerfile.dev",
            "/docker-compose.yml",
            "/docker-compose.yaml",
            "/docker-compose.prod.yml",
            "/docker-compose.dev.yml",
            "/docker-compose.override.yml",
            "/docker-compose.production.yml",
            "/docker-compose.staging.yml",
            "/.dockerignore",
            "/docker-stack.yml",
            "/Vagrantfile",
            // CI / pipeline metadata commonly leaks tokens
            "/.npm/_logs",
            "/.npm-debug.log",
            "/npm-debug.log",
            "/yarn-debug.log",
            "/yarn-error.log",
            "/pnpm-debug.log",
            "/composer.phar",
            "/.composer/auth.json",
            "/auth.json",
            // Source map files (recover original source + path disclosure)
            "/main.js.map",
            "/app.js.map",
            "/bundle.js.map",
            "/vendor.js.map",
            "/runtime.js.map",
            "/polyfills.js.map",
            "/chunk-vendors.js.map",
            "/index.js.map",
            "/main.css.map",
            "/app.css.map",
            "/style.css.map",
            "/styles.css.map",
            "/sourcemaps/main.js.map",
            "/static/js/main.js.map",
            "/static/css/main.css.map",
            "/static/js/bundle.js.map",
            "/dist/main.js.map",
            "/dist/bundle.js.map",
            "/build/static/js/main.js.map",
            "/_next/static/chunks/main.js.map",
            // Spring Boot Actuator RCE / data exposure paths
            "/actuator/loggers",
            "/actuator/scheduledtasks",
            "/actuator/sessions",
            "/actuator/refresh",
            "/actuator/restart",
            "/actuator/jolokia",
            "/actuator/jolokia/list",
            "/actuator/gateway",
            "/actuator/gateway/routes",
            "/actuator/integrationgraph",
            "/actuator/auditevents",
            "/actuator/conditions",
            "/actuator/caches",
            "/actuator/flyway",
            "/actuator/liquibase",
            "/actuator/quartz",
            "/actuator/httptrace",
            "/actuator/shutdown",
            "/actuator/prometheus",
            "/actuator/hystrix.stream",
            "/jolokia",
            "/jolokia/list",
            "/jolokia/read",
            "/heapdump",
            "/heapdump.json",
            "/threaddump",
            "/threaddump.json",
            "/env.json",
            "/mappings.json",
            "/info.json",
            "/beans.json",
            "/trace.json",
            "/conftrue",
            "/configprops",
            // .NET / Java / IIS config exposure
            "/web.config.bak",
            "/web.config.old",
            "/Web.config.bak",
            "/applicationhost.config",
            "/application.properties.bak",
            "/application.properties.old",
            "/application-prod.properties",
            "/application-dev.properties",
            "/application-local.properties",
            "/bootstrap.properties",
            "/log4j.properties",
            "/log4j2.xml",
            "/logback.xml",
            // .well-known endpoints (OIDC/OAuth disclosure)
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
            "/.well-known/openid-federation",
            "/.well-known/jwks.json",
            "/.well-known/webfinger",
            "/.well-known/security.txt",
            "/.well-known/host-meta",
            "/.well-known/assetlinks.json",
            "/.well-known/apple-app-site-association",
            "/apple-app-site-association",
            "/.well-known/change-password",
            "/.well-known/dnt-policy.txt",
            "/.well-known/matrix/client",
            "/.well-known/matrix/server",
            // Server configuration / status disclosure
            "/.htaccess",
            "/.user.ini",
            "/php.ini",
            "/php.ini.bak",
            "/php-fpm.conf",
            "/nginx.conf",
            "/nginx.conf.bak",
            "/sites-enabled/default",
            "/sites-available/default",
            "/httpd.conf",
            "/apache2.conf",
            "/.env-cmdrc",
            "/.cnf",
            "/my.cnf",
            // OS / Mac / Windows metadata
            "/.DS_Store/._.DS_Store",
            "/desktop.ini",
            "/__MACOSX",
            // Flash / Silverlight cross-domain
            "/crossdomain.xml",
            "/clientaccesspolicy.xml",
            // Pip / Python packaging
            "/pip.conf",
            "/.pip/pip.conf",
            "/setup.cfg",
            "/setup.py",
            "/poetry.lock",
            "/pyproject.toml",
            "/Pipfile.lock",
            "/uv.lock",
            "/conda-meta",
            // Node / pnpm / lockfiles often leaked alongside install logs
            "/pnpm-lock.yaml",
            "/.pnp.cjs",
            "/.pnp.loader.mjs",
            // Database admin / introspection
            "/_cat",
            "/_cat/indices",
            "/_cluster/state",
            "/_cluster/health",
            "/_nodes",
            "/_search",
            "/_all/_search",
            "/_xpack",
            "/admin/indices.json",
            "/_admin",
            "/_admin/db",
            "/_utils/",
            "/_session",
            "/api/admin/queries",
            // Gitea / Gitlab / Bitbucket internal endpoints
            "/api/v4/users",
            "/api/v4/projects",
            "/api/v4/version",
            "/api/v3/users",
            "/users/sign_in",
            "/explore/repos",
            "/api/v1/repos/search",
            // GraphQL & REST schema introspection beyond /graphql
            "/api/graphiql",
            "/console",
            "/altair",
            "/voyager",
            "/api/voyager",
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
