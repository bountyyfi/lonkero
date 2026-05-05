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
            // SECRETS & ORCHESTRATION CONTROL PLANES
            // (high-impact, low false-positive — these paths only respond
            //  meaningfully when the actual product is running)
            // ========================================
            // HashiCorp Vault — unauth endpoints leak seal-status / mount info.
            "/v1/sys/health",
            "/v1/sys/seal-status",
            "/v1/sys/init",
            "/v1/sys/leader",
            "/v1/sys/mounts",
            "/v1/sys/auth",
            "/v1/sys/policies",
            "/v1/sys/policies/acl",
            "/v1/sys/internal/ui/mounts",
            "/ui/vault/auth",
            // HashiCorp Consul — KV / ACL / agent self leak full topology + secrets.
            "/v1/agent/self",
            "/v1/agent/checks",
            "/v1/agent/services",
            "/v1/catalog/services",
            "/v1/catalog/datacenters",
            "/v1/kv/?recurse",
            "/v1/kv/?keys",
            "/v1/acl/list",
            "/v1/acl/tokens",
            // HashiCorp Nomad — job + alloc enumeration.
            "/v1/jobs",
            "/v1/nodes",
            "/v1/agent/members",
            "/v1/acl/policies",
            // etcd v2 / v3 — full datastore dump if unauthenticated.
            "/v2/keys/?recursive=true",
            "/v2/stats/self",
            "/v2/members",
            "/v3/kv/range",
            "/version",
            // Kubernetes API server — anonymous-allowed endpoints.
            "/api",
            "/apis",
            "/openapi/v2",
            "/openapi/v3",
            "/healthz",
            "/livez",
            "/readyz",
            "/metrics",
            "/api/v1/namespaces",
            "/api/v1/pods",
            "/api/v1/secrets",
            "/api/v1/configmaps",
            "/api/v1/serviceaccounts",
            "/api/v1/nodes",
            "/apis/apps/v1/deployments",
            // Kubelet (when proxied or directly exposed).
            "/pods",
            "/runningpods",
            "/stats/summary",
            "/spec",
            "/configz",
            // Docker Engine API — unauth = full host RCE.
            "/_ping",
            "/info",
            "/version",
            "/containers/json",
            "/images/json",
            "/networks",
            "/volumes",
            "/v1.41/info",
            "/v1.41/containers/json",
            "/v1.41/images/json",
            // Portainer / Rancher.
            "/api/system/status",
            "/api/users/admin/check",
            "/api/endpoints",
            "/api/stacks",
            "/v3/clusters",
            "/v3/projects",
            "/v3/users",
            // ========================================
            // OBSERVABILITY / DEVOPS DASHBOARDS
            // ========================================
            // Prometheus / Alertmanager — config + targets reveal infra.
            "/-/healthy",
            "/-/ready",
            "/-/reload",
            "/-/quit",
            "/api/v1/targets",
            "/api/v1/status/config",
            "/api/v1/status/runtimeinfo",
            "/api/v1/status/buildinfo",
            "/api/v1/status/flags",
            "/api/v1/alerts",
            "/api/v1/rules",
            "/federate",
            "/graph",
            // Grafana — admin settings + datasource creds.
            "/api/health",
            "/api/admin/settings",
            "/api/admin/stats",
            "/api/datasources",
            "/api/org",
            "/api/orgs",
            "/api/users",
            "/login/generic_oauth",
            "/render/d-solo",
            // Kibana / Elasticsearch — index dumps and saved objects.
            "/api/status",
            "/api/spaces/space",
            "/api/saved_objects/_find",
            "/_cat/indices",
            "/_cat/indices?v",
            "/_cat/health",
            "/_cat/nodes",
            "/_cat/aliases",
            "/_cat/templates",
            "/_cluster/health",
            "/_cluster/stats",
            "/_cluster/state",
            "/_nodes",
            "/_nodes/stats",
            "/_search",
            "/.kibana/_search",
            "/_security/user",
            "/_xpack",
            // Jenkins — script console = unauth RCE if allowed.
            "/script",
            "/manage",
            "/asynchPeople/",
            "/people/",
            "/computer/",
            "/userContent/",
            "/jenkins/script",
            "/jenkins/manage",
            // GitLab metrics + CI.
            "/api/v4/version",
            "/api/v4/projects",
            "/api/v4/runners",
            "/-/metrics",
            "/-/health",
            "/-/readiness",
            "/-/liveness",
            "/admin",
            "/admin/runners",
            // Argo CD / Argo Workflows.
            "/api/v1/applications",
            "/api/v1/projects",
            "/api/v1/clusters",
            "/api/v1/workflows",
            "/api/v1/info",
            // Spinnaker / Octant / Harness.
            "/health",
            "/info",
            "/env",
            // Tableau / Looker / Metabase admin endpoints.
            "/api/health",
            "/api/setup",
            "/api/session/properties",
            "/api/setting",
            "/api/permissions/group",
            "/api/database",
            // ========================================
            // SOURCE-CODE LEAK ARTIFACTS
            // (deterministic file paths — a 200 with the expected magic bytes
            //  is conclusive)
            // ========================================
            "/.git/HEAD",
            "/.git/config",
            "/.git/index",
            "/.git/packed-refs",
            "/.git/logs/HEAD",
            "/.git/refs/heads/main",
            "/.git/refs/heads/master",
            "/.git/refs/heads/develop",
            "/.git/description",
            "/.git/info/exclude",
            "/.git/COMMIT_EDITMSG",
            "/.git/ORIG_HEAD",
            "/.gitconfig",
            "/.gitlab-ci.yml",
            "/.gitea/issue_template",
            "/.svn/wc.db",
            "/.svn/entries",
            "/.svn/format",
            "/.svn/pristine",
            "/.hg/hgrc",
            "/.hg/store",
            "/.hg/dirstate",
            "/.bzr/branch/branch.conf",
            // CI/CD definitions on disk
            "/.travis.yml",
            "/.circleci/config.yml",
            "/.drone.yml",
            "/.gitlab-ci.yaml",
            "/azure-pipelines.yml",
            "/bitbucket-pipelines.yml",
            "/.github/workflows/",
            "/.github/dependabot.yml",
            "/.github/codeql/codeql-config.yml",
            "/Jenkinsfile",
            "/buildspec.yml",
            "/buildspec.yaml",
            // ========================================
            // DOTFILES & APP-LOCAL SECRETS
            // ========================================
            // Cloud SDK creds left in webroot.
            "/.aws/credentials",
            "/.aws/config",
            "/.azure/credentials",
            "/.gcloud/credentials.db",
            "/.gcloud/access_tokens.db",
            "/.config/gcloud/credentials.db",
            "/.config/doctl/config.yaml",
            "/.config/hub",
            "/.config/openai",
            "/.config/anthropic",
            // SSH keys.
            "/.ssh/id_rsa",
            "/.ssh/id_dsa",
            "/.ssh/id_ecdsa",
            "/.ssh/id_ed25519",
            "/.ssh/id_xmss",
            "/.ssh/known_hosts",
            "/.ssh/authorized_keys",
            "/.ssh/config",
            // GPG / age / sops.
            "/.gnupg/pubring.kbx",
            "/.gnupg/private-keys-v1.d/",
            "/.sops.yaml",
            "/.age.key",
            // Editor / IDE leaks (database connection metadata is the killer).
            "/.vscode/settings.json",
            "/.vscode/sftp.json",
            "/.idea/workspace.xml",
            "/.idea/dataSources.xml",
            "/.idea/dataSources.local.xml",
            "/.idea/WebServers.xml",
            "/.idea/deployment.xml",
            "/nbproject/private/private.properties",
            "/.project",
            "/.classpath",
            // Vim swap files (often contain partial source / creds).
            "/.config.swp",
            "/.config.swo",
            "/.env.swp",
            "/.htaccess.swp",
            "/.bash_history",
            "/.zsh_history",
            "/.python_history",
            "/.lesshst",
            "/.viminfo",
            "/.netrc",
            "/.pgpass",
            "/.my.cnf",
            "/.mysql_history",
            "/.psql_history",
            "/.rediscli_history",
            "/.sqlite_history",
            // Package manager auth files.
            "/.npmrc",
            "/.yarnrc",
            "/.yarnrc.yml",
            "/.pypirc",
            "/.gem/credentials",
            "/.cargo/credentials",
            "/.cargo/credentials.toml",
            "/.composer/auth.json",
            "/auth.json",
            "/.docker/config.json",
            "/.dockercfg",
            "/.kube/config",
            "/.helm/repository/repositories.yaml",
            "/.m2/settings.xml",
            "/.m2/settings-security.xml",
            "/.gradle/gradle.properties",
            "/.netrc.gpg",
            // Ansible / Chef / Puppet / Salt artifacts.
            "/ansible.cfg",
            "/.vault_pass",
            "/.vault_pass.txt",
            "/group_vars/all.yml",
            "/group_vars/vault.yml",
            "/host_vars/",
            "/.chef/knife.rb",
            "/.chef/credentials",
            "/inventory.ini",
            "/hosts.ini",
            // Terraform / IaC state — full infra blueprint with creds.
            "/terraform.tfstate",
            "/terraform.tfstate.backup",
            "/.terraform/terraform.tfstate",
            "/terraform.tfvars",
            "/terraform.tfvars.json",
            "/.terraformrc",
            "/.tflint.hcl",
            "/cdk.out/",
            "/serverless.yml",
            "/serverless.yaml",
            "/sam.yaml",
            "/sam.yml",
            "/template.yaml",
            "/cloudformation.yaml",
            // Container manifests.
            "/Dockerfile",
            "/Dockerfile.prod",
            "/Dockerfile.dev",
            "/.dockerignore",
            "/docker-compose.yml",
            "/docker-compose.yaml",
            "/docker-compose.override.yml",
            "/docker-compose.prod.yml",
            "/docker-compose.dev.yml",
            "/docker-stack.yml",
            "/podman-compose.yml",
            // Env files (every flavour seen in the wild).
            "/.env",
            "/.env.local",
            "/.env.development",
            "/.env.development.local",
            "/.env.dev",
            "/.env.production",
            "/.env.production.local",
            "/.env.prod",
            "/.env.staging",
            "/.env.stage",
            "/.env.test",
            "/.env.testing",
            "/.env.qa",
            "/.env.uat",
            "/.env.preview",
            "/.env.example",
            "/.env.sample",
            "/.env.backup",
            "/.env.bak",
            "/.env.old",
            "/.env.save",
            "/.env.swp",
            "/.env.original",
            "/env.js",
            "/env.json",
            "/environment.json",
            "/runtime-config.json",
            // Application configuration commonly checked into webroot.
            "/config.json",
            "/config.prod.json",
            "/config.production.json",
            "/config.dev.json",
            "/config.local.json",
            "/config.yml",
            "/config.yaml",
            "/secrets.json",
            "/secrets.yml",
            "/secrets.yaml",
            "/credentials.json",
            "/credentials.yml",
            "/private.json",
            "/private.yml",
            "/appsettings.json",
            "/appsettings.Development.json",
            "/appsettings.Production.json",
            "/appsettings.Local.json",
            "/web.config.bak",
            "/connectionstrings.config",
            "/applicationhost.config",
            "/parameters.yml",
            "/parameters.yaml",
            "/local.settings.json",
            // ========================================
            // BACKUP / DUMP FILE NAMES
            // (target serves these directly when left in webroot)
            // ========================================
            "/backup.tar",
            "/backup.tgz",
            "/backup.tar.bz2",
            "/backup.7z",
            "/backup.rar",
            "/site.tar.gz",
            "/site.zip",
            "/site-backup.zip",
            "/website.zip",
            "/www.zip",
            "/www.tar.gz",
            "/web.zip",
            "/wwwroot.zip",
            "/htdocs.zip",
            "/public_html.zip",
            "/source.zip",
            "/source.tar.gz",
            "/src.zip",
            "/code.zip",
            "/release.zip",
            "/prod.zip",
            "/staging.zip",
            "/db_backup.sql",
            "/db_backup.sql.gz",
            "/database.sql.gz",
            "/dump.sql.gz",
            "/dump.sql.bz2",
            "/mysqldump.sql",
            "/pg_dump.sql",
            "/prod.sql",
            "/production.sql",
            "/staging.sql",
            "/users.sql",
            "/users.csv",
            "/customers.csv",
            "/sitemap.xml.gz",
            "/wp-config.bak",
            "/wp-config.php.bak",
            "/wp-config.old",
            "/wp-config.php~",
            "/wp-config.php.swp",
            "/wp-content/debug.log",
            "/wp-content/uploads/wp-config.php.bak",
            "/configuration.php.bak",
            "/configuration.php.old",
            // ========================================
            // CLOUD METADATA (SSRF target list — useful when target proxies)
            // ========================================
            "/latest/meta-data/",
            "/latest/meta-data/iam/security-credentials/",
            "/latest/user-data",
            "/latest/dynamic/instance-identity/document",
            "/computeMetadata/v1/",
            "/computeMetadata/v1/instance/service-accounts/default/token",
            "/computeMetadata/v1/instance/service-accounts/default/identity",
            "/metadata/identity/oauth2/token",
            "/metadata/instance",
            "/metadata/v1/",
            "/openstack/latest/meta_data.json",
            // ========================================
            // SPRING BOOT ACTUATOR (every modern endpoint, /env + /heapdump =
            // creds in clear text)
            // ========================================
            "/actuator",
            "/actuator/auditevents",
            "/actuator/beans",
            "/actuator/caches",
            "/actuator/conditions",
            "/actuator/configprops",
            "/actuator/env",
            "/actuator/flyway",
            "/actuator/health",
            "/actuator/heapdump",
            "/actuator/httptrace",
            "/actuator/info",
            "/actuator/integrationgraph",
            "/actuator/jolokia",
            "/actuator/liquibase",
            "/actuator/logfile",
            "/actuator/loggers",
            "/actuator/mappings",
            "/actuator/metrics",
            "/actuator/prometheus",
            "/actuator/quartz",
            "/actuator/refresh",
            "/actuator/scheduledtasks",
            "/actuator/sessions",
            "/actuator/shutdown",
            "/actuator/threaddump",
            "/actuator/gateway/routes",
            "/actuator/gateway/globalfilters",
            // Legacy (Spring Boot 1.x) — same data, different prefix.
            "/auditevents",
            "/autoconfig",
            "/beans",
            "/configprops",
            "/dump",
            "/env",
            "/flyway",
            "/heapdump",
            "/info",
            "/loggers",
            "/mappings",
            "/metrics",
            "/refresh",
            "/threaddump",
            "/trace",
            // Spring Cloud Config server.
            "/encrypt",
            "/decrypt",
            "/bus-refresh",
            "/bus-env",
            // ========================================
            // SECURITY-RELEVANT WELL-KNOWN URIS
            // ========================================
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
            "/.well-known/jwks.json",
            "/.well-known/webfinger",
            "/.well-known/host-meta",
            "/.well-known/host-meta.json",
            "/.well-known/assetlinks.json",
            "/.well-known/apple-app-site-association",
            "/.well-known/change-password",
            "/.well-known/dnt-policy.txt",
            "/.well-known/matrix/client",
            "/.well-known/matrix/server",
            "/.well-known/nodeinfo",
            "/.well-known/saml/metadata",
            // ========================================
            // PHPMYADMIN / DBA TOOL VARIANTS
            // ========================================
            "/_phpMyAdmin",
            "/phpMyAdmin",
            "/PMA",
            "/phpmyadmin2",
            "/mysqlmanager",
            "/myadmin",
            "/sqlmanager",
            "/sqlweb",
            "/websql",
            "/dbweb",
            "/db/phpmyadmin",
            "/sql/phpmyadmin",
            "/admin/phpmyadmin",
            "/forum/phpmyadmin",
            "/typo3/phpmyadmin",
            "/phppgadmin",
            "/redis-commander",
            "/rediscommander",
            "/mongoexpress",
            "/mongo-express",
            "/elasticvue",
            "/elasticHQ",
            "/cerebro",
            // ========================================
            // FRAMEWORK DEBUG / DEVELOPMENT CONSOLES
            // (RCE-grade if reachable in production)
            // ========================================
            // Symfony.
            "/_profiler",
            "/_profiler/phpinfo",
            "/_profiler/empty/search/results",
            "/_profiler/open?file=",
            "/_wdt",
            "/app_dev.php",
            "/app_dev.php/_profiler",
            "/config.php",
            "/index.php?_profiler=1",
            // Laravel.
            "/_ignition/health-check",
            "/_ignition/execute-solution",
            "/_debugbar",
            "/_debugbar/open",
            "/telescope",
            "/telescope/requests",
            "/horizon",
            "/horizon/api/stats",
            "/log-viewer",
            "/laravel-websockets",
            "/livewire/livewire.js",
            // Django.
            "/__debug__/",
            "/__debug__/render_panel/",
            "/django-rq/",
            "/silk/",
            "/admin/login/?next=/admin/",
            // Flask.
            "/console",
            "/debugger",
            // Rails.
            "/rails/info",
            "/rails/info/properties",
            "/rails/info/routes",
            "/rails/conductor",
            "/rails/db",
            "/rails/mailers",
            "/letter_opener",
            "/sidekiq",
            "/sidekiq/dashboard",
            "/resque",
            "/que",
            "/good_job",
            "/_carrierwave",
            // ASP.NET.
            "/elmah.axd",
            "/trace.axd",
            "/sitefinity/sign-in",
            "/Telerik.Web.UI.WebResource.axd",
            "/Telerik.Web.UI.DialogHandler.aspx",
            "/api/_signalr/hubs",
            "/_vti_pvt/service.cnf",
            "/_vti_inf.html",
            // Node.js / Express.
            "/__webpack_hmr",
            "/sockjs-node/info",
            "/__nextjs_original-stack-frame",
            "/_next/data/",
            "/_next/server/",
            "/_remix/manifest",
            "/_remix-debug",
            // ========================================
            // QUEUE / MESSAGE BROKER ADMIN
            // ========================================
            "/api/queues",
            "/api/exchanges",
            "/api/connections",
            "/api/whoami",
            "/rabbitmq/api/whoami",
            "/rabbitmq/api/overview",
            "/hawtio",
            "/hawtio/auth/login",
            "/jolokia",
            "/jolokia/list",
            "/console/login.do",
            "/admin/console",
            // Kafka REST proxy / Schema Registry.
            "/topics",
            "/subjects",
            "/schemas",
            "/v3/clusters",
            // ========================================
            // SECRET MANAGERS / KMS WEB UIS
            // ========================================
            "/secretmanager",
            "/secrets-manager",
            "/secrets-engine",
            "/akeyless",
            "/cyberark",
            "/passbolt",
            "/bitwarden",
            "/vaultwarden",
            "/keycloak",
            "/auth/realms/master",
            "/auth/admin/master/console",
            "/auth/admin/realms",
            // ========================================
            // SUPPLY-CHAIN / REGISTRY UIS
            // ========================================
            "/v2/_catalog",
            "/v2/",
            "/api/repository",
            "/artifactory/api/repositories",
            "/artifactory/api/system/ping",
            "/nexus",
            "/nexus/service/local/status",
            "/repository",
            "/registry/v2/_catalog",
            "/harbor/api/v2.0/health",
            "/harbor/sign-in",
            "/sonatype-nexus",
            // ========================================
            // FILE STORAGE BUCKETS / OBJECT BROWSERS
            // ========================================
            "/?list-type=2",
            "/?delimiter=/",
            "/storage/v1/b",
            "/minio",
            "/minio/login",
            "/minio/v2/metrics/cluster",
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
