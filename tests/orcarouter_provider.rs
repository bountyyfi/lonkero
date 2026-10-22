// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! OrcaRouter provider tests.
//!
//! These tests live in `tests/` because the library's in-module test targets
//! have pre-existing compile errors in unrelated scanner modules. Everything
//! here exercises the real provider code (`lonkero_scanner::ai::provider`)
//! against either fixtures or a local fake gateway on 127.0.0.1. The only
//! network test is `live_orcarouter_chat_and_catalog`, which is skipped unless
//! `ORCAROUTER_API_KEY` is present in the environment.

use std::sync::{Arc, Mutex};

use lonkero_scanner::ai::provider::{
    self, build_orca_messages, normalize_api_base, parse_catalog, parse_orca_response,
    redact_api_key, resolve_api_base_from, resolve_orca_api_key, verified_seed_models,
    ContentBlock, LlmProvider, Message, OrcaCapability, OrcaModality, OrcaModelInfo,
    OrcaSelection, OrcaStreamState, OrcaRouterProvider, ProviderType, Role,
};
use lonkero_scanner::ai::tools::ToolDefinition;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Mirrors the shape of a live `GET /v1/models` response.
const CATALOG_FIXTURE: &str = r#"{
  "object": "list",
  "data": [
    {
      "id": "openai/gpt-5.5",
      "object": "model",
      "supported_endpoint_types": ["openai", "openai-response"],
      "context_length": 272000,
      "max_completion_tokens": 128000,
      "reasoning_efforts": ["low", "medium", "high", "xhigh"],
      "architecture": {"input_modalities": ["file", "image", "text"], "output_modalities": ["text"]}
    },
    {
      "id": "deepseek/deepseek-v4-pro",
      "object": "model",
      "supported_endpoint_types": ["openai"],
      "context_length": 1048576,
      "architecture": {"input_modalities": ["text"]}
    },
    {
      "id": "acme/text-embed",
      "object": "model",
      "supported_endpoint_types": ["embeddings"],
      "architecture": {"input_modalities": ["text"]}
    },
    {
      "id": "acme/image-gen",
      "object": "model",
      "supported_endpoint_types": ["image-generation"],
      "architecture": {"input_modalities": ["text"]}
    },
    {
      "id": "acme/video-gen",
      "object": "model",
      "supported_endpoint_types": ["openai-video"],
      "architecture": {"input_modalities": ["text"]}
    },
    {
      "id": "acme/rerank-v1",
      "object": "model",
      "supported_endpoint_types": ["jina-rerank"],
      "architecture": {"input_modalities": ["text"]}
    },
    {
      "id": "orcarouter/fusion",
      "object": "model",
      "supported_endpoint_types": ["openai", "openai-response", "anthropic", "gemini"],
      "context_length": 1000000,
      "architecture": {"input_modalities": ["text"]}
    },
    {"id": "", "object": "model"},
    {"object": "model"}
  ]
}"#;

fn catalog() -> Vec<OrcaModelInfo> {
    parse_catalog(&serde_json::from_str(CATALOG_FIXTURE).expect("fixture is valid JSON"))
}

fn ids(models: &[OrcaModelInfo]) -> Vec<&str> {
    models.iter().map(|m| m.id.as_str()).collect()
}

fn tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "run_scan".to_string(),
        description: "Run a scanner module".to_string(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"]
        }),
    }
}

// ---------------------------------------------------------------------------
// provider (selection / factory)
// ---------------------------------------------------------------------------

#[test]
fn provider_type_parses_orcarouter_aliases() {
    for alias in ["orcarouter", "OrcaRouter", "orca", "orca-router"] {
        let parsed: ProviderType = alias.parse().expect("alias must parse");
        assert_eq!(parsed, ProviderType::OrcaRouter, "alias {alias}");
    }
    assert_eq!("claude".parse::<ProviderType>().unwrap(), ProviderType::Claude);
    assert_eq!("ollama".parse::<ProviderType>().unwrap(), ProviderType::Ollama);
    assert!("openai".parse::<ProviderType>().is_err());
}

#[test]
fn factory_builds_named_orcarouter_provider() {
    let provider = provider::create_provider(
        ProviderType::OrcaRouter,
        Some("orcarouter/fusion".to_string()),
        Some("sk-orca-test-key".to_string()),
        None,
    )
    .expect("explicit key must be enough");

    assert_eq!(provider.name(), "orcarouter");
    assert_eq!(provider.model(), "orcarouter/fusion");
}

#[test]
fn factory_defaults_to_orcacyber_zero() {
    let provider = provider::create_provider(
        ProviderType::OrcaRouter,
        None,
        Some("sk-orca-test-key".to_string()),
        None,
    )
    .unwrap();
    assert_eq!(provider.model(), provider::ORCA_CYBER_MODEL);
    assert_eq!(provider::ORCA_CYBER_MODEL, "orcacyber-zero");
}

#[test]
fn factory_requires_a_key_with_actionable_message() {
    // Only valid when the test process has no OrcaRouter key configured.
    if resolve_orca_api_key(None).is_ok() {
        return;
    }
    let result = provider::create_provider(ProviderType::OrcaRouter, None, None, None);
    let error = match result {
        Ok(_) => panic!("missing key must fail"),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(message.contains("ORCAROUTER_API_KEY"), "{message}");
    assert!(message.contains("www.orcarouter.ai"), "{message}");
}

// ---------------------------------------------------------------------------
// api_key (resolution / redaction / auth errors)
// ---------------------------------------------------------------------------

#[test]
fn explicit_api_key_wins_and_is_required_to_be_non_empty() {
    let key = resolve_orca_api_key(Some("sk-orca-explicit".to_string())).unwrap();
    assert_eq!(key, "sk-orca-explicit");

    // A blank explicit value is ignored in favour of the environment/default
    // path rather than being used verbatim.
    if resolve_orca_api_key(None).is_err() {
        assert!(resolve_orca_api_key(Some("   ".to_string())).is_err());
    }
}

#[test]
fn api_key_is_redacted_from_error_text() {
    let key = "sk-orca-very-secret-value";
    let body = format!("upstream said: invalid key {key} provided");
    let redacted = redact_api_key(&body, key);
    assert!(!redacted.contains(key), "key leaked: {redacted}");
    assert!(redacted.contains("[redacted]"));
}

#[test]
fn auth_errors_point_at_console_without_echoing_the_key() {
    let key = "sk-orca-very-secret-value";
    let error = provider::orca_api_error(401, "bad key sk-orca-very-secret-value", key, "orcarouter/fusion");
    let message = error.to_string();
    assert!(message.contains("401"), "{message}");
    assert!(message.contains("www.orcarouter.ai"), "{message}");
    assert!(!message.contains(key), "key leaked: {message}");

    let forbidden = provider::orca_api_error(403, "", key, "orcacyber-zero");
    let message = forbidden.to_string();
    assert!(message.contains("403"), "{message}");
    assert!(message.contains("business verification"), "{message}");

    let rate_limited = provider::orca_api_error(429, "", key, "orcarouter/fusion");
    assert!(rate_limited.to_string().contains("rate limit"));
}

// ---------------------------------------------------------------------------
// Base URL precedence and transport security
// ---------------------------------------------------------------------------

#[test]
fn api_base_precedence_api_override_beats_shared_base() {
    let resolved = resolve_api_base_from(
        Some("https://api.example.test/v1"),
        Some("https://shared.example.test/v1"),
    )
    .unwrap();
    assert_eq!(resolved, "https://api.example.test/v1");

    let shared_only = resolve_api_base_from(None, Some("https://shared.example.test/v1")).unwrap();
    assert_eq!(shared_only, "https://shared.example.test/v1");

    let default = resolve_api_base_from(None, None).unwrap();
    assert_eq!(default, "https://api.orcarouter.ai/v1");

    let blank_override = resolve_api_base_from(Some("  "), None).unwrap();
    assert_eq!(blank_override, "https://api.orcarouter.ai/v1");
}

#[test]
fn api_base_rejects_remote_http_and_accepts_loopback_http() {
    assert!(normalize_api_base("http://api.orcarouter.ai/v1").is_err());
    assert!(normalize_api_base("ftp://api.orcarouter.ai/v1").is_err());
    assert!(normalize_api_base("https://api.orcarouter.ai/v1?x=1").is_err());

    assert_eq!(
        normalize_api_base("http://127.0.0.1:8080/v1").unwrap(),
        "http://127.0.0.1:8080/v1"
    );
    assert_eq!(
        normalize_api_base("http://localhost:8080").unwrap(),
        "http://localhost:8080/v1"
    );
    assert_eq!(
        normalize_api_base("https://api.orcarouter.ai/v1/").unwrap(),
        "https://api.orcarouter.ai/v1"
    );
}

#[test]
fn provider_uses_console_separate_from_api_base() {
    // Inference stays on the API origin; the console origin is only guidance.
    assert_eq!(provider::ORCA_CONSOLE_URL, "https://www.orcarouter.ai");
    assert_eq!(provider::ORCA_DEFAULT_API_BASE, "https://api.orcarouter.ai/v1");
    assert!(!provider::ORCA_DEFAULT_API_BASE.contains("/auth"));
}

// ---------------------------------------------------------------------------
// catalog (source of truth + capability filtering)
// ---------------------------------------------------------------------------

#[test]
fn catalog_parses_entries_and_drops_invalid_ids() {
    let models = catalog();
    let ids = ids(&models);
    assert_eq!(ids.len(), 7, "invalid entries dropped: {ids:?}");
    assert!(ids.contains(&"openai/gpt-5.5"));
    assert!(ids.contains(&"orcarouter/fusion"));
    assert!(!ids.iter().any(|id| id.is_empty()));

    let gpt = models.iter().find(|m| m.id == "openai/gpt-5.5").unwrap();
    assert_eq!(gpt.context_length, Some(272_000));
    assert_eq!(gpt.input_modalities, vec!["file", "image", "text"]);
    assert_eq!(gpt.reasoning_efforts, ["low", "medium", "high", "xhigh"]);
}

#[test]
fn catalog_accepts_bare_array_payload() {
    let payload = serde_json::json!([
        {"id": "a/one", "supported_endpoint_types": ["openai"]},
        {"id": "a/one", "supported_endpoint_types": ["openai"]},
        {"id": "a/two", "supported_endpoint_types": ["openai"]}
    ]);
    let models = parse_catalog(&payload);
    assert_eq!(ids(&models), vec!["a/one", "a/two"], "duplicates collapse");
}

#[test]
fn chat_filter_excludes_non_text_specialists() {
    let models = catalog();
    let chat: Vec<_> = models
        .iter()
        .filter(|m| OrcaCapability::Chat.matches(m))
        .cloned()
        .collect();
    let ids = ids(&chat);

    assert!(ids.contains(&"openai/gpt-5.5"));
    assert!(ids.contains(&"deepseek/deepseek-v4-pro"));
    assert!(ids.contains(&"orcarouter/fusion"));
    assert!(!ids.contains(&"acme/text-embed"));
    assert!(!ids.contains(&"acme/image-gen"));
    assert!(!ids.contains(&"acme/video-gen"));
    assert!(!ids.contains(&"acme/rerank-v1"));
}

#[test]
fn multimodal_filter_fails_closed_without_declared_modality() {
    let models = catalog();
    let image_chat: Vec<_> = models
        .iter()
        .filter(|m| OrcaCapability::ChatWithModality(OrcaModality::Image).matches(m))
        .cloned()
        .collect();
    let ids = ids(&image_chat);

    assert_eq!(ids, vec!["openai/gpt-5.5"], "only declared image input");

    let audio_chat: Vec<_> = models
        .iter()
        .filter(|m| OrcaCapability::ChatWithModality(OrcaModality::Audio).matches(m))
        .collect();
    assert!(audio_chat.is_empty(), "undeclared audio must fail closed");
}

#[test]
fn non_chat_capabilities_match_strict_endpoint_types() {
    let models = catalog();
    let by_capability = |capability: OrcaCapability| -> Vec<String> {
        models
            .iter()
            .filter(|m| capability.matches(m))
            .map(|m| m.id.clone())
            .collect()
    };

    assert_eq!(by_capability(OrcaCapability::Embedding), vec!["acme/text-embed"]);
    assert_eq!(
        by_capability(OrcaCapability::ImageGeneration),
        vec!["acme/image-gen"]
    );
    assert_eq!(
        by_capability(OrcaCapability::VideoGeneration),
        vec!["acme/video-gen"]
    );
    assert_eq!(by_capability(OrcaCapability::Rerank), vec!["acme/rerank-v1"]);
}

#[test]
fn verified_seed_is_small_documented_and_chat_capable() {
    let seed = verified_seed_models();
    let ids: Vec<&str> = seed.iter().map(|m| m.id.as_str()).collect();
    assert_eq!(
        ids,
        vec![
            "openai/gpt-5.5",
            "anthropic/claude-opus-4.8",
            "google/gemini-3.5-flash",
            "deepseek/deepseek-v4-pro",
            "orcarouter/fusion",
        ]
    );
    assert!(seed.iter().all(|m| OrcaCapability::Chat.matches(m)));
    assert!(!ids.contains(&"orcarouter/auto"), "unverified id must not be seeded");

    let gpt = seed.iter().find(|m| m.id == "openai/gpt-5.5").unwrap();
    assert_eq!(gpt.reasoning_efforts, ["low", "medium", "high", "xhigh"]);
    assert!(gpt.input_modalities.contains(&"image".to_string()));

    let deepseek = seed
        .iter()
        .find(|m| m.id == "deepseek/deepseek-v4-pro")
        .unwrap();
    assert!(!OrcaCapability::ChatWithModality(OrcaModality::Image).matches(deepseek));
}

// ---------------------------------------------------------------------------
// Request/response mapping (DTO)
// ---------------------------------------------------------------------------

#[test]
fn messages_map_tool_results_to_openai_tool_messages() {
    let messages = vec![
        Message {
            role: Role::Assistant,
            content: vec![
                ContentBlock::Text {
                    text: "Checking headers.".to_string(),
                },
                ContentBlock::ToolUse {
                    id: "call_1".to_string(),
                    name: "run_scan".to_string(),
                    input: serde_json::json!({"url": "https://target.test"}),
                },
            ],
        },
        Message {
            role: Role::User,
            content: vec![ContentBlock::ToolResult {
                tool_use_id: "call_1".to_string(),
                content: "no CSP".to_string(),
                is_error: None,
            }],
        },
    ];

    let mapped = build_orca_messages("system prompt", &messages);
    assert_eq!(mapped[0]["role"], "system");
    assert_eq!(mapped[0]["content"], "system prompt");
    assert_eq!(mapped[1]["role"], "assistant");
    assert_eq!(mapped[1]["tool_calls"][0]["id"], "call_1");
    assert_eq!(mapped[1]["tool_calls"][0]["function"]["name"], "run_scan");
    // Arguments must be a JSON string, as OpenAI-compatible gateways expect.
    assert!(mapped[1]["tool_calls"][0]["function"]["arguments"].is_string());
    assert_eq!(mapped[2]["role"], "tool");
    assert_eq!(mapped[2]["tool_call_id"], "call_1");
    assert_eq!(mapped[2]["content"], "no CSP");
}

#[test]
fn non_streaming_response_maps_text_and_tool_calls() {
    let payload = serde_json::json!({
        "id": "chatcmpl-1",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "Running recon.",
                "tool_calls": [{
                    "id": "call_9",
                    "type": "function",
                    "function": {"name": "run_scan", "arguments": "{\"url\":\"https://x.test\"}"}
                }]
            },
            "finish_reason": "tool_calls"
        }],
        "usage": {
            "prompt_tokens": 120,
            "completion_tokens": 30,
            "prompt_tokens_details": {"cached_tokens": 100}
        }
    });

    let response = parse_orca_response(&payload).unwrap();
    assert_eq!(response.stop_reason.as_deref(), Some("tool_use"));
    assert_eq!(response.content.len(), 2);
    match &response.content[1] {
        ContentBlock::ToolUse { id, name, input } => {
            assert_eq!(id, "call_9");
            assert_eq!(name, "run_scan");
            assert_eq!(input["url"], "https://x.test");
        }
        other => panic!("unexpected block: {other:?}"),
    }
    let usage = response.usage.unwrap();
    assert_eq!(usage.input_tokens, 120);
    assert_eq!(usage.output_tokens, 30);
    assert_eq!(usage.cache_read_input_tokens, 100);
}

#[test]
fn streaming_state_accumulates_text_and_tool_call_deltas() {
    let mut state = OrcaStreamState::default();
    let lines = [
        r#"data: {"choices":[{"index":0,"delta":{"role":"assistant","content":""}}]}"#,
        r#"data: {"choices":[{"index":0,"delta":{"content":"Hello "}}]}"#,
        r#"data: {"choices":[{"index":0,"delta":{"content":"world"}}]}"#,
        r#"data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_a","type":"function","function":{"name":"run_scan","arguments":"{\"url\":"}}]}}]}"#,
        r#"data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"https://x.test\"}"}}]}}]}"#,
        r#"data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}"#,
        "data: [DONE]",
        "",
    ];

    let deltas: String = lines
        .iter()
        .filter_map(|line| state.ingest_line(line))
        .collect();
    assert_eq!(deltas, "Hello world");

    let response = state.finish();
    assert_eq!(response.stop_reason.as_deref(), Some("tool_use"));
    match &response.content[0] {
        ContentBlock::Text { text } => assert_eq!(text, "Hello world"),
        other => panic!("unexpected block: {other:?}"),
    }
    match &response.content[1] {
        ContentBlock::ToolUse { id, name, input } => {
            assert_eq!(id, "call_a");
            assert_eq!(name, "run_scan");
            assert_eq!(input["url"], "https://x.test");
        }
        other => panic!("unexpected block: {other:?}"),
    }
}

#[test]
fn streaming_state_ignores_comments_and_malformed_events() {
    let mut state = OrcaStreamState::default();
    assert!(state.ingest_line(": keep-alive").is_none());
    assert!(state.ingest_line("data: {not json").is_none());
    assert!(state.ingest_line("event: ping").is_none());
    assert!(state.ingest_line("").is_none());
    assert!(state.finish().content.is_empty());
}

// ---------------------------------------------------------------------------
// Fake gateway: the real HTTP path exercised end-to-end on loopback
// ---------------------------------------------------------------------------

mod fake_gateway {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    pub struct Gateway {
        pub base_url: String,
        pub requests: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    /// Spawn a one-request-at-a-time HTTP server.
    /// `handler` receives (path, authorization_header) and returns
    /// (status, content_type, body).
    pub async fn spawn<F>(handler: F) -> Gateway
    where
        F: Fn(&str, Option<&str>) -> (u16, &'static str, String) + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = requests.clone();
        let handler = std::sync::Arc::new(handler);

        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let log = log.clone();
                let handler = handler.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    // Read until end of headers, then the declared body.
                    loop {
                        let n = match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        buf.extend_from_slice(&chunk[..n]);
                        if let Some(pos) = find_headers_end(&buf) {
                            let head = String::from_utf8_lossy(&buf[..pos]).to_string();
                            let content_length = head
                                .lines()
                                .find_map(|l| {
                                    l.to_ascii_lowercase()
                                        .strip_prefix("content-length:")
                                        .and_then(|v| v.trim().parse::<usize>().ok())
                                })
                                .unwrap_or(0);
                            let body_start = pos + 4;
                            if buf.len() >= body_start + content_length {
                                break;
                            }
                        }
                    }

                    let head = String::from_utf8_lossy(&buf).to_string();
                    let mut lines = head.lines();
                    let request_line = lines.next().unwrap_or("").to_string();
                    let path = request_line
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("/")
                        .to_string();
                    let auth = lines.find_map(|l| {
                        let lower = l.to_ascii_lowercase();
                        lower
                            .strip_prefix("authorization:")
                            .map(|_| l["authorization:".len()..].trim().to_string())
                    });
                    log.lock().unwrap().push(format!("{} {}", request_line, path));

                    let (status, content_type, body) = handler(&path, auth.as_deref());
                    let response = format!(
                        "HTTP/1.1 {} {}\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        status,
                        status_text(status),
                        content_type,
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });

        Gateway {
            base_url: format!("http://127.0.0.1:{}/v1", addr.port()),
            requests,
        }
    }

    fn find_headers_end(buf: &[u8]) -> Option<usize> {
        buf.windows(4).position(|w| w == b"\r\n\r\n")
    }

    fn status_text(status: u16) -> &'static str {
        match status {
            200 => "OK",
            401 => "Unauthorized",
            403 => "Forbidden",
            500 => "Internal Server Error",
            _ => "Error",
        }
    }
}

#[tokio::test]
async fn catalog_is_fetched_with_bearer_auth_and_filtered() {
    let gateway = fake_gateway::spawn(|path, auth| {
        if path.starts_with("/v1/models") {
            assert_eq!(auth.as_deref(), Some("Bearer sk-orca-fake"));
            (200, "application/json", CATALOG_FIXTURE.to_string())
        } else {
            (404, "application/json", "{}".to_string())
        }
    })
    .await;

    let provider = OrcaRouterProvider::new(
        "sk-orca-fake".to_string(),
        None,
        Some(gateway.base_url.clone()),
    )
    .unwrap();

    let models = provider
        .fetch_models(Some(&OrcaCapability::Chat))
        .await
        .expect("catalog fetch should succeed");
    let ids = ids(&models);
    assert!(ids.contains(&"openai/gpt-5.5"));
    assert!(!ids.contains(&"acme/image-gen"));
    assert_eq!(ids, {
        let mut sorted = ids.clone();
        sorted.sort();
        sorted
    });

    let requests = gateway.requests.lock().unwrap().clone();
    assert!(
        requests.iter().any(|r| r.contains("/v1/models?capability=chat")),
        "capability query must be sent: {requests:?}"
    );
}

#[tokio::test]
async fn catalog_auth_failure_is_actionable_and_degrades_to_seed() {
    let gateway = fake_gateway::spawn(|_path, _auth| {
        (
            401,
            "application/json",
            r#"{"error":{"message":"invalid api key sk-orca-fake"}}"#.to_string(),
        )
    })
    .await;

    let provider = OrcaRouterProvider::new(
        "sk-orca-fake".to_string(),
        None,
        Some(gateway.base_url.clone()),
    )
    .unwrap();

    let error = provider.fetch_models(None).await.expect_err("401 must fail");
    let message = error.to_string();
    assert!(message.contains("401"), "{message}");
    assert!(message.contains("www.orcarouter.ai"), "{message}");
    assert!(!message.contains("sk-orca-fake"), "key leaked: {message}");

    let (models, degraded, reason) = provider
        .fetch_models_with_fallback(Some(&OrcaCapability::Chat))
        .await;
    assert!(degraded, "failed discovery must be marked degraded");
    assert!(reason.is_some());
    assert!(!models.is_empty());
    assert!(models.iter().all(|m| OrcaCapability::Chat.matches(m)));
    assert!(!ids(&models).contains(&"acme/text-embed"));
}

#[tokio::test]
async fn streaming_chat_goes_through_the_provider_with_tools() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let saw_tools = Arc::new(AtomicBool::new(false));
    let flag = saw_tools.clone();
    let gateway = fake_gateway::spawn(move |path, auth| {
        assert_eq!(auth.as_deref(), Some("Bearer sk-orca-fake"));
        assert_eq!(path, "/v1/chat/completions");
        flag.store(true, Ordering::SeqCst);
        let body = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Scanning\"}}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\" now\"}}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            "data: [DONE]\n\n"
        );
        (200, "text/event-stream", body.to_string())
    })
    .await;

    let provider = OrcaRouterProvider::new(
        "sk-orca-fake".to_string(),
        Some("orcarouter/fusion".to_string()),
        Some(gateway.base_url.clone()),
    )
    .unwrap();

    let messages = vec![Message {
        role: Role::User,
        content: vec![ContentBlock::Text {
            text: "scan https://target.test".to_string(),
        }],
    }];

    let collected = Arc::new(Mutex::new(String::new()));
    let sink = collected.clone();
    let response = provider
        .chat_stream(
            "system",
            &messages,
            &[tool_def()],
            Box::new(move |delta| sink.lock().unwrap().push_str(delta)),
        )
        .await
        .expect("streaming chat should succeed");

    assert!(saw_tools.load(Ordering::SeqCst));
    assert_eq!(*collected.lock().unwrap(), "Scanning now");
    assert_eq!(response.stop_reason.as_deref(), Some("end_turn"));
    match &response.content[0] {
        ContentBlock::Text { text } => assert_eq!(text, "Scanning now"),
        other => panic!("unexpected block: {other:?}"),
    }
}

#[tokio::test]
async fn cyber_model_403_falls_back_to_fusion_once() {
    let gateway = fake_gateway::spawn(|_path, _auth| {
        (
            403,
            "application/json",
            r#"{"error":{"message":"not entitled"}}"#.to_string(),
        )
    })
    .await;

    // The fallback path is modelled by the request handler above: both calls
    // get 403, but the provider must attempt the fallback model at least once
    // and the surfaced error must be about the fallback attempt, not a hang.
    let provider = OrcaRouterProvider::new(
        "sk-orca-fake".to_string(),
        Some(provider::ORCA_CYBER_MODEL.to_string()),
        Some(gateway.base_url.clone()),
    )
    .unwrap();

    let messages = vec![Message {
        role: Role::User,
        content: vec![ContentBlock::Text {
            text: "hi".to_string(),
        }],
    }];
    let error = provider.chat("system", &messages, &[]).await.expect_err("403");
    assert!(error.to_string().contains("403"), "{}", error);

    let requests = gateway.requests.lock().unwrap().clone();
    assert_eq!(
        requests.len(),
        2,
        "cyber model plus one fusion retry: {requests:?}"
    );
}

#[tokio::test]
async fn network_error_is_wrapped_with_actionable_context() {
    // Bind and immediately drop the listener to obtain a closed loopback port.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let provider = OrcaRouterProvider::new(
        "sk-orca-fake".to_string(),
        None,
        Some(format!("http://127.0.0.1:{}/v1", port)),
    )
    .unwrap();

    let error = provider.fetch_models(None).await.expect_err("closed port");
    let message = error.to_string();
    assert!(message.contains("OrcaRouter"), "{message}");
    assert!(message.contains("ORCA_API_BASE_URL"), "{message}");
    assert!(!message.contains("sk-orca-fake"), "key leaked: {message}");
}

// ---------------------------------------------------------------------------
// model selection (dropdown-equivalent logic)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn selection_accepts_only_catalog_chat_models() {
    let gateway = fake_gateway::spawn(|path, _auth| {
        if path.starts_with("/v1/models") {
            (200, "application/json", CATALOG_FIXTURE.to_string())
        } else {
            (404, "application/json", "{}".to_string())
        }
    })
    .await;
    let provider = OrcaRouterProvider::new(
        "sk-orca-fake".to_string(),
        None,
        Some(gateway.base_url.clone()),
    )
    .unwrap();

    // A chat model present in the live catalog is accepted verbatim.
    let accepted = provider::resolve_chat_selection(&provider, Some("deepseek/deepseek-v4-pro")).await;
    assert_eq!(
        accepted,
        OrcaSelection::Verified {
            model: "deepseek/deepseek-v4-pro".to_string()
        }
    );

    // An embedding/image model from the same catalog is not offerable for chat.
    let rejected = provider::resolve_chat_selection(&provider, Some("acme/image-gen")).await;
    match rejected {
        OrcaSelection::Rejected { model, available } => {
            assert_eq!(model, "acme/image-gen");
            assert!(available.contains(&"orcarouter/fusion".to_string()));
            assert!(!available.contains(&"acme/image-gen".to_string()));
        }
        other => panic!("expected rejection, got {other:?}"),
    }

    // Without an explicit model the default comes from the catalog.
    let defaulted = provider::resolve_chat_selection(&provider, None).await;
    assert_eq!(
        defaulted,
        OrcaSelection::Verified {
            model: "orcarouter/fusion".to_string()
        },
        "fusion is the preferred verified default when the cyber tier is absent"
    );
}

#[tokio::test]
async fn selection_degrades_but_never_fabricates_a_catalog() {
    let gateway = fake_gateway::spawn(|_path, _auth| {
        (500, "application/json", r#"{"error":"boom"}"#.to_string())
    })
    .await;
    let provider = OrcaRouterProvider::new(
        "sk-orca-fake".to_string(),
        None,
        Some(gateway.base_url.clone()),
    )
    .unwrap();

    match provider::resolve_chat_selection(&provider, Some("openai/gpt-5.5")).await {
        OrcaSelection::Unverified { model, reason } => {
            assert_eq!(model, "openai/gpt-5.5");
            assert!(reason.contains("500"), "{reason}");
        }
        other => panic!("expected unverified selection, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// live (real OrcaRouter account; skipped without a key)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn live_orcarouter_chat_and_catalog() {
    let Ok(key) = resolve_orca_api_key(None) else {
        eprintln!("skipping live test: ORCAROUTER_API_KEY is not set");
        return;
    };

    // Fetch the live catalog first (anonymous shape, workspace-filtered when a
    // key is present), then pick a model the workspace can actually call.
    let discovery = OrcaRouterProvider::new(
        key.clone(),
        Some(provider::ORCA_FALLBACK_MODEL.to_string()),
        None,
    )
    .expect("provider with live base");

    let models = discovery
        .fetch_models(Some(&OrcaCapability::Chat))
        .await
        .expect("live catalog must be reachable");
    assert!(
        !models.is_empty(),
        "live chat catalog must contain at least one model"
    );
    assert!(models
        .iter()
        .all(|m| OrcaCapability::Chat.matches(m)));
    assert!(
        models.iter().all(|m| m.id.contains('/')),
        "model IDs must preserve the vendor/model namespace"
    );
    eprintln!(
        "live chat catalog: {} model(s): {:?}",
        models.len(),
        ids(&models)
    );

    let messages = vec![Message {
        role: Role::User,
        content: vec![ContentBlock::Text {
            text: "Reply with exactly: ORCA_OK".to_string(),
        }],
    }];

    // A workspace-visible model can still be outside this key's scope, so try
    // a few catalog entries (gateway-routed first) until one accepts the call.
    let mut candidates: Vec<String> = vec![
        provider::ORCA_FALLBACK_MODEL.to_string(),
        "orcarouter/free".to_string(),
    ];
    candidates.extend(models.iter().map(|m| m.id.clone()));

    let mut attempts = 0;
    let mut last_error: Option<String> = None;
    for model in candidates {
        if attempts >= 4 {
            break;
        }
        let provider = OrcaRouterProvider::new(key.clone(), Some(model.clone()), None)
            .expect("provider with live base");

        let collected = Arc::new(Mutex::new(String::new()));
        let sink = collected.clone();
        let result = provider
            .chat_stream(
                "You are a terse assistant.",
                &messages,
                &[],
                Box::new(move |delta| sink.lock().unwrap().push_str(delta)),
            )
            .await;
        attempts += 1;

        match result {
            Ok(response) => {
                let text: String = response
                    .content
                    .iter()
                    .filter_map(|b| match b {
                        ContentBlock::Text { text } => Some(text.as_str()),
                        _ => None,
                    })
                    .collect();
                if text.trim().is_empty() {
                    last_error = Some(format!("{} returned no text", model));
                    continue;
                }
                eprintln!("live OrcaRouter reply ({}): {}", model, text.trim());
                eprintln!("live catalog + chat verified after {} attempt(s)", attempts);
                return;
            }
            Err(error) => {
                last_error = Some(format!("{}", error));
                eprintln!("live attempt {} skipped: {}", attempts, error);
            }
        }
    }

    panic!(
        "live chat completion failed for every catalog model tried: {}",
        last_error.unwrap_or_else(|| "no candidates".to_string())
    );
}

