// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! LLM Provider abstraction layer.
//!
//! Supports:
//! - Claude API (Anthropic) — default, best reasoning
//! - Ollama (local) — offline/privacy mode
//! - OrcaRouter — named OpenAI-compatible gateway provider
//!   (inference: <https://api.orcarouter.ai/v1>, console: <https://www.orcarouter.ai>)

use anyhow::{Context, Result};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::tools::ToolDefinition;

// ---------------------------------------------------------------------------
// Message types (Claude API compatible, Ollama-adaptable)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    pub content: Vec<ContentBlock>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    User,
    Assistant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    #[serde(rename = "tool_result")]
    ToolResult {
        tool_use_id: String,
        content: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        is_error: Option<bool>,
    },
    /// Server-side tool use (e.g. web_search). Passed through verbatim.
    #[serde(rename = "server_tool_use")]
    ServerToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    /// Server-side tool result (e.g. web_search_tool_result).
    /// Contains encrypted content that must be passed back verbatim for multi-turn.
    #[serde(rename = "web_search_tool_result")]
    WebSearchToolResult {
        tool_use_id: String,
        content: serde_json::Value,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmResponse {
    pub content: Vec<ContentBlock>,
    pub stop_reason: Option<String>,
    pub usage: Option<Usage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Cat 5: Cache read tokens (prompt caching hit — 90% cheaper)
    #[serde(default)]
    pub cache_read_input_tokens: u64,
    /// Cat 5: Cache creation tokens (first time caching — 25% more expensive)
    #[serde(default)]
    pub cache_creation_input_tokens: u64,
}

// ---------------------------------------------------------------------------
// Provider trait
// ---------------------------------------------------------------------------

/// Callback invoked as streaming text arrives from the LLM.
/// Receives each text delta so the agent can print it incrementally.
pub type StreamCallback = Box<dyn Fn(&str) + Send + Sync>;

#[async_trait::async_trait]
pub trait LlmProvider: Send + Sync {
    /// Send messages to the LLM and get a response.
    /// The provider handles system prompt injection internally.
    async fn chat(
        &self,
        system: &str,
        messages: &[Message],
        tools: &[ToolDefinition],
    ) -> Result<LlmResponse>;

    /// Send messages to the LLM with streaming text output.
    /// Calls `on_text` with each text delta as it arrives, so the UI
    /// can display it in real time. Returns the full accumulated response.
    /// Default: falls back to non-streaming `chat()`.
    async fn chat_stream(
        &self,
        system: &str,
        messages: &[Message],
        tools: &[ToolDefinition],
        on_text: StreamCallback,
    ) -> Result<LlmResponse> {
        let resp = self.chat(system, messages, tools).await?;
        // Emit any text blocks through the callback
        for block in &resp.content {
            if let ContentBlock::Text { text } = block {
                on_text(text);
            }
        }
        Ok(resp)
    }

    /// Provider name for display
    fn name(&self) -> &str;

    /// Model identifier for display
    fn model(&self) -> &str;
}

// ---------------------------------------------------------------------------
// Claude API provider
// ---------------------------------------------------------------------------

pub struct ClaudeProvider {
    api_key: String,
    model: String,
    client: reqwest::Client,
    max_tokens: u32,
    /// Cat 5: Enable prompt caching for the system prompt (reduces cost on multi-turn)
    pub enable_prompt_caching: bool,
    /// Cat 5: Cumulative cache read/creation tokens for cost tracking
    pub cache_read_tokens: std::sync::atomic::AtomicU64,
    pub cache_creation_tokens: std::sync::atomic::AtomicU64,
}

impl ClaudeProvider {
    pub fn new(api_key: String, model: Option<String>) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .context("Failed to create HTTP client for Claude API")?;

        Ok(Self {
            api_key,
            model: model.unwrap_or_else(|| "claude-sonnet-4-5-20250929".to_string()),
            client,
            max_tokens: 16384,
            enable_prompt_caching: true,
            cache_read_tokens: std::sync::atomic::AtomicU64::new(0),
            cache_creation_tokens: std::sync::atomic::AtomicU64::new(0),
        })
    }
}

#[async_trait::async_trait]
impl LlmProvider for ClaudeProvider {
    async fn chat(
        &self,
        system: &str,
        messages: &[Message],
        tools: &[ToolDefinition],
    ) -> Result<LlmResponse> {
        // Cat 5: Build system prompt with optional cache_control for prompt caching
        let system_value = if self.enable_prompt_caching {
            serde_json::json!([{
                "type": "text",
                "text": system,
                "cache_control": { "type": "ephemeral" }
            }])
        } else {
            serde_json::json!(system)
        };

        // Build Claude API request body
        let mut body = serde_json::json!({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system_value,
            "messages": messages,
        });

        // Only include tools if we have them
        if !tools.is_empty() {
            let mut claude_tools: Vec<serde_json::Value> = tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name,
                        "description": t.description,
                        "input_schema": t.input_schema,
                    })
                })
                .collect();

            // Server-side web search tool — Anthropic handles execution
            claude_tools.push(serde_json::json!({
                "type": "web_search_20250305",
                "name": "web_search",
                "max_uses": 5
            }));

            body["tools"] = serde_json::Value::Array(claude_tools);
        }

        let response = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .context("Failed to send request to Claude API")?;

        let status = response.status();
        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();
            anyhow::bail!("Claude API error ({}): {}", status, error_body);
        }

        let api_response: serde_json::Value = response
            .json()
            .await
            .context("Failed to parse Claude API response")?;

        // Parse response into our types
        let content = parse_claude_content(&api_response)?;
        let stop_reason = api_response["stop_reason"].as_str().map(|s| s.to_string());
        let usage = if let Some(u) = api_response.get("usage") {
            // Cat 5: Track cache tokens for cost optimization reporting
            let cache_read = u["cache_read_input_tokens"].as_u64().unwrap_or(0);
            let cache_create = u["cache_creation_input_tokens"].as_u64().unwrap_or(0);
            if cache_read > 0 {
                self.cache_read_tokens.fetch_add(cache_read, std::sync::atomic::Ordering::Relaxed);
            }
            if cache_create > 0 {
                self.cache_creation_tokens.fetch_add(cache_create, std::sync::atomic::Ordering::Relaxed);
            }

            Some(Usage {
                input_tokens: u["input_tokens"].as_u64().unwrap_or(0),
                output_tokens: u["output_tokens"].as_u64().unwrap_or(0),
                cache_read_input_tokens: cache_read,
                cache_creation_input_tokens: cache_create,
            })
        } else {
            None
        };

        Ok(LlmResponse {
            content,
            stop_reason,
            usage,
        })
    }

    async fn chat_stream(
        &self,
        system: &str,
        messages: &[Message],
        tools: &[ToolDefinition],
        on_text: StreamCallback,
    ) -> Result<LlmResponse> {
        // Cat 5: Build system prompt with cache_control for multi-turn cost savings
        let system_value = if self.enable_prompt_caching {
            serde_json::json!([{
                "type": "text",
                "text": system,
                "cache_control": { "type": "ephemeral" }
            }])
        } else {
            serde_json::json!(system)
        };

        // Build Claude API request body with stream: true
        let mut body = serde_json::json!({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system_value,
            "messages": messages,
            "stream": true,
        });

        if !tools.is_empty() {
            let mut claude_tools: Vec<serde_json::Value> = tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name,
                        "description": t.description,
                        "input_schema": t.input_schema,
                    })
                })
                .collect();

            // Server-side web search tool — Anthropic handles execution
            claude_tools.push(serde_json::json!({
                "type": "web_search_20250305",
                "name": "web_search",
                "max_uses": 5
            }));

            body["tools"] = serde_json::Value::Array(claude_tools);
        }

        let response = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .context("Failed to send streaming request to Claude API")?;

        let status = response.status();
        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();
            anyhow::bail!("Claude API error ({}): {}", status, error_body);
        }

        // Parse SSE stream
        let mut content_blocks: Vec<ContentBlock> = Vec::new();
        let mut current_text = String::new();
        let mut current_tool_id = String::new();
        let mut current_tool_name = String::new();
        let mut current_tool_input_json = String::new();
        let mut in_tool_use = false;
        let mut in_server_tool = false; // server_tool_use accumulates input like tool_use
        let mut usage: Option<Usage> = None;
        let mut stop_reason: Option<String> = None;

        let mut stream = response.bytes_stream();
        let mut buffer = String::new();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("Stream read error")?;
            buffer.push_str(&String::from_utf8_lossy(&chunk));

            // Process complete SSE lines from buffer
            while let Some(line_end) = buffer.find('\n') {
                let line = buffer[..line_end].trim_end_matches('\r').to_string();
                buffer = buffer[line_end + 1..].to_string();

                if line.is_empty() || line.starts_with(':') {
                    continue;
                }

                if let Some(data) = line.strip_prefix("data: ") {
                    if data == "[DONE]" {
                        continue;
                    }

                    let event: serde_json::Value = match serde_json::from_str(data) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };

                    match event["type"].as_str() {
                        Some("content_block_start") => {
                            let block = &event["content_block"];
                            match block["type"].as_str() {
                                Some("text") => {
                                    current_text.clear();
                                    in_tool_use = false;
                                    in_server_tool = false;
                                }
                                Some("tool_use") => {
                                    current_tool_id = block["id"]
                                        .as_str()
                                        .unwrap_or("")
                                        .to_string();
                                    current_tool_name = block["name"]
                                        .as_str()
                                        .unwrap_or("")
                                        .to_string();
                                    current_tool_input_json.clear();
                                    in_tool_use = true;
                                    in_server_tool = false;
                                }
                                Some("server_tool_use") => {
                                    // Server-side tool (e.g. web_search).
                                    // Accumulates input via deltas like tool_use.
                                    current_tool_id = block["id"]
                                        .as_str()
                                        .unwrap_or("")
                                        .to_string();
                                    current_tool_name = block["name"]
                                        .as_str()
                                        .unwrap_or("")
                                        .to_string();
                                    current_tool_input_json.clear();
                                    in_server_tool = true;
                                    in_tool_use = false;
                                    on_text(&format!("\n[web search: searching...]\n"));
                                }
                                Some("web_search_tool_result") => {
                                    // Complete result block — arrives fully formed
                                    content_blocks.push(ContentBlock::WebSearchToolResult {
                                        tool_use_id: block["tool_use_id"]
                                            .as_str()
                                            .unwrap_or("")
                                            .to_string(),
                                        content: block["content"].clone(),
                                    });
                                    on_text("[web search: results received]\n");
                                }
                                _ => {}
                            }
                        }
                        Some("content_block_delta") => {
                            let delta = &event["delta"];
                            match delta["type"].as_str() {
                                Some("text_delta") => {
                                    if let Some(text) = delta["text"].as_str() {
                                        current_text.push_str(text);
                                        on_text(text);
                                    }
                                }
                                Some("input_json_delta") => {
                                    // Both tool_use and server_tool_use send input via deltas
                                    if let Some(json_chunk) =
                                        delta["partial_json"].as_str()
                                    {
                                        current_tool_input_json.push_str(json_chunk);
                                    }
                                }
                                _ => {}
                            }
                        }
                        Some("content_block_stop") => {
                            if in_tool_use {
                                let input: serde_json::Value =
                                    serde_json::from_str(&current_tool_input_json)
                                        .unwrap_or(serde_json::json!({}));
                                content_blocks.push(ContentBlock::ToolUse {
                                    id: current_tool_id.clone(),
                                    name: current_tool_name.clone(),
                                    input,
                                });
                                in_tool_use = false;
                            } else if in_server_tool {
                                let input: serde_json::Value =
                                    serde_json::from_str(&current_tool_input_json)
                                        .unwrap_or(serde_json::json!({}));
                                content_blocks.push(ContentBlock::ServerToolUse {
                                    id: current_tool_id.clone(),
                                    name: current_tool_name.clone(),
                                    input,
                                });
                                in_server_tool = false;
                            } else if !current_text.is_empty() {
                                content_blocks.push(ContentBlock::Text {
                                    text: current_text.clone(),
                                });
                                current_text.clear();
                            }
                        }
                        Some("message_delta") => {
                            if let Some(sr) = event["delta"]["stop_reason"].as_str() {
                                stop_reason = Some(sr.to_string());
                            }
                            if let Some(u) = event.get("usage") {
                                let output_tokens =
                                    u["output_tokens"].as_u64().unwrap_or(0);
                                // Merge: keep input_tokens from message_start,
                                // add output_tokens from message_delta
                                usage = Some(Usage {
                                    input_tokens: usage
                                        .as_ref()
                                        .map(|prev| prev.input_tokens)
                                        .unwrap_or(0),
                                    output_tokens,
                                    cache_read_input_tokens: usage
                                        .as_ref()
                                        .map(|prev| prev.cache_read_input_tokens)
                                        .unwrap_or(0),
                                    cache_creation_input_tokens: usage
                                        .as_ref()
                                        .map(|prev| prev.cache_creation_input_tokens)
                                        .unwrap_or(0),
                                });
                            }
                        }
                        Some("message_start") => {
                            if let Some(msg) = event.get("message") {
                                if let Some(u) = msg.get("usage") {
                                    let input_tokens =
                                        u["input_tokens"].as_u64().unwrap_or(0);
                                    let cache_read = u["cache_read_input_tokens"].as_u64().unwrap_or(0);
                                    let cache_create = u["cache_creation_input_tokens"].as_u64().unwrap_or(0);
                                    usage = Some(Usage {
                                        input_tokens,
                                        output_tokens: 0,
                                        cache_read_input_tokens: cache_read,
                                        cache_creation_input_tokens: cache_create,
                                    });
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        // Merge usage from message_start (input) and message_delta (output)
        // The message_delta usage only has output_tokens
        // Already handled above via progressive updates

        Ok(LlmResponse {
            content: content_blocks,
            stop_reason,
            usage,
        })
    }

    fn name(&self) -> &str {
        "claude"
    }

    fn model(&self) -> &str {
        &self.model
    }
}

fn parse_claude_content(response: &serde_json::Value) -> Result<Vec<ContentBlock>> {
    let content_array = response["content"]
        .as_array()
        .context("Missing content array in Claude response")?;

    let mut blocks = Vec::new();
    for item in content_array {
        match item["type"].as_str() {
            Some("text") => {
                blocks.push(ContentBlock::Text {
                    text: item["text"].as_str().unwrap_or("").to_string(),
                });
            }
            Some("tool_use") => {
                blocks.push(ContentBlock::ToolUse {
                    id: item["id"].as_str().unwrap_or("").to_string(),
                    name: item["name"].as_str().unwrap_or("").to_string(),
                    input: item["input"].clone(),
                });
            }
            Some("server_tool_use") => {
                blocks.push(ContentBlock::ServerToolUse {
                    id: item["id"].as_str().unwrap_or("").to_string(),
                    name: item["name"].as_str().unwrap_or("").to_string(),
                    input: item["input"].clone(),
                });
            }
            Some("web_search_tool_result") => {
                blocks.push(ContentBlock::WebSearchToolResult {
                    tool_use_id: item["tool_use_id"].as_str().unwrap_or("").to_string(),
                    content: item["content"].clone(),
                });
            }
            _ => {}
        }
    }

    Ok(blocks)
}

// ---------------------------------------------------------------------------
// Ollama provider (local models)
// ---------------------------------------------------------------------------

pub struct OllamaProvider {
    base_url: String,
    model: String,
    client: reqwest::Client,
}

impl OllamaProvider {
    pub fn new(model: Option<String>, base_url: Option<String>) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(300)) // Local models can be slow
            .build()
            .context("Failed to create HTTP client for Ollama")?;

        Ok(Self {
            base_url: base_url.unwrap_or_else(|| "http://localhost:11434".to_string()),
            model: model.unwrap_or_else(|| "llama3.1:70b".to_string()),
            client,
        })
    }
}

#[async_trait::async_trait]
impl LlmProvider for OllamaProvider {
    async fn chat(
        &self,
        system: &str,
        messages: &[Message],
        tools: &[ToolDefinition],
    ) -> Result<LlmResponse> {
        // Convert to Ollama's chat format
        let mut ollama_messages = Vec::new();

        // System message
        ollama_messages.push(serde_json::json!({
            "role": "system",
            "content": system,
        }));

        // Conversation messages — flatten content blocks to text for Ollama
        for msg in messages {
            let role = match msg.role {
                Role::User => "user",
                Role::Assistant => "assistant",
            };

            let text: String = msg
                .content
                .iter()
                .filter_map(|block| match block {
                    ContentBlock::Text { text } => Some(text.clone()),
                    ContentBlock::ToolResult { content, .. } => {
                        Some(format!("[Tool Result]: {}", content))
                    }
                    ContentBlock::ToolUse { name, input, .. } => {
                        Some(format!("[Calling tool: {} with {}]", name, input))
                    }
                    ContentBlock::ServerToolUse { name, input, .. } => {
                        Some(format!("[Server tool: {} with {}]", name, input))
                    }
                    ContentBlock::WebSearchToolResult { .. } => {
                        Some("[Web search results]".to_string())
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");

            ollama_messages.push(serde_json::json!({
                "role": role,
                "content": text,
            }));
        }

        // Build Ollama tools array if tools are provided
        let mut body = serde_json::json!({
            "model": self.model,
            "messages": ollama_messages,
            "stream": false,
        });

        if !tools.is_empty() {
            let ollama_tools: Vec<serde_json::Value> = tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "type": "function",
                        "function": {
                            "name": t.name,
                            "description": t.description,
                            "parameters": t.input_schema,
                        }
                    })
                })
                .collect();
            body["tools"] = serde_json::Value::Array(ollama_tools);
        }

        let response = self
            .client
            .post(format!("{}/api/chat", self.base_url))
            .json(&body)
            .send()
            .await
            .context("Failed to connect to Ollama. Is it running? (ollama serve)")?;

        let status = response.status();
        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();
            anyhow::bail!("Ollama error ({}): {}", status, error_body);
        }

        let api_response: serde_json::Value = response
            .json()
            .await
            .context("Failed to parse Ollama response")?;

        // Parse Ollama response
        let mut blocks = Vec::new();

        // Check for tool calls in the response
        if let Some(message) = api_response.get("message") {
            if let Some(content) = message["content"].as_str() {
                if !content.is_empty() {
                    blocks.push(ContentBlock::Text {
                        text: content.to_string(),
                    });
                }
            }

            // Ollama tool calls format
            if let Some(tool_calls) = message.get("tool_calls").and_then(|tc| tc.as_array()) {
                for (i, tc) in tool_calls.iter().enumerate() {
                    if let Some(function) = tc.get("function") {
                        blocks.push(ContentBlock::ToolUse {
                            id: format!("ollama_tool_{}", i),
                            name: function["name"]
                                .as_str()
                                .unwrap_or("unknown")
                                .to_string(),
                            input: function["arguments"].clone(),
                        });
                    }
                }
            }
        }

        let stop_reason = if blocks.iter().any(|b| matches!(b, ContentBlock::ToolUse { .. })) {
            Some("tool_use".to_string())
        } else {
            Some("end_turn".to_string())
        };

        Ok(LlmResponse {
            content: blocks,
            stop_reason,
            usage: None, // Ollama doesn't always report tokens
        })
    }

    fn name(&self) -> &str {
        "ollama"
    }

    fn model(&self) -> &str {
        &self.model
    }
}

// ---------------------------------------------------------------------------
// OrcaRouter provider (named OpenAI-compatible gateway)
// ---------------------------------------------------------------------------
//
// OrcaRouter exposes an OpenAI-compatible inference API at
// <https://api.orcarouter.ai/v1> and an account console at
// <https://www.orcarouter.ai>. Authentication for this provider is a plain
// OrcaRouter API key (`sk-orca-…`), supplied through the project's usual
// environment-variable/flag mechanism. No OAuth/PKCE flow is implemented here:
// this codebase has no OAuth seam to hook into, and inventing one would be a
// fake integration rather than a real one.

/// Default inference base. Overridable via `ORCA_API_BASE_URL` (explicit API
/// base) or `ORCA_BASE_URL` (shared self-hosted base); explicit wins.
pub const ORCA_DEFAULT_API_BASE: &str = "https://api.orcarouter.ai/v1";

/// Public console origin, used only for user-facing guidance (key creation and
/// rotation). Never used for inference requests.
pub const ORCA_CONSOLE_URL: &str = "https://www.orcarouter.ai";

/// Recommended default model for security work. OrcaCyber Zero is available to
/// OrcaRouter accounts with business verification; accounts without that
/// entitlement fall back to [`ORCA_FALLBACK_MODEL`].
pub const ORCA_CYBER_MODEL: &str = "orcacyber-zero";

/// General-purpose fallback model used when the cyber tier is not entitled.
pub const ORCA_FALLBACK_MODEL: &str = "orcarouter/fusion";

/// Upper bound on catalog entries we are willing to parse from one response.
const ORCA_MAX_CATALOG_MODELS: usize = 2000;
/// Upper bound on an error body echoed to the user (and never the key).
const ORCA_MAX_ERROR_BODY: usize = 600;

/// Normalize and validate an OrcaRouter API base URL.
///
/// Remote bases must be HTTPS; plain HTTP is only accepted for loopback hosts
/// (local gateways and tests). An empty path is normalized to `/v1`, matching
/// the documented base `https://api.orcarouter.ai/v1`.
pub fn normalize_api_base(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        anyhow::bail!("OrcaRouter API base URL must not be empty");
    }

    let mut url = url::Url::parse(trimmed)
        .with_context(|| format!("Invalid OrcaRouter API base URL: {}", trimmed))?;

    let host = url.host_str().unwrap_or("");
    if url.scheme() != "https" && !(url.scheme() == "http" && is_loopback_host(host)) {
        anyhow::bail!(
            "OrcaRouter API base must use https (http is only allowed for loopback): {}",
            trimmed
        );
    }
    if url.query().is_some() || url.fragment().is_some() {
        anyhow::bail!(
            "OrcaRouter API base must not contain a query or fragment: {}",
            trimmed
        );
    }

    let path = url.path().trim_end_matches('/').to_string();
    let path = if path.is_empty() { "/v1" } else { &path };
    url.set_path(path);

    Ok(url.as_str().trim_end_matches('/').to_string())
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    matches!(host, "localhost" | "127.0.0.1" | "::1")
        || host.starts_with("127.")
}

/// Resolve the API base from explicit sources (pure, testable).
///
/// Precedence: `ORCA_API_BASE_URL` > `ORCA_BASE_URL` > official default.
pub fn resolve_api_base_from(
    api_base_env: Option<&str>,
    shared_base_env: Option<&str>,
) -> Result<String> {
    let raw = api_base_env
        .filter(|v| !v.trim().is_empty())
        .or_else(|| shared_base_env.filter(|v| !v.trim().is_empty()))
        .unwrap_or(ORCA_DEFAULT_API_BASE);
    normalize_api_base(raw)
}

/// Resolve the API base from the process environment.
pub fn resolve_api_base() -> Result<String> {
    let api_base = std::env::var("ORCA_API_BASE_URL").ok();
    let shared_base = std::env::var("ORCA_BASE_URL").ok();
    resolve_api_base_from(api_base.as_deref(), shared_base.as_deref())
}

/// Resolve the OrcaRouter API key: explicit flag/config first, then the
/// documented environment variables.
pub fn resolve_orca_api_key(explicit: Option<String>) -> Result<String> {
    explicit
        .filter(|k| !k.trim().is_empty())
        .or_else(|| std::env::var("ORCAROUTER_API_KEY").ok().filter(|k| !k.trim().is_empty()))
        .or_else(|| std::env::var("ORCA_API_KEY").ok().filter(|k| !k.trim().is_empty()))
        .context(
            "OrcaRouter API key required. Set ORCAROUTER_API_KEY, or pass --api-key, \
             with a key created at https://www.orcarouter.ai (keys start with sk-orca-).",
        )
}

// --- Model catalog ---------------------------------------------------------

/// A capability selector used to filter the live OrcaRouter model catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrcaCapability {
    /// Text chat / agentic tool use.
    Chat,
    /// Chat plus an explicitly declared non-text input modality.
    ChatWithModality(OrcaModality),
    /// Embeddings.
    Embedding,
    /// Image generation.
    ImageGeneration,
    /// Video generation.
    VideoGeneration,
    /// Reranking.
    Rerank,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrcaModality {
    Image,
    Audio,
    Video,
    File,
}

impl OrcaModality {
    pub fn as_str(&self) -> &'static str {
        match self {
            OrcaModality::Image => "image",
            OrcaModality::Audio => "audio",
            OrcaModality::Video => "video",
            OrcaModality::File => "file",
        }
    }
}

impl OrcaCapability {
    /// `?capability=` query value understood by the gateway, if any.
    pub fn query_value(&self) -> Option<&'static str> {
        match self {
            OrcaCapability::Chat | OrcaCapability::ChatWithModality(_) => Some("chat"),
            OrcaCapability::Embedding => Some("embedding"),
            OrcaCapability::ImageGeneration => Some("image"),
            // No server-side capability alias documented for these; filter
            // strictly client-side on `supported_endpoint_types`.
            OrcaCapability::VideoGeneration | OrcaCapability::Rerank => None,
        }
    }

    /// Strict, fail-closed match against catalog metadata.
    pub fn matches(&self, model: &OrcaModelInfo) -> bool {
        let types = &model.supported_endpoint_types;
        match self {
            OrcaCapability::Chat => is_chat_capable(types),
            OrcaCapability::ChatWithModality(modality) => {
                is_chat_capable(types)
                    && model
                        .input_modalities
                        .iter()
                        .any(|m| m.eq_ignore_ascii_case(modality.as_str()))
            }
            OrcaCapability::Embedding => types.iter().any(|t| t == "embeddings"),
            OrcaCapability::ImageGeneration => types.iter().any(|t| t == "image-generation"),
            OrcaCapability::VideoGeneration => types.iter().any(|t| t == "openai-video"),
            OrcaCapability::Rerank => types.iter().any(|t| t == "jina-rerank"),
        }
    }
}

fn is_chat_capable(types: &[String]) -> bool {
    let has_chat_endpoint = types.iter().any(|t| {
        matches!(
            t.as_str(),
            "openai" | "openai-response" | "anthropic" | "gemini"
        )
    });
    let is_non_text_specialist = types.iter().any(|t| {
        matches!(
            t.as_str(),
            "image-generation" | "openai-video" | "jina-rerank" | "embeddings"
        )
    });
    has_chat_endpoint && !is_non_text_specialist
}

/// Minimal, provider-agnostic model metadata used for selection UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrcaModelInfo {
    /// Raw catalog ID, preserving the `vendor/model` namespace.
    pub id: String,
    pub name: Option<String>,
    pub context_length: Option<u64>,
    pub max_completion_tokens: Option<u64>,
    pub supported_endpoint_types: Vec<String>,
    pub input_modalities: Vec<String>,
    /// Documented reasoning effort levels, when the catalog/provider states them.
    pub reasoning_efforts: Vec<String>,
}

impl OrcaModelInfo {
    fn from_json(value: &serde_json::Value) -> Option<Self> {
        let id = value.get("id")?.as_str()?.trim();
        if id.is_empty() {
            return None;
        }
        Some(Self {
            id: id.to_string(),
            name: value
                .get("name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            context_length: value
                .get("context_length")
                .and_then(|v| v.as_u64())
                .filter(|v| *v > 0),
            max_completion_tokens: value
                .get("max_completion_tokens")
                .and_then(|v| v.as_u64())
                .filter(|v| *v > 0),
            supported_endpoint_types: string_array(value, "supported_endpoint_types"),
            input_modalities: value
                .get("architecture")
                .map(|a| string_array(a, "input_modalities"))
                .unwrap_or_default(),
            reasoning_efforts: string_array(value, "reasoning_efforts"),
        })
    }

    /// Human-readable modality summary for CLI output.
    pub fn modality_summary(&self) -> String {
        if self.input_modalities.is_empty() {
            "text".to_string()
        } else {
            self.input_modalities.join(",")
        }
    }
}

fn string_array(value: &serde_json::Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// Parse a `GET /models` payload into catalog entries.
///
/// Accepts both the OpenAI-shaped `{ "data": [...] }` envelope and a bare
/// array. Duplicate IDs are collapsed (first wins) and the entry count is
/// bounded so a hostile/broken gateway cannot exhaust memory.
pub fn parse_catalog(value: &serde_json::Value) -> Vec<OrcaModelInfo> {
    let array = value
        .get("data")
        .and_then(|v| v.as_array())
        .or_else(|| value.as_array());

    let Some(array) = array else {
        return Vec::new();
    };

    let mut seen = std::collections::HashSet::new();
    let mut models = Vec::new();
    for item in array.iter().take(ORCA_MAX_CATALOG_MODELS) {
        if let Some(model) = OrcaModelInfo::from_json(item) {
            if seen.insert(model.id.clone()) {
                models.push(model);
            }
        }
    }
    models
}

/// Small, verified cold-start catalog used only when live discovery fails.
///
/// Every entry below was observed in the live `GET /v1/models` catalog and
/// keeps only metadata that catalog actually advertises (context window and
/// declared input modalities). `orcarouter/auto` is intentionally omitted
/// because the live catalog does not advertise it; including it would be an
/// unverified guess. The GPT-5.5 reasoning efforts are the documented
/// low/medium/high/xhigh levels.
pub fn verified_seed_models() -> Vec<OrcaModelInfo> {
    fn seed(
        id: &str,
        context_length: Option<u64>,
        modalities: &[&str],
        reasoning_efforts: &[&str],
    ) -> OrcaModelInfo {
        OrcaModelInfo {
            id: id.to_string(),
            name: None,
            context_length,
            max_completion_tokens: None,
            supported_endpoint_types: vec!["openai".to_string(), "openai-response".to_string()],
            input_modalities: modalities.iter().map(|m| m.to_string()).collect(),
            reasoning_efforts: reasoning_efforts.iter().map(|r| r.to_string()).collect(),
        }
    }

    vec![
        seed(
            "openai/gpt-5.5",
            None,
            &["text", "image", "file"],
            &["low", "medium", "high", "xhigh"],
        ),
        seed(
            "anthropic/claude-opus-4.8",
            Some(1_000_000),
            &["text", "image", "file"],
            &[],
        ),
        seed(
            "google/gemini-3.5-flash",
            Some(1_048_576),
            &["text", "image", "video", "file", "audio"],
            &[],
        ),
        seed(
            "deepseek/deepseek-v4-pro",
            Some(1_048_576),
            &["text"],
            &[],
        ),
        seed(ORCA_FALLBACK_MODEL, Some(1_000_000), &[], &[]),
    ]
}

// --- HTTP errors -----------------------------------------------------------

/// Error returned for a non-success HTTP response from OrcaRouter.
#[derive(Debug)]
pub struct OrcaApiError {
    pub status: u16,
    pub message: String,
}

impl std::fmt::Display for OrcaApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for OrcaApiError {}

/// Remove the API key from any text we might surface to the user.
pub fn redact_api_key(text: &str, api_key: &str) -> String {
    let without_key = if api_key.is_empty() {
        text.to_string()
    } else {
        text.replace(api_key, "[redacted]")
    };
    without_key.chars().take(ORCA_MAX_ERROR_BODY).collect()
}

/// Build the user-facing error for a failed OrcaRouter HTTP response.
///
/// The response body is redacted before it is included, and the API key is
/// never echoed. Exposed so the wording can be regression-tested.
pub fn orca_api_error(
    status: u16,
    body: &str,
    api_key: &str,
    model: &str,
) -> OrcaApiError {
    let detail = redact_api_key(body.trim(), api_key);
    let detail = if detail.is_empty() {
        String::new()
    } else {
        format!(" Response: {}", detail)
    };

    let guidance = match status {
        401 => format!(
            "OrcaRouter authentication failed (HTTP 401): the API key was rejected. \
             Set a valid key in ORCAROUTER_API_KEY or pass --api-key, and create or rotate \
             keys at {}.{}",
            ORCA_CONSOLE_URL, detail
        ),
        403 => {
            let entitling = if model == ORCA_CYBER_MODEL {
                format!(
                    " OrcaCyber Zero is available to OrcaRouter accounts with business \
                     verification; without it, use --model {}.",
                    ORCA_FALLBACK_MODEL
                )
            } else {
                " Check this key's model scope and your workspace entitlements.".to_string()
            };
            format!(
                "OrcaRouter denied access to model '{}' (HTTP 403). The key is valid but \
                 this API key or workspace is not entitled to the model.{} Manage access \
                 at {}.{}",
                model, entitling, ORCA_CONSOLE_URL, detail
            )
        }
        404 => format!(
            "OrcaRouter could not find model '{}' (HTTP 404). Use `lonkero ai --provider \
             orcarouter --list-models` to pick an available model.{}",
            model, detail
        ),
        429 => format!(
            "OrcaRouter rate limit reached (HTTP 429). Wait and retry, or check your quota \
             at {}.{}",
            ORCA_CONSOLE_URL, detail
        ),
        _ => format!(
            "OrcaRouter API error (HTTP {}).{}",
            status, detail
        ),
    };

    OrcaApiError {
        status,
        message: guidance,
    }
}

// --- Request building ------------------------------------------------------

/// Convert the provider-neutral conversation into OpenAI-compatible messages.
pub fn build_orca_messages(system: &str, messages: &[Message]) -> Vec<serde_json::Value> {
    let mut out = Vec::new();

    if !system.is_empty() {
        out.push(serde_json::json!({ "role": "system", "content": system }));
    }

    for msg in messages {
        match msg.role {
            Role::Assistant => {
                let mut text = String::new();
                let mut tool_calls = Vec::new();
                for block in &msg.content {
                    match block {
                        ContentBlock::Text { text: t } => text.push_str(t),
                        ContentBlock::ToolUse { id, name, input } => {
                            tool_calls.push(serde_json::json!({
                                "id": id,
                                "type": "function",
                                "function": {
                                    "name": name,
                                    "arguments": input.to_string(),
                                }
                            }));
                        }
                        ContentBlock::ServerToolUse { name, .. } => {
                            text.push_str(&format!("\n[server tool: {}]", name));
                        }
                        ContentBlock::ToolResult { content, .. } => {
                            text.push_str(content);
                        }
                        ContentBlock::WebSearchToolResult { .. } => {}
                    }
                }

                if !text.is_empty() || !tool_calls.is_empty() {
                    let content = if text.is_empty() {
                        serde_json::Value::Null
                    } else {
                        serde_json::json!(text)
                    };
                    let mut message = serde_json::json!({
                        "role": "assistant",
                        "content": content,
                    });
                    if !tool_calls.is_empty() {
                        message["tool_calls"] = serde_json::Value::Array(tool_calls);
                    }
                    out.push(message);
                }
            }
            Role::User => {
                // Tool results are their own `role: tool` messages in the
                // OpenAI schema. Emit them before any user text so tool call
                // ordering stays valid.
                let mut text_parts = Vec::new();
                let mut tool_messages = Vec::new();
                for block in &msg.content {
                    match block {
                        ContentBlock::ToolResult {
                            tool_use_id,
                            content,
                            ..
                        } => tool_messages.push(serde_json::json!({
                            "role": "tool",
                            "tool_call_id": tool_use_id,
                            "content": content,
                        })),
                        ContentBlock::Text { text } => text_parts.push(text.clone()),
                        ContentBlock::WebSearchToolResult { .. } => {
                            text_parts.push("[web search results]".to_string());
                        }
                        ContentBlock::ToolUse { .. } | ContentBlock::ServerToolUse { .. } => {}
                    }
                }
                out.extend(tool_messages);
                if !text_parts.is_empty() {
                    out.push(serde_json::json!({
                        "role": "user",
                        "content": text_parts.join("\n"),
                    }));
                }
            }
        }
    }

    out
}

fn build_orca_tools(tools: &[ToolDefinition]) -> Vec<serde_json::Value> {
    tools
        .iter()
        .map(|t| {
            serde_json::json!({
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.input_schema,
                }
            })
        })
        .collect()
}

fn map_finish_reason(reason: &str) -> String {
    match reason {
        "tool_calls" | "function_call" => "tool_use".to_string(),
        "stop" => "end_turn".to_string(),
        "length" => "max_tokens".to_string(),
        "content_filter" => "stop_sequence".to_string(),
        other => other.to_string(),
    }
}

fn parse_orca_usage(value: &serde_json::Value) -> Option<Usage> {
    let usage = value.get("usage")?;
    let input = usage.get("prompt_tokens").and_then(|v| v.as_u64())?;
    let output = usage
        .get("completion_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let cached = usage
        .get("prompt_tokens_details")
        .and_then(|d| d.get("cached_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    Some(Usage {
        input_tokens: input,
        output_tokens: output,
        cache_read_input_tokens: cached,
        cache_creation_input_tokens: 0,
    })
}

fn parse_tool_arguments(raw: &str) -> serde_json::Value {
    if raw.trim().is_empty() {
        return serde_json::json!({});
    }
    serde_json::from_str(raw)
        .unwrap_or_else(|_| serde_json::json!({ "_raw_arguments": raw }))
}

/// Parse a non-streaming OpenAI-compatible response.
pub fn parse_orca_response(value: &serde_json::Value) -> Result<LlmResponse> {
    let choice = value
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|c| c.first())
        .context("Missing choices in OrcaRouter response")?;
    let message = choice
        .get("message")
        .context("Missing message in OrcaRouter response")?;

    let mut blocks = Vec::new();
    if let Some(text) = message.get("content").and_then(|c| c.as_str()) {
        if !text.is_empty() {
            blocks.push(ContentBlock::Text {
                text: text.to_string(),
            });
        }
    }

    if let Some(tool_calls) = message.get("tool_calls").and_then(|t| t.as_array()) {
        for (index, call) in tool_calls.iter().enumerate() {
            let function = call.get("function");
            let name = function
                .and_then(|f| f.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let arguments = function
                .and_then(|f| f.get("arguments"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let id = call
                .get("id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("orca_tool_{}", index));
            blocks.push(ContentBlock::ToolUse {
                id,
                name,
                input: parse_tool_arguments(arguments),
            });
        }
    }

    let stop_reason = choice
        .get("finish_reason")
        .and_then(|v| v.as_str())
        .map(map_finish_reason)
        .or_else(|| {
            if blocks
                .iter()
                .any(|b| matches!(b, ContentBlock::ToolUse { .. }))
            {
                Some("tool_use".to_string())
            } else {
                None
            }
        });

    Ok(LlmResponse {
        content: blocks,
        stop_reason,
        usage: parse_orca_usage(value),
    })
}

/// Incremental SSE accumulator for OpenAI-compatible chat chunks.
///
/// Kept as a plain struct (no I/O) so the streaming protocol can be tested
/// without a network server.
#[derive(Default)]
pub struct OrcaStreamState {
    text: String,
    tool_calls: Vec<Option<(String, String, String)>>, // index -> (id, name, args)
    usage: Option<Usage>,
    finish_reason: Option<String>,
}

impl OrcaStreamState {
    /// Feed one SSE line. Returns a text delta when the line carries content.
    pub fn ingest_line(&mut self, line: &str) -> Option<String> {
        let line = line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with(':') {
            return None;
        }
        let data = line
            .strip_prefix("data:")
            .map(|d| d.trim_start())?;
        if data == "[DONE]" {
            return None;
        }

        let event: serde_json::Value = serde_json::from_str(data).ok()?;

        if self.usage.is_none() {
            self.usage = parse_orca_usage(&event);
        }

        let choice = event
            .get("choices")
            .and_then(|c| c.as_array())
            .and_then(|c| c.first())?;

        if let Some(reason) = choice.get("finish_reason").and_then(|v| v.as_str()) {
            self.finish_reason = Some(map_finish_reason(reason));
        }

        let delta = choice.get("delta")?;
        let mut text_delta = None;
        if let Some(content) = delta.get("content").and_then(|v| v.as_str()) {
            if !content.is_empty() {
                self.text.push_str(content);
                text_delta = Some(content.to_string());
            }
        }

        if let Some(calls) = delta.get("tool_calls").and_then(|v| v.as_array()) {
            for call in calls {
                let index = call
                    .get("index")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as usize;
                if index > 512 {
                    continue; // defensive bound on hostile streams
                }
                if self.tool_calls.len() <= index {
                    self.tool_calls.resize(index + 1, None);
                }
                let slot = self
                    .tool_calls
                    .get_mut(index)
                    .expect("resized above")
                    .get_or_insert_with(|| (String::new(), String::new(), String::new()));

                if let Some(id) = call.get("id").and_then(|v| v.as_str()) {
                    if !id.is_empty() {
                        slot.0 = id.to_string();
                    }
                }
                if let Some(function) = call.get("function") {
                    if let Some(name) = function.get("name").and_then(|v| v.as_str()) {
                        if !name.is_empty() {
                            slot.1 = name.to_string();
                        }
                    }
                    if let Some(args) = function.get("arguments").and_then(|v| v.as_str()) {
                        slot.2.push_str(args);
                    }
                }
            }
        }

        text_delta
    }

    /// Finalize the accumulated stream into a provider-neutral response.
    pub fn finish(self) -> LlmResponse {
        let mut content = Vec::new();
        if !self.text.is_empty() {
            content.push(ContentBlock::Text { text: self.text });
        }
        for (index, call) in self.tool_calls.into_iter().enumerate() {
            let Some((id, name, args)) = call else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            content.push(ContentBlock::ToolUse {
                id: if id.is_empty() {
                    format!("orca_tool_{}", index)
                } else {
                    id
                },
                name,
                input: parse_tool_arguments(&args),
            });
        }

        let has_tool_use = content
            .iter()
            .any(|b| matches!(b, ContentBlock::ToolUse { .. }));
        let stop_reason = self.finish_reason.or_else(|| {
            if has_tool_use {
                Some("tool_use".to_string())
            } else {
                None
            }
        });

        LlmResponse {
            content,
            stop_reason,
            usage: self.usage,
        }
    }
}

// --- Provider --------------------------------------------------------------

pub struct OrcaRouterProvider {
    api_key: String,
    model: String,
    base_url: String,
    client: reqwest::Client,
    max_tokens: u32,
}

impl OrcaRouterProvider {
    pub fn new(
        api_key: String,
        model: Option<String>,
        api_base: Option<String>,
    ) -> Result<Self> {
        let base_url = match api_base {
            Some(base) => normalize_api_base(&base)?,
            None => resolve_api_base()?,
        };

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(180))
            .build()
            .context("Failed to create HTTP client for OrcaRouter")?;

        Ok(Self {
            api_key,
            model: model.unwrap_or_else(|| ORCA_CYBER_MODEL.to_string()),
            base_url,
            client,
            max_tokens: 16384,
        })
    }

    /// Configured inference base (never the console origin).
    pub fn api_base(&self) -> &str {
        &self.base_url
    }

    fn build_body(
        &self,
        model: &str,
        system: &str,
        messages: &[Message],
        tools: &[ToolDefinition],
        stream: bool,
    ) -> serde_json::Value {
        let mut body = serde_json::json!({
            "model": model,
            "max_tokens": self.max_tokens,
            "messages": build_orca_messages(system, messages),
            "stream": stream,
        });
        if !tools.is_empty() {
            body["tools"] = serde_json::Value::Array(build_orca_tools(tools));
        }
        body
    }

    async fn send_chat(
        &self,
        model: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::Response> {
        let response = self
            .client
            .post(format!("{}/chat/completions", self.base_url))
            .header("authorization", format!("Bearer {}", self.api_key))
            .header("content-type", "application/json")
            .json(body)
            .send()
            .await
            .with_context(|| {
                format!(
                    "Failed to reach OrcaRouter at {}. Check network connectivity and \
                     ORCA_API_BASE_URL/ORCA_BASE_URL overrides.",
                    self.base_url
                )
            })?;

        let status = response.status();
        if !status.is_success() {
            let body_text = response.text().await.unwrap_or_default();
            return Err(
                orca_api_error(status.as_u16(), &body_text, &self.api_key, model).into(),
            );
        }

        Ok(response)
    }

    /// Retry once with the general-purpose fallback when the cyber model is not
    /// entitled for this workspace. Any other error is propagated unchanged.
    fn should_fallback_to_fusion(error: &anyhow::Error, model: &str) -> bool {
        model == ORCA_CYBER_MODEL
            && error
                .downcast_ref::<OrcaApiError>()
                .map(|e| matches!(e.status, 403 | 404))
                .unwrap_or(false)
    }

    async fn send_with_cyber_fallback(
        &self,
        model: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::Response> {
        match self.send_chat(model, body).await {
            Ok(response) => Ok(response),
            Err(error) if Self::should_fallback_to_fusion(&error, model) => {
                eprintln!(
                    "\x1b[33m  OrcaRouter: '{}' is not enabled for this workspace. \
                     OrcaCyber Zero is available to business-verified security teams; \
                     falling back to '{}'.\x1b[0m",
                    ORCA_CYBER_MODEL, ORCA_FALLBACK_MODEL
                );
                let mut fallback_body = body.clone();
                fallback_body["model"] = serde_json::json!(ORCA_FALLBACK_MODEL);
                self.send_chat(ORCA_FALLBACK_MODEL, &fallback_body).await
            }
            Err(error) => Err(error),
        }
    }

    /// Fetch the live model catalog, optionally filtered by capability.
    ///
    /// The catalog under the configured API origin is the only source of
    /// truth. Callers that need outage resilience should use
    /// [`Self::fetch_models_with_fallback`].
    pub async fn fetch_models(
        &self,
        capability: Option<&OrcaCapability>,
    ) -> Result<Vec<OrcaModelInfo>> {
        let mut url = format!("{}/models", self.base_url);
        if let Some(query) = capability.and_then(|c| c.query_value()) {
            url = format!("{}?capability={}", url, query);
        }

        let response = self
            .client
            .get(&url)
            .header("authorization", format!("Bearer {}", self.api_key))
            .send()
            .await
            .with_context(|| {
                format!(
                    "Failed to fetch the OrcaRouter model catalog from {}. Check network \
                     connectivity and ORCA_API_BASE_URL/ORCA_BASE_URL overrides.",
                    self.base_url
                )
            })?;

        let status = response.status();
        if !status.is_success() {
            let body_text = response.text().await.unwrap_or_default();
            let detail = redact_api_key(body_text.trim(), &self.api_key);
            let detail = if detail.is_empty() {
                String::new()
            } else {
                format!(" Response: {}", detail)
            };
            let message = match status.as_u16() {
                401 => format!(
                    "OrcaRouter authentication failed (HTTP 401) while loading the model \
                     catalog: the API key was rejected. Set a valid key in \
                     ORCAROUTER_API_KEY or pass --api-key, and create or rotate keys at \
                     {}.{}",
                    ORCA_CONSOLE_URL, detail
                ),
                403 => format!(
                    "OrcaRouter denied access to the model catalog (HTTP 403). The key is \
                     valid but the workspace cannot list models. Check workspace \
                     entitlements at {}.{}",
                    ORCA_CONSOLE_URL, detail
                ),
                429 => format!(
                    "OrcaRouter rate limit reached while loading the model catalog \
                     (HTTP 429). Wait and retry, or check your quota at {}.{}",
                    ORCA_CONSOLE_URL, detail
                ),
                other => format!(
                    "OrcaRouter model catalog error (HTTP {}).{}",
                    other, detail
                ),
            };
            return Err(OrcaApiError {
                status: status.as_u16(),
                message,
            }
            .into());
        }

        let payload: serde_json::Value = response
            .json()
            .await
            .context("Failed to parse the OrcaRouter model catalog response")?;

        let mut models = parse_catalog(&payload);
        if let Some(capability) = capability {
            models.retain(|m| capability.matches(m));
        }
        models.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(models)
    }

    /// Live catalog with a clearly-labelled degraded fallback.
    ///
    /// Returns `(models, degraded, error)`; when `degraded` is true the caller
    /// must display the verified seed as an outage fallback, never as live data.
    pub async fn fetch_models_with_fallback(
        &self,
        capability: Option<&OrcaCapability>,
    ) -> (Vec<OrcaModelInfo>, bool, Option<String>) {
        match self.fetch_models(capability).await {
            Ok(models) => (models, false, None),
            Err(error) => {
                let mut seed = verified_seed_models();
                if let Some(capability) = capability {
                    seed.retain(|m| capability.matches(m));
                }
                (seed, true, Some(format!("{}", error)))
            }
        }
    }
}

#[async_trait::async_trait]
impl LlmProvider for OrcaRouterProvider {
    async fn chat(
        &self,
        system: &str,
        messages: &[Message],
        tools: &[ToolDefinition],
    ) -> Result<LlmResponse> {
        let model = self.model.as_str();
        let body = self.build_body(model, system, messages, tools, false);
        let response = self.send_with_cyber_fallback(model, &body).await?;

        let api_response: serde_json::Value = response
            .json()
            .await
            .context("Failed to parse OrcaRouter response")?;

        parse_orca_response(&api_response)
    }

    async fn chat_stream(
        &self,
        system: &str,
        messages: &[Message],
        tools: &[ToolDefinition],
        on_text: StreamCallback,
    ) -> Result<LlmResponse> {
        let model = self.model.as_str();
        let body = self.build_body(model, system, messages, tools, true);
        let response = self.send_with_cyber_fallback(model, &body).await?;

        let mut state = OrcaStreamState::default();
        let mut stream = response.bytes_stream();
        let mut buffer = String::new();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("Stream read error from OrcaRouter")?;
            buffer.push_str(&String::from_utf8_lossy(&chunk));

            while let Some(line_end) = buffer.find('\n') {
                let line = buffer[..line_end].to_string();
                buffer = buffer[line_end + 1..].to_string();
                if let Some(delta) = state.ingest_line(&line) {
                    on_text(&delta);
                }
            }
        }
        if !buffer.trim().is_empty() {
            if let Some(delta) = state.ingest_line(&buffer) {
                on_text(&delta);
            }
        }

        Ok(state.finish())
    }

    fn name(&self) -> &str {
        "orcarouter"
    }

    fn model(&self) -> &str {
        &self.model
    }
}

/// Live catalog from the process environment, for the `--list-models` CLI path.
///
/// Returns `(models, degraded, error)` using the same fallback semantics as
/// [`OrcaRouterProvider::fetch_models_with_fallback`].
pub async fn orca_catalog_from_env(
    api_key: Option<String>,
    capability: Option<OrcaCapability>,
) -> Result<(Vec<OrcaModelInfo>, bool, Option<String>)> {
    let key = resolve_orca_api_key(api_key)?;
    let provider = OrcaRouterProvider::new(key, None, None)?;
    Ok(provider
        .fetch_models_with_fallback(capability.as_ref())
        .await)
}

/// Outcome of matching a requested model against the live chat catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrcaSelection {
    /// The catalog could not be reached; the requested/default model is kept
    /// and the caller should surface the reason as a degraded warning.
    Unverified { model: String, reason: String },
    /// The catalog was authoritative and the selection is compatible.
    Verified { model: String },
    /// The catalog was authoritative and the selection is not a chat model.
    Rejected { model: String, available: Vec<String> },
}

/// Choose a default chat model from a live catalog.
///
/// Prefers OrcaCyber Zero (business-verified accounts), then the
/// general-purpose fusion model, then the first catalog entry.
pub fn choose_default_chat_model(models: &[OrcaModelInfo]) -> Option<String> {
    for preferred in [ORCA_CYBER_MODEL, ORCA_FALLBACK_MODEL] {
        if models
            .iter()
            .any(|m| m.id == preferred && OrcaCapability::Chat.matches(m))
        {
            return Some(preferred.to_string());
        }
    }
    models
        .iter()
        .find(|m| OrcaCapability::Chat.matches(m))
        .map(|m| m.id.clone())
}

/// Reconcile a requested model with the live catalog.
///
/// This is the CLI counterpart of a model dropdown: options come from
/// `GET /v1/models`, an incompatible value is rejected instead of being sent,
/// and a discovery outage degrades to an explicitly-labelled unverified choice
/// rather than pretending the catalog was consulted.
pub async fn resolve_chat_selection(
    provider: &OrcaRouterProvider,
    requested: Option<&str>,
) -> OrcaSelection {
    let requested = requested.map(|m| m.trim()).filter(|m| !m.is_empty());

    match provider.fetch_models(Some(&OrcaCapability::Chat)).await {
        Ok(models) => {
            let available: Vec<String> = models.iter().map(|m| m.id.clone()).collect();
            match requested {
                Some(model) => {
                    if available.iter().any(|id| id == model) {
                        OrcaSelection::Verified {
                            model: model.to_string(),
                        }
                    } else {
                        OrcaSelection::Rejected {
                            model: model.to_string(),
                            available,
                        }
                    }
                }
                None => match choose_default_chat_model(&models) {
                    Some(model) => OrcaSelection::Verified { model },
                    None => OrcaSelection::Rejected {
                        model: ORCA_CYBER_MODEL.to_string(),
                        available,
                    },
                },
            }
        }
        Err(error) => OrcaSelection::Unverified {
            model: requested.unwrap_or(ORCA_CYBER_MODEL).to_string(),
            reason: format!("{}", error),
        },
    }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum ProviderType {
    Claude,
    Ollama,
    OrcaRouter,
}

impl std::str::FromStr for ProviderType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "claude" | "anthropic" => Ok(ProviderType::Claude),
            "ollama" | "local" => Ok(ProviderType::Ollama),
            "orcarouter" | "orca" | "orca-router" => Ok(ProviderType::OrcaRouter),
            _ => anyhow::bail!(
                "Unknown provider '{}'. Use 'claude', 'ollama', or 'orcarouter'.",
                s
            ),
        }
    }
}

/// Create an LLM provider based on configuration.
pub fn create_provider(
    provider_type: ProviderType,
    model: Option<String>,
    api_key: Option<String>,
    ollama_url: Option<String>,
) -> Result<Box<dyn LlmProvider>> {
    match provider_type {
        ProviderType::Claude => {
            let key = api_key
                .or_else(|| std::env::var("ANTHROPIC_API_KEY").ok())
                .context(
                    "Claude API key required. Set ANTHROPIC_API_KEY env var or use --api-key flag.",
                )?;
            Ok(Box::new(ClaudeProvider::new(key, model)?))
        }
        ProviderType::Ollama => Ok(Box::new(OllamaProvider::new(model, ollama_url)?)),
        ProviderType::OrcaRouter => {
            let key = resolve_orca_api_key(api_key)?;
            Ok(Box::new(OrcaRouterProvider::new(key, model, None)?))
        }
    }
}
