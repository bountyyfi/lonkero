// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! LLM Provider abstraction layer.
//!
//! Supports:
//! - Claude API (Anthropic) — default, best reasoning
//! - Ollama (local) — offline/privacy mode

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
            max_tokens: 4096,
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
        // Build Claude API request body
        let mut body = serde_json::json!({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system,
            "messages": messages,
        });

        // Only include tools if we have them
        if !tools.is_empty() {
            let claude_tools: Vec<serde_json::Value> = tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name,
                        "description": t.description,
                        "input_schema": t.input_schema,
                    })
                })
                .collect();
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
            Some(Usage {
                input_tokens: u["input_tokens"].as_u64().unwrap_or(0),
                output_tokens: u["output_tokens"].as_u64().unwrap_or(0),
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
        // Build Claude API request body with stream: true
        let mut body = serde_json::json!({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system,
            "messages": messages,
            "stream": true,
        });

        if !tools.is_empty() {
            let claude_tools: Vec<serde_json::Value> = tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name,
                        "description": t.description,
                        "input_schema": t.input_schema,
                    })
                })
                .collect();
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
                                });
                            }
                        }
                        Some("message_start") => {
                            if let Some(msg) = event.get("message") {
                                if let Some(u) = msg.get("usage") {
                                    let input_tokens =
                                        u["input_tokens"].as_u64().unwrap_or(0);
                                    // message_start has input_tokens, message_delta has output_tokens
                                    // We'll merge them
                                    usage = Some(Usage {
                                        input_tokens,
                                        output_tokens: 0,
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
// Factory
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum ProviderType {
    Claude,
    Ollama,
}

impl std::str::FromStr for ProviderType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "claude" | "anthropic" => Ok(ProviderType::Claude),
            "ollama" | "local" => Ok(ProviderType::Ollama),
            _ => anyhow::bail!("Unknown provider '{}'. Use 'claude' or 'ollama'.", s),
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
    }
}
