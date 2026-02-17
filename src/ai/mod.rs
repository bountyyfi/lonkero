// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! AI-Powered Interactive Security Testing Agent
//!
//! This module adds an AI agent layer on top of Lonkero's scanning engine.
//! The agent can:
//! - Run surgical, single-module scans (not just full blasts)
//! - Reason about findings and decide what to test next
//! - Maintain session state across a multi-step pentest
//! - Take user direction via natural language
//!
//! Architecture:
//! - `provider`: LLM backend abstraction (Claude API, Ollama)
//! - `tools`: Lonkero capabilities exposed as LLM tool definitions
//! - `system_prompt`: Scanner knowledge base injected into the LLM
//! - `session`: Conversation + findings state management
//! - `agent`: Main interactive agent loop
//!
//! Usage:
//!   lonkero ai <target>
//!   lonkero ai <target> --provider claude --model claude-sonnet-4-5
//!   lonkero ai <target> --provider ollama --model llama3.1:70b
//!   lonkero ai <target> --auto --format pdf -o report.pdf

pub mod agent;
pub mod provider;
pub mod session;
pub mod system_prompt;
pub mod tools;
