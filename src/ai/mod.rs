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
//! - Form and test hypotheses about the target
//! - Synthesize exploit chains from individual findings
//! - Save/resume sessions for multi-day assessments
//! - Enforce scope and intensity guardrails
//! - Send custom HTTP requests for manual probing
//!
//! Architecture:
//! - `provider`: LLM backend abstraction (Claude API with prompt caching, Ollama)
//! - `tools`: Lonkero capabilities + analysis tools exposed as LLM tool definitions
//! - `system_prompt`: Scanner knowledge base + methodology injected into the LLM
//! - `session`: Conversation, findings, hypotheses, knowledge graph, scope, audit log
//! - `agent`: Main interactive agent loop with scope enforcement and progress tracking
//!
//! ## Capability Categories
//! - Cat 1 (Memory & Learning): Session persistence, knowledge graph, attack patterns
//! - Cat 2 (Reasoning & Planning): Hypotheses, attack plans, audit log, reasoning trail
//! - Cat 3 (Tool Execution): Custom HTTP requests, scope-checked scan dispatch
//! - Cat 4 (Analysis): FP triage, exploit chain synthesis, severity re-assessment
//! - Cat 5 (Provider & Model): Prompt caching, token budget, cache token tracking
//! - Cat 6 (Security & Guardrails): Scope enforcement, intensity limits, credential rotation detection, output redaction
//! - Cat 7 (User Experience): Phase-based progress tracking, session export, enhanced help
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
