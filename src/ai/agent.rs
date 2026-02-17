// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Main AI agent loop.
//!
//! Orchestrates the conversation between user, LLM, and lonkero scanner.
//! The agent:
//! 1. Takes user input (natural language)
//! 2. Sends it to the LLM with session context and tool definitions
//! 3. If the LLM calls a tool → executes it (lonkero CLI) → feeds result back
//! 4. If the LLM responds with text → shows it to the user
//! 5. Loops until the user exits

use anyhow::{Context, Result};
use regex::Regex;
use std::io::{self, BufRead, Write as IoWrite};
use std::process::Stdio;

use super::provider::{ContentBlock, LlmProvider};
use super::session::Session;
use super::system_prompt::build_system_prompt;
use super::tools;

/// Configuration for the AI agent.
pub struct AgentConfig {
    /// Path to the lonkero binary (default: "lonkero" in PATH)
    pub lonkero_bin: String,

    /// Whether to run in auto mode (no user interaction)
    pub auto_mode: bool,

    /// Maximum tool call rounds before forcing a text response
    pub max_rounds: u32,

    /// License key to pass through to lonkero scans
    pub license_key: Option<String>,

    /// Extra CLI args to pass through to every lonkero invocation
    /// (e.g. --cookie, --token, --proxy, etc.)
    pub passthrough_args: Vec<String>,

    /// Authentication description for the system prompt
    pub auth_info: Option<String>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            lonkero_bin: "lonkero".to_string(),
            auto_mode: false,
            max_rounds: 20,
            license_key: None,
            passthrough_args: Vec::new(),
            auth_info: None,
        }
    }
}

/// Run the interactive AI agent loop.
pub async fn run_agent(
    provider: Box<dyn LlmProvider>,
    target: String,
    config: AgentConfig,
) -> Result<()> {
    let mut session = Session::new(target.clone());
    let tool_defs = tools::get_tool_definitions();
    let system_prompt = build_system_prompt(&target, config.auth_info.as_deref());

    // Print banner
    print_banner(&target, provider.name(), provider.model());

    if config.auto_mode {
        // Auto mode: AI drives the entire pentest autonomously
        run_auto_mode(&provider, &mut session, &tool_defs, &system_prompt, &config).await
    } else {
        // Interactive mode: user drives via natural language
        run_interactive_mode(&provider, &mut session, &tool_defs, &system_prompt, &config).await
    }
}

// ---------------------------------------------------------------------------
// Interactive mode
// ---------------------------------------------------------------------------

async fn run_interactive_mode(
    provider: &Box<dyn LlmProvider>,
    session: &mut Session,
    tool_defs: &[tools::ToolDefinition],
    system_prompt: &str,
    config: &AgentConfig,
) -> Result<()> {
    // Start with an initial recon suggestion
    session.add_user_message(&format!(
        "I want to test {}. Start with reconnaissance to understand the target, \
         then tell me what you found and suggest what to test next.",
        session.target
    ));

    // Run the initial turn
    run_agent_turn(provider, session, tool_defs, system_prompt, config).await?;

    // Interactive loop
    let stdin = io::stdin();
    loop {
        // Prompt for user input
        print!("\n\x1b[36mlonkero-ai>\x1b[0m ");
        io::stdout().flush()?;

        let mut input = String::new();
        let bytes_read = stdin.lock().read_line(&mut input)?;

        // EOF (Ctrl+D)
        if bytes_read == 0 {
            println!("\nSession ended.");
            print_session_summary(session);
            break;
        }

        let input = input.trim();

        // Handle special commands
        match input {
            "" => continue,
            "exit" | "quit" | "q" => {
                print_session_summary(session);
                break;
            }
            "findings" | "results" => {
                println!("{}", session.findings_summary());
                continue;
            }
            "help" => {
                print_help();
                continue;
            }
            _ => {}
        }

        // Send to LLM
        session.add_user_message(input);
        run_agent_turn(provider, session, tool_defs, system_prompt, config).await?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Auto mode
// ---------------------------------------------------------------------------

async fn run_auto_mode(
    provider: &Box<dyn LlmProvider>,
    session: &mut Session,
    tool_defs: &[tools::ToolDefinition],
    system_prompt: &str,
    config: &AgentConfig,
) -> Result<()> {
    println!("\x1b[33m[AUTO MODE]\x1b[0m Running autonomous security assessment...\n");

    session.add_user_message(&format!(
        "Run a complete security assessment of {}. \
         Start with recon, then crawl to discover endpoints, \
         then test the most interesting endpoints with relevant scanners. \
         Focus on high-impact vulnerabilities first. \
         When you've covered the main attack surface, generate a summary of all findings.",
        session.target
    ));

    // Run up to max_rounds of agent turns
    for round in 0..config.max_rounds {
        let turn_result = run_agent_turn(provider, session, tool_defs, system_prompt, config).await;

        match turn_result {
            Ok(()) => {}
            Err(e) => {
                eprintln!("\x1b[31m[Error in round {}]: {}\x1b[0m", round, e);
                break;
            }
        }

        // Check if the LLM's last message was a final text response (no tool calls pending)
        if let Some(last_msg) = session.messages.last() {
            let has_tool_calls = last_msg
                .content
                .iter()
                .any(|b| matches!(b, ContentBlock::ToolUse { .. }));
            if !has_tool_calls {
                // LLM finished with text — auto mode complete
                break;
            }
        }
    }

    print_session_summary(session);
    Ok(())
}

// ---------------------------------------------------------------------------
// Core agent turn: send to LLM, handle tool calls, recurse until text response
// ---------------------------------------------------------------------------

async fn run_agent_turn(
    provider: &Box<dyn LlmProvider>,
    session: &mut Session,
    tool_defs: &[tools::ToolDefinition],
    system_prompt: &str,
    config: &AgentConfig,
) -> Result<()> {
    let mut rounds = 0;
    let max_tool_rounds = 10; // Max consecutive tool call rounds before forcing a response

    loop {
        rounds += 1;
        if rounds > max_tool_rounds {
            tracing::warn!("Max tool call rounds ({}) reached, breaking", max_tool_rounds);
            break;
        }

        // Call the LLM
        let response = provider
            .chat(system_prompt, &session.messages, tool_defs)
            .await
            .context("LLM API call failed")?;

        // Track usage
        if let Some(ref usage) = response.usage {
            session.track_usage(usage.input_tokens, usage.output_tokens);
        }

        // Separate text blocks and tool_use blocks
        let mut text_blocks = Vec::new();
        let mut tool_calls = Vec::new();

        for block in &response.content {
            match block {
                ContentBlock::Text { text } => {
                    text_blocks.push(text.clone());
                }
                ContentBlock::ToolUse { id, name, input } => {
                    tool_calls.push((id.clone(), name.clone(), input.clone()));
                }
                _ => {}
            }
        }

        // Print any text the LLM produced
        for text in &text_blocks {
            if !text.is_empty() {
                println!("\n\x1b[32m{}\x1b[0m", text);
            }
        }

        // Record the assistant message
        session.add_assistant_message(response.content.clone());

        // If no tool calls, the turn is done
        if tool_calls.is_empty() {
            break;
        }

        // Execute tool calls and collect results
        let mut tool_results = Vec::new();

        for (tool_id, tool_name, tool_input) in &tool_calls {
            println!(
                "\n\x1b[33m[Running: {}]\x1b[0m {}",
                tool_name,
                format_tool_input(tool_name, tool_input)
            );

            let result = execute_tool(tool_name, tool_input, session, config).await;

            match &result {
                Ok(output) => {
                    // Parse scan results and merge findings
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(output) {
                        let new_findings = session.merge_findings(&json);
                        if new_findings > 0 {
                            println!(
                                "\x1b[31m  [!] {} new vulnerabilities found\x1b[0m",
                                new_findings
                            );
                        }
                    }

                    // SMAC: Sanitize tool output before LLM ingestion
                    // Removes invisible content (HTML comments, zero-width chars, etc.)
                    // that adversarial targets could use for prompt injection
                    let sanitized = sanitize_for_llm(output);

                    // Truncate very long outputs for the LLM context
                    let truncated = if sanitized.len() > 15000 {
                        format!(
                            "{}...\n\n[Output truncated. {} total chars. Use list_findings to see all results.]",
                            &sanitized[..15000],
                            sanitized.len()
                        )
                    } else {
                        sanitized
                    };

                    tool_results.push(ContentBlock::ToolResult {
                        tool_use_id: tool_id.clone(),
                        content: truncated,
                        is_error: None,
                    });
                }
                Err(e) => {
                    eprintln!("\x1b[31m  [Error]: {}\x1b[0m", e);
                    tool_results.push(ContentBlock::ToolResult {
                        tool_use_id: tool_id.clone(),
                        content: format!("Error: {}", e),
                        is_error: Some(true),
                    });
                }
            }
        }

        // Send tool results back to the LLM
        session.add_tool_results(tool_results);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tool execution
// ---------------------------------------------------------------------------

async fn execute_tool(
    tool_name: &str,
    input: &serde_json::Value,
    session: &Session,
    config: &AgentConfig,
) -> Result<String> {
    match tool_name {
        // Non-CLI tools handled directly
        "list_findings" => Ok(session.findings_summary()),

        "list_modules" => {
            // Return the module list from our knowledge
            Ok(get_module_list())
        }

        "generate_report" => {
            let format = input["format"].as_str().unwrap_or("json");
            let report = generate_session_report(session, format);
            if let Some(path) = input["output_path"].as_str() {
                std::fs::write(path, &report)
                    .context(format!("Failed to write report to {}", path))?;
                Ok(format!("Report written to: {}", path))
            } else {
                Ok(report)
            }
        }

        // CLI-backed tools — translate to lonkero command and execute
        _ => {
            let cli_args = tools::tool_to_cli_args(tool_name, input)
                .context(format!("Unknown tool: {}", tool_name))?;

            execute_lonkero(&config.lonkero_bin, &cli_args, &config.passthrough_args, &config.license_key).await
        }
    }
}

/// Execute lonkero CLI and capture JSON output.
/// Streams stderr to the terminal in real-time so the user sees scan progress,
/// while capturing stdout for JSON result parsing.
async fn execute_lonkero(
    bin: &str,
    args: &[String],
    passthrough: &[String],
    license_key: &Option<String>,
) -> Result<String> {
    let mut cmd_args = args.to_vec();

    // Add passthrough args (cookie, token, proxy, etc.)
    cmd_args.extend_from_slice(passthrough);

    // Add license key if available
    if let Some(ref key) = license_key {
        cmd_args.push("--license-key".into());
        cmd_args.push(key.clone());
    }

    tracing::debug!("Executing: {} {}", bin, cmd_args.join(" "));

    let mut child = tokio::process::Command::new(bin)
        .args(&cmd_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit()) // Stream stderr to terminal for real-time progress
        .spawn()
        .context(format!("Failed to execute lonkero. Is '{}' in PATH?", bin))?;

    // Read stdout while the child runs
    let stdout_handle = child.stdout.take();
    let stdout = if let Some(stdout_pipe) = stdout_handle {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        let mut reader = tokio::io::BufReader::new(stdout_pipe);
        reader.read_to_end(&mut buf).await.unwrap_or(0);
        String::from_utf8_lossy(&buf).to_string()
    } else {
        String::new()
    };

    let status = child.wait().await
        .context("Failed to wait for lonkero process")?;

    if !status.success() {
        // Scan produced JSON output even though exit code was non-zero
        // (this can happen with license warnings, etc.)
        if !stdout.is_empty() && (stdout.starts_with('{') || stdout.starts_with('[')) {
            return Ok(stdout);
        }
        anyhow::bail!(
            "lonkero exited with {}",
            status,
        );
    }

    if stdout.is_empty() {
        Ok("Scan completed. No JSON output produced.".to_string())
    } else {
        Ok(stdout)
    }
}

// ---------------------------------------------------------------------------
// SMAC: Secure Markdown/HTML for AI Consumption + GhostCSS Defenses
// ---------------------------------------------------------------------------
// Sanitizes tool output before it enters the LLM context, preventing
// prompt injection via invisible content in scanned targets.
//
// SMAC-1: Strip HTML comments (<!-- ... -->)
// SMAC-2: Strip markdown reference-only links ([//]: # (...))
// SMAC-3: Strip zero-width Unicode characters
// SMAC-4: Log discarded content for audit trail
// SMAC-5: System prompt boundary (in system_prompt.rs)
//
// GhostCSS defenses:
// GCSS-1: Strip elements with inline style display:none / visibility:hidden / opacity:0
// GCSS-2: Strip elements with sr-only / visually-hidden / screen-reader-text classes
// GCSS-3: Strip elements with aria-hidden="true"
// GCSS-4: Strip elements with style containing off-screen positioning, zero font-size, etc.
// GCSS-5: Strip CSS-generated content (::before/::after content properties)

/// Sanitize scan output before passing to the LLM.
/// Removes invisible content that could contain prompt injection payloads
/// from adversarial targets being scanned.
fn sanitize_for_llm(input: &str) -> String {
    // SMAC-1: Strip HTML comments (primary injection vector)
    let html_comment_re = Regex::new(r"(?s)<!--.*?-->").unwrap();
    let stripped = html_comment_re.replace_all(input, "");

    // SMAC-2: Strip markdown reference-only links (invisible metadata)
    let md_ref_re = Regex::new(r#"(?m)^\[//\]:\s*#\s*[\("](.*?)[\)"]\s*$"#).unwrap();
    let stripped = md_ref_re.replace_all(&stripped, "");

    // GCSS-1: Strip HTML elements with inline visibility-hiding styles
    // Matches <tag style="...display:none...">...content...</tag> and self-closing variants
    let hidden_style_re = Regex::new(
        r#"(?si)<(\w+)\s[^>]*style\s*=\s*"[^"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?(?:\s|;|"))[^"]*"[^>]*>.*?</\1>"#
    ).unwrap();
    let stripped = hidden_style_re.replace_all(&stripped, "");

    // GCSS-1b: Self-closing hidden elements (e.g. <input style="display:none" .../>)
    let hidden_self_closing_re = Regex::new(
        r#"(?si)<\w+\s[^>]*style\s*=\s*"[^"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?(?:\s|;|"))[^"]*"[^>]*/>"#
    ).unwrap();
    let stripped = hidden_self_closing_re.replace_all(&stripped, "");

    // GCSS-2: Strip elements with screen-reader-only / visually-hidden classes
    let sr_only_re = Regex::new(
        r#"(?si)<(\w+)\s[^>]*class\s*=\s*"[^"]*(?:sr-only|visually-hidden|screen-reader-text|clip-hide|a11y-hidden)[^"]*"[^>]*>.*?</\1>"#
    ).unwrap();
    let stripped = sr_only_re.replace_all(&stripped, "");

    // GCSS-3: Strip elements with aria-hidden="true"
    let aria_hidden_re = Regex::new(
        r#"(?si)<(\w+)\s[^>]*aria-hidden\s*=\s*"true"[^>]*>.*?</\1>"#
    ).unwrap();
    let stripped = aria_hidden_re.replace_all(&stripped, "");

    // GCSS-4: Strip elements with off-screen positioning and size tricks
    // Catches: position:absolute with large negative left/top, font-size:0,
    // height:0;overflow:hidden, text-indent:-9999px, clip:rect(0,0,0,0)
    let offscreen_re = Regex::new(
        r#"(?si)<(\w+)\s[^>]*style\s*=\s*"[^"]*(?:text-indent\s*:\s*-\d{4,}|font-size\s*:\s*0(?:px)?(?:\s|;|")|clip\s*:\s*rect\s*\(\s*0|clip-path\s*:\s*inset\s*\(\s*(?:50|100)%)[^"]*"[^>]*>.*?</\1>"#
    ).unwrap();
    let stripped = offscreen_re.replace_all(&stripped, "");

    // GCSS-5: Strip CSS content property declarations (used in ::before/::after injection)
    let css_content_re = Regex::new(
        r#"(?si)content\s*:\s*"[^"]{20,}""#
    ).unwrap();
    let stripped = css_content_re.replace_all(&stripped, r#"content:"""#);

    // SMAC-3: Strip zero-width characters and Unicode tricks used for invisible text
    let stripped = stripped
        .replace('\u{200B}', "")  // Zero-width space
        .replace('\u{200C}', "")  // Zero-width non-joiner
        .replace('\u{200D}', "")  // Zero-width joiner
        .replace('\u{FEFF}', "")  // Zero-width no-break space (BOM)
        .replace('\u{2060}', "")  // Word joiner
        .replace('\u{2062}', "")  // Invisible times
        .replace('\u{2063}', "")  // Invisible separator
        .replace('\u{2064}', ""); // Invisible plus

    // SMAC-4: Log if anything was stripped (audit trail)
    if stripped.len() < input.len() {
        let bytes_stripped = input.len() - stripped.len();
        tracing::info!(
            "[SMAC/GhostCSS] Stripped {} bytes of invisible/hidden content before LLM ingestion",
            bytes_stripped
        );
    }

    stripped
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn format_tool_input(tool_name: &str, input: &serde_json::Value) -> String {
    match tool_name {
        "recon" | "crawl" | "scan_xss" | "scan_sqli" | "scan_ssrf" | "scan_idor"
        | "scan_auth" | "scan_injection" | "scan_graphql" | "scan_api"
        | "scan_waf_bypass" | "scan_business_logic" | "full_scan" => {
            let url = input["url"].as_str().unwrap_or("?");
            let intensity = input["intensity"].as_str().unwrap_or("standard");
            format!("{} (intensity: {})", url, intensity)
        }
        "scan_framework" => {
            let url = input["url"].as_str().unwrap_or("?");
            let fw = input["framework"].as_str().unwrap_or("?");
            format!("{} (framework: {})", url, fw)
        }
        "scan_custom" => {
            let url = input["url"].as_str().unwrap_or("?");
            let modules = input["modules"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            format!("{} (modules: {})", url, modules)
        }
        "subdomain_enum" => {
            let domain = input["domain"].as_str().unwrap_or("?");
            domain.to_string()
        }
        _ => format!("{}", input),
    }
}

fn get_module_list() -> String {
    let ids = crate::modules::ids::get_all_module_ids();
    let mut output = format!("Available scanner modules ({} total):\n\n", ids.len());
    for id in ids {
        let tier = crate::modules::ids::get_required_feature(id)
            .unwrap_or("free");
        output.push_str(&format!("  {:40} [{}]\n", id, tier));
    }
    output
}

fn generate_session_report(session: &Session, format: &str) -> String {
    // For now, generate a JSON report of all findings
    // In the future, this could invoke lonkero's reporting module
    match format {
        "json" => {
            serde_json::to_string_pretty(&serde_json::json!({
                "target": session.target,
                "totalFindings": session.findings.len(),
                "scansRun": session.scan_count,
                "endpointsTested": session.tested.len(),
                "findings": session.findings,
                "tokenUsage": {
                    "inputTokens": session.total_input_tokens,
                    "outputTokens": session.total_output_tokens,
                }
            }))
            .unwrap_or_else(|_| "Error generating JSON report".into())
        }
        "markdown" => {
            let mut md = format!("# Security Assessment: {}\n\n", session.target);
            md.push_str(&format!(
                "**Scans:** {} | **Endpoints:** {} | **Findings:** {}\n\n",
                session.scan_count,
                session.tested.len(),
                session.findings.len()
            ));

            let severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
            for severity in &severity_order {
                let in_sev: Vec<&_> = session
                    .findings
                    .iter()
                    .filter(|f| f.severity.to_uppercase() == *severity)
                    .collect();
                if in_sev.is_empty() {
                    continue;
                }
                md.push_str(&format!("\n## {} ({})\n\n", severity, in_sev.len()));
                for f in in_sev {
                    md.push_str(&format!("### {}\n", f.vuln_type));
                    md.push_str(&format!("- **URL:** {}\n", f.url));
                    if let Some(ref p) = f.parameter {
                        md.push_str(&format!("- **Parameter:** {}\n", p));
                    }
                    md.push_str(&format!("- **Confidence:** {}\n", f.confidence));
                    md.push_str(&format!("- **Description:** {}\n", f.description));
                    if let Some(ref r) = f.remediation {
                        md.push_str(&format!("- **Remediation:** {}\n", r));
                    }
                    md.push('\n');
                }
            }
            md
        }
        _ => format!(
            "Report format '{}' not yet supported in AI session mode. Use 'json' or 'markdown'.",
            format
        ),
    }
}

fn print_banner(target: &str, provider: &str, model: &str) {
    println!();
    println!("\x1b[36m================================================================\x1b[0m");
    println!("\x1b[36m  Lonkero AI - Interactive Security Testing Agent\x1b[0m");
    println!("\x1b[36m================================================================\x1b[0m");
    println!("  Target:   {}", target);
    println!("  Provider: {} ({})", provider, model);
    println!();
    println!("  Type natural language commands to guide the assessment.");
    println!("  The AI will run targeted scans and reason about results.");
    println!();
    println!("  Commands: 'help', 'findings', 'exit'");
    println!("\x1b[36m================================================================\x1b[0m");
    println!();
}

fn print_help() {
    println!();
    println!("\x1b[36m--- Lonkero AI Help ---\x1b[0m");
    println!();
    println!("  Natural language examples:");
    println!("    'scan for XSS on the search page'");
    println!("    'test the API for IDOR'");
    println!("    'dig deeper into that finding'");
    println!("    'try to bypass the WAF'");
    println!("    'check for SQL injection with maximum payloads'");
    println!("    'run the JWT scanner on /api/auth/token'");
    println!("    'generate a markdown report'");
    println!("    'what should we test next?'");
    println!();
    println!("  Special commands:");
    println!("    findings  - Show all findings so far");
    println!("    help      - Show this help");
    println!("    exit      - End session and show summary");
    println!();
}

fn print_session_summary(session: &Session) {
    println!();
    println!("\x1b[36m================================================================\x1b[0m");
    println!("\x1b[36m  Session Summary\x1b[0m");
    println!("\x1b[36m================================================================\x1b[0m");
    println!("  Target:           {}", session.target);
    println!("  Scans executed:   {}", session.scan_count);
    println!("  Endpoints tested: {}", session.tested.len());
    println!("  Findings:         {}", session.findings.len());

    // Breakdown by severity
    let critical = session.findings.iter().filter(|f| f.severity == "CRITICAL").count();
    let high = session.findings.iter().filter(|f| f.severity == "HIGH").count();
    let medium = session.findings.iter().filter(|f| f.severity == "MEDIUM").count();
    let low = session.findings.iter().filter(|f| f.severity == "LOW").count();

    if !session.findings.is_empty() {
        println!(
            "    \x1b[31mCRITICAL: {}\x1b[0m  \x1b[91mHIGH: {}\x1b[0m  \x1b[33mMEDIUM: {}\x1b[0m  LOW: {}",
            critical, high, medium, low
        );
    }

    println!("  Token usage:      {} in / {} out",
        session.total_input_tokens, session.total_output_tokens);

    // Estimate cost (Sonnet pricing)
    let cost_estimate = (session.total_input_tokens as f64 * 3.0 / 1_000_000.0)
        + (session.total_output_tokens as f64 * 15.0 / 1_000_000.0);
    println!("  Est. API cost:    ${:.4}", cost_estimate);

    println!("\x1b[36m================================================================\x1b[0m");
    println!();
}
