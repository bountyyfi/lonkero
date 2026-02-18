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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

use super::provider::{ContentBlock, LlmProvider, StreamCallback};
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

    /// License tier for display (e.g. "Personal", "Professional", "Enterprise")
    pub license_type: Option<String>,

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
            license_type: None,
            passthrough_args: Vec::new(),
            auth_info: None,
        }
    }
}

/// User input event sent from the stdin reader task.
enum UserInput {
    /// A line of text from the user
    Line(String),
    /// EOF (Ctrl+D) — user wants to quit
    Eof,
}

/// Spawn a background task that reads stdin lines and sends them through a channel.
/// This allows the agent loop to remain responsive while waiting for user input.
fn spawn_stdin_reader() -> mpsc::UnboundedReceiver<UserInput> {
    let (tx, rx) = mpsc::unbounded_channel();
    // Use a blocking thread since stdin is synchronous
    std::thread::spawn(move || {
        let stdin = io::stdin();
        loop {
            let mut line = String::new();
            match stdin.lock().read_line(&mut line) {
                Ok(0) => {
                    // EOF
                    let _ = tx.send(UserInput::Eof);
                    break;
                }
                Ok(_) => {
                    let _ = tx.send(UserInput::Line(line));
                }
                Err(_) => {
                    let _ = tx.send(UserInput::Eof);
                    break;
                }
            }
        }
    });
    rx
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
    print_banner(&target, provider.name(), provider.model(), config.license_type.as_deref());

    // Spawn async stdin reader — shared between interactive and auto mode
    let mut stdin_rx = spawn_stdin_reader();

    if config.auto_mode {
        run_auto_mode(&provider, &mut session, &tool_defs, &system_prompt, &config, &mut stdin_rx).await
    } else {
        run_interactive_mode(&provider, &mut session, &tool_defs, &system_prompt, &config, &mut stdin_rx).await
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
    stdin_rx: &mut mpsc::UnboundedReceiver<UserInput>,
) -> Result<()> {
    // Start with an initial recon suggestion
    session.add_user_message(&format!(
        "I want to test {}. Start with reconnaissance to understand the target, \
         then tell me what you found and suggest what to test next.",
        session.target
    ));

    // Run the initial turn
    run_agent_turn(provider, session, tool_defs, system_prompt, config, stdin_rx).await?;

    // Interactive loop — reads from channel, never blocks the event loop
    loop {
        print!("\n\x1b[36mlonkero-ai>\x1b[0m ");
        io::stdout().flush()?;

        // Wait for user input from the background reader
        let input = match stdin_rx.recv().await {
            Some(UserInput::Line(line)) => line,
            Some(UserInput::Eof) | None => {
                println!("\nSession ended.");
                print_session_summary(session);
                break;
            }
        };

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
        run_agent_turn(provider, session, tool_defs, system_prompt, config, stdin_rx).await?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Auto mode — AI drives the pentest, user can chat anytime
// ---------------------------------------------------------------------------

async fn run_auto_mode(
    provider: &Box<dyn LlmProvider>,
    session: &mut Session,
    tool_defs: &[tools::ToolDefinition],
    system_prompt: &str,
    config: &AgentConfig,
    stdin_rx: &mut mpsc::UnboundedReceiver<UserInput>,
) -> Result<()> {
    println!("\x1b[33m[AUTO MODE]\x1b[0m Running autonomous security assessment...");
    println!("\x1b[90m  You can type commands anytime — they'll be processed between scan rounds.\x1b[0m");
    println!("\x1b[90m  Type 'findings' to check progress, 'help' for commands, 'exit' to stop.\x1b[0m\n");

    session.add_user_message(&format!(
        "Run a security assessment of {}. Follow this approach:\n\
         1. Run recon to understand the target\n\
         2. Crawl to discover endpoints and parameters\n\
         3. Based on what you find, run TARGETED scans on specific endpoints:\n\
            - Use scan_xss, scan_sqli, scan_idor etc. on individual endpoints\n\
            - Pick scanners based on what recon/crawl reveals (e.g. forms → XSS, APIs → IDOR)\n\
            - Do NOT use full_scan — use specific scanners on specific URLs\n\
         4. After testing key endpoints, summarize all findings.\n\
         Focus on high-impact vulnerabilities. Be surgical, not noisy.",
        session.target
    ));

    // Run up to max_rounds of agent turns
    for round in 0..config.max_rounds {
        let turn_result = run_agent_turn(provider, session, tool_defs, system_prompt, config, stdin_rx).await;

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
                // LLM finished — auto scan complete
                // Drop into interactive mode so user can ask follow-ups
                println!("\n\x1b[33m[Auto scan complete]\x1b[0m Type a follow-up or 'exit' to finish.");

                loop {
                    print!("\n\x1b[36mlonkero-ai>\x1b[0m ");
                    io::stdout().flush()?;

                    let input = match stdin_rx.recv().await {
                        Some(UserInput::Line(line)) => line,
                        Some(UserInput::Eof) | None => break,
                    };

                    let input = input.trim();

                    match input {
                        "" => continue,
                        "exit" | "quit" | "q" => break,
                        "findings" | "results" => {
                            println!("{}", session.findings_summary());
                            continue;
                        }
                        "help" => {
                            print_help();
                            continue;
                        }
                        _ => {
                            session.add_user_message(input);
                            if let Err(e) = run_agent_turn(provider, session, tool_defs, system_prompt, config, stdin_rx).await {
                                eprintln!("\x1b[31m[Error]: {}\x1b[0m", e);
                            }
                        }
                    }
                }
                break;
            }
        }
    }

    print_session_summary(session);
    Ok(())
}

fn print_auto_help() {
    println!();
    println!("\x1b[36m--- Auto Mode Commands ---\x1b[0m");
    println!();
    println!("  Type while scans run — commands are processed between rounds:");
    println!("    findings  - Show all findings found so far");
    println!("    exit      - Stop auto mode and show summary");
    println!("    <text>    - Send a message to the AI (e.g. 'also test /admin')");
    println!();
}

// ---------------------------------------------------------------------------
// Core agent turn: send to LLM, handle tool calls, recurse until text response
// ---------------------------------------------------------------------------

/// Status line displayed during long-running operations.
/// Instead of a spinner that uses cursor movement (which interferes with
/// user input echo), we print a static status line and let the user type
/// freely below it. No cursor movement, no line clearing.
fn print_status(label: &str) {
    eprintln!("\x1b[90m  [{}]\x1b[0m", label);
}

/// Drain queued user input from the channel.
/// Handles built-in commands (findings, help) immediately.
/// Returns (user_messages, should_exit).
fn drain_user_input(
    stdin_rx: &mut mpsc::UnboundedReceiver<UserInput>,
    session: &Session,
) -> (Vec<String>, bool) {
    let mut user_messages = Vec::new();
    loop {
        match stdin_rx.try_recv() {
            Ok(UserInput::Line(line)) => {
                let trimmed = line.trim().to_string();
                if trimmed.is_empty() {
                    continue;
                }
                match trimmed.as_str() {
                    "exit" | "quit" | "q" => {
                        return (user_messages, true);
                    }
                    "findings" | "results" => {
                        println!("\n{}", session.findings_summary());
                    }
                    "help" => {
                        print_auto_help();
                    }
                    _ => {
                        println!("\x1b[90m  [Queued: \"{}\" — will send to AI after current scan]\x1b[0m", trimmed);
                        user_messages.push(trimmed);
                    }
                }
            }
            Ok(UserInput::Eof) => {
                return (user_messages, true);
            }
            Err(mpsc::error::TryRecvError::Empty) => break,
            Err(mpsc::error::TryRecvError::Disconnected) => {
                return (user_messages, true);
            }
        }
    }
    (user_messages, false)
}

async fn run_agent_turn(
    provider: &Box<dyn LlmProvider>,
    session: &mut Session,
    tool_defs: &[tools::ToolDefinition],
    system_prompt: &str,
    config: &AgentConfig,
    stdin_rx: &mut mpsc::UnboundedReceiver<UserInput>,
) -> Result<()> {
    let mut rounds = 0;
    let max_tool_rounds = 10; // Max consecutive tool call rounds before forcing a response

    loop {
        rounds += 1;
        if rounds > max_tool_rounds {
            tracing::warn!("Max tool call rounds ({}) reached, breaking", max_tool_rounds);
            break;
        }

        // Drain any queued user input between LLM rounds
        let (user_msgs, should_exit) = drain_user_input(stdin_rx, session);
        if should_exit {
            break;
        }
        if !user_msgs.is_empty() {
            let combined = user_msgs.join("\n");
            println!("\n\x1b[36m[User]\x1b[0m {}", combined);
            session.add_user_message(&format!(
                "[User message during scan]: {}\n\
                 Address this and continue with the assessment.",
                combined
            ));
        }

        // Show status while waiting for LLM
        print_status("Thinking...");

        // Use streaming to print text as it arrives
        let started_printing = Arc::new(AtomicBool::new(false));
        let started_ref = started_printing.clone();
        let on_text: StreamCallback = Box::new(move |delta: &str| {
            if !started_ref.swap(true, Ordering::Relaxed) {
                print!("\n\x1b[32m");
            }
            print!("{}", delta);
            let _ = io::stdout().flush();
        });

        let response = provider
            .chat_stream(system_prompt, &session.messages, tool_defs, on_text)
            .await
            .context("LLM API call failed")?;

        // Close the green color if we printed streaming text
        if started_printing.load(Ordering::Relaxed) {
            println!("\x1b[0m");
        }

        // Track usage
        if let Some(ref usage) = response.usage {
            session.track_usage(usage.input_tokens, usage.output_tokens);
        }

        // Extract tool calls from response
        let mut tool_calls = Vec::new();
        for block in &response.content {
            if let ContentBlock::ToolUse { id, name, input } = block {
                tool_calls.push((id.clone(), name.clone(), input.clone()));
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
        let mut pending_user_msgs: Vec<String> = Vec::new();

        for (tool_id, tool_name, tool_input) in &tool_calls {
            println!(
                "\n\x1b[33m[Running: {}]\x1b[0m {}",
                tool_name,
                format_tool_input(&tool_name, &tool_input)
            );

            // Handle non-CLI tools synchronously (they're instant, no need for select!)
            if let Some(instant_result) = handle_instant_tool(&tool_name, &tool_input, session) {
                match &instant_result {
                    Ok(output) => {
                        tool_results.push(ContentBlock::ToolResult {
                            tool_use_id: tool_id.clone(),
                            content: sanitize_and_truncate(output),
                            is_error: None,
                        });
                    }
                    Err(e) => {
                        tool_results.push(ContentBlock::ToolResult {
                            tool_use_id: tool_id.clone(),
                            content: format!("Error: {}", e),
                            is_error: Some(true),
                        });
                    }
                }
                continue;
            }

            // CLI-backed tool — run concurrently with user input monitoring.
            // This is the key: while lonkero scan runs (which can take minutes),
            // we simultaneously listen for user input and acknowledge it.
            let tool_future = execute_cli_tool(&tool_name, &tool_input, config);
            tokio::pin!(tool_future);

            let result = loop {
                tokio::select! {
                    // Tool finished — we have the result
                    result = &mut tool_future => {
                        break result;
                    }
                    // User typed something while tool is running
                    input = stdin_rx.recv() => {
                        match input {
                            Some(UserInput::Line(line)) => {
                                let trimmed = line.trim().to_string();
                                if trimmed.is_empty() {
                                    continue;
                                }
                                match trimmed.as_str() {
                                    "exit" | "quit" | "q" => {
                                        println!("\n\x1b[33m[Stopping — waiting for current scan to finish...]\x1b[0m");
                                        // Let the current tool finish, then exit
                                        let result = tool_future.await;
                                        // Record partial result
                                        match &result {
                                            Ok(output) => {
                                                if let Ok(json) = serde_json::from_str::<serde_json::Value>(output) {
                                                    session.merge_findings(&json);
                                                }
                                                tool_results.push(ContentBlock::ToolResult {
                                                    tool_use_id: tool_id.clone(),
                                                    content: sanitize_and_truncate(output),
                                                    is_error: None,
                                                });
                                            }
                                            Err(e) => {
                                                tool_results.push(ContentBlock::ToolResult {
                                                    tool_use_id: tool_id.clone(),
                                                    content: format!("Error: {}", e),
                                                    is_error: Some(true),
                                                });
                                            }
                                        }
                                        session.add_tool_results(tool_results);
                                        return Ok(());
                                    }
                                    "findings" | "results" => {
                                        println!("\n{}", session.findings_summary());
                                    }
                                    "help" => {
                                        print_auto_help();
                                    }
                                    _ => {
                                        println!("\n\x1b[36m  [Received]\x1b[0m \"{}\" — will send to AI after this scan finishes.", trimmed);
                                        pending_user_msgs.push(trimmed);
                                    }
                                }
                            }
                            Some(UserInput::Eof) | None => {
                                // EOF during scan — let it finish
                                break tool_future.await;
                            }
                        }
                    }
                }
            };

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

                    tool_results.push(ContentBlock::ToolResult {
                        tool_use_id: tool_id.clone(),
                        content: sanitize_and_truncate(output),
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

        // Inject any user messages that arrived during tool execution
        if !pending_user_msgs.is_empty() {
            let combined = pending_user_msgs.join("\n");
            println!("\n\x1b[36m[User]\x1b[0m {}", combined);
            session.add_user_message(&format!(
                "[User message during scan]: {}\n\
                 Address this and continue with the assessment.",
                combined
            ));
            pending_user_msgs.clear();
        }
    }

    Ok(())
}

/// Extract a human-readable error reason from lonkero's stderr output.
/// Lonkero logs look like: "2026-02-18T... ERROR Scanner disabled: License has been deactivated"
/// We want to extract just: "Scanner disabled: License has been deactivated"
fn extract_error_reason(stderr: &str) -> String {
    if stderr.is_empty() {
        return "Scan failed (no error output)".to_string();
    }

    // Look for ERROR lines and extract the message after "ERROR "
    let error_messages: Vec<&str> = stderr
        .lines()
        .filter_map(|line| {
            if let Some(pos) = line.find("ERROR ") {
                let msg = line[pos + 6..].trim();
                // Skip decorative lines (=====)
                if msg.is_empty() || msg.chars().all(|c| c == '=') {
                    None
                } else {
                    Some(msg)
                }
            } else {
                None
            }
        })
        .collect();

    if !error_messages.is_empty() {
        // Return the most meaningful error line (usually the first non-header one)
        // Common pattern: "LICENSE VERIFICATION FAILED" then "Scanner disabled: reason"
        for msg in &error_messages {
            if msg.starts_with("Scanner disabled:") || msg.contains("deactivated") || msg.contains("expired") {
                return msg.to_string();
            }
        }
        // Fall back to joining unique error messages
        let unique: Vec<&str> = error_messages.into_iter().take(3).collect();
        return unique.join(" — ");
    }

    // No ERROR lines found — check for "Error:" at end of output (anyhow error)
    if let Some(last_line) = stderr.lines().last() {
        if last_line.starts_with("Error:") {
            return last_line.to_string();
        }
    }

    // Fall back: last 3 lines of stderr
    let lines: Vec<&str> = stderr.lines().collect();
    let relevant: Vec<&str> = lines.iter().rev().take(3).rev().copied().collect();
    relevant.join("\n")
}

/// Sanitize and truncate tool output for LLM context.
fn sanitize_and_truncate(output: &str) -> String {
    let sanitized = sanitize_for_llm(output);
    if sanitized.len() > 15000 {
        format!(
            "{}...\n\n[Output truncated. {} total chars. Use list_findings to see all results.]",
            &sanitized[..15000],
            sanitized.len()
        )
    } else {
        sanitized
    }
}

// ---------------------------------------------------------------------------
// Tool execution
// ---------------------------------------------------------------------------

/// Handle tools that are instant (no CLI execution needed).
/// Returns Some(result) if handled, None if this is a CLI tool.
fn handle_instant_tool(
    tool_name: &str,
    input: &serde_json::Value,
    session: &Session,
) -> Option<Result<String>> {
    match tool_name {
        "list_findings" => Some(Ok(session.findings_summary())),

        "list_modules" => Some(Ok(get_module_list())),

        "generate_report" => {
            let format = input["format"].as_str().unwrap_or("json");
            let report = generate_session_report(session, format);
            if let Some(path) = input["output_path"].as_str() {
                match std::fs::write(path, &report) {
                    Ok(()) => Some(Ok(format!("Report written to: {}", path))),
                    Err(e) => Some(Err(anyhow::anyhow!("Failed to write report to {}: {}", path, e))),
                }
            } else {
                Some(Ok(report))
            }
        }

        _ => None, // CLI tool — needs async execution
    }
}

/// Execute a CLI-backed tool. Does not borrow Session, so can be run
/// concurrently with user input handling via tokio::select!
async fn execute_cli_tool(
    tool_name: &str,
    input: &serde_json::Value,
    config: &AgentConfig,
) -> Result<String> {
    let cli_args = tools::tool_to_cli_args(tool_name, input)
        .context(format!("Unknown tool: {}", tool_name))?;

    execute_lonkero(&config.lonkero_bin, &cli_args, &config.passthrough_args, &config.license_key).await
}

/// Execute lonkero CLI and capture JSON output.
/// Captures both stdout (JSON results) and stderr (progress/errors).
/// Stderr is streamed to the terminal in real-time for progress visibility.
async fn execute_lonkero(
    bin: &str,
    args: &[String],
    passthrough: &[String],
    license_key: &Option<String>,
) -> Result<String> {
    // Build args: license key goes BEFORE the subcommand for clap global args
    let resolved_key = license_key.clone()
        .or_else(|| std::env::var("LONKERO_LICENSE_KEY").ok());

    let mut cmd_args = Vec::new();
    if let Some(ref key) = resolved_key {
        cmd_args.push("--license-key".into());
        cmd_args.push(key.clone());
    }
    // Now add the subcommand and its args (e.g. "scan", url, "--only", ...)
    cmd_args.extend_from_slice(args);
    // Add passthrough args (cookie, token, proxy, etc.)
    cmd_args.extend_from_slice(passthrough);

    tracing::debug!("Executing: {} {}", bin, cmd_args.join(" "));

    let mut cmd = tokio::process::Command::new(bin);
    cmd.args(&cmd_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Also set the env var on the child process to ensure it's available
    if let Some(ref key) = resolved_key {
        cmd.env("LONKERO_LICENSE_KEY", key);
    }

    let mut child = cmd
        .spawn()
        .context(format!("Failed to execute lonkero. Is '{}' in PATH?", bin))?;

    // Read both stdout and stderr concurrently
    let stdout_handle = child.stdout.take();
    let stderr_handle = child.stderr.take();

    let stdout_fut = async {
        if let Some(pipe) = stdout_handle {
            use tokio::io::AsyncReadExt;
            let mut buf = Vec::new();
            let mut reader = tokio::io::BufReader::new(pipe);
            reader.read_to_end(&mut buf).await.unwrap_or(0);
            String::from_utf8_lossy(&buf).to_string()
        } else {
            String::new()
        }
    };

    let stderr_fut = async {
        if let Some(pipe) = stderr_handle {
            use tokio::io::AsyncReadExt;
            let mut buf = Vec::new();
            let mut reader = tokio::io::BufReader::new(pipe);
            reader.read_to_end(&mut buf).await.unwrap_or(0);
            let text = String::from_utf8_lossy(&buf).to_string();
            // Stream stderr to terminal for real-time progress
            if !text.is_empty() {
                eprint!("{}", text);
            }
            text
        } else {
            String::new()
        }
    };

    let (stdout, stderr) = tokio::join!(stdout_fut, stderr_fut);

    let status = child.wait().await
        .context("Failed to wait for lonkero process")?;

    if !status.success() {
        // Scan produced JSON output even though exit code was non-zero
        // (this can happen with license warnings, etc.)
        if !stdout.is_empty() && (stdout.starts_with('{') || stdout.starts_with('[')) {
            return Ok(stdout);
        }

        // Extract human-readable error from stderr
        // Lonkero logs look like: "2026-... ERROR message" — extract the message part
        let error_reason = extract_error_reason(&stderr);

        anyhow::bail!("{}", error_reason);
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

fn print_banner(target: &str, provider: &str, model: &str, license_type: Option<&str>) {
    println!();
    println!("\x1b[36m================================================================\x1b[0m");
    println!("\x1b[36m  Lonkero AI - Interactive Security Testing Agent\x1b[0m");
    println!("\x1b[36m================================================================\x1b[0m");
    println!("  Target:   {}", target);
    println!("  Provider: {} ({})", provider, model);
    match license_type {
        Some(lt) => println!("  License:  {}", lt),
        None => {
            // Check if env var is set even if license_type wasn't resolved
            if std::env::var("LONKERO_LICENSE_KEY").is_ok() {
                println!("  License:  \x1b[33m(from LONKERO_LICENSE_KEY env)\x1b[0m");
            } else {
                println!("  License:  \x1b[33mNo license key (set LONKERO_LICENSE_KEY or use -L)\x1b[0m");
            }
        }
    }
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

    // Breakdown by severity (case-insensitive to handle any JSON casing)
    let critical = session.findings.iter().filter(|f| f.severity.eq_ignore_ascii_case("CRITICAL")).count();
    let high = session.findings.iter().filter(|f| f.severity.eq_ignore_ascii_case("HIGH")).count();
    let medium = session.findings.iter().filter(|f| f.severity.eq_ignore_ascii_case("MEDIUM")).count();
    let low = session.findings.iter().filter(|f| f.severity.eq_ignore_ascii_case("LOW")).count();
    let info = session.findings.iter().filter(|f| f.severity.eq_ignore_ascii_case("INFO")).count();

    if !session.findings.is_empty() {
        println!(
            "    \x1b[31mCRITICAL: {}\x1b[0m  \x1b[91mHIGH: {}\x1b[0m  \x1b[33mMEDIUM: {}\x1b[0m  LOW: {}  \x1b[90mINFO: {}\x1b[0m",
            critical, high, medium, low, info
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
