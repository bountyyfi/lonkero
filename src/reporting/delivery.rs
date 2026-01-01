// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::reporting::types::ReportOutput;
use anyhow::{Context, Result};
use lettre::{
    message::{header::ContentType, Attachment, MultiPart, SinglePart},
    transport::smtp::authentication::Credentials,
    Message, SmtpTransport, Transport,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    pub smtp_server: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub from_email: String,
    pub from_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub url: String,
    pub method: String,
    pub headers: Option<std::collections::HashMap<String, String>>,
}

pub struct ReportDeliveryService {
    email_config: Option<EmailConfig>,
    http_client: Client,
}

impl ReportDeliveryService {
    pub fn new(email_config: Option<EmailConfig>) -> Self {
        Self {
            email_config,
            http_client: Client::new(),
        }
    }

    pub async fn send_email(
        &self,
        to_email: &str,
        subject: &str,
        body: &str,
        report: Option<ReportOutput>,
    ) -> Result<()> {
        let config = self
            .email_config
            .as_ref()
            .context("Email configuration not provided")?;

        let message_builder = Message::builder()
            .from(
                format!("{} <{}>", config.from_name, config.from_email)
                    .parse()
                    .context("Failed to parse from email")?,
            )
            .to(to_email.parse().context("Failed to parse to email")?)
            .subject(subject);

        let email = if let Some(report_output) = report {
            let content_type = ContentType::parse(&report_output.mime_type)
                .unwrap_or(ContentType::TEXT_PLAIN);

            let attachment = Attachment::new(report_output.filename.clone())
                .body(report_output.data, content_type);

            let multipart = MultiPart::mixed()
                .singlepart(SinglePart::plain(body.to_string()))
                .singlepart(attachment);

            message_builder
                .multipart(multipart)
                .context("Failed to build multipart email")?
        } else {
            message_builder
                .body(body.to_string())
                .context("Failed to build email body")?
        };

        let creds = Credentials::new(
            config.smtp_username.clone(),
            config.smtp_password.clone(),
        );

        let mailer = SmtpTransport::relay(&config.smtp_server)
            .context("Failed to create SMTP transport")?
            .credentials(creds)
            .port(config.smtp_port)
            .build();

        mailer
            .send(&email)
            .context("Failed to send email")?;

        Ok(())
    }

    pub async fn send_slack_webhook(
        &self,
        webhook_url: &str,
        report_summary: &SlackReportSummary,
    ) -> Result<()> {
        let payload = serde_json::json!({
            "text": format!("[SECURITY] Security Scan Report - {}", report_summary.target),
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": format!("Security Scan Report: {}", report_summary.target)
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": format!("*Scan ID:*\n{}", report_summary.scan_id)
                        },
                        {
                            "type": "mrkdwn",
                            "text": format!("*Risk Score:*\n{:.2}/10.0 ({})", report_summary.risk_score, report_summary.risk_level)
                        }
                    ]
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": format!("*Critical:* {}", report_summary.critical_count)
                        },
                        {
                            "type": "mrkdwn",
                            "text": format!("*High:* {}", report_summary.high_count)
                        },
                        {
                            "type": "mrkdwn",
                            "text": format!("*Medium:* {}", report_summary.medium_count)
                        },
                        {
                            "type": "mrkdwn",
                            "text": format!("*Low:* {}", report_summary.low_count)
                        }
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": format!("*Total Vulnerabilities:* {}", report_summary.total_vulnerabilities)
                    }
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": format!("Generated: {}", report_summary.generated_at)
                        }
                    ]
                }
            ]
        });

        let response = self
            .http_client
            .post(webhook_url)
            .json(&payload)
            .send()
            .await
            .context("Failed to send Slack webhook")?;

        if !response.status().is_success() {
            anyhow::bail!(
                "Slack webhook returned error status: {}",
                response.status()
            );
        }

        Ok(())
    }

    pub async fn send_teams_webhook(
        &self,
        webhook_url: &str,
        report_summary: &TeamsReportSummary,
    ) -> Result<()> {
        let payload = serde_json::json!({
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": format!("Security Scan Report - {}", report_summary.target),
            "themeColor": self.get_theme_color(&report_summary.risk_level),
            "title": format!("[SECURITY] Security Scan Report: {}", report_summary.target),
            "sections": [
                {
                    "activityTitle": "Scan Summary",
                    "facts": [
                        {
                            "name": "Scan ID",
                            "value": report_summary.scan_id
                        },
                        {
                            "name": "Risk Score",
                            "value": format!("{:.2}/10.0 ({})", report_summary.risk_score, report_summary.risk_level)
                        },
                        {
                            "name": "Critical",
                            "value": report_summary.critical_count.to_string()
                        },
                        {
                            "name": "High",
                            "value": report_summary.high_count.to_string()
                        },
                        {
                            "name": "Medium",
                            "value": report_summary.medium_count.to_string()
                        },
                        {
                            "name": "Low",
                            "value": report_summary.low_count.to_string()
                        },
                        {
                            "name": "Total Vulnerabilities",
                            "value": report_summary.total_vulnerabilities.to_string()
                        },
                        {
                            "name": "Generated",
                            "value": report_summary.generated_at.clone()
                        }
                    ]
                }
            ]
        });

        let response = self
            .http_client
            .post(webhook_url)
            .json(&payload)
            .send()
            .await
            .context("Failed to send Teams webhook")?;

        if !response.status().is_success() {
            anyhow::bail!(
                "Teams webhook returned error status: {}",
                response.status()
            );
        }

        Ok(())
    }

    pub async fn send_custom_webhook(
        &self,
        config: &WebhookConfig,
        payload: serde_json::Value,
    ) -> Result<()> {
        let mut request = match config.method.to_uppercase().as_str() {
            "POST" => self.http_client.post(&config.url),
            "PUT" => self.http_client.put(&config.url),
            "PATCH" => self.http_client.patch(&config.url),
            _ => anyhow::bail!("Unsupported HTTP method: {}", config.method),
        };

        if let Some(headers) = &config.headers {
            for (key, value) in headers {
                request = request.header(key, value);
            }
        }

        let response = request
            .json(&payload)
            .send()
            .await
            .context("Failed to send custom webhook")?;

        if !response.status().is_success() {
            anyhow::bail!(
                "Custom webhook returned error status: {}",
                response.status()
            );
        }

        Ok(())
    }

    fn get_theme_color(&self, risk_level: &str) -> &str {
        match risk_level.to_uppercase().as_str() {
            "CRITICAL" => "FF0000",
            "HIGH" => "FF8C00",
            "MEDIUM" => "FFD700",
            "LOW" => "00BFFF",
            _ => "0078D4",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackReportSummary {
    pub scan_id: String,
    pub target: String,
    pub risk_score: f64,
    pub risk_level: String,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub total_vulnerabilities: usize,
    pub generated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamsReportSummary {
    pub scan_id: String,
    pub target: String,
    pub risk_score: f64,
    pub risk_level: String,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub total_vulnerabilities: usize,
    pub generated_at: String,
}
