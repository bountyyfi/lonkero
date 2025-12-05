// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::reporting::{
    delivery::{ReportDeliveryService, SlackReportSummary, TeamsReportSummary},
    engine::ReportEngine,
    types::{ReportConfig, ReportFormat},
};
use crate::types::ScanResults;
use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info};

pub struct ReportingApiState {
    pub engine: Arc<ReportEngine>,
    pub delivery_service: Arc<ReportDeliveryService>,
}

pub fn create_reporting_router(state: Arc<ReportingApiState>) -> Router {
    Router::new()
        .route("/api/v1/reports/generate", post(generate_report_handler))
        .route("/api/v1/reports/:scan_id", get(get_report_handler))
        .route("/api/v1/reports/:scan_id/email", post(email_report_handler))
        .route("/api/v1/reports/:scan_id/slack", post(slack_webhook_handler))
        .route("/api/v1/reports/:scan_id/teams", post(teams_webhook_handler))
        .route("/api/v1/reports/formats", get(list_formats_handler))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct GenerateReportRequest {
    scan_results: ScanResults,
    config: ReportConfig,
}

#[derive(Debug, Serialize)]
struct GenerateReportResponse {
    success: bool,
    message: String,
    filename: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    download_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EmailReportRequest {
    to_email: String,
    subject: Option<String>,
    body: Option<String>,
    config: ReportConfig,
    scan_results: ScanResults,
}

#[derive(Debug, Deserialize)]
struct WebhookRequest {
    webhook_url: String,
    scan_results: ScanResults,
}

#[derive(Debug, Deserialize)]
struct ReportQueryParams {
    format: Option<String>,
}

async fn generate_report_handler(
    State(state): State<Arc<ReportingApiState>>,
    Json(request): Json<GenerateReportRequest>,
) -> Result<impl IntoResponse, ApiError> {
    info!(
        "Generating report for scan ID: {} in format: {:?}",
        request.scan_results.scan_id, request.config.format
    );

    let report_output = state
        .engine
        .generate_report(request.scan_results.clone(), request.config.clone())
        .await
        .map_err(|e| {
            error!("Failed to generate report: {}", e);
            ApiError::InternalError(format!("Failed to generate report: {}", e))
        })?;

    let response = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, report_output.mime_type.clone())],
        report_output.data,
    );

    Ok(response)
}

async fn get_report_handler(
    State(_state): State<Arc<ReportingApiState>>,
    Path(_scan_id): Path<String>,
    Query(params): Query<ReportQueryParams>,
) -> Result<impl IntoResponse, ApiError> {
    let format = params
        .format
        .unwrap_or_else(|| "json".to_string())
        .to_lowercase();

    let _report_format: ReportFormat = match format.as_str() {
        "pdf" => ReportFormat::Pdf,
        "html" => ReportFormat::Html,
        "json" => ReportFormat::Json,
        "csv" => ReportFormat::Csv,
        "sarif" => ReportFormat::Sarif,
        "junit" => ReportFormat::JunitXml,
        "xlsx" => ReportFormat::Xlsx,
        "markdown" | "md" => ReportFormat::Markdown,
        _ => {
            return Err::<axum::response::Response, _>(ApiError::BadRequest(format!(
                "Unsupported format: {}",
                format
            )))
        }
    };

    Err(ApiError::NotImplemented(
        "Report retrieval from storage not yet implemented. Use /generate endpoint instead."
            .to_string(),
    ))
}

async fn email_report_handler(
    State(state): State<Arc<ReportingApiState>>,
    Json(request): Json<EmailReportRequest>,
) -> Result<impl IntoResponse, ApiError> {
    info!(
        "Sending report via email for scan ID: {}",
        request.scan_results.scan_id
    );

    let report_output = state
        .engine
        .generate_report(request.scan_results.clone(), request.config)
        .await
        .map_err(|e| {
            error!("Failed to generate report: {}", e);
            ApiError::InternalError(format!("Failed to generate report: {}", e))
        })?;

    let subject = request.subject.unwrap_or_else(|| {
        format!(
            "Security Assessment Report - {}",
            request.scan_results.target
        )
    });

    let body = request.body.unwrap_or_else(|| {
        format!(
            "Please find attached the security assessment report for {}.\n\n\
             Scan ID: {}\n\
             Total Vulnerabilities: {}\n\
             Scan Duration: {:.2}s",
            request.scan_results.target,
            request.scan_results.scan_id,
            request.scan_results.vulnerabilities.len(),
            request.scan_results.duration_seconds
        )
    });

    state
        .delivery_service
        .send_email(&request.to_email, &subject, &body, Some(report_output))
        .await
        .map_err(|e| {
            error!("Failed to send email: {}", e);
            ApiError::InternalError(format!("Failed to send email: {}", e))
        })?;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": format!("Report sent to {}", request.to_email)
    })))
}

async fn slack_webhook_handler(
    State(state): State<Arc<ReportingApiState>>,
    Json(request): Json<WebhookRequest>,
) -> Result<impl IntoResponse, ApiError> {
    info!(
        "Sending Slack webhook for scan ID: {}",
        request.scan_results.scan_id
    );

    let summary = SlackReportSummary {
        scan_id: request.scan_results.scan_id.clone(),
        target: request.scan_results.target.clone(),
        risk_score: calculate_quick_risk_score(&request.scan_results),
        risk_level: calculate_risk_level(calculate_quick_risk_score(&request.scan_results)),
        critical_count: count_by_severity(&request.scan_results, "CRITICAL"),
        high_count: count_by_severity(&request.scan_results, "HIGH"),
        medium_count: count_by_severity(&request.scan_results, "MEDIUM"),
        low_count: count_by_severity(&request.scan_results, "LOW"),
        total_vulnerabilities: request.scan_results.vulnerabilities.len(),
        generated_at: chrono::Utc::now().to_rfc3339(),
    };

    state
        .delivery_service
        .send_slack_webhook(&request.webhook_url, &summary)
        .await
        .map_err(|e| {
            error!("Failed to send Slack webhook: {}", e);
            ApiError::InternalError(format!("Failed to send Slack webhook: {}", e))
        })?;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Slack notification sent successfully"
    })))
}

async fn teams_webhook_handler(
    State(state): State<Arc<ReportingApiState>>,
    Json(request): Json<WebhookRequest>,
) -> Result<impl IntoResponse, ApiError> {
    info!(
        "Sending Teams webhook for scan ID: {}",
        request.scan_results.scan_id
    );

    let summary = TeamsReportSummary {
        scan_id: request.scan_results.scan_id.clone(),
        target: request.scan_results.target.clone(),
        risk_score: calculate_quick_risk_score(&request.scan_results),
        risk_level: calculate_risk_level(calculate_quick_risk_score(&request.scan_results)),
        critical_count: count_by_severity(&request.scan_results, "CRITICAL"),
        high_count: count_by_severity(&request.scan_results, "HIGH"),
        medium_count: count_by_severity(&request.scan_results, "MEDIUM"),
        low_count: count_by_severity(&request.scan_results, "LOW"),
        total_vulnerabilities: request.scan_results.vulnerabilities.len(),
        generated_at: chrono::Utc::now().to_rfc3339(),
    };

    state
        .delivery_service
        .send_teams_webhook(&request.webhook_url, &summary)
        .await
        .map_err(|e| {
            error!("Failed to send Teams webhook: {}", e);
            ApiError::InternalError(format!("Failed to send Teams webhook: {}", e))
        })?;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Teams notification sent successfully"
    })))
}

async fn list_formats_handler() -> impl IntoResponse {
    Json(serde_json::json!({
        "formats": [
            {
                "id": "pdf",
                "name": "PDF Report",
                "description": "Professional PDF report with branding",
                "mime_type": "application/pdf"
            },
            {
                "id": "html",
                "name": "HTML Interactive Report",
                "description": "Interactive HTML report with charts",
                "mime_type": "text/html"
            },
            {
                "id": "json",
                "name": "JSON Report",
                "description": "Machine-readable JSON format",
                "mime_type": "application/json"
            },
            {
                "id": "csv",
                "name": "CSV Report",
                "description": "Spreadsheet-compatible CSV format",
                "mime_type": "text/csv"
            },
            {
                "id": "sarif",
                "name": "SARIF Report",
                "description": "Static Analysis Results Interchange Format",
                "mime_type": "application/json"
            },
            {
                "id": "junit",
                "name": "JUnit XML Report",
                "description": "JUnit XML format for CI/CD integration",
                "mime_type": "application/xml"
            },
            {
                "id": "xlsx",
                "name": "Excel Report",
                "description": "Microsoft Excel spreadsheet format",
                "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            },
            {
                "id": "markdown",
                "name": "Markdown Report",
                "description": "Markdown format for documentation",
                "mime_type": "text/markdown"
            }
        ]
    }))
}

fn calculate_quick_risk_score(scan_results: &ScanResults) -> f64 {
    if scan_results.vulnerabilities.is_empty() {
        return 0.0;
    }

    let critical = count_by_severity(scan_results, "CRITICAL") as f64;
    let high = count_by_severity(scan_results, "HIGH") as f64;
    let medium = count_by_severity(scan_results, "MEDIUM") as f64;
    let total = scan_results.vulnerabilities.len() as f64;

    ((critical * 10.0 + high * 7.0 + medium * 4.0) / total).min(10.0)
}

fn calculate_risk_level(score: f64) -> String {
    match score {
        s if s >= 9.0 => "CRITICAL",
        s if s >= 7.0 => "HIGH",
        s if s >= 4.0 => "MEDIUM",
        s if s >= 1.0 => "LOW",
        _ => "INFO",
    }
    .to_string()
}

fn count_by_severity(scan_results: &ScanResults, severity: &str) -> usize {
    scan_results
        .vulnerabilities
        .iter()
        .filter(|v| v.severity.to_string() == severity)
        .count()
}

#[derive(Debug)]
enum ApiError {
    BadRequest(String),
    NotFound(String),
    InternalError(String),
    NotImplemented(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            ApiError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            ApiError::NotImplemented(msg) => (StatusCode::NOT_IMPLEMENTED, msg),
        };

        let body = Json(serde_json::json!({
            "error": message
        }));

        (status, body).into_response()
    }
}
