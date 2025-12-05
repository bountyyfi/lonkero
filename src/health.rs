// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Health Check & Monitoring
 * Production-ready health endpoints with detailed status
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Health status levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Component health information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentHealth {
    pub name: String,
    pub status: HealthStatus,
    pub message: Option<String>,
    pub last_check: String,
    pub response_time_ms: Option<u64>,
}

/// Overall health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthCheckResponse {
    pub status: HealthStatus,
    pub timestamp: String,
    pub uptime_seconds: u64,
    pub version: String,
    pub components: Vec<ComponentHealth>,
}

/// Readiness check response (for Kubernetes)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadinessCheckResponse {
    pub ready: bool,
    pub timestamp: String,
    pub checks: Vec<ComponentHealth>,
}

/// Liveness check response (for Kubernetes)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LivenessCheckResponse {
    pub alive: bool,
    pub timestamp: String,
}

/// Health checker state
#[derive(Clone)]
pub struct HealthChecker {
    start_time: Instant,
    version: String,
    component_checks: Arc<RwLock<Vec<ComponentHealth>>>,
}

impl HealthChecker {
    /// Create a new health checker
    pub fn new(version: String) -> Self {
        Self {
            start_time: Instant::now(),
            version,
            component_checks: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Update component health status
    pub async fn update_component_health(
        &self,
        name: String,
        status: HealthStatus,
        message: Option<String>,
        response_time_ms: Option<u64>,
    ) {
        let health = ComponentHealth {
            name: name.clone(),
            status,
            message,
            last_check: chrono::Utc::now().to_rfc3339(),
            response_time_ms,
        };

        let mut checks = self.component_checks.write().await;
        if let Some(existing) = checks.iter_mut().find(|c| c.name == name) {
            *existing = health;
        } else {
            checks.push(health);
        }

        debug!(
            component = %name,
            status = ?status,
            "Component health updated"
        );
    }

    /// Check database health
    pub async fn check_database_health(&self, pool: &deadpool_postgres::Pool) -> ComponentHealth {
        let start = Instant::now();
        let (status, message, response_time_ms) = match pool.get().await {
            Ok(client) => match client.query("SELECT 1", &[]).await {
                Ok(_) => {
                    let response_time = start.elapsed().as_millis() as u64;
                    (HealthStatus::Healthy, None, Some(response_time))
                }
                Err(e) => (
                    HealthStatus::Unhealthy,
                    Some(format!("Query failed: {}", e)),
                    None,
                ),
            },
            Err(e) => (
                HealthStatus::Unhealthy,
                Some(format!("Connection failed: {}", e)),
                None,
            ),
        };

        ComponentHealth {
            name: "database".to_string(),
            status,
            message,
            last_check: chrono::Utc::now().to_rfc3339(),
            response_time_ms,
        }
    }

    /// Check Redis health
    pub async fn check_redis_health(
        &self,
        redis_client: &redis::Client,
    ) -> ComponentHealth {
        let start = Instant::now();
        let (status, message, response_time_ms) = match redis_client.get_multiplexed_async_connection().await {
            Ok(mut conn) => {
                match redis::cmd("PING").query_async::<String>(&mut conn).await {
                    Ok(_) => {
                        let response_time = start.elapsed().as_millis() as u64;
                        (HealthStatus::Healthy, None, Some(response_time))
                    }
                    Err(e) => (
                        HealthStatus::Unhealthy,
                        Some(format!("PING failed: {}", e)),
                        None,
                    ),
                }
            }
            Err(e) => (
                HealthStatus::Unhealthy,
                Some(format!("Connection failed: {}", e)),
                None,
            ),
        };

        ComponentHealth {
            name: "redis".to_string(),
            status,
            message,
            last_check: chrono::Utc::now().to_rfc3339(),
            response_time_ms,
        }
    }

    /// Get overall health status
    pub async fn get_health(&self) -> HealthCheckResponse {
        let components = self.component_checks.read().await.clone();

        let overall_status = if components.iter().any(|c| c.status == HealthStatus::Unhealthy) {
            HealthStatus::Unhealthy
        } else if components.iter().any(|c| c.status == HealthStatus::Degraded) {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        HealthCheckResponse {
            status: overall_status,
            timestamp: chrono::Utc::now().to_rfc3339(),
            uptime_seconds: self.start_time.elapsed().as_secs(),
            version: self.version.clone(),
            components,
        }
    }

    /// Check if service is ready (for Kubernetes readiness probe)
    pub async fn is_ready(&self) -> ReadinessCheckResponse {
        let checks = self.component_checks.read().await.clone();

        let ready = checks
            .iter()
            .all(|c| c.status == HealthStatus::Healthy || c.status == HealthStatus::Degraded);

        ReadinessCheckResponse {
            ready,
            timestamp: chrono::Utc::now().to_rfc3339(),
            checks,
        }
    }

    /// Check if service is alive (for Kubernetes liveness probe)
    pub async fn is_alive(&self) -> LivenessCheckResponse {
        LivenessCheckResponse {
            alive: true,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Start periodic health checks
    pub async fn start_periodic_checks(
        self: Arc<Self>,
        interval: Duration,
        db_pool: Option<deadpool_postgres::Pool>,
        redis_client: Option<redis::Client>,
    ) {
        info!(
            interval_secs = interval.as_secs(),
            "Starting periodic health checks"
        );

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            interval_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval_timer.tick().await;

                if let Some(ref pool) = db_pool {
                    let health = self.check_database_health(pool).await;
                    self.update_component_health(
                        health.name.clone(),
                        health.status.clone(),
                        health.message.clone(),
                        health.response_time_ms,
                    )
                    .await;
                }

                if let Some(ref client) = redis_client {
                    let health = self.check_redis_health(client).await;
                    self.update_component_health(
                        health.name.clone(),
                        health.status.clone(),
                        health.message.clone(),
                        health.response_time_ms,
                    )
                    .await;
                }
            }
        });
    }
}

/// Health check handler
async fn health_handler(State(checker): State<Arc<HealthChecker>>) -> impl IntoResponse {
    let health = checker.get_health().await;
    let status_code = match health.status {
        HealthStatus::Healthy => StatusCode::OK,
        HealthStatus::Degraded => StatusCode::OK,
        HealthStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
    };
    (status_code, Json(health))
}

/// Readiness check handler
async fn readiness_handler(State(checker): State<Arc<HealthChecker>>) -> impl IntoResponse {
    let readiness = checker.is_ready().await;
    let status_code = if readiness.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status_code, Json(readiness))
}

/// Liveness check handler
async fn liveness_handler(State(checker): State<Arc<HealthChecker>>) -> impl IntoResponse {
    let liveness = checker.is_alive().await;
    (StatusCode::OK, Json(liveness))
}

/// Create health check router
pub fn create_health_router(checker: Arc<HealthChecker>) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/health/ready", get(readiness_handler))
        .route("/health/live", get(liveness_handler))
        .with_state(checker)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_checker_creation() {
        let checker = HealthChecker::new("1.0.0".to_string());
        let health = checker.get_health().await;
        assert_eq!(health.status, HealthStatus::Healthy);
        assert_eq!(health.version, "1.0.0");
        assert!(health.uptime_seconds >= 0);
    }

    #[tokio::test]
    async fn test_update_component_health() {
        let checker = HealthChecker::new("1.0.0".to_string());

        checker
            .update_component_health(
                "test_component".to_string(),
                HealthStatus::Healthy,
                None,
                Some(100),
            )
            .await;

        let health = checker.get_health().await;
        assert_eq!(health.components.len(), 1);
        assert_eq!(health.components[0].name, "test_component");
        assert_eq!(health.components[0].status, HealthStatus::Healthy);
    }

    #[tokio::test]
    async fn test_overall_health_status() {
        let checker = HealthChecker::new("1.0.0".to_string());

        checker
            .update_component_health(
                "component1".to_string(),
                HealthStatus::Healthy,
                None,
                None,
            )
            .await;

        checker
            .update_component_health(
                "component2".to_string(),
                HealthStatus::Unhealthy,
                Some("Error".to_string()),
                None,
            )
            .await;

        let health = checker.get_health().await;
        assert_eq!(health.status, HealthStatus::Unhealthy);
    }

    #[tokio::test]
    async fn test_readiness_check() {
        let checker = HealthChecker::new("1.0.0".to_string());

        checker
            .update_component_health(
                "component1".to_string(),
                HealthStatus::Healthy,
                None,
                None,
            )
            .await;

        let readiness = checker.is_ready().await;
        assert!(readiness.ready);
    }

    #[tokio::test]
    async fn test_liveness_check() {
        let checker = HealthChecker::new("1.0.0".to_string());
        let liveness = checker.is_alive().await;
        assert!(liveness.alive);
    }
}
