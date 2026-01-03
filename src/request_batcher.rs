// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Request Batching Module
 * Sends multiple HTTP requests concurrently for 10x speedup within worker
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */
use crate::http_client::{HttpClient, HttpResponse};
use anyhow::Result;
use futures::future::join_all;
use std::sync::Arc;
use tracing::debug;

/// Batch HTTP requests for concurrent execution
pub struct RequestBatcher {
    http_client: Arc<HttpClient>,
    batch_size: usize,
}

impl RequestBatcher {
    /// Create a new request batcher
    pub fn new(http_client: Arc<HttpClient>, batch_size: usize) -> Self {
        Self {
            http_client,
            batch_size,
        }
    }

    /// Send multiple GET requests concurrently in batches
    pub async fn batch_get(&self, urls: Vec<String>) -> Vec<Result<HttpResponse>> {
        if urls.is_empty() {
            return Vec::new();
        }

        let total_urls = urls.len();
        debug!(
            "Batching {} requests with batch_size={}",
            total_urls, self.batch_size
        );

        let mut all_results = Vec::new();

        // Process URLs in chunks of batch_size
        for chunk in urls.chunks(self.batch_size) {
            debug!("Processing batch of {} requests", chunk.len());

            // Create futures for all requests in this batch
            let futures: Vec<_> = chunk
                .iter()
                .map(|url| {
                    let client = Arc::clone(&self.http_client);
                    let url = url.clone();
                    async move { client.get(&url).await }
                })
                .collect();

            // Execute all requests in this batch concurrently
            let batch_results = join_all(futures).await;
            all_results.extend(batch_results);
        }

        all_results
    }

    /// Send multiple POST requests concurrently in batches
    pub async fn batch_post(
        &self,
        requests: Vec<(String, String)>, // (url, body) pairs
    ) -> Vec<Result<HttpResponse>> {
        if requests.is_empty() {
            return Vec::new();
        }

        let total_requests = requests.len();
        debug!(
            "Batching {} POST requests with batch_size={}",
            total_requests, self.batch_size
        );

        let mut all_results = Vec::new();

        // Process requests in chunks of batch_size
        for chunk in requests.chunks(self.batch_size) {
            debug!("Processing batch of {} POST requests", chunk.len());

            // Create futures for all requests in this batch
            let futures: Vec<_> = chunk
                .iter()
                .map(|(url, body)| {
                    let client = Arc::clone(&self.http_client);
                    let url = url.clone();
                    let body = body.clone();
                    async move { client.post(&url, body).await }
                })
                .collect();

            // Execute all requests in this batch concurrently
            let batch_results = join_all(futures).await;
            all_results.extend(batch_results);
        }

        all_results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_batch_get_empty() {
        let client = Arc::new(HttpClient::new(5, 2).unwrap());
        let batcher = RequestBatcher::new(client, 10);

        let results = batcher.batch_get(vec![]).await;
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_batch_size_chunking() {
        let client = Arc::new(HttpClient::new(5, 2).unwrap());
        let batcher = RequestBatcher::new(client, 3);

        // 7 URLs should be processed in 3 batches (3, 3, 1)
        let urls = vec![
            "http://example.com/1".to_string(),
            "http://example.com/2".to_string(),
            "http://example.com/3".to_string(),
            "http://example.com/4".to_string(),
            "http://example.com/5".to_string(),
            "http://example.com/6".to_string(),
            "http://example.com/7".to_string(),
        ];

        let results = batcher.batch_get(urls).await;
        assert_eq!(results.len(), 7);
    }
}
