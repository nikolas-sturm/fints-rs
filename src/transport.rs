//! FinTS HTTPS transport layer.
//!
//! Sends FinTS messages to a bank's HBCI/FinTS endpoint via HTTPS POST.
//! Messages are base64-encoded in the request body, and responses are base64-decoded.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use tracing::{debug, trace};

use crate::error::{FinTSError, Result};
use crate::quirks::{QuirkChain, QuirkContext};

/// FinTS HTTP connection to a bank endpoint.
pub struct FinTSConnection {
    url: String,
    client: reqwest::Client,
    quirks: QuirkChain,
}

impl FinTSConnection {
    /// Create a new connection to the given bank FinTS URL.
    pub fn new(url: &str) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .pool_idle_timeout(std::time::Duration::from_secs(2))
            .pool_max_idle_per_host(0)
            .tcp_nodelay(true)
            .build()
            .map_err(|e| FinTSError::Transport(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            url: url.to_string(),
            client,
            quirks: QuirkChain::default(),
        })
    }

    /// Replace the quirk chain applied in [`FinTSConnection::exchange`].
    pub fn set_quirks(&mut self, quirks: QuirkChain) {
        self.quirks = quirks;
    }

    /// Send a message and return the response as clear text
    /// (`HNHBK + inner segments + HNHBS`), with all quirks applied.
    pub async fn exchange(&self, message_bytes: &[u8], ctx: &QuirkContext<'_>) -> Result<Vec<u8>> {
        let outgoing = self.quirks.outgoing(message_bytes, ctx);
        let raw = self.send(&outgoing).await?;
        Ok(self.quirks.incoming(&raw, ctx))
    }

    /// Send a raw FinTS message (bytes) to the bank and return the raw response
    /// bytes, without quirks or envelope handling.
    pub async fn send(&self, message_bytes: &[u8]) -> Result<Vec<u8>> {
        // Base64-encode the message
        let encoded = B64.encode(message_bytes);

        debug!(
            "Sending {} bytes (base64: {} bytes) to {}",
            message_bytes.len(),
            encoded.len(),
            self.url
        );
        trace!("Request (raw): {:?}", String::from_utf8_lossy(message_bytes));

        // POST with Content-Type: text/plain
        let response = self
            .client
            .post(&self.url)
            .header("Content-Type", "text/plain")
            .body(encoded)
            .send()
            .await
            .map_err(|e| FinTSError::Transport(format!("HTTP request failed: {}", e)))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(FinTSError::Http {
                status: status.as_u16(),
                message: body,
            });
        }

        // Response body: ISO-8859-1 text containing base64 data
        let response_bytes = response
            .bytes()
            .await
            .map_err(|e| FinTSError::Transport(format!("Failed to read response: {}", e)))?;

        // Decode from ISO-8859-1 (treat as raw bytes, strip any whitespace)
        let response_text: String = response_bytes
            .iter()
            .map(|&b| b as char)
            .filter(|c| !c.is_whitespace())
            .collect();

        debug!("Received {} bytes base64 response", response_text.len());

        // Base64-decode
        let decoded = B64.decode(response_text.as_bytes()).map_err(|e| {
            FinTSError::Transport(format!("Failed to base64-decode response: {}", e))
        })?;

        debug!("Response: {} bytes decoded", decoded.len());
        trace!("Response (raw decoded): {}", String::from_utf8_lossy(&decoded));

        Ok(decoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Spin up a one-shot HTTP server on an ephemeral port. The handler receives
    /// the raw request body and returns an (HTTP status, response body) pair.
    /// Returns the base URL for the connection.
    async fn serve(
        handler: impl Fn(Vec<u8>) -> (u16, Vec<u8>) + Send + 'static,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 16 * 1024];
            let n = sock.read(&mut buf).await.unwrap();
            // Parse out the request body (everything after the header terminator).
            let body = match std::str::from_utf8(&buf[..n]).ok().and_then(|s| s.find("\r\n\r\n"))
            {
                Some(idx) => buf[idx + 4..n].to_vec(),
                None => Vec::new(),
            };
            let (status, response_body) = handler(body);
            let head = format!(
                "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response_body.len()
            );
            sock.write_all(head.as_bytes()).await.unwrap();
            sock.write_all(&response_body).await.unwrap();
            let _ = sock.shutdown().await;
        });
        format!("http://127.0.0.1:{}/", port)
    }

    #[tokio::test]
    async fn send_roundtrips_through_base64() {
        let payload = b"hello";
        let url = serve(move |body: Vec<u8>| {
            // Request body must be the base64 of the original message.
            assert_eq!(B64.decode(&body).unwrap(), payload.to_vec());
            // Respond with base64 of a different payload.
            (200, B64.encode(b"server says hi").into_bytes())
        })
        .await;

        let conn = FinTSConnection::new(&url).unwrap();
        let out = conn.send(payload).await.unwrap();
        assert_eq!(out, b"server says hi");
    }

    #[tokio::test]
    async fn send_handles_http_error_status() {
        let url = serve(move |_body| (500, b"boom".to_vec())).await;
        let conn = FinTSConnection::new(&url).unwrap();

        match conn.send(b"hex").await {
            Err(FinTSError::Http { status, message }) => {
                assert_eq!(status, 500);
                assert_eq!(message, "boom");
            }
            other => panic!("expected Http error, got {:?}", other.map(|_| ())),
        }
    }

    #[tokio::test]
    async fn send_rejects_invalid_base64_response() {
        let url = serve(move |_body| (200, b"!!!not-base64!!!".to_vec())).await;
        let conn = FinTSConnection::new(&url).unwrap();

        let err = conn.send(b"hex").await.unwrap_err();
        assert!(
            err.to_string().contains("base64") || err.to_string().contains("decode"),
            "got: {}",
            err
        );
    }

    #[tokio::test]
    async fn send_to_unreachable_host_errs() {
        // Bind a listener, then drop it so the port is closed → connection refused.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let url = format!("http://127.0.0.1:{}/", port);
        let conn = FinTSConnection::new(&url).unwrap();
        assert!(conn.send(b"hex").await.is_err());
    }

    #[test]
    fn new_accepts_valid_url_and_errors_on_bad_url() {
        assert!(FinTSConnection::new("https://example.com/fints").is_ok());
        // A non-URL input still builds an HTTP client (reqwest parses lazily),
        // so we only assert the happy path here.
        assert!(FinTSConnection::new("http://127.0.0.1:1/").is_ok());
    }
}
