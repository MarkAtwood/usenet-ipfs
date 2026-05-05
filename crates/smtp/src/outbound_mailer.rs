use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;

/// The type of a message being sent, used for provider routing decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// Triggered by a direct user action (password reset, notification, etc.).
    Transactional,
    /// Marketing or newsletter-style bulk mail.
    Bulk,
    /// Internal system-generated mail (health alerts, admin notices, etc.).
    System,
}

/// An outbound mail envelope ready to hand to a provider.
#[derive(Debug, Clone)]
pub struct OutboundEnvelope {
    /// RFC 5321 MAIL FROM address (no angle brackets).
    pub mail_from: String,
    /// RFC 5321 RCPT TO addresses (no angle brackets).
    pub rcpt_to: Vec<String>,
    /// Raw RFC 5322 message bytes.
    pub message: Bytes,
    /// Routing hint for provider selection.
    pub message_type: MessageType,
}

/// Receipt returned by a successful send.
#[derive(Debug, Clone)]
pub struct SendReceipt {
    /// Provider-assigned message identifier, if the provider supplies one.
    pub provider_message_id: Option<String>,
    /// Human-readable provider name (e.g. `"smtp-relay"`, `"ses"`).
    pub provider: &'static str,
}

/// Error returned when a send attempt fails.
///
/// The variant determines whether the caller should retry or abandon.
#[derive(Debug)]
pub enum OutboundError {
    /// Transient failure: connection refused, timeout, 4xx response.
    /// The caller may retry after a backoff.
    Transient(String),
    /// Permanent failure: 5xx content rejection, invalid address, auth error.
    /// The message should be moved to dead-letter; retrying will not help.
    Permanent(String),
}

impl std::fmt::Display for OutboundError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutboundError::Transient(msg) => write!(f, "transient: {msg}"),
            OutboundError::Permanent(msg) => write!(f, "permanent: {msg}"),
        }
    }
}

impl std::error::Error for OutboundError {}

impl OutboundError {
    /// Returns `true` if the error is transient and delivery should be retried.
    pub fn is_transient(&self) -> bool {
        matches!(self, OutboundError::Transient(_))
    }
}

/// Abstraction over outbound mail delivery providers.
///
/// Implementations include [`SmtpRelayMailer`] (disk-backed queue over SMTP),
/// `SesMailer` (AWS SES v2 HTTP API), and the composite [`RoutingMailer`] that
/// selects among multiple providers.
#[async_trait]
pub trait OutboundMailer: Send + Sync {
    /// Attempt to deliver `envelope`.  Returns a [`SendReceipt`] on success.
    async fn send(&self, envelope: OutboundEnvelope) -> Result<SendReceipt, OutboundError>;

    /// Short, stable provider name for metrics labels (e.g. `"smtp-relay"`).
    fn name(&self) -> &'static str;

    /// Returns `true` if this provider is currently believed to be healthy.
    ///
    /// The default implementation always returns `true`.  Providers that
    /// maintain health state (e.g. [`SmtpRelayMailer`]) override this to
    /// reflect peer availability.  [`RoutingMailer`] uses this to skip
    /// unhealthy providers before attempting delivery.
    fn healthy(&self) -> bool {
        true
    }
}

/// An [`OutboundMailer`] that delegates to the durable [`SmtpRelayQueue`].
///
/// `SmtpRelayMailer` is the default provider for deployments that do not need
/// HTTP API providers.  It wraps the existing filesystem-backed queue so that
/// no behaviour changes for current deployments after the refactor.
pub struct SmtpRelayMailer {
    queue: Arc<crate::relay_queue::SmtpRelayQueue>,
}

impl SmtpRelayMailer {
    /// Create a new `SmtpRelayMailer` wrapping `queue`.
    pub fn new(queue: Arc<crate::relay_queue::SmtpRelayQueue>) -> Self {
        Self { queue }
    }
}

#[async_trait]
impl OutboundMailer for SmtpRelayMailer {
    async fn send(&self, envelope: OutboundEnvelope) -> Result<SendReceipt, OutboundError> {
        let rcpt_refs: Vec<&str> = envelope.rcpt_to.iter().map(String::as_str).collect();
        self.queue
            .enqueue(&envelope.message, &envelope.mail_from, &rcpt_refs, false)
            .await
            .map_err(|e| OutboundError::Transient(e.to_string()))?;
        Ok(SendReceipt {
            provider_message_id: None,
            provider: "smtp-relay",
        })
    }

    fn name(&self) -> &'static str {
        "smtp-relay"
    }

    fn healthy(&self) -> bool {
        // Delegate to peer health: at least one peer must be up.
        // The lock is never poisoned: no code panics while holding it.
        self.queue
            .health()
            .lock()
            .expect("health lock")
            .has_healthy_peer()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_relay_queue() -> (Arc<crate::relay_queue::SmtpRelayQueue>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let peer = crate::config::SmtpRelayPeerConfig {
            host: "smtp.example.com".to_string(),
            port: 587,
            tls: false,
            username: None,
            password: None,
        };
        let q = crate::relay_queue::SmtpRelayQueue::new(
            dir.path(),
            vec![peer],
            Duration::from_secs(300),
            None,
            "test.example.com",
            None,
        )
        .expect("queue");
        (q, dir)
    }

    // Oracle: SmtpRelayMailer.send() with valid recipients must succeed and
    // produce a .env file in the queue directory, identical to calling
    // SmtpRelayQueue.enqueue() directly.
    #[tokio::test]
    async fn smtp_relay_mailer_enqueues_message() {
        let (queue, dir) = make_relay_queue();
        let mailer = SmtpRelayMailer::new(Arc::clone(&queue));

        let envelope = OutboundEnvelope {
            mail_from: "from@example.com".to_string(),
            rcpt_to: vec!["to@example.com".to_string()],
            message: Bytes::from_static(b"From: from@example.com\r\n\r\nHello"),
            message_type: MessageType::Transactional,
        };

        let receipt = mailer.send(envelope).await.expect("send must succeed");
        assert_eq!(receipt.provider, "smtp-relay");
        assert!(receipt.provider_message_id.is_none());

        let env_count = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "env"))
            .count();
        assert_eq!(env_count, 1, "expected 1 .env file in queue after send");
    }

    // Oracle: SmtpRelayMailer.send() with no recipients must be a no-op
    // (queue.enqueue() returns Ok without writing files when rcpt_to is empty).
    #[tokio::test]
    async fn smtp_relay_mailer_no_recipients_is_noop() {
        let (queue, dir) = make_relay_queue();
        let mailer = SmtpRelayMailer::new(Arc::clone(&queue));

        let envelope = OutboundEnvelope {
            mail_from: "from@example.com".to_string(),
            rcpt_to: vec![],
            message: Bytes::from_static(b"From: from@example.com\r\n\r\nHello"),
            message_type: MessageType::Transactional,
        };

        let receipt = mailer
            .send(envelope)
            .await
            .expect("send must succeed even with no recipients");
        assert_eq!(receipt.provider, "smtp-relay");

        let env_count = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "env"))
            .count();
        assert_eq!(env_count, 0, "no recipients: no .env files expected");
    }

    // Oracle: SmtpRelayMailer.name() returns the constant string "smtp-relay".
    #[test]
    fn smtp_relay_mailer_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let q = crate::relay_queue::SmtpRelayQueue::new(
            dir.path(),
            vec![],
            Duration::from_secs(300),
            None,
            "",
            None,
        )
        .expect("queue");
        let mailer = SmtpRelayMailer::new(q);
        assert_eq!(mailer.name(), "smtp-relay");
    }
}
