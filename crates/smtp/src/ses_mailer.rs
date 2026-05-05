/// AWS SES v2 outbound mail provider.
///
/// This module is compiled only when the `ses` feature is enabled:
/// ```toml
/// stoa-smtp = { ..., features = ["ses"] }
/// ```
///
/// `SesMailer` implements [`OutboundMailer`] using the SES v2 `SendEmail`
/// API with raw RFC 5322 message bytes.  Authentication is performed via the
/// standard AWS credential chain (IAM role, environment variables,
/// `~/.aws/credentials`).
use std::sync::Arc;

use crate::outbound_mailer::{OutboundEnvelope, OutboundError, OutboundMailer, SendReceipt};
use async_trait::async_trait;
use aws_sdk_sesv2::{
    config::{Builder as SesConfigBuilder, Credentials},
    types::{Destination, EmailContent, RawMessage},
    Client,
};

/// SES v2-based [`OutboundMailer`].
///
/// Created once at startup and shared behind `Arc`.  The underlying
/// [`aws_sdk_sesv2::Client`] is thread-safe and manages its own connection
/// pool.
pub struct SesMailer {
    client: Client,
    /// Human-readable name returned by [`OutboundMailer::name`].
    provider_name: &'static str,
}

impl SesMailer {
    /// Build a `SesMailer` from an explicit [`aws_sdk_sesv2::Config`].
    ///
    /// Prefer [`SesMailer::from_env`] for production deployments.
    /// Use this constructor in tests to inject a custom endpoint override.
    pub fn from_config(config: aws_sdk_sesv2::Config) -> Arc<Self> {
        Arc::new(Self {
            client: Client::from_conf(config),
            provider_name: "ses",
        })
    }

    /// Build a `SesMailer` by loading credentials from the standard AWS
    /// credential chain (IAM role, environment variables, `~/.aws/credentials`).
    pub async fn from_env() -> Arc<Self> {
        let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let config = aws_sdk_sesv2::config::Builder::from(&sdk_config).build();
        Self::from_config(config)
    }

    /// Build a `SesMailer` pointing at a custom endpoint URL.
    ///
    /// Used in tests to redirect calls to a local mock server.
    /// `region` must be a valid AWS region string (e.g. `"us-east-1"`).
    pub fn with_endpoint(endpoint_url: &str, region: &str) -> Arc<Self> {
        let config = SesConfigBuilder::new()
            .endpoint_url(endpoint_url)
            .region(aws_sdk_sesv2::config::Region::new(region.to_string()))
            .credentials_provider(Credentials::new(
                "test-key",
                "test-secret",
                None,
                None,
                "test",
            ))
            .behavior_version(aws_sdk_sesv2::config::BehaviorVersion::latest())
            .build();
        Self::from_config(config)
    }
}

#[async_trait]
impl OutboundMailer for SesMailer {
    async fn send(&self, envelope: OutboundEnvelope) -> Result<SendReceipt, OutboundError> {
        let raw = aws_sdk_sesv2::primitives::Blob::new(envelope.message.to_vec());

        let mut destination = Destination::builder();
        for addr in &envelope.rcpt_to {
            destination = destination.to_addresses(addr);
        }

        let result = self
            .client
            .send_email()
            .from_email_address(&envelope.mail_from)
            .destination(destination.build())
            .content(
                EmailContent::builder()
                    .raw(RawMessage::builder().data(raw).build().map_err(|e| {
                        OutboundError::Permanent(format!("SES RawMessage build error: {e}"))
                    })?)
                    .build(),
            )
            .send()
            .await;

        match result {
            Ok(output) => {
                let msg_id = output.message_id().map(str::to_owned);
                Ok(SendReceipt {
                    provider_message_id: msg_id,
                    provider: self.provider_name,
                })
            }
            Err(e) => {
                // Classify the error as transient or permanent.
                // SES 4xx (except 429 throttle) are typically permanent;
                // 5xx and throttle are transient.
                let is_transient = is_transient_ses_error(&e);
                let msg = format!("SES send error: {e}");
                if is_transient {
                    Err(OutboundError::Transient(msg))
                } else {
                    Err(OutboundError::Permanent(msg))
                }
            }
        }
    }

    fn name(&self) -> &'static str {
        self.provider_name
    }
}

/// Classify an SES SDK error as transient (retryable) or permanent.
///
/// - Throttling (`TooManyRequestsException`, HTTP 429) → transient
/// - Service unavailable (HTTP 5xx) → transient
/// - Client errors (HTTP 4xx except 429) → permanent
/// - Network / connection errors → transient
fn is_transient_ses_error(
    err: &aws_sdk_sesv2::error::SdkError<aws_sdk_sesv2::operation::send_email::SendEmailError>,
) -> bool {
    use aws_sdk_sesv2::error::SdkError;
    match err {
        SdkError::ServiceError(se) => {
            // Check the HTTP response code: 5xx = transient, 4xx = permanent,
            // except HTTP 429 (TooManyRequests) which is transient.
            let status = se.raw().status().as_u16();
            status >= 500 || status == 429
        }
        // Dispatch / timeout / connection errors are always transient.
        SdkError::DispatchFailure(_) | SdkError::TimeoutError(_) | SdkError::ResponseError(_) => {
            true
        }
        // Construction errors are permanent (misconfigured SDK).
        SdkError::ConstructionFailure(_) => false,
        // Unknown variants default to transient (safe to retry).
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use crate::outbound_mailer::{MessageType, OutboundEnvelope};

    fn make_envelope() -> OutboundEnvelope {
        OutboundEnvelope {
            mail_from: "from@example.com".to_string(),
            rcpt_to: vec!["to@example.com".to_string()],
            message: Bytes::from_static(
                b"From: from@example.com\r\nTo: to@example.com\r\nSubject: Test\r\n\r\nHello",
            ),
            message_type: MessageType::Transactional,
        }
    }

    // Oracle: SES v2 send_email API path is POST /v2/email/outbound-emails.
    // A 200 response with a message_id must produce SendReceipt::provider_message_id.
    #[tokio::test]
    async fn ses_send_returns_message_id_on_200() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/email/outbound-emails"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"MessageId": "ses-test-message-id-123"}"#),
            )
            .mount(&server)
            .await;

        let mailer = SesMailer::with_endpoint(&server.uri(), "us-east-1");
        let receipt = mailer
            .send(make_envelope())
            .await
            .expect("send must succeed on 200");

        assert_eq!(receipt.provider, "ses");
        assert_eq!(
            receipt.provider_message_id.as_deref(),
            Some("ses-test-message-id-123")
        );
    }

    // Oracle: HTTP 500 from SES must map to OutboundError::Transient.
    #[tokio::test]
    async fn ses_send_500_returns_transient_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/email/outbound-emails"))
            .respond_with(
                ResponseTemplate::new(500)
                    .set_body_string(r#"{"message": "Internal Server Error"}"#),
            )
            .mount(&server)
            .await;

        let mailer = SesMailer::with_endpoint(&server.uri(), "us-east-1");
        let err = mailer
            .send(make_envelope())
            .await
            .expect_err("send must fail on 500");

        assert!(err.is_transient(), "500 must be transient: {err}");
    }

    // Oracle: HTTP 400 (permanent error like invalid address) must map to
    // OutboundError::Permanent.
    #[tokio::test]
    async fn ses_send_400_returns_permanent_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/email/outbound-emails"))
            .respond_with(ResponseTemplate::new(400).set_body_string(
                r#"{"__type": "InvalidParameterValue", "message": "bad address"}"#,
            ))
            .mount(&server)
            .await;

        let mailer = SesMailer::with_endpoint(&server.uri(), "us-east-1");
        let err = mailer
            .send(make_envelope())
            .await
            .expect_err("send must fail on 400");

        assert!(!err.is_transient(), "400 must be permanent: {err}");
    }

    // Oracle: HTTP 429 (throttling) must map to OutboundError::Transient.
    #[tokio::test]
    async fn ses_send_429_returns_transient_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/email/outbound-emails"))
            .respond_with(ResponseTemplate::new(429).set_body_string(
                r#"{"__type": "TooManyRequestsException", "message": "rate exceeded"}"#,
            ))
            .mount(&server)
            .await;

        let mailer = SesMailer::with_endpoint(&server.uri(), "us-east-1");
        let err = mailer
            .send(make_envelope())
            .await
            .expect_err("send must fail on 429");

        assert!(err.is_transient(), "429 must be transient: {err}");
    }
}
