/// Runtime environment classification.
///
/// Defaults to [`RuntimeEnvironment::Production`] when `STOA_ENV` is unset — the fail-safe
/// choice. Set `STOA_ENV=development` or `STOA_ENV=dev` to permit dev-mode config keys.
/// Set `STOA_ENV=test` for automated test runners.
///
/// Note: this classification is used for startup banners and observability.
/// The security guards (dev-mode auth, signing-key, admin token) check
/// configuration struct fields and listen addresses — not `STOA_ENV`.
/// Setting `STOA_ENV=development` does NOT bypass any security guard;
/// it only changes the log level of the startup banner from `info` to `warn`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeEnvironment {
    Production,
    Development,
    Test,
}

impl RuntimeEnvironment {
    /// Read the runtime environment from the `STOA_ENV` environment variable.
    ///
    /// Returns [`RuntimeEnvironment::Production`] if `STOA_ENV` is unset or contains an
    /// unrecognised value — production is the fail-safe default.
    pub fn from_env() -> Self {
        match std::env::var("STOA_ENV").as_deref() {
            Ok("development") | Ok("dev") => Self::Development,
            Ok("test") => Self::Test,
            // Unset, unrecognised, or non-UTF-8: default to Production (fail-safe).
            _ => Self::Production,
        }
    }

    /// Returns `true` for Development and Test environments.
    pub fn is_dev(&self) -> bool {
        matches!(self, Self::Development | Self::Test)
    }

    /// Returns a static string suitable for log fields.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Development => "development",
            Self::Test => "test",
        }
    }
}

/// Emit the standard startup banner to the tracing subscriber.
///
/// Logs at `warn` level in development/test environments and `info` in production.
/// Call this once per daemon after the tracing subscriber has been initialised.
///
/// # Example
/// ```no_run
/// stoa_core::emit_startup_banner(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
/// ```
pub fn emit_startup_banner(binary: &str, version: &str) {
    let env = RuntimeEnvironment::from_env();
    if env.is_dev() {
        tracing::warn!(
            environment = env.as_str(),
            binary,
            version,
            "runtime environment: development mode active — do not use in production"
        );
    } else {
        tracing::info!(
            environment = env.as_str(),
            binary,
            version,
            "runtime environment: production"
        );
    }
}

impl std::fmt::Display for RuntimeEnvironment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serialize all env-var mutations to prevent test races.
    // std::env::set_var is not thread-safe; tests that mutate STOA_ENV must
    // hold this lock for the duration of each test.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_env<F: FnOnce()>(val: Option<&str>, f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        match val {
            Some(v) => std::env::set_var("STOA_ENV", v),
            None => std::env::remove_var("STOA_ENV"),
        }
        f();
        std::env::remove_var("STOA_ENV");
        // _guard released here → other tests can proceed
    }

    #[test]
    fn test_default_is_production() {
        with_env(None, || {
            assert_eq!(
                RuntimeEnvironment::from_env(),
                RuntimeEnvironment::Production
            )
        });
    }

    #[test]
    fn test_development() {
        with_env(Some("development"), || {
            assert_eq!(
                RuntimeEnvironment::from_env(),
                RuntimeEnvironment::Development
            )
        });
    }

    #[test]
    fn test_dev_shorthand() {
        with_env(Some("dev"), || {
            assert_eq!(
                RuntimeEnvironment::from_env(),
                RuntimeEnvironment::Development
            )
        });
    }

    #[test]
    fn test_test_variant() {
        with_env(Some("test"), || {
            assert_eq!(RuntimeEnvironment::from_env(), RuntimeEnvironment::Test)
        });
    }

    #[test]
    fn test_unknown_is_production() {
        with_env(Some("staging"), || {
            assert_eq!(
                RuntimeEnvironment::from_env(),
                RuntimeEnvironment::Production
            )
        });
    }

    #[test]
    fn test_is_dev() {
        assert!(!RuntimeEnvironment::Production.is_dev());
        assert!(RuntimeEnvironment::Development.is_dev());
        assert!(RuntimeEnvironment::Test.is_dev());
    }

    #[test]
    fn test_display() {
        assert_eq!(RuntimeEnvironment::Production.to_string(), "production");
        assert_eq!(RuntimeEnvironment::Development.to_string(), "development");
        assert_eq!(RuntimeEnvironment::Test.to_string(), "test");
    }
}
