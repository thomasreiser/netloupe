//! Retry-with-backoff for calls to external, third-party APIs that
//! *support* a check (crt.sh, RDAP, MaxMind's GeoIP Update API, provider
//! IP-range list hosts, the Tor exit list, AbuseIPDB, ...) -- never for
//! probing the host under inspection itself. A DNS/HTTP/TLS/port failure
//! against the target *is* the measurement (see `checks::http`,
//! `checks::tls`, `checks::acme`'s challenge probes, ...); retrying those
//! would misreport what's actually there. This is only for "our own
//! helper request to some third party had a transient hiccup."

use std::future::Future;
use std::time::Duration;

/// Whether a failed attempt is worth trying again.
#[derive(Debug)]
pub enum Failure<E> {
    /// A network-level hiccup (timeout, connection reset) or a 5xx/429
    /// response -- plausibly transient.
    Retryable(E),
    /// A 4xx (other than 429) or anything else where trying the exact
    /// same request again wouldn't plausibly get a different answer.
    Fatal(E),
}

#[derive(Debug, Clone, Copy)]
pub struct Policy {
    pub max_attempts: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
}

impl Default for Policy {
    /// Three attempts, exponential backoff from 250ms capped at 2s: a
    /// worst case of a couple of extra seconds of waiting on top of
    /// whatever the request's own timeout already costs, which is worth
    /// paying to ride out a blip rather than reporting a check as failed
    /// or missing evidence over one dropped packet.
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(2),
        }
    }
}

/// Runs `attempt` up to `policy.max_attempts` times, sleeping an
/// exponentially growing, jittered backoff between retryable failures.
/// Stops immediately on `Failure::Fatal`, or once attempts are
/// exhausted -- either way returning the last error.
pub async fn run<T, E, F, Fut>(policy: &Policy, mut attempt: F) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, Failure<E>>>,
{
    let attempts = policy.max_attempts.max(1);
    let mut last_err = None;
    for n in 0..attempts {
        match attempt().await {
            Ok(v) => return Ok(v),
            Err(Failure::Fatal(e)) => return Err(e),
            Err(Failure::Retryable(e)) => {
                last_err = Some(e);
                if n + 1 < attempts {
                    tokio::time::sleep(backoff_delay(policy, n)).await;
                }
            }
        }
    }
    Err(last_err.expect(
        "the loop runs at least once (max_attempts.max(1)), and every non-Ok, non-Fatal \
         outcome records last_err before the loop can exit, so exhausting it always leaves one",
    ))
}

/// Full jitter (as recommended by AWS's backoff writeup): a uniformly
/// random delay between 0 and `base_delay * 2^attempt` (capped at
/// `max_delay`), so a burst of independent retries -- e.g. every
/// provider's range list refreshing at once -- doesn't retry in lockstep.
fn backoff_delay(policy: &Policy, attempt: u32) -> Duration {
    let exp = policy.base_delay.saturating_mul(1u32 << attempt.min(16));
    let capped = exp.min(policy.max_delay);
    let jittered_ms = rand::random_range(0..=capped.as_millis().max(1) as u64);
    Duration::from_millis(jittered_ms)
}

/// Classifies a failed `send().await` -- a timeout or connection failure
/// is plausibly transient; anything else (a malformed URL, TLS setup
/// failure, ...) won't fix itself on retry.
pub fn classify_send_error(err: reqwest::Error) -> Failure<String> {
    if err.is_timeout() || err.is_connect() {
        Failure::Retryable(err.to_string())
    } else {
        Failure::Fatal(err.to_string())
    }
}

/// Classifies an unsuccessful HTTP status: 5xx and 429 (Too Many
/// Requests) are worth another attempt after backing off; any other 4xx
/// means the request itself was wrong, so retrying it verbatim wouldn't
/// help.
pub fn classify_status(status: reqwest::StatusCode) -> Failure<String> {
    let message = format!("HTTP {status}");
    if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        Failure::Retryable(message)
    } else {
        Failure::Fatal(message)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    fn fast_policy() -> Policy {
        // Real delays would make the test suite slow for no benefit --
        // the backoff math itself is covered by `backoff_delay_*` below.
        Policy {
            max_attempts: 3,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(2),
        }
    }

    #[tokio::test]
    async fn succeeds_without_retrying_when_the_first_attempt_works() {
        let calls = AtomicU32::new(0);
        let result: Result<u32, String> = run(&fast_policy(), || async {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok(42)
        })
        .await;
        assert_eq!(result, Ok(42));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn retries_a_retryable_failure_until_it_succeeds() {
        let calls = AtomicU32::new(0);
        let result: Result<u32, String> = run(&fast_policy(), || async {
            let n = calls.fetch_add(1, Ordering::Relaxed);
            if n < 2 {
                Err(Failure::Retryable(format!("transient #{n}")))
            } else {
                Ok(7)
            }
        })
        .await;
        assert_eq!(result, Ok(7));
        assert_eq!(calls.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn gives_up_after_max_attempts_and_returns_the_last_error() {
        let calls = AtomicU32::new(0);
        let result: Result<u32, String> = run(&fast_policy(), || async {
            let n = calls.fetch_add(1, Ordering::Relaxed);
            Err(Failure::Retryable(format!("still failing #{n}")))
        })
        .await;
        assert_eq!(result, Err("still failing #2".to_string()));
        assert_eq!(calls.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn stops_immediately_on_a_fatal_failure_without_retrying() {
        let calls = AtomicU32::new(0);
        let result: Result<u32, String> = run(&fast_policy(), || async {
            calls.fetch_add(1, Ordering::Relaxed);
            Err(Failure::Fatal(
                "bad request, retrying won't help".to_string(),
            ))
        })
        .await;
        assert_eq!(result, Err("bad request, retrying won't help".to_string()));
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "a fatal failure must not be retried"
        );
    }

    #[test]
    fn backoff_delay_never_exceeds_max_delay() {
        let policy = Policy {
            max_attempts: 10,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(1),
        };
        for attempt in 0..10 {
            assert!(backoff_delay(&policy, attempt) <= Duration::from_secs(1));
        }
    }

    #[test]
    fn classify_send_error_and_status_agree_with_the_documented_rules() {
        assert!(matches!(
            classify_status(reqwest::StatusCode::TOO_MANY_REQUESTS),
            Failure::Retryable(_)
        ));
        assert!(matches!(
            classify_status(reqwest::StatusCode::INTERNAL_SERVER_ERROR),
            Failure::Retryable(_)
        ));
        assert!(matches!(
            classify_status(reqwest::StatusCode::NOT_FOUND),
            Failure::Fatal(_)
        ));
        assert!(matches!(
            classify_status(reqwest::StatusCode::BAD_REQUEST),
            Failure::Fatal(_)
        ));
    }
}
