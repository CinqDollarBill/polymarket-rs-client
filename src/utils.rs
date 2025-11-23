use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE, Engine};
use serde::Serialize;
use serde_json_fmt::JsonFormat;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn get_current_unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

pub fn build_hmac_signature<T>(
    secret: &str,
    timestamp: u64,
    method: &str,
    req_path: &str,
    body: Option<&T>,
) -> Result<String>
where
    T: ?Sized + Serialize,
{
    // 1. Base64 URL-safe decode the secret key.
    let decoded = URL_SAFE
        .decode(secret)
        .context("Can't decode secret to base64")?;

    let message = match body {
        None => {
            // Case 1: No body (e.g., GET requests)
            format!("{timestamp}{method}{req_path}")
        }
        Some(s) => {
            // Case 2: Request has a body (e.g., POST /order)
            // CRITICAL FIX: Use serde_json to produce the compact, canonical JSON string
            let json_body_string = serde_json::to_string(&s)
                .context("Failed to serialize request body to canonical JSON")?;

            // The signature message is concatenated without separation
            format!("{timestamp}{method}{req_path}{json_body_string}")
            // 
        }
    };

    // 2. Compute HMAC-SHA256
    let mut mac = HmacSha256::new_from_slice(&decoded).context("HMAC init error")?;
    mac.update(message.as_bytes());

    let result = mac.finalize();

    // 3. Encode the resulting hash (byte array) back to base64 URL-safe.
    Ok(URL_SAFE.encode(&result.into_bytes()[..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_build_hmac_signature() {
        let body = HashMap::from([("hash", "0x123")]);
        let signature = build_hmac_signature(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            1000000,
            "test-sign",
            "/orders",
            Some(&body),
        )
        .unwrap();

        assert_eq!(signature, "ZwAdJKvoYRlEKDkNMwd5BuwNNtg93kNaR_oU2HrfVvc=");
    }
}
