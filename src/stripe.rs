//! stripe payment processor with tpm-secured api keys
//!
//! uses vault to store and retrieve stripe secrets securely.

use hmac::{Hmac, Mac};
use secrecy::ExposeSecret;
use sha2::Sha256;

use crate::vault::{Vault, VaultError, SecretId, SecretKey};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
pub enum StripeError {
    Vault(VaultError),
    InvalidSignature,
    InvalidTimestamp,
    Request(String),
    Api(String),
}

impl std::fmt::Display for StripeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Vault(e) => write!(f, "vault: {}", e),
            Self::InvalidSignature => write!(f, "invalid webhook signature"),
            Self::InvalidTimestamp => write!(f, "invalid timestamp"),
            Self::Request(s) => write!(f, "request: {}", s),
            Self::Api(s) => write!(f, "api: {}", s),
        }
    }
}

impl std::error::Error for StripeError {}

impl From<VaultError> for StripeError {
    fn from(e: VaultError) -> Self {
        Self::Vault(e)
    }
}

/// stripe processor with tpm-secured credentials
pub struct StripeProcessor {
    secret_key: SecretKey,
    webhook_secret: Option<SecretKey>,
}

impl StripeProcessor {
    /// create from vault (loads tpm-sealed keys)
    pub fn from_vault(vault: &mut Vault) -> Result<Self, VaultError> {
        let secret_key = vault.load(SecretId::StripeSecretKey)?;
        let webhook_secret = vault.load(SecretId::StripeWebhookSecret).ok();

        Ok(Self {
            secret_key,
            webhook_secret,
        })
    }

    /// verify stripe webhook signature
    pub fn verify_webhook(&self, payload: &[u8], signature: &str) -> Result<(), StripeError> {
        let webhook_secret = self.webhook_secret.as_ref()
            .ok_or(VaultError::NotFound(SecretId::StripeWebhookSecret))?;

        // parse signature header: t=timestamp,v1=signature
        let mut timestamp = None;
        let mut sig = None;

        for part in signature.split(',') {
            if let Some(t) = part.strip_prefix("t=") {
                timestamp = Some(t);
            } else if let Some(s) = part.strip_prefix("v1=") {
                sig = Some(s);
            }
        }

        let timestamp = timestamp.ok_or(StripeError::InvalidTimestamp)?;
        let sig = sig.ok_or(StripeError::InvalidSignature)?;

        // validate timestamp is recent (within 5 minutes)
        let ts: i64 = timestamp.parse()
            .map_err(|_| StripeError::InvalidTimestamp)?;
        let now = chrono::Utc::now().timestamp();
        if (now - ts).abs() > 300 {
            return Err(StripeError::InvalidTimestamp);
        }

        // compute expected signature
        let signed_payload = format!("{}.{}", timestamp, String::from_utf8_lossy(payload));
        let mut mac = HmacSha256::new_from_slice(webhook_secret.expose_secret())
            .map_err(|_| StripeError::InvalidSignature)?;
        mac.update(signed_payload.as_bytes());

        let expected = hex::encode(mac.finalize().into_bytes());

        if expected != sig {
            return Err(StripeError::InvalidSignature);
        }

        Ok(())
    }

    /// create a payment intent
    pub async fn create_payment_intent(
        &self,
        amount: u64,
        currency: &str,
        metadata: Option<&serde_json::Value>,
    ) -> Result<PaymentIntent, StripeError> {
        let client = reqwest::Client::new();

        let secret = String::from_utf8_lossy(self.secret_key.expose_secret());

        let mut form = vec![
            ("amount", amount.to_string()),
            ("currency", currency.to_string()),
        ];

        if let Some(meta) = metadata {
            if let Some(obj) = meta.as_object() {
                for (k, v) in obj {
                    if let Some(s) = v.as_str() {
                        form.push((Box::leak(format!("metadata[{}]", k).into_boxed_str()), s.to_string()));
                    }
                }
            }
        }

        let resp = client
            .post("https://api.stripe.com/v1/payment_intents")
            .basic_auth(secret.as_ref(), None::<&str>)
            .form(&form)
            .send()
            .await
            .map_err(|e| StripeError::Request(e.to_string()))?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(StripeError::Api(text));
        }

        let intent: PaymentIntent = resp.json().await
            .map_err(|e| StripeError::Api(e.to_string()))?;

        Ok(intent)
    }

    /// retrieve a payment intent
    pub async fn get_payment_intent(&self, id: &str) -> Result<PaymentIntent, StripeError> {
        let client = reqwest::Client::new();
        let secret = String::from_utf8_lossy(self.secret_key.expose_secret());

        let resp = client
            .get(&format!("https://api.stripe.com/v1/payment_intents/{}", id))
            .basic_auth(secret.as_ref(), None::<&str>)
            .send()
            .await
            .map_err(|e| StripeError::Request(e.to_string()))?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(StripeError::Api(text));
        }

        let intent: PaymentIntent = resp.json().await
            .map_err(|e| StripeError::Api(e.to_string()))?;

        Ok(intent)
    }

    /// create a checkout session
    pub async fn create_checkout_session(
        &self,
        amount: u64,
        currency: &str,
        success_url: &str,
        cancel_url: &str,
        metadata: Option<&serde_json::Value>,
    ) -> Result<CheckoutSession, StripeError> {
        let client = reqwest::Client::new();
        let secret = String::from_utf8_lossy(self.secret_key.expose_secret());

        let mut form = vec![
            ("mode", "payment".to_string()),
            ("success_url", success_url.to_string()),
            ("cancel_url", cancel_url.to_string()),
            ("line_items[0][price_data][currency]", currency.to_string()),
            ("line_items[0][price_data][unit_amount]", amount.to_string()),
            ("line_items[0][price_data][product_data][name]", "credits".to_string()),
            ("line_items[0][quantity]", "1".to_string()),
        ];

        if let Some(meta) = metadata {
            if let Some(obj) = meta.as_object() {
                for (k, v) in obj {
                    if let Some(s) = v.as_str() {
                        form.push((Box::leak(format!("metadata[{}]", k).into_boxed_str()), s.to_string()));
                    }
                }
            }
        }

        let resp = client
            .post("https://api.stripe.com/v1/checkout/sessions")
            .basic_auth(secret.as_ref(), None::<&str>)
            .form(&form)
            .send()
            .await
            .map_err(|e| StripeError::Request(e.to_string()))?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(StripeError::Api(text));
        }

        let session: CheckoutSession = resp.json().await
            .map_err(|e| StripeError::Api(e.to_string()))?;

        Ok(session)
    }
}

/// stripe payment intent
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct PaymentIntent {
    pub id: String,
    pub amount: u64,
    pub currency: String,
    pub status: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// stripe checkout session
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CheckoutSession {
    pub id: String,
    pub url: Option<String>,
    pub status: String,
    pub payment_status: String,
    #[serde(default)]
    pub metadata: serde_json::Value,
    #[serde(default)]
    pub amount_total: Option<u64>,
}

/// webhook event from stripe
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct WebhookEvent {
    pub id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub data: WebhookEventData,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct WebhookEventData {
    pub object: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_parsing() {
        // this would need a real signature to test properly
        // but we can test the parsing logic
        let sig = "t=1234567890,v1=abc123";
        let mut timestamp = None;
        let mut v1 = None;

        for part in sig.split(',') {
            if let Some(t) = part.strip_prefix("t=") {
                timestamp = Some(t);
            } else if let Some(s) = part.strip_prefix("v1=") {
                v1 = Some(s);
            }
        }

        assert_eq!(timestamp, Some("1234567890"));
        assert_eq!(v1, Some("abc123"));
    }
}
