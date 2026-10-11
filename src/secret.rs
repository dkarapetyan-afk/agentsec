use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Protected in-memory secret string that zeroizes its buffer when dropped.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(val: impl Into<String>) -> Self {
        Self(val.into())
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[SECRET_REDACTED]")
    }
}

impl Serialize for SecretValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(SecretValue::new(s))
    }
}

/// Metadata about a secret exposed in listing endpoints (does not contain the raw secret).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretMetadata {
    pub name: String,
    pub namespace: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub masked_preview: String,
}

impl SecretMetadata {
    pub fn remaining_ttl_seconds(&self) -> Option<i64> {
        self.expires_at
            .map(|e| (e - Utc::now()).num_seconds().max(0))
    }
    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.expires_at {
            Utc::now() >= exp
        } else {
            false
        }
    }
}

/// A stored secret entry combining metadata and protected value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    pub metadata: SecretMetadata,
    pub value: SecretValue,
}

impl SecretEntry {
    pub fn new(
        name: impl Into<String>,
        namespace: impl Into<String>,
        value: impl Into<String>,
        description: Option<String>,
        tags: Vec<String>,
        ttl_seconds: Option<u64>,
    ) -> Self {
        let name_str = name.into();
        let ns_str = namespace.into();
        let val_str = value.into();
        let now = Utc::now();
        let expires_at = ttl_seconds.map(|secs| now + chrono::Duration::seconds(secs as i64));
        let masked = mask_secret(&val_str);

        let metadata = SecretMetadata {
            name: name_str,
            namespace: ns_str,
            created_at: now,
            updated_at: now,
            expires_at,
            description,
            tags,
            masked_preview: masked,
        };

        Self {
            metadata,
            value: SecretValue::new(val_str),
        }
    }

    pub fn update(
        &mut self,
        value: impl Into<String>,
        description: Option<String>,
        tags: Option<Vec<String>>,
        ttl_seconds: Option<u64>,
    ) {
        let val_str = value.into();
        let now = Utc::now();
        self.metadata.updated_at = now;
        self.metadata.masked_preview = mask_secret(&val_str);
        if let Some(desc) = description {
            self.metadata.description = Some(desc);
        }
        if let Some(t) = tags {
            self.metadata.tags = t;
        }
        if let Some(secs) = ttl_seconds {
            self.metadata.expires_at = Some(now + chrono::Duration::seconds(secs as i64));
        }
        self.value = SecretValue::new(val_str);
    }

    pub fn is_expired(&self) -> bool {
        self.metadata.is_expired()
    }
}

/// Generates a safe masked preview of a secret string (e.g., `sk-ant-****98af`)
pub fn mask_secret(raw: &str) -> String {
    let len = raw.chars().count();
    if len == 0 {
        return "".to_string();
    }
    if len <= 6 {
        return "******".to_string();
    }
    if len <= 12 {
        let chars: Vec<char> = raw.chars().collect();
        let first2: String = chars[..2].iter().collect();
        let last2: String = chars[len - 2..].iter().collect();
        return format!("{}****{}", first2, last2);
    }

    let chars: Vec<char> = raw.chars().collect();
    let first4: String = chars[..4].iter().collect();
    let last4: String = chars[len - 4..].iter().collect();
    format!("{}...****...{}", first4, last4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_masking() {
        assert_eq!(mask_secret(""), "");
        assert_eq!(mask_secret("123"), "******");
        assert_eq!(mask_secret("123456"), "******");
        assert_eq!(mask_secret("12345678"), "12****78");
        assert_eq!(
            mask_secret("sk-ant-api03-verylongsecretkey12345"),
            "sk-a...****...2345"
        );
    }

    #[test]
    fn test_debug_redaction() {
        let secret = SecretValue::new("super-secret-password");
        let debug_str = format!("{:?}", secret);
        assert!(!debug_str.contains("super-secret-password"));
        assert!(debug_str.contains("[SECRET_REDACTED]"));
    }

    #[test]
    fn test_expiration() {
        let entry = SecretEntry::new("TEST_KEY", "default", "val", None, vec![], Some(1));
        assert!(!entry.is_expired());

        let mut expired_entry = entry.clone();
        expired_entry.metadata.expires_at = Some(Utc::now() - chrono::Duration::seconds(10));
        assert!(expired_entry.is_expired());
    }
}
