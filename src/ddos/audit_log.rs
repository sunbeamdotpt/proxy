use serde::Deserialize;

#[derive(Deserialize)]
pub struct AuditLog {
    pub timestamp: String,
    pub fields: AuditFields,
}

#[derive(Deserialize)]
pub struct AuditFields {
    pub method: String,
    pub host: String,
    pub path: String,
    pub client_ip: String,
    #[serde(deserialize_with = "flexible_u16")]
    pub status: u16,
    #[serde(deserialize_with = "flexible_u64")]
    pub duration_ms: u64,
    #[serde(default)]
    pub backend: String,
    #[serde(default)]
    pub content_length: u64,
    #[serde(default = "default_ua")]
    pub user_agent: String,
    #[serde(default)]
    pub query: String,
    #[serde(default)]
    pub has_cookies: Option<bool>,
    #[serde(default)]
    pub referer: Option<String>,
    #[serde(default)]
    pub accept_language: Option<String>,
    /// Optional ground-truth label from external datasets (e.g. CSIC 2010).
    /// Values: "attack", "normal". When present, trainers should use this
    /// instead of heuristic labeling.
    #[serde(default)]
    pub label: Option<String>,
}

fn default_ua() -> String {
    "-".to_string()
}

pub fn flexible_u64<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<u64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrNum {
        Num(u64),
        Str(String),
    }
    match StringOrNum::deserialize(deserializer)? {
        StringOrNum::Num(n) => Ok(n),
        StringOrNum::Str(s) => s.parse().map_err(serde::de::Error::custom),
    }
}

pub fn flexible_u16<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<u16, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrNum {
        Num(u16),
        Str(String),
    }
    match StringOrNum::deserialize(deserializer)? {
        StringOrNum::Num(n) => Ok(n),
        StringOrNum::Str(s) => s.parse().map_err(serde::de::Error::custom),
    }
}

/// Strip the port suffix from a socket address string.
pub fn strip_port(addr: &str) -> &str {
    if addr.starts_with('[') {
        addr.find(']').map(|i| &addr[1..i]).unwrap_or(addr)
    } else if let Some(pos) = addr.rfind(':') {
        &addr[..pos]
    } else {
        addr
    }
}
