use std::fmt;
use std::str::FromStr;

use axum_extra::extract::cookie::Key;
use thiserror::Error;

#[derive(Clone)]
pub struct SessionSecretKey(Key);

impl fmt::Debug for SessionSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionSecretKey(<redacted>)")
    }
}

#[derive(Debug, Error)]
pub enum InvalidSessionSecretKey {
    #[error("session secret key must be at least 64 bytes")]
    InvalidLength,
    #[error("session secret key must be formatted as hex string")]
    InvalidHexValue,
}

impl SessionSecretKey {
    pub fn generate() -> Self {
        Self(Key::generate())
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.master()
    }

    pub(crate) fn cookie_key(&self) -> Key {
        self.0.clone()
    }
}

impl FromStr for SessionSecretKey {
    type Err = InvalidSessionSecretKey;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bin = hex::decode(s).map_err(|_| InvalidSessionSecretKey::InvalidHexValue)?;
        Key::try_from(bin.as_slice()).map(Self).map_err(|_| InvalidSessionSecretKey::InvalidLength)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_secret_key_accepts_64_bytes() {
        let actual = "00".repeat(64).parse::<SessionSecretKey>();
        assert!(actual.is_ok());
    }

    #[test]
    fn test_session_secret_key_rejects_63_bytes() {
        let actual = "00".repeat(63).parse::<SessionSecretKey>();
        assert!(actual.is_err());
    }

    #[test]
    fn test_session_secret_key_rejects_invalid_hex() {
        let actual = "zz".repeat(64).parse::<SessionSecretKey>();
        assert!(matches!(actual, Err(InvalidSessionSecretKey::InvalidHexValue)));
    }

    #[test]
    fn test_session_secret_key_debug_is_redacted() {
        let key = "2a".repeat(64).parse::<SessionSecretKey>().unwrap();
        let actual = format!("{:?}", key);
        assert_eq!(actual, "SessionSecretKey(<redacted>)");
    }
}
