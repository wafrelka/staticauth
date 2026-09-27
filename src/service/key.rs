use std::fmt;

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
#[error("session secret key must be at least 64 bytes")]
pub struct InvalidSessionSecretKey;

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

impl TryFrom<Vec<u8>> for SessionSecretKey {
    type Error = InvalidSessionSecretKey;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Key::try_from(value.as_slice()).map(Self).map_err(|_| InvalidSessionSecretKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_secret_key_accepts_64_bytes() {
        let actual = SessionSecretKey::try_from(vec![0; 64]);
        assert!(actual.is_ok());
    }

    #[test]
    fn test_session_secret_key_rejects_63_bytes() {
        let actual = SessionSecretKey::try_from(vec![0; 63]);
        assert!(actual.is_err());
    }

    #[test]
    fn test_session_secret_key_debug_is_redacted() {
        let key = SessionSecretKey::try_from(vec![42; 64]).unwrap();
        let actual = format!("{:?}", key);
        assert_eq!(actual, "SessionSecretKey(<redacted>)");
    }
}
