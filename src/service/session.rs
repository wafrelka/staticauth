use std::time::Duration;

use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

type UtcDateTime = DateTime<Utc>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    #[serde(rename = "sub")]
    pub subject: String,
    #[serde(rename = "iat")]
    pub issued_at: UtcDateTime,
}

#[derive(Debug, Clone)]
pub struct ValidationOptions {
    pub now: Option<UtcDateTime>,
    pub absolute_timeout: Duration,
}

impl Session {
    pub fn from_cookie(cookie: Cookie) -> Self {
        serde_json::from_str(cookie.value()).expect("could not deserialize session")
    }

    pub fn to_cookie<'a>(&self, name: &'a str) -> Cookie<'a> {
        let value = serde_json::to_string(&self).expect("could not serialize session");
        let mut cookie = Cookie::new(name, value);
        cookie.set_path("/");
        cookie.set_http_only(true);
        cookie.set_same_site(SameSite::Strict);
        cookie
    }

    pub fn is_valid(&self, options: ValidationOptions) -> bool {
        let now = options.now.unwrap_or_else(Utc::now);
        self.issued_at + options.absolute_timeout >= now
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timestamp(secs: i64) -> UtcDateTime {
        UtcDateTime::from_timestamp(secs, 0).unwrap()
    }

    #[test]
    fn test_session_is_valid_ok() {
        let options = ValidationOptions {
            now: Some(timestamp(100000 + 100)),
            absolute_timeout: Duration::from_secs(100),
        };
        let session = Session { subject: "".into(), issued_at: timestamp(100000) };
        let expected = true;
        let actual = session.is_valid(options);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_session_is_valid_expired() {
        let options = ValidationOptions {
            now: Some(timestamp(100000 + 101)),
            absolute_timeout: Duration::from_secs(100),
        };
        let session = Session { subject: "".into(), issued_at: timestamp(100000) };
        let expected = false;
        let actual = session.is_valid(options);
        assert_eq!(expected, actual);
    }
}
