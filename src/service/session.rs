use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

type UtcDateTime = DateTime<Utc>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    #[serde(rename = "sub")]
    pub subject: String,
    #[serde(rename = "exp")]
    pub expiration: UtcDateTime,
}

impl Session {
    pub fn from_cookie(cookie: Cookie) -> Self {
        serde_json::from_str(cookie.value()).expect("could not deserialize session")
    }

    pub fn to_cookie<'a>(&self, name: &'a str) -> Cookie<'a> {
        let value = serde_json::to_string(&self).expect("could not serialize session");
        let mut cookie = Cookie::new(name, value);
        cookie.set_http_only(true);
        cookie.set_same_site(SameSite::Strict);
        cookie
    }

    pub fn is_valid(&self, now: Option<UtcDateTime>) -> bool {
        self.expiration >= now.unwrap_or_else(Utc::now)
    }
}
