use std::collections::HashMap;
use std::time::Duration;

use super::auth::verify_password;
use super::page::get_signin_html;
use super::redirection::normalize_path;
use super::session::{Session, ValidationOptions};

use axum::extract::{FromRef, Query, State};
use axum::headers::{Host, Origin};
use axum::http::{StatusCode, Uri};
use axum::response::Result as AxumResult;
use axum::response::{IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{Json, Router, TypedHeader};
use axum_extra::extract::cookie::{Cookie, Key, SignedCookieJar};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;

const SESSION_COOKIE_NAME: &str = "session";

#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub session_absolute_timeout: Duration,
    pub session_secret_key: Vec<u8>,
    pub users: HashMap<String, String>,
}

impl FromRef<ServiceConfig> for Key {
    fn from_ref(config: &ServiceConfig) -> Self {
        let key: &[u8] = &config.session_secret_key;
        key.try_into().expect("invalid session secret key")
    }
}

impl ServiceConfig {
    pub fn build(self) -> Router {
        Router::new()
            .route("/", get(|| async { Redirect::permanent("./signin") }))
            .route("/signin", get(signin))
            .route("/signout", get(signout))
            .route("/authenticate", post(authenticate))
            .route("/userinfo", get(userinfo))
            .fallback(|| async { (StatusCode::NOT_FOUND, "not found") })
            .with_state(self)
    }

    pub fn generate_key() -> Vec<u8> {
        Key::generate().master().into()
    }
}

enum JsonError {
    InvalidCredential,
    InvalidOrigin,
    InvalidRedirect,
    Unauthenticated,
    InternalError,
}

impl IntoResponse for JsonError {
    fn into_response(self) -> axum::response::Response {
        use JsonError::*;
        let resp = match self {
            InvalidCredential => {
                (StatusCode::BAD_REQUEST, Json::from(json!({"error": "invalid_credential"})))
            }
            InvalidOrigin => {
                (StatusCode::BAD_REQUEST, Json::from(json!({"error": "invalid_origin"})))
            }
            InvalidRedirect => {
                (StatusCode::BAD_REQUEST, Json::from(json!({"error": "invalid_redirect"})))
            }
            Unauthenticated => {
                (StatusCode::UNAUTHORIZED, Json::from(json!({"error": "unauthenticated"})))
            }
            InternalError => {
                (StatusCode::INTERNAL_SERVER_ERROR, Json::from(json!({"error": "internal_error"})))
            }
        };
        resp.into_response()
    }
}

fn check_origin(origin: &Origin, host: &Host) -> bool {
    origin.hostname() == host.hostname() && origin.port() == host.port()
}

async fn signin() -> impl IntoResponse {
    get_signin_html()
}

#[derive(Debug, Clone, Deserialize)]
struct SignOutQuery {
    #[serde(rename = "rd")]
    redirect_to: Option<String>,
}

async fn signout(
    uri: Uri,
    Query(query): Query<SignOutQuery>,
    jar: SignedCookieJar,
) -> AxumResult<impl IntoResponse> {
    let rd = match query.redirect_to {
        Some(r) if !r.is_empty() => r,
        _ => "./signin".into(),
    };
    let rd = normalize_path(uri.path(), &rd).ok_or(StatusCode::BAD_REQUEST)?;
    let mut cookie = Cookie::named(SESSION_COOKIE_NAME);
    cookie.set_path("/");
    let jar = jar.remove(cookie);
    Ok((jar, Redirect::to(&rd)))
}

#[derive(Debug, Clone, Deserialize)]
struct AuthenticateRequest {
    username: String,
    password: String,
    redirect_to: Option<String>,
}

async fn authenticate(
    State(config): State<ServiceConfig>,
    uri: Uri,
    jar: SignedCookieJar,
    TypedHeader(origin): TypedHeader<Origin>,
    TypedHeader(host): TypedHeader<Host>,
    Json(req): Json<AuthenticateRequest>,
) -> AxumResult<impl IntoResponse> {
    if !check_origin(&origin, &host) {
        log::debug!("invalid origin: origin = '{}', host = '{}'", origin, host);
        return Err(JsonError::InvalidOrigin.into());
    }

    let rd = match req.redirect_to {
        Some(r) if !r.is_empty() => r,
        _ => "./userinfo".into(),
    };
    let rd = normalize_path(uri.path(), &rd).ok_or(JsonError::InvalidRedirect)?;

    let ok = verify_password(config.users, &req.username, &req.password).map_err(|err| {
        log::error!("password verification error: {}", err);
        JsonError::InternalError
    })?;
    if !ok {
        return Err(JsonError::InvalidCredential.into());
    }

    log::info!("user '{}' authenticated", req.username);

    let session = Session { subject: req.username, issued_at: Utc::now() };
    let jar = jar.add(session.to_cookie(SESSION_COOKIE_NAME));
    Ok((jar, Json::from(json!({"redirect_to": rd, "username": session.subject}))))
}

async fn userinfo(
    State(config): State<ServiceConfig>,
    jar: SignedCookieJar,
) -> AxumResult<impl IntoResponse> {
    let cookie = jar.get(SESSION_COOKIE_NAME).ok_or(JsonError::Unauthenticated)?;
    let session = Session::from_cookie(cookie);
    let options =
        ValidationOptions { now: None, absolute_timeout: config.session_absolute_timeout };
    if !session.is_valid(options) {
        return Err(JsonError::Unauthenticated.into());
    }
    let headers = [("X-Request-User", session.subject.clone())];
    let resp = Json::from(session);
    Ok((headers, resp))
}
