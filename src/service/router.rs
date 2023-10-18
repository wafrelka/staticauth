use std::collections::HashMap;
use std::time::Duration;

use super::auth::verify_password;
use super::page::get_signin_html;
use super::redirection::normalize_path;
use super::session::{Session, ValidationOptions};

use axum::extract::{FromRef, Query, State};
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Redirect, Response, Result as ResponseResult};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
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
            .route("/signin", get(front).post(signin))
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

#[derive(Debug, Clone, Deserialize)]
struct SignInForm {
    username: String,
    password: String,
}

#[derive(Debug, Clone, Deserialize)]
struct SignInQuery {
    #[serde(rename = "rd")]
    redirect_to: Option<String>,
}

async fn front() -> impl IntoResponse {
    get_signin_html("")
}

async fn signin(
    State(config): State<ServiceConfig>,
    uri: Uri,
    jar: SignedCookieJar,
    Query(query): Query<SignInQuery>,
    Form(form): Form<SignInForm>,
) -> ResponseResult<Response> {
    let rd = match query.redirect_to {
        Some(r) if !r.is_empty() => r,
        _ => "./userinfo".into(),
    };
    let rd = normalize_path(uri.path(), &rd).ok_or(StatusCode::BAD_REQUEST)?;

    let ok = verify_password(config.users, &form.username, &form.password).map_err(|err| {
        log::error!("password verification error: {}", err);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    if !ok {
        let html = get_signin_html("invalid_username_password");
        return Err((StatusCode::FORBIDDEN, html).into());
    }

    log::info!("user '{}' authenticated", form.username);

    let session = Session { subject: form.username, issued_at: Utc::now() };
    let jar = jar.add(session.to_cookie(SESSION_COOKIE_NAME));
    Ok((jar, Redirect::to(&rd)).into_response())
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
) -> ResponseResult<Response> {
    let rd = match query.redirect_to {
        Some(r) if !r.is_empty() => r,
        _ => "./signin".into(),
    };
    let rd = normalize_path(uri.path(), &rd).ok_or(StatusCode::BAD_REQUEST)?;
    let jar = jar.remove(Cookie::named(SESSION_COOKIE_NAME));
    Ok((jar, Redirect::to(&rd)).into_response())
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
    Json(req): Json<AuthenticateRequest>,
) -> ResponseResult<Response> {
    let rd = match req.redirect_to {
        Some(r) if !r.is_empty() => r,
        _ => "./userinfo".into(),
    };
    let rd = normalize_path(uri.path(), &rd)
        .ok_or((StatusCode::BAD_REQUEST, Json::from(json!({"error": "invalid_redirect"}))))?;

    let ok = verify_password(config.users, &req.username, &req.password).map_err(|err| {
        log::error!("password verification error: {}", err);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    if !ok {
        return Err(
            (StatusCode::FORBIDDEN, Json::from(json!({ "error": "invalid_credential" }))).into()
        );
    }

    log::info!("user '{}' authenticated", req.username);

    let session = Session { subject: req.username, issued_at: Utc::now() };
    let jar = jar.add(session.to_cookie(SESSION_COOKIE_NAME));
    Ok((jar, Json::from(json!({"redirect_to": rd, "username": session.subject}))).into_response())
}

async fn userinfo(
    State(config): State<ServiceConfig>,
    jar: SignedCookieJar,
) -> ResponseResult<Response> {
    let unauthenticated = (StatusCode::FORBIDDEN, Json::from(json!({"error": "unauthenticated"})));
    let cookie = jar.get(SESSION_COOKIE_NAME).ok_or(unauthenticated.clone())?;
    let session = Session::from_cookie(cookie);
    let options =
        ValidationOptions { now: None, absolute_timeout: config.session_absolute_timeout };
    if !session.is_valid(options) {
        return Err(unauthenticated.into());
    }
    let headers = [("X-Request-User", session.subject.clone())];
    let resp = Json::from(session);
    Ok((headers, resp).into_response())
}
