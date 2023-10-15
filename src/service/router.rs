use std::collections::HashMap;
use std::time::Duration;

use super::auth::verify_password;
use super::redirection::normalize_path;
use super::session::Session;

use axum::extract::{FromRef, Query, State};
use axum::http::{StatusCode, Uri};
use axum::response::{Html, IntoResponse, Redirect, Response, Result as ResponseResult};
use axum::routing::get;
use axum::{Form, Json, Router};
use axum_extra::extract::cookie::{Cookie, Key, SignedCookieJar};
use chrono::Utc;
use handlebars::Handlebars;
use serde::Deserialize;
use serde::Serialize;

const SESSION_COOKIE_NAME: &str = "session";
const SIGNIN_HTML_TEMPLATE: &str = include_str!("../../resources/signin.html");

fn get_signin_html(error: String) -> String {
    #[derive(Serialize)]
    struct Context {
        error: String,
    }
    Handlebars::new().render_template(SIGNIN_HTML_TEMPLATE, &Context { error }).unwrap()
}

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
            .route("/auth", get(auth))
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
    let html = get_signin_html("".into());
    Html::from(html)
}

async fn signin(
    State(config): State<ServiceConfig>,
    uri: Uri,
    jar: SignedCookieJar,
    Query(query): Query<SignInQuery>,
    Form(form): Form<SignInForm>,
) -> ResponseResult<Response> {
    let rd = match query.redirect_to {
        Some(r) if r.is_empty() => "./auth".into(),
        Some(r) => r,
        None => "./auth".into(),
    };
    let rd = normalize_path(uri.path(), &rd).ok_or(StatusCode::BAD_REQUEST)?;

    let ok = verify_password(config.users, &form.username, &form.password).map_err(|err| {
        log::error!("password verification error: {}", err);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    if !ok {
        let html = get_signin_html("invalid_username_password".into());
        return Err((StatusCode::FORBIDDEN, Html::from(html)).into());
    }

    log::info!("user '{}' authenticated", form.username);

    let session = Session {
        subject: form.username,
        expiration: Utc::now() + config.session_absolute_timeout,
    };
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
        Some(r) if r.is_empty() => "./signin".into(),
        Some(r) => r,
        None => "./signin".into(),
    };
    let rd = normalize_path(uri.path(), &rd).ok_or(StatusCode::BAD_REQUEST)?;
    let jar = jar.remove(Cookie::named(SESSION_COOKIE_NAME));
    Ok((jar, Redirect::to(&rd)).into_response())
}

async fn auth(jar: SignedCookieJar) -> ResponseResult<Response> {
    let cookie = jar.get(SESSION_COOKIE_NAME).ok_or(StatusCode::UNAUTHORIZED)?;
    let session = Session::from_cookie(cookie);
    if !session.is_valid(None) {
        return Err(StatusCode::UNAUTHORIZED.into());
    }
    let headers = [("X-Auth-Request-User", session.subject.clone())];
    let resp = Json::from(session);
    Ok((headers, resp).into_response())
}
