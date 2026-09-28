use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use super::auth::verify_password;
use super::headers::{X_AUTH_REQUEST_REDIRECT, X_AUTH_REQUEST_SIGNIN, X_AUTH_REQUEST_USER};
use super::key::SessionSecretKey;
use super::page::get_signin_html;
use super::redirection::{add_query_to_path, normalize_path};
use super::session::{Session, ValidationOptions};

use axum::extract::{FromRef, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::Result as AxumResult;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use axum_extra::TypedHeader;
use axum_extra::extract::cookie::{Cookie, Key, SignedCookieJar};
use axum_extra::headers::{Host, Origin};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;

const SESSION_COOKIE_NAME: &str = "session";

#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub session_absolute_timeout: Duration,
    pub session_secret_key: SessionSecretKey,
    pub users: HashMap<String, String>,
}

#[derive(Debug, Clone)]
struct AppState {
    session_absolute_timeout: Duration,
    session_secret_key: SessionSecretKey,
    users: Arc<HashMap<String, String>>,
}

impl From<ServiceConfig> for AppState {
    fn from(config: ServiceConfig) -> Self {
        Self {
            session_absolute_timeout: config.session_absolute_timeout,
            session_secret_key: config.session_secret_key,
            users: Arc::new(config.users),
        }
    }
}

impl ServiceConfig {
    pub fn build(self) -> Router {
        Router::new()
            .route("/", get(|| async { Redirect::permanent("./signin") }))
            .route("/signin", get(signin))
            .route("/signout", get(signout))
            .route("/authenticate", post(authenticate))
            .route("/userinfo", any(userinfo))
            .fallback(|| async { (StatusCode::NOT_FOUND, "not found") })
            .with_state(AppState::from(self))
    }
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.session_secret_key.cookie_key()
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

fn no_store(response: impl IntoResponse) -> Response {
    let mut response = response.into_response();
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn unauthenticated_response(uri: &Uri, headers: &HeaderMap) -> Result<Response, StatusCode> {
    let Some(signin_header) = headers.get(X_AUTH_REQUEST_SIGNIN) else {
        return Ok(no_store(JsonError::Unauthenticated));
    };

    let signin = signin_header.to_str().ok().ok_or(StatusCode::BAD_REQUEST)?;
    let signin = normalize_path(uri.path(), signin).ok_or(StatusCode::BAD_REQUEST)?;
    let location = match headers.get(X_AUTH_REQUEST_REDIRECT) {
        Some(redirect_header) => {
            let rd = redirect_header.to_str().ok().ok_or(StatusCode::BAD_REQUEST)?;
            let rd = normalize_path(uri.path(), rd).ok_or(StatusCode::BAD_REQUEST)?;
            add_query_to_path(&signin, "rd", &rd).ok_or(StatusCode::BAD_REQUEST)?
        }
        None => signin,
    };

    Ok(no_store(Redirect::to(&location)))
}

#[derive(Debug, Clone, Deserialize)]
struct SignInQuery {
    #[serde(rename = "rd")]
    redirect_to: Option<String>,
}

async fn signin(
    uri: Uri,
    headers: HeaderMap,
    Query(query): Query<SignInQuery>,
) -> AxumResult<impl IntoResponse> {
    if query.redirect_to.is_none() {
        let Some(redirect_header) = headers.get(X_AUTH_REQUEST_REDIRECT) else {
            return Ok(get_signin_html().into_response());
        };
        let rd = redirect_header.to_str().ok().ok_or(StatusCode::BAD_REQUEST)?;
        let rd = normalize_path(uri.path(), rd).ok_or(StatusCode::BAD_REQUEST)?;
        let signin_redirect =
            add_query_to_path(uri.path(), "rd", &rd).ok_or(StatusCode::BAD_REQUEST)?;
        return Ok(Redirect::to(&signin_redirect).into_response());
    }
    Ok(get_signin_html().into_response())
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
    let jar = jar.remove(Cookie::build(SESSION_COOKIE_NAME));
    Ok((jar, Redirect::to(&rd)))
}

#[derive(Debug, Clone, Deserialize)]
struct AuthenticateRequest {
    username: String,
    password: String,
    redirect_to: Option<String>,
}

async fn authenticate(
    State(state): State<AppState>,
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

    let ok = verify_password(&state.users, &req.username, &req.password).map_err(|err| {
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
    State(state): State<AppState>,
    uri: Uri,
    headers: HeaderMap,
    jar: SignedCookieJar,
) -> Result<Response, StatusCode> {
    let Some(cookie) = jar.get(SESSION_COOKIE_NAME) else {
        return unauthenticated_response(&uri, &headers);
    };
    let session = match Session::from_cookie(cookie) {
        Ok(session) => session,
        Err(err) => {
            log::debug!("invalid session cookie: {}", err);
            return unauthenticated_response(&uri, &headers);
        }
    };
    let options = ValidationOptions { now: None, absolute_timeout: state.session_absolute_timeout };
    if !session.is_valid(options) {
        return unauthenticated_response(&uri, &headers);
    }
    let headers = [(X_AUTH_REQUEST_USER, session.subject.clone())];
    let resp = Json::from(session);
    Ok(no_store((headers, resp)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_origin_rejects_different_host() {
        let origin = Origin::try_from_parts("http", "example.com", 8080).unwrap();
        let host = Host::from("localhost:8080".parse::<axum::http::uri::Authority>().unwrap());

        assert!(!check_origin(&origin, &host));
    }

    #[tokio::test]
    async fn test_signout_removes_session_cookie() {
        let key = Key::generate();
        let response = SignedCookieJar::new(key.clone())
            .add(Cookie::new(SESSION_COOKIE_NAME, "value"))
            .into_response();
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_str(cookie).unwrap());
        let jar = SignedCookieJar::from_headers(&headers, key);
        assert!(jar.get(SESSION_COOKIE_NAME).is_some());
        let uri = Uri::from_static("/signout");
        let query = Query::<SignOutQuery>::try_from_uri(&uri).unwrap();

        let response = signout(uri, query, jar).await.unwrap().into_response();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/signin");
        let removal_cookie = response.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap();
        assert!(removal_cookie.starts_with("session=;"));
        assert!(removal_cookie.contains("Max-Age=0"));
    }

    #[tokio::test]
    async fn test_signin_redirects_from_redirect_header_without_redirect_query() {
        let uri = Uri::from_static("/signin");
        let mut headers = HeaderMap::new();
        headers.insert(X_AUTH_REQUEST_REDIRECT, HeaderValue::from_static("/private?page=1"));
        let query = Query::<SignInQuery>::try_from_uri(&uri).unwrap();

        let response = signin(uri, headers.clone(), query).await.unwrap().into_response();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "/signin?rd=%2Fprivate%3Fpage%3D1"
        );
    }

    #[tokio::test]
    async fn test_signin_ignores_redirect_header_with_redirect_query() {
        let uri = Uri::from_static("/signin?rd=%2Fprivate%3Fpage%3D1");
        let mut headers = HeaderMap::new();
        headers.insert(X_AUTH_REQUEST_REDIRECT, HeaderValue::from_static("/private?page=1"));
        let query = Query::<SignInQuery>::try_from_uri(&uri).unwrap();
        let response = signin(uri, headers, query).await.unwrap().into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::LOCATION).is_none());
    }

    #[test]
    fn test_unauthenticated_response_without_signin() {
        let uri = Uri::from_static("/userinfo");
        let headers = HeaderMap::new();

        let response = unauthenticated_response(&uri, &headers).unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers().get(header::CACHE_CONTROL).unwrap(), "no-store");
    }

    #[test]
    fn test_unauthenticated_response_with_signin() {
        let uri = Uri::from_static("/userinfo");
        let mut headers = HeaderMap::new();
        headers.insert(X_AUTH_REQUEST_SIGNIN, HeaderValue::from_static("/_auth/signin"));
        headers.insert(X_AUTH_REQUEST_REDIRECT, HeaderValue::from_static("/private?page=1"));

        let response = unauthenticated_response(&uri, &headers).unwrap();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "/_auth/signin?rd=%2Fprivate%3Fpage%3D1"
        );
        assert_eq!(response.headers().get(header::CACHE_CONTROL).unwrap(), "no-store");
    }

    #[test]
    fn test_unauthenticated_response_with_signin_without_redirect() {
        let uri = Uri::from_static("/userinfo");
        let mut headers = HeaderMap::new();
        headers.insert(X_AUTH_REQUEST_SIGNIN, HeaderValue::from_static("/_auth/signin"));

        let response = unauthenticated_response(&uri, &headers).unwrap();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/_auth/signin");
    }

    #[test]
    fn test_unauthenticated_response_rejects_external_signin() {
        let uri = Uri::from_static("/userinfo");
        let mut headers = HeaderMap::new();
        headers
            .insert(X_AUTH_REQUEST_SIGNIN, HeaderValue::from_static("https://example.com/signin"));

        assert!(unauthenticated_response(&uri, &headers).is_err());
    }
}
