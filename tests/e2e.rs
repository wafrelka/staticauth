use std::fs;
use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hyper::body::to_bytes;
use hyper::header;
use hyper::{Body, Client, Request, Response, StatusCode};
use serde_json::{Value, json};

const BINARY: &str = env!("CARGO_BIN_EXE_staticauth");

#[tokio::test]
async fn user_can_authenticate_and_access_userinfo() {
    let password = "correct horse battery staple";
    let server = TestServer::start(password);
    let client = Client::new();

    let response = client.get(server.uri("/userinfo")).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response_json(response).await, json!({"error": "unauthenticated"}));

    let credentials = json!({
        "username": "alice",
        "password": password,
        "redirect_to": "/private"
    });
    let response = client
        .request(
            Request::post(server.uri("/authenticate"))
                .header(header::ORIGIN, &server.base_url)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(credentials.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let session_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    assert_eq!(
        response_json(response).await,
        json!({"redirect_to": "/private", "username": "alice"})
    );

    let response = client
        .request(
            Request::builder()
                .uri(server.uri("/userinfo"))
                .header(header::COOKIE, session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get("x-auth-request-user").unwrap(), "alice");
    assert_eq!(response.headers().get(header::CACHE_CONTROL).unwrap(), "no-store");
    assert_eq!(response_json(response).await["sub"], "alice");
}

struct TestServer {
    child: Child,
    base_url: String,
    temp_dir: PathBuf,
}

impl TestServer {
    fn start(password: &str) -> Self {
        let password_hash = hash_password(password);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);

        let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let temp_dir =
            std::env::temp_dir().join(format!("staticauth-e2e-{}-{unique}", std::process::id()));
        fs::create_dir(&temp_dir).unwrap();
        let config_path = temp_dir.join("config.toml");
        let config = format!(
            r#"session_secret_key = "{}"
address = "{address}"

[[users]]
username = "alice"
password = "{password_hash}"
"#,
            "00".repeat(64)
        );
        fs::write(&config_path, config).unwrap();

        let child = Command::new(BINARY)
            .arg("--config")
            .arg(config_path)
            .arg("serve")
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut server = Self { child, base_url: format!("http://{address}"), temp_dir };
        server.wait_until_ready(address);
        server
    }

    fn uri(&self, path: &str) -> hyper::Uri {
        format!("{}{path}", self.base_url).parse().unwrap()
    }

    fn wait_until_ready(&mut self, address: SocketAddr) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
                return;
            }
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!("staticauth exited before accepting connections: {status}");
            }
            assert!(Instant::now() < deadline, "staticauth did not start within 5 seconds");
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

fn hash_password(password: &str) -> String {
    let mut child = Command::new(BINARY)
        .arg("hash")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{password}").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "staticauth hash failed: {}", output.status);
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

async fn response_json(response: Response<Body>) -> Value {
    let body = to_bytes(response.into_body()).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}
