//! Run with
//!
//! ```not_rust
//! cargo run -p example-readme
//! ```

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts, Query, State},
    http::{request::Parts, StatusCode},
    response::{Html, IntoResponse, Redirect},
    routing::get,
    Router,
};
use axum_extra::extract::{
    cookie::{Cookie, Key, SameSite},
    CookieJar, PrivateCookieJar,
};
use base64::Engine;
use color_eyre::eyre::Context;
use reqwest::tls::Version;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

macro_rules! unwrap_env {
    ($name:literal) => {
        std::env::var($name).expect(&format!("missing `{}` env var", $name))
    };
}

mod oauth2;

#[derive(Clone)]
struct AppState {
    http: reqwest::Client,
    oauth: Arc<oauth2::OauthClient>,
    tutors: Arc<Mutex<HashSet<u64>>>,
    key: Key,
}

impl FromRef<AppState> for Key {
    fn from_ref(input: &AppState) -> Self {
        input.key.clone()
    }
}

#[derive(Deserialize, Debug)]
struct User42 {
    id: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct GroupsUsers {
    id: u64,
}

async fn tutors(config: AppState) {
    loop {
        {
            let mut lock = config.tutors.lock().await;
            lock.clear();
            let mut page_nb = 0;
            loop {
                info!("tutor request (page {page_nb})");
                let res = config
                    .oauth
                    .do_request::<Vec<User42>>(
                        "https://api.intra.42.fr/v2/groups/166/users",
                        &json! ({
                            "page[number]": page_nb,
                            "page[size]": 100,
                        }),
                        Option::<&oauth2::Token>::None,
                    )
                    .await
                    .unwrap();
                let do_next = res.len() == 100;
                lock.extend(res.into_iter().map(|s| s.id));
                if !do_next {
                    break;
                }
                page_nb += 1;
            }
        }
        tokio::time::sleep(Duration::new(3600 * 24 /*tout les jours*/, 0)).await;
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            // initialize tracing
            let http = reqwest::ClientBuilder::new()
                // Following redirects opens the client up to SSRF vulnerabilities.
                .redirect(reqwest::redirect::Policy::none())
                .user_agent("AlterPoste/1.0")
                .tls_info(true)
                .min_tls_version(Version::TLS_1_0)
                .max_tls_version(Version::TLS_1_2)
                .build()
                .expect("Client should build");

            let cookie_secret = unwrap_env!("COOKIE_SECRET");
            let base64_value = base64::engine::general_purpose::URL_SAFE
                .decode(cookie_secret)
                .unwrap();
            let key: Key = Key::from(&base64_value);
            let oauth = oauth2::OauthClient::new(
                http.clone(),
                unwrap_env!("CLIENT_ID"),
                unwrap_env!("CLIENT_SECRET"),
                "http://local.maix.me:9911/auth/callback",
            )
            .await
            .unwrap();

            let state = AppState {
                http,
                key,
                oauth: Arc::new(oauth),
                tutors: Default::default(),
            };
            tokio::task::spawn_local(tutors(state.clone()));

            // build our application with a route
            let app = Router::new()
                // `GET /` goes to `root`
                .route("/", get(root))
                .route("/status", get(status))
                .route("/stop", get(stop))
                .route("/start", get(start))
                .route("/restart", get(restart))
                .route("/pull", get(git_pull))
                .route("/auth/callback", get(oauth2_callback))
                .route("/auth/login", get(oauth2_login))
                .with_state(state);

            // run our app with hyper
            let listener = tokio::net::TcpListener::bind(format!(
                "0.0.0.0:{}",
                std::env::args()
                    .nth(1)
                    .and_then(|s| s.parse::<u16>().ok())
                    .unwrap_or(9911)
            ))
            .await
            .unwrap();
            tracing::info!("listening on {}", listener.local_addr().unwrap());
            axum::serve(listener, app).await.unwrap();
        })
        .await;
}

async fn oauth2_login(State(state): State<AppState>) -> Result<Redirect, StatusCode> {
    Ok(Redirect::to(
        &(state
            .oauth
            .get_auth_url()
            .await
            .map_err(|e| {
                error!("{e}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .to_string()),
    ))
}

#[axum::debug_handler]
async fn oauth2_callback(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    jar: PrivateCookieJar,
) -> Result<impl IntoResponse, StatusCode> {
    let inner = || async {
        let Some(code) = params.get("code") else {
            return Ok::<_, color_eyre::eyre::Report>((jar, Redirect::to("/")));
        };
        let Some(state_csrf) = params.get("state") else {
            return Ok((jar, Redirect::to("/")));
        };
        let token = state
            .oauth
            .get_user_token(code, state_csrf)
            .await
            .wrap_err("callback")?;

        let res: User42 = state
            .oauth
            .do_request("https://api.intra.42.fr/v2/me", &(), Some(&token))
            .await
            .wrap_err("Unable to get user self")?;

        let mut cookie = Cookie::new("token", res.id.to_string());
        cookie.set_same_site(SameSite::None);
        cookie.set_secure(false);
        cookie.set_path("/");
        // cookie.set_domain("localhost:3000");
        // cookie.set_http_only(Some(false));
        let ujar = jar.add(cookie);
        Ok((ujar, Redirect::to("/")))
    };
    match inner().await {
        Ok(ret) => Ok(ret),
        Err(e) => {
            error!("{:?}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(Clone, Debug)]
struct UserLoggedIn;

#[async_trait]
impl FromRequestParts<AppState> for UserLoggedIn {
    type Rejection = (StatusCode, PrivateCookieJar, Redirect);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let jar = PrivateCookieJar::from_request_parts(parts, state)
            .await
            .unwrap();
        let Some(id) = jar.get("token") else {
            return Err((
                StatusCode::TEMPORARY_REDIRECT,
                jar,
                Redirect::to("/auth/login"),
            ));
        };

        let Ok(user_id) = id.value().parse::<u64>() else {
            let jar = jar.remove("token");
            return Err((
                StatusCode::TEMPORARY_REDIRECT,
                jar,
                Redirect::to("/auth/login"),
            ));
        };

        if state.tutors.lock().await.contains(&user_id) {
            Ok(UserLoggedIn)
        } else {
            let jar = jar.remove("token");
            Err((
                StatusCode::TEMPORARY_REDIRECT,
                jar,
                Redirect::to("/auth/login"),
            ))
        }
    }
}

// basic handler that responds with a static string
async fn root(_user: UserLoggedIn) -> Html<&'static str> {
    info!("Request link page");
    Html(
        r#"
        <a href="/restart">restart</a><br>
        <a href="/stop">stop</a><br>
        <a href="/start">start</a><br>
        <a href="/status">status</a><br>
        <a href="/pull">git pull (ask before!)</a><br>
        "#,
    )
}

async fn restart(_user: UserLoggedIn) -> Redirect {
    info!("Requested to restart the bot");
    tokio::spawn(async {
        tokio::process::Command::new("systemctl")
            .args(["--user", "restart", "botloc.service"])
            .spawn()
            .unwrap()
    });
    Redirect::to("/")
}

async fn start(_user: UserLoggedIn) -> Redirect {
    info!("Requested to start the bot");
    tokio::spawn(async {
        tokio::process::Command::new("systemctl")
            .args(["--user", "start", "botloc.service"])
            .spawn()
            .unwrap()
    });
    Redirect::to("/")
}

async fn stop(_user: UserLoggedIn) -> Redirect {
    info!("Requested to stop the bot");
    tokio::spawn(async {
        tokio::process::Command::new("systemctl")
            .args(["--user", "stop", "botloc.service"])
            .spawn()
            .unwrap()
    });
    Redirect::to("/")
}

async fn status() -> Result<String, StatusCode> {
    info!("Requested status");
    let mut output = tokio::process::Command::new("journalctl")
        .args(["-xeu", "botloc"])
        .output()
        .await
        // let mut output = child.wait_with_output().await
        .map_err(|e| {
            error!("Error with systemctl status {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    output.stdout.push(b'\n');
    output.stdout.append(&mut output.stderr);
    String::from_utf8(output.stdout).map_err(|e| {
        error!("Error with systemctl  status output {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

async fn git_pull() -> Result<String, (StatusCode, &'static str)> {
    info!("Requested to pull");
    let mut output = tokio::process::Command::new("/home/maix/.nix-profile/bin/git")
        .current_dir(std::env::var("BOTLOC_DIR").map_err(|e| {
            error!("Error with git pull command {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Please set the BOTLOC_DIR variable",
            )
        })?)
        .args(["pull"])
        .output()
        .await
        // let mut output = child.wait_with_output().await
        .map_err(|e| {
            error!("Error with git pull command {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error with the git pull command!",
            )
        })?;
    output.stdout.push(b'\n');
    output.stdout.append(&mut output.stderr);
    String::from_utf8(output.stdout).map_err(|e| {
        error!("Error with git pull output {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error with the git pull output!",
        )
    })
}
