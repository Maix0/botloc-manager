//! Run with
//!
//! ```not_rust
//! cargo run -p example-readme
//! ```

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
    time::Duration,
};

use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts, Query, State},
    http::{request::Parts, StatusCode},
    response::{AppendHeaders, Html, IntoResponse, Redirect},
    routing::get,
    Json, Router,
};
use axum_extra::extract::{
    cookie::{Cookie, Expiration, Key, SameSite},
    CookieJar,
};
use base64::Engine;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::AsyncReadExt;
use tracing::{error, info};

use oauth2::{
    basic::*, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointNotSet,
    EndpointSet, IntrospectionUrl, RedirectUrl, RefreshToken, TokenResponse, TokenUrl,
};

macro_rules! unwrap_env {
    ($name:literal) => {
        std::env::var($name).expect(&format!("missing `{}` env var", $name))
    };
}

type OClient = BasicClient<EndpointSet, EndpointNotSet, EndpointSet, EndpointNotSet, EndpointSet>;

#[derive(Clone, Debug)]
struct Token {
    token: String,
    refresh: String,
}

impl Token {
    async fn refresh(tok: &BearerToken, config: &AppState) -> Result<(), ()> {
        let token = match tok {
            BearerToken::User(i) => {
                let users = config.users.write().unwrap();
                users.get(&i).ok_or(())?.refresh.clone()
            }
            BearerToken::Provided(_) => return Err(()),
            BearerToken::App => {
                let code = config
                    .oauth
                    .exchange_client_credentials()
                    .request_async(&config.http)
                    .await
                    .unwrap();
                config.token.write().unwrap().token = code.access_token().secret().clone();
                return Ok(());
            }
        };
        let refresh_token = RefreshToken::new(token);

        match config
            .oauth
            .exchange_refresh_token(&refresh_token)
            .request_async(&config.http)
            .await
        {
            Err(e) => Err(error!("Unable to refresh token ! {e}")),
            Ok(t) => {
                info!("Refreshed a token !");
                match tok {
                    BearerToken::User(i) => {
                        let mut users = config.users.write().unwrap();
                        let u = users.get_mut(&i).ok_or(())?;
                        u.token = t.access_token().secret().clone();
                        u.refresh = t.refresh_token().unwrap().secret().clone();
                    }
                    _ => return Err(()),
                };
                Ok(())
            }
        }
    }
}

#[derive(Clone)]
struct AppState {
    http: reqwest::Client,
    oauth: OClient,
    key: Key,
    users: Arc<RwLock<HashMap<u64, Token>>>,
    token: Arc<RwLock<Token>>,
    tutors: Arc<RwLock<HashSet<u64>>>,
}
impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.key.clone()
    }
}

enum BearerToken {
    App,
    User(u64),
    Provided(Token),
}

impl AppState {
    async fn do_request<R: DeserializeOwned>(
        &self,
        url: impl reqwest::IntoUrl + Clone,
        query: impl Serialize,
        mut tok: BearerToken,
    ) -> Result<R, ()> {
        let res = {
            let mut users = self.users.write().unwrap();
            let mut lock = match &tok {
                BearerToken::App => Some(self.token.write().unwrap()),
                _ => None,
            };
            let token = match &mut lock {
                Some(s) => Ok(&mut **s),
                None => {
                    if let BearerToken::User(id) = &tok {
                        users.get_mut(&id).ok_or(())
                    } else if let BearerToken::Provided(t) = &mut tok {
                        Ok(t)
                    } else {
                        Err(())
                    }
                }
            }?;

            self.http
                .get(url.clone())
                .bearer_auth(&token.token)
                .query(&query)
                .send()
        };
        let res = res.await.map_err(|e| error!("Error with request {e}"))?;
        let json = res
            .json::<Value>()
            .await
            .map_err(|e| error!("Error with request response {e}"))?;

        if !json["error"].is_null() && json["message"].as_str() == Some("The access token expired")
        {
            Token::refresh(&tok, self).await?;
            return Box::pin(Self::do_request(self, url, query, tok)).await;
        }

        serde_json::from_value(json).map_err(|e| error!("error when parsing json {e}"))
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
            let mut lock = config.tutors.write().unwrap();
            lock.clear();
            let mut page_nb = 0;
            loop {
                info!("tutor request (page {page_nb})");
                let res = config
                    .do_request::<Vec<GroupsUsers>>(
                        "https://api.intra.42.fr/v2/groups/166/users",
                        json! ({
                            "page[number]": page_nb,
                            "page[size]": 100,
                        }),
                        BearerToken::App,
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
            let oauth = BasicClient::new(ClientId::new(unwrap_env!("CLIENT_ID")))
                .set_redirect_uri(
                    RedirectUrl::new("https://t.maix.me/auth/callback".to_string()).unwrap(),
                )
                .set_introspection_url(
                    IntrospectionUrl::new("https://api.intra.42.fr/oauth/token/info".to_string())
                        .unwrap(),
                )
                .set_client_secret(ClientSecret::new(unwrap_env!("CLIENT_SECRET")))
                .set_auth_uri(
                    AuthUrl::new("https://api.intra.42.fr/oauth/authorize".to_string())
                        .expect("invalid authUrl"),
                )
                .set_token_uri(
                    TokenUrl::new("https://api.intra.42.fr/oauth/token".to_string())
                        .expect("invalid tokenUrl"),
                );

            let http = reqwest::ClientBuilder::new()
                // Following redirects opens the client up to SSRF vulnerabilities.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("Client should build");

            let cookie_secret = unwrap_env!("COOKIE_SECRET");
            let base64_value = base64::engine::general_purpose::URL_SAFE
                .decode(cookie_secret)
                .unwrap();
            let key: Key = Key::from(&base64_value);

            let code = oauth
                .exchange_client_credentials()
                .request_async(&http)
                .await
                .unwrap();
            let state = AppState {
                token: Arc::new(RwLock::new(Token {
                    token: code.access_token().secret().clone(),
                    refresh: String::new(),
                })),
                tutors: Default::default(),
                key,
                http,
                oauth,
                users: Default::default(),
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
                .route("/config", get(get_config))
                .route("/db", get(get_db))
                .route("/pull", get(git_pull))
                .route("/auth/callback", get(oauth2_callback))
                .route("/auth/login", get(oauth2_login))
                .with_state(state);

            // run our app with hyper
            let listener = tokio::net::TcpListener::bind("127.0.0.1:9911")
                .await
                .unwrap();
            tracing::info!("listening on {}", listener.local_addr().unwrap());
            axum::serve(listener, app).await.unwrap();
        })
        .await;
}

async fn oauth2_login(State(state): State<AppState>) -> Redirect {
    let (url, _) = state.oauth.authorize_url(CsrfToken::new_random).url();
    Redirect::to(url.as_str())
}

use time::Duration as TDuration;
use time::OffsetDateTime;

#[axum::debug_handler]
async fn oauth2_callback(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    jar: CookieJar,
) -> impl IntoResponse {
    let Some(code) = params.get("code") else {
        return (jar, Redirect::to("/"));
    };
    let Some(state_csrf) = params.get("state") else {
        return (jar, Redirect::to("/"));
    };
    let mut form_data = HashMap::new();
    form_data.insert("grant_type", "authorization_code".to_string());
    form_data.insert("client_id", unwrap_env!("CLIENT_ID"));
    form_data.insert("client_secret", unwrap_env!("CLIENT_SECRET"));
    form_data.insert("code", code.to_string());
    form_data.insert(
        "redirect_uri",
        state.oauth.redirect_uri().unwrap().to_string(),
    );
    form_data.insert("state", state_csrf.to_string());
    let token_res = match state
        .http
        .post(state.oauth.token_uri().as_str())
        .form(&form_data)
        .send()
        .await
    {
        Ok(o) => o.json::<Value>().await.unwrap(),
        Err(e) => {
            error!("{e}");
            return (jar, Redirect::to("/auth/error"));
        }
    };
    let Ok(rep) = state
        .do_request::<User42>(
            "https://api.intra.42.fr/v2/me",
            (),
            BearerToken::Provided(
                match token_res["access_token"].as_str().ok_or(()).and_then(|t| {
                    token_res["refresh_token"]
                        .as_str()
                        .ok_or(())
                        .map(|r| Token {
                            token: t.to_string(),
                            refresh: r.to_string(),
                        })
                }) {
                    Ok(v) => v,
                    Err(_) => return (jar, Redirect::to("/error/")),
                },
            ),
        )
        .await
    else {
        info!("failed to get id");
        return (jar, Redirect::to("/error/"));
    };

    if !state.tutors.read().unwrap().contains(&rep.id) {
        info!("non tutor tried to login");
        return (jar, Redirect::to("/error/"));
    }

    let mut cookie = Cookie::new("token", rep.id.to_string());
    let mut now = OffsetDateTime::now_utc();
    now += TDuration::weeks(52);
    cookie.set_expires(Some(now));
    cookie.set_same_site(SameSite::None);
    cookie.set_secure(true);
    // cookie.set_domain("localhost:3000");
    cookie.set_path("/");
    //cookie.set_http_only(Some(false));
    state.users.write().unwrap().insert(
        rep.id,
        match token_res["access_token"].as_str().ok_or(()).and_then(|t| {
            dbg!(&token_res)["refresh_token"]
                .as_str()
                .ok_or(())
                .map(|r| Token {
                    token: t.to_string(),
                    refresh: r.to_string(),
                })
        }) {
            Ok(v) => v,
            Err(_) => return (jar, Redirect::to("/error/")),
        },
    );

    let ujar = jar.add(cookie);
    info!("logged in");
    (ujar, Redirect::to("/"))
}

#[derive(Clone, Debug)]
struct UserLoggedIn {
    id: u64,
}

#[async_trait]
impl FromRequestParts<AppState> for UserLoggedIn {
    type Rejection = (StatusCode, CookieJar, Redirect);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        info!("banane");
        let jar = CookieJar::from_request_parts(parts, state).await.unwrap();
        dbg!(&jar);
        let Some(id) = jar.get("token") else {
            info!("no cookie");
            return Err((
                StatusCode::TEMPORARY_REDIRECT,
                jar,
                Redirect::to("/auth/login"),
            ));
        };

        let Ok(user_id) = id.value().parse::<u64>() else {
            let jar = jar.remove("token");
            info!("not id");
            return Err((
                StatusCode::TEMPORARY_REDIRECT,
                jar,
                Redirect::to("/auth/login"),
            ));
        };

        if state.tutors.read().unwrap().contains(&user_id) {
            info!("is tut");
            Ok(UserLoggedIn { id: user_id })
        } else {
            info!("not tut");
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
        <a href="/config">config</a><br>
        <a href="/db">db</a><br>
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

#[derive(Serialize, Deserialize)]
struct BotConfig {
    piscine: Vec<String>,
    pc_tut: Vec<String>,
    id_server: u64,
    id_channel_alerte: u64,
    id_role: u64,
    mois: String,
    annee: String,
}

async fn get_config(_user: UserLoggedIn) -> Result<Json<BotConfig>, (StatusCode, String)> {
    info!("Requested config");
    let Ok(mut file) = tokio::fs::File::open(
        std::env::var("BOTLOC_DIR").map_err(|e| {
            error!("Failed to open config file: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "please set env CONFIG_PATH".to_string(),
            )
        })? + "/config.json",
    )
    .await
    .map_err(|e| {
        error!("Failed to open config file: {e}");
        e
    }) else {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "failed to open config file: {}/config.json",
                std::env::var("BOTLOC_DIR").unwrap()
            ),
        ));
    };

    let mut s = String::new();
    if file
        .read_to_string(&mut s)
        .await
        .map_err(|e| {
            error!("Failed to open config file: {e}");
            e
        })
        .is_err()
    {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "Failed to read config file at {}/config.json",
                std::env::var("BOTLOC_DIR").unwrap()
            ),
        ));
    };
    let Ok(val) = serde_json::from_str::<BotConfig>(&s).map_err(|e| {
        error!("Failed to open config file: {e}");
        e
    }) else {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "Failed to read config file as json at {}/config.json",
                std::env::var("BOTLOC_DIR").unwrap()
            ),
        ));
    };
    Ok(Json(val))
}

async fn get_db(_user: UserLoggedIn) -> Result<Json<Value>, (StatusCode, String)> {
    info!("Requested config");
    let Ok(mut file) = tokio::fs::File::open(
        std::env::var("BOTLOC_DIR").map_err(|e| {
            error!("Failed to open config file: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "please set env CONFIG_PATH".to_string(),
            )
        })? + "/db.json",
    )
    .await
    .map_err(|e| {
        error!("Failed to open config file: {e}");
        e
    }) else {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "failed to open config file: {}/db.json",
                std::env::var("BOTLOC_DIR").unwrap()
            ),
        ));
    };

    let mut s = String::new();
    if file
        .read_to_string(&mut s)
        .await
        .map_err(|e| {
            error!("Failed to open config file: {e}");
            e
        })
        .is_err()
    {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "Failed to read config file at {}/db.json",
                std::env::var("BOTLOC_DIR").unwrap()
            ),
        ));
    };
    let Ok(val) = serde_json::from_str::<Value>(&s).map_err(|e| {
        error!("Failed to open config file: {e}");
        e
    }) else {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "Failed to read config file as json at {}/db.json",
                std::env::var("BOTLOC_DIR").unwrap()
            ),
        ));
    };
    Ok(Json(val))
}

async fn status() -> Result<String, StatusCode> {
    info!("Requested status");
    let mut output = tokio::process::Command::new("systemctl")
        .args(["--user", "status", "botloc.service"])
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
    dbg!(std::env::var("PATH"));
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
