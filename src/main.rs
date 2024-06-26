//! Run with
//!
//! ```not_rust
//! cargo run -p example-readme
//! ```

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
};

use axum::{
    extract::{FromRef, Query, State},
    http::StatusCode,
    response::{Html, Redirect},
    routing::get,
    Json, Router,
};
use axum_extra::extract::{
    cookie::{Cookie, Expiration, Key, SameSite},
    CookieJar, PrivateCookieJar,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::AsyncReadExt;
use tracing::{error, info};

use oauth2::{
    basic::*, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointNotSet,
    EndpointSet, IntrospectionUrl, RedirectUrl, TokenResponse, TokenUrl,
};

macro_rules! unwrap_env {
    ($name:literal) => {
        std::env::var($name).expect(&format!("missing `{}` env var", $name))
    };
}

type OClient = BasicClient<EndpointSet, EndpointNotSet, EndpointSet, EndpointNotSet, EndpointSet>;

#[derive(Clone)]
struct AppState {
    http: reqwest::Client,
    oauth: OClient,
    key: Key,
    users: Arc<RwLock<HashSet<String>>>,
    code: Arc<String>,
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.key.clone()
    }
}

struct UserLoggedIn;

#[derive(Deserialize, Debug)]
struct User42 {
    groups: Vec<serde_json::Value>,
}

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();
    let oauth = BasicClient::new(ClientId::new(unwrap_env!("CLIENT_ID")))
        .set_redirect_uri(RedirectUrl::new(format!("http://localhost:3000/auth/callback")).unwrap())
        .set_introspection_url(
            IntrospectionUrl::new("https://api.intra.42.fr/oauth/token/info".to_string()).unwrap(),
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
    dbg!(&cookie_secret);
    let base64_value = base64::engine::general_purpose::URL_SAFE
        .decode(cookie_secret)
        .unwrap();
    let key: Key = Key::from(&base64_value);

    let code = oauth
        .exchange_client_credentials()
        .request_async(&http)
        .await
        .unwrap();
    // build our application with a route
    let app = Router::new()
        // `GET /` goes to `root`
        .route("/", get(root))
        .route("/status", get(status))
        .route("/stop", get(stop))
        .route("/start", get(start))
        .route("/restart", get(restart))
        .route("/config", get(get_config))
        .route("/auth/callback", get(oauth2_callback))
        .route("/auth/login", get(oauth2_login))
        .with_state(AppState {
            key,
            http,
            oauth,
            users: Default::default(),
            code: dbg!(code.access_token().secret().clone().into()),
        });

    // run our app with hyper
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    tracing::info!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

async fn oauth2_login(
    State(AppState {
        http, oauth, users, ..
    }): State<AppState>,
) -> Redirect {
    let (url, _) = oauth.authorize_url(|| CsrfToken::new_random()).url() else {
        dbg!("got an error");
        return Redirect::to("/error/1");
    };
    dbg!(&url);
    Redirect::to(url.as_str())
}

async fn oauth2_callback(
    State(AppState {
        http,
        oauth,
        users,
        code: app_code,
        ..
    }): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    jar: PrivateCookieJar,
) -> (PrivateCookieJar, Redirect) {
    let Some(code) = params.get("code") else {
        dbg!(());
        return (jar, Redirect::to("/"));
    };
    let Some(state) = params.get("state") else {
        dbg!(());
        return (jar, Redirect::to("/"));
    };
    dbg!(&code);

    let mut form_data = HashMap::new();
    form_data.insert("grant_type", "authorization_code".to_string());
    form_data.insert("client_id", unwrap_env!("CLIENT_ID"));
    form_data.insert("client_secret", unwrap_env!("CLIENT_SECRET"));
    form_data.insert("code", code.to_string());
    form_data.insert("redirect_uri", oauth.redirect_uri().unwrap().to_string());
    form_data.insert("state", state.to_string());
    dbg!(&form_data);
    let token_res = match http
        .post(oauth.token_uri().as_str())
        .form(&form_data)
        .send()
        .await
    {
        Ok(o) => o.json::<Value>().await.unwrap(),
        Err(e) => {
            error!("{e}");
            return (jar, Redirect::to("/auth/"));
        }
    };
    dbg!(&token_res);

    let Ok(rep) = http
        .get("https://api.intra.42.fr/v2/me")
        .bearer_auth(token_res["access_token"].as_str().unwrap())
        .send()
        .await
        .map_err(|e| println!("{e}"))
    else {
        return (jar, Redirect::to("/error/2"));
    };
    let Ok(json) = rep.json::<Value>().await else {
        return (jar, Redirect::to("/error/3"));
    };

    let id = json["id"].as_u64().unwrap();
    dbg!(&id);
    let Ok(rep) = http
        .get(dbg!(format!(
            "https://api.intra.42.fr/v2/users/{}/groups",
            id
        )))
        .query(&[
            ("page[size]", 100), /*("filter[id]", id.as_u64().unwrap())*/
        ])
        .bearer_auth(&app_code)
        .send()
        .await
        .map_err(|e| println!("{e}"))
    else {
        return (jar, Redirect::to("/error/2"));
    };
    let Ok(json) = rep.json::<Value>().await else {
        return (jar, Redirect::to("/error/3"));
    };
    let is_tut = json
        .as_array()
        .map(|s| s.iter().any(|s| s["id"] == 166))
        .unwrap_or_default();

    if !is_tut {
        return (jar, Redirect::to("https://maix.me/"));
    }
    let mut cookie = Cookie::new("token", id.to_string());
    cookie.set_same_site(SameSite::None);
    cookie.set_expires(None);
    cookie.set_secure(Some(false));
    users.write().unwrap().insert(id.to_string());

    let jar = jar.add(cookie);

    (jar, Redirect::to("/"))
}

// basic handler that responds with a static string
async fn root() -> Html<&'static str> {
    info!("Request link page");
    Html(
        r#"
        <a href="/restart">restart</a><br>
        <a href="/stop">stop</a><br>
        <a href="/start">start</a><br>
        <a href="/status">status</a><br>
        <a href="/config">config</a><br>
    "#,
    )
}

async fn restart() -> Redirect {
    info!("Requested to restart the bot");
    tokio::spawn(async {
        tokio::process::Command::new("systemctl")
            .args(["--user", "restart", "botloc.service"])
            .spawn()
            .unwrap()
    });
    Redirect::to("/")
}

async fn start() -> Redirect {
    info!("Requested to start the bot");
    tokio::spawn(async {
        tokio::process::Command::new("systemctl")
            .args(["--user", "start", "botloc.service"])
            .spawn()
            .unwrap()
    });
    Redirect::to("/")
}

async fn stop() -> Redirect {
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
}

async fn get_config() -> Result<Json<BotConfig>, (StatusCode, String)> {
    info!("Requested config");
    let Ok(mut file) = tokio::fs::File::open(std::env::var("CONFIG_PATH").map_err(|e| {
        error!("Failed to open config file: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "please set env CONFIG_PATH".to_string(),
        )
    })?)
    .await
    .map_err(|e| {
        error!("Failed to open config file: {e}");
        e
    }) else {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "failed to open config file: {}",
                std::env::var("CONFIG_PATH").unwrap()
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
                "Failed to read config file at {}",
                std::env::var("CONFIG_PATH").unwrap()
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
                "Failed to read config file as json at {}",
                std::env::var("CONFIG_PATH").unwrap()
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
