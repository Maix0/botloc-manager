//! Run with
//!
//! ```not_rust
//! cargo run -p example-readme
//! ```

use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info};

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    // build our application with a route
    let app = Router::new()
        // `GET /` goes to `root`
        .route("/", get(root))
        .route("/status", get(status))
        .route("/stop", get(stop))
        .route("/start", get(start))
        .route("/restart", get(restart))
        .route("/config", get(get_config).post(post_config));

    // run our app with hyper
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

// basic handler that responds with a static string
async fn root() -> Html<&'static str> {
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

async fn post_config(Json(body): Json<BotConfig>) -> (StatusCode, String) {
    info!("Posted config");
    let Ok(mut file) = tokio::fs::File::open(
        match std::env::var("CONFIG_PATH").map_err(|e| {
            error!("Unset env {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "please set env CONFIG_PATH".to_string(),
            )
        }) {
            Ok(v) => v,
            Err(e) => return e,
        },
    )
    .await
    .map_err(|e| {
        error!("Failed to open config file: {e}");
        e
    }) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "failed to open config file: {}",
                std::env::var("CONFIG_PATH").unwrap()
            ),
        );
    };

    match serde_json::to_string_pretty(&body) {
        Err(e) => {
            error!("Failed to convert to json {e}");
            return (StatusCode::OK, "Done".to_string());
        }
        Ok(s) => match file.write(s.as_bytes()).await {
            Err(e) => error!("Got an error when writing file: {e}"),
            Ok(_) => (),
        },
    }
    
    (StatusCode::OK, "Done".to_string())
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
