use std::collections::HashMap;

use base64::Engine;
use color_eyre::eyre::{self, WrapErr};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::info;

#[derive(Clone, Serialize, Deserialize)]
struct ApiError<'a> {
    message: &'a str,
    error: &'a str,
}

#[derive(Clone, Debug)]
pub struct OauthClient {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    token: std::sync::Arc<tokio::sync::Mutex<Token>>,
    http: reqwest::Client,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Token {
    #[serde(default)]
    refresh_token: Option<String>,
    access_token: String,
    token_type: String,
    expires_in: u64,
    scope: String,
    created_at: u64,
}

pub trait IntoToken {
    fn get_token(&self) -> &str;
}

impl IntoToken for Token {
    fn get_token(&self) -> &str {
        &self.access_token
    }
}

impl OauthClient {
    async fn get_app_token(
        client: reqwest::Client,
        uid: impl AsRef<str>,
        secret: impl AsRef<str>,
    ) -> eyre::Result<Token> {
        let uid = uid.as_ref();
        let secret = secret.as_ref();

        let mut form_data = HashMap::new();
        form_data.insert("grant_type", "client_credentials");
        form_data.insert("client_id", uid);
        form_data.insert("client_secret", secret);
        let res = client
            .post("https://api.intra.42.fr/oauth/token")
            .form(&form_data)
            .send()
            .await
            .wrap_err("Sending request to fetch 42 API token")?;
        let text = res.text().await.wrap_err("API reponse to text")?;
        let json: Token = serde_json::from_str(&text)
            .wrap_err_with(|| format!("API response to json: {text}"))?;
        Ok(json)
    }
    pub async fn new(
        client: reqwest::Client,
        uid: impl AsRef<str>,
        secret: impl AsRef<str>,
        redirect_uri: impl AsRef<str>,
    ) -> eyre::Result<Self> {
        let uid = uid.as_ref();
        let secret = secret.as_ref();
        let redirect_uri = redirect_uri.as_ref().to_string();
        let token = Self::get_app_token(client.clone(), uid, secret).await?;
        Ok(Self {
            client_id: uid.to_string(),
            client_secret: secret.to_string(),
            token: std::sync::Arc::new(tokio::sync::Mutex::new(token)),
            redirect_uri,
            http: client,
        })
    }

    pub async fn get_auth_url(&self) -> eyre::Result<http::Uri> {
        let redirect_uri =
            pct_str::PctString::encode(self.redirect_uri.chars(), pct_str::URIReserved);
        let csrf = [(); 64].map(|()| rand::random());

        let uri = http::Uri::builder()
            .scheme("https")
            .authority("api.intra.42.fr")
            .path_and_query(format!(
                "/oauth/authorize?client_id={}&scope=public&response_type=code&redirect_uri={redirect_uri}&state={}",
                self.client_id, base64::engine::general_purpose::URL_SAFE.encode(csrf)
            ))
            .build()
            .wrap_err("Failed to build URI")?;
        Ok(dbg!(uri))
    }

    pub async fn get_user_token(
        &self,
        code: impl AsRef<str>,
        csrf: impl AsRef<str>,
    ) -> eyre::Result<Token> {
        let code = code.as_ref();
        let csrf = csrf.as_ref();

        let mut form_data = HashMap::new();
        form_data.insert("code", code);
        form_data.insert("state", csrf);
        form_data.insert("client_id", &self.client_id);
        form_data.insert("client_secret", &self.client_secret);
        form_data.insert("redirect_uri", &self.redirect_uri);
        form_data.insert("grant_type", "authorization_code");
        let res = self
            .http
            .post("https://api.intra.42.fr/oauth/token")
            .form(&form_data)
            .send()
            .await
            .wrap_err("Failed to get token for user")?;
        let text = res.text().await.wrap_err("API reponse to text")?;
        let json: Token = serde_json::from_str(&text)
            .wrap_err_with(|| format!("API response to json: {text}"))?;
        Ok(json)
    }

    pub async fn do_request<R: DeserializeOwned>(
        &self,
        url: impl AsRef<str>,
        qs: impl Serialize,
        token: Option<&Token>,
    ) -> eyre::Result<R> {
        loop {
            let url = url.as_ref();
            let is_apptoken = token.is_none();
            let s: String;
            let token = match token {
                Some(i) => i.get_token(),
                None => {
                    s = self.token.lock().await.get_token().to_string();
                    s.as_str()
                }
            };
            let res = self
                .http
                .get(url)
                .query(&qs)
                .bearer_auth(token)
                .send()
                .await
                .wrap_err("Failed to send request")?;
            let text = res.text().await.wrap_err("API reponse to text")?;
            if let Ok(err) = serde_json::from_str::<ApiError<'_>>(&text) {
                if is_apptoken
                    && err.message == "The access token expired"
                    && err.error == "Not authorized"
                {
                    info!("Refreshing token !");

                    let tok = Self::get_app_token(
                        self.http.clone(),
                        &self.client_id,
                        &self.client_secret,
                    )
                    .await?;
                    *self.token.lock().await = tok;
                    continue;
                }
            }
            let json = serde_json::from_str(&text)
                .wrap_err_with(|| format!("API response to json: {text}"))?;
            break Ok(json);
        }
    }
}
