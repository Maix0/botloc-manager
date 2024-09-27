use std::collections::HashMap;

use base64::Engine;
use color_eyre::eyre::{self, WrapErr};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct OauthClient {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    token: Token,
    http: reqwest::Client,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Token {
    #[serde(default)]
    refresh_token: Option<String>,
    pub access_token: String,
    token_type: String,
    expires_in: u64,
    scope: String,
    created_at: u64,
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
        let response = client
            .post("https://api.intra.42.fr/oauth/token")
            .form(&form_data)
            .send()
            .await
            .wrap_err("Sending request to fetch 42 API token")?;
        let body = response.bytes().await?;
        let text = String::from_utf8_lossy(&body);
        println!("{}", text);
        let json: Token = serde_json::from_slice(&body).unwrap(); // response.json().await.wrap_err("API response to json")?;
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
            token,
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
                "/oauth/authorize?client_id={}&scope=public&response_type=code&redirect_uri={redirect_uri}&code={}",
                self.client_id, base64::engine::general_purpose::URL_SAFE.encode(csrf)
            ))
            .build()
            .wrap_err("Failed to build URI")?;
        Ok(uri)
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
        let response = self
            .http
            .post("https://api.intra.42.fr/oauth/token")
            .form(&form_data)
            .send()
            .await
            .wrap_err("Failed to get token for user")?;
        let json: Token = response.json().await.wrap_err("API response to json")?;
        Ok(json)
    }

    pub async fn do_request<R: DeserializeOwned>(
        &self,
        url: impl AsRef<str>,
        qs: &impl Serialize,
    ) -> eyre::Result<R> {
        let url = url.as_ref();
        let req = self
            .http
            .get(url)
            .query(qs)
            .bearer_auth(&self.token.access_token)
            .send()
            .await
            .wrap_err("Failed to send request")?;
        let json = req
            .json()
            .await
            .wrap_err("Failed to Deserialize response")?;
        Ok(json)
    }
}
