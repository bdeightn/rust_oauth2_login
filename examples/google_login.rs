use std::{error::Error, thread, time::Duration};

use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, TokenResponse, TokenUrl};
use oauth2_login::{request_token, RequestTokenOptions};
use serde::{Deserialize, Serialize};

const CLIENT_ID: &str = "OAUTH_CLIENT_ID";
const CLIENT_SECRET: &str = "OAUTH_CLIENT_SECRET";
const BASE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL: &str = "https://www.googleapis.com/oauth2/v3/token";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let client = BasicClient::new(
        ClientId::new(CLIENT_ID.to_owned()),
        Some(ClientSecret::new(CLIENT_SECRET.to_owned())),
        AuthUrl::new(BASE_AUTH_URL.to_string())?,
        Some(TokenUrl::new(TOKEN_URL.to_string())?)
    );
    let options = RequestTokenOptions{
        port: 3000,
        host: "localhost".to_string(),
        redirect_path: "/auth/google_callback".to_string(),
        scopes: vec!["openid".to_string(), "email".to_string(), "profile".to_string()],
        ..Default::default()
    };

    let token = match request_token(&client, options).await {
        Ok(token) => token,
        Err(e) => {
            println!("error: {}", e.to_string());
            return Ok(())
        },
    };
    println!("request token: {:?}", token);

    let user_info = get_profile(token.access_token().secret()).await?;
    println!("Hey {}! Thank you for Login!", user_info.name);
    thread::sleep(Duration::from_millis(2000));

    Ok(())
}



#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserInfo {
    email: String,
    name: String,
    sub: String

}

async fn get_profile(access_token: &str)  -> Result<UserInfo, Box<dyn Error>>  {
    let client = reqwest::Client::new();
    let response = client
        .get("https://openidconnect.googleapis.com/v1/userinfo")
        .bearer_auth(access_token.to_owned())
        .send()
        .await?;

    let user_info = response.json::<UserInfo>().await?;
    Ok(user_info)
}
