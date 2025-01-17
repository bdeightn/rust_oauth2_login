# A Wrapper Library for OAuth2 Authorization

This library aims at helping CLI tools in using OAuth2 for user authorization.


## Function Provided

```
pub async fn request_token(
    basic_client: &oauth2::basic::BasicClient,
    options: RequestTokenOptions) ->
Result<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>, RequestTokenError>
```

This function will
- Prompt the user to login with the consent screen
- Start a server *temporarily* for handling the OAuth 2.0 server response
- Retreive and return the Access Token upon success
- Stop the server upon sucess or User cancelling the Login by closing the consent screen tab


### Parameters
- `basic_client`: [oauth2::basic::BasicClient](https://docs.rs/oauth2/latest/oauth2/struct.Client.html). If `redirect_uri` is not defined on the client, a `redirect_uri` of format "http://{host}:{port}/{path}" will be set. The `redirect_uri` should be an *exact match* to that set up on the OAuth provider side.
- `options`: [RequestTokenOptions](#requesttokenoptions). Options for configuring authorizaion scopes, server, and browser while requesting for token. Default values provided.


#### RequestTokenOptions

```
pub struct RequestTokenOptions {
    #[builder(default = "3000")]
    pub port: u16,

    #[builder(default = r#""localhost".to_string()"#)]
    pub host: String,

    #[builder(default = r#""/auth/google_callback".to_string()"#)]
    pub redirect_path: String,

    #[builder(default = "vec![]")]
    pub scopes: Vec<String>,

    #[builder(default = "None")]
    pub browser_window_size: Option<(u32, u32)>,

    #[builder(default = "Duration::from_secs(30)")]
    pub idle_browser_timeout: Duration,

}
```


## Main Crates Used
It uses the following crates internally.
- [`oauth2`](https://docs.rs/oauth2/latest/oauth2/) for token introspection
- [`axum`](https://docs.rs/axum/latest/axum/) for handling OAuth server reponses
- [`headless_chrome`](https://docs.rs/headless_chrome/latest/headless_chrome/) for browser manipulation


## Example
[Example with Google OAuth2](./examples/google_login.rs).

### Set up in Google
- Create a project in the [Google Cloud Console](https://console.cloud.google.com/)
- Enable APIs for the project from the [API Library](https://console.developers.google.com/apis/library)
- Set up the [OAuth Consent Screen](https://console.cloud.google.com/apis/credentials/consent) with the [scopes](https://developers.google.com/identity/protocols/oauth2/scopes) needed.
- Create an OAuth client ID from the [Credentials page](https://console.developers.google.com/apis/credentials).
    - **Application type**: Web application
    - **redirect URIs**: http://localhost:3000/auth/google_callback
- Obtain the Client Id and Client Secret creating the credentials


### Request for Token

```
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

```

![](./readme_assets/full_demo.gif)