use std::{
    ffi::OsStr,
    sync::{
        mpsc::{channel, Sender},
        Arc,
    },
    time::Duration,
};

use axum::{
    extract::{Query, State},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use derive_builder::Builder;
use errors::{ApiError, RequestTokenError};
use headless_chrome::{Browser, LaunchOptions, Tab};
use modules::{AppState, CallbackParams, Message};
use oauth2::{
    basic::{BasicClient, BasicTokenType},
    reqwest::async_http_client,
    AuthorizationCode, CsrfToken, EmptyExtraTokenFields, RedirectUrl, Scope, StandardTokenResponse,
};
use url::Url;

pub mod errors;
mod modules;

/// Configurations for request OAuth access token.
#[derive(Clone, Debug, Builder)]
pub struct RequestTokenOptions {
    /// Server port for receiving OAuth server response.
    /// Default to `3000`.
    #[builder(default = "3000")]
    pub port: u16,

    /// Server host for receiving OAuth server response.
    /// Default to `localhost`.
    #[builder(default = r#""localhost".to_string()"#)]
    pub host: String,

    /// Path to handle OAuth server response.
    /// /// Default to `/auth/google_callback`.
    #[builder(default = r#""/auth/google_callback".to_string()"#)]
    pub redirect_path: String,

    /// Scopes to request token for.
    #[builder(default = "vec![]")]
    pub scopes: Vec<String>,

    /// Launch the browser with a specific window width and height.
    #[builder(default = "None")]
    pub browser_window_size: Option<(u32, u32)>,

    /// How long to keep the WebSocket to the browser for after not receiving any events from it.
    /// Defaults to `30` seconds.
    #[builder(default = "Duration::from_secs(30)")]
    pub idle_browser_timeout: Duration,

    /// Provides a way to append "params" to the url. This enables the account picker on google oauth.
    /// e.g: &params=select_account
    #[builder(default = "vec![]")]
    pub extra_params: Vec<String>,

    #[builder(default = "vec![]")]
    pub browser_args: Vec<String>,
}

impl Default for RequestTokenOptions {
    fn default() -> Self {
        RequestTokenOptions {
            port: 3000,
            host: "localhost".to_string(),
            redirect_path: "/auth/google_callback".to_string(),
            scopes: vec![],
            browser_window_size: None,
            idle_browser_timeout: Duration::from_secs(30),
            extra_params: vec![],
            browser_args: vec![],
        }
    }
}

/// Request for OAuth2 access token.
///
/// This function will
/// - Prompt the user to login with the consent screen
/// - Start a server *temporarily* for handling the OAuth 2.0 server response
/// - Retreive and return the Access Token upon success
/// - Stop the server upon sucess or User cancelling the Login by closing the consent screen tab
///
/// Parameters
/// - `basic_client`: [oauth2::basic::BasicClient]. If `redirect_uri` is not defined on the client, a `redirect_uri` of format "http://{host}:{port}/{path}" will be set.
/// - `options`: [RequestTokenOptions]. Options for configuring authorizaion scopes, server, and browser while requesting for token. Default values provided.
///
///
/// # Errors
///
/// This function will return [RequestTokenError] for following cases.
/// - RedirectUrlNotMatch: redirect path specifed in the `redirect_uri` of `basic_client` does not match that of the `options`.
/// - RedirectUrlCreation: [url::ParseError] while creating `redirect_uri`
/// - LoginCancelled: Login cancelled by the user by closing the authorization tab opened.
/// - [ApiError]: Errors in handling server response.
/// - Other: Other errors such as url parsing.
pub async fn request_token(
    basic_client: &BasicClient,
    options: RequestTokenOptions,
) -> Result<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>, RequestTokenError> {
    let client = check_redirect(
        &basic_client,
        &options.port,
        &options.host,
        &options.redirect_path,
    )?;
    let (auth_url, csrf_token) = get_auth_url(&client, &options.scopes, &options.extra_params);

    let (sender, receiver) = channel::<Message>();
    let client_clone = client.clone();

    let handler: tokio::task::JoinHandle<()> = tokio::spawn(async move {
        let browser = match Browser::new(LaunchOptions {
            window_size: options.browser_window_size,
            headless: false,
            ignore_certificate_errors: false,
            disable_default_args: true,
            args: vec![],
            idle_browser_timeout: options.idle_browser_timeout,
            ..Default::default()
        }) {
            Ok(b) => b,
            Err(e) => {
                send_message(sender.clone(), Message::OtherError(e.to_string()));
                return;
            }
        };

        let tab = match browser.new_tab() {
            Ok(t) => t,
            Err(e) => {
                send_message(sender.clone(), Message::OtherError(e.to_string()));
                return;
            }
        };

        send_message(sender.clone(), Message::TabCreated(tab.clone()));
        if let Err(e) = tab.navigate_to(auth_url.as_str()) {
            send_message(sender.clone(), Message::OtherError(e.to_string()));
            return;
        };

        let app = Router::new()
            .route(&options.redirect_path, get(handle_google_callback))
            .with_state(AppState {
                state_token: csrf_token,
                client: client_clone,
                sender: sender.clone(),
            });

        let listener =
            match tokio::net::TcpListener::bind(format!("{}:{}", &options.host, &options.port))
                .await
            {
                Ok(l) => l,
                Err(e) => {
                    send_message(sender.clone(), Message::OtherError(e.to_string()));
                    return;
                }
            };
        if let Err(e) = axum::serve(listener, app).await {
            send_message(sender.clone(), Message::OtherError(e.to_string()));
            return;
        };
        return;
    });

    let mut tab: Option<Arc<Tab>> = None;

    let token = loop {
        let result = receiver.try_recv();
        if let Err(error) = result {
            match error {
                std::sync::mpsc::TryRecvError::Empty => {
                    if let Some(t) = tab.clone() {
                        if t.get_target_info().is_err() {
                            return Err(RequestTokenError::LoginCancelled);
                        }
                    }
                }
                std::sync::mpsc::TryRecvError::Disconnected => {
                    return Err(RequestTokenError::Other("Sender Disconnected.".to_owned()))
                }
            }
            continue;
        }
        let message = result.unwrap();
        match message {
            Message::TabCreated(t) => tab = Some(t),
            Message::TokenReceived(token) => break token,
            Message::ApiError(e) => return Err(RequestTokenError::ApiError(e)),
            Message::OtherError(e) => return Err(RequestTokenError::Other(e)),
        }
    };

    handler.abort();

    return Ok(token);
}

async fn handle_google_callback(
    State(state): State<AppState>,
    Query(params): Query<CallbackParams>,
) -> Response {
    if let Some(params) = params.error {
        let error = ApiError::AuthError(params.error.to_owned());
        send_message(state.sender.clone(), Message::ApiError(error.clone()));
        return error.into_response();
    }
    if params.success.is_none() {
        let error = ApiError::AuthError("unknown".to_owned());
        send_message(state.sender.clone(), Message::ApiError(error.clone()));
        return error.into_response();
    }
    let params = params.success.unwrap();
    if state.state_token.secret().to_owned() != params.state {
        let error = ApiError::AuthError("Csrf Tokens do not match.".to_owned());
        send_message(state.sender.clone(), Message::ApiError(error.clone()));
        return error.into_response();
    }
    let token = match state
        .client
        .exchange_code(AuthorizationCode::new(params.code))
        .request_async(async_http_client)
        .await
    {
        Ok(token) => token,
        Err(error) => {
            let error = ApiError::TokenError(error.to_string());
            send_message(state.sender.clone(), Message::ApiError(error.clone()));
            return error.into_response();
        }
    };

    send_message(state.sender.clone(), Message::TokenReceived(token));
    return Response::new("Login success".into());
}

fn send_message(sender: Sender<Message>, message: Message) {
    if let Err(e) = sender.send(message) {
        println!("Error Sending Message: {}", e.to_string());
    };
}

fn get_auth_url(
    basic_client: &BasicClient,
    scopes: &Vec<String>,
    extra_params: &Vec<String>,
) -> (Url, CsrfToken) {
    let scopes: Vec<Scope> = scopes
        .into_iter()
        .map(|s| Scope::new(s.to_owned()))
        .collect();

    let mut auth_url_builder = basic_client
        .authorize_url(CsrfToken::new_random)
        .add_scopes(scopes);

    // Check if extra_params exists and iterate through them
    match extra_params {
        params => {
            for param in params {
                if let Some((key, value)) = param.split_once('=') {
                    // Add each parameter to the builder
                    auth_url_builder = auth_url_builder.add_extra_param(key, value);
                }
            }
        }
        _ => (),
    }

    // Finalize the URL
    let (auth_url, csrf_token) = auth_url_builder.url();
    (auth_url, csrf_token)
}

fn check_redirect(
    basic_client: &BasicClient,
    port: &u16,
    host: &str,
    redirect_path: &str,
) -> Result<BasicClient, RequestTokenError> {
    match basic_client.redirect_url() {
        Some(url) => {
            if let Ok(url) = url.parse::<Url>() {
                if url.path() == redirect_path {
                    return Ok(basic_client.to_owned());
                } else {
                    return Err(RequestTokenError::RedirectUrlNotMatch);
                }
            } else {
                return Err(RequestTokenError::Other("Error parsing url.".to_owned()));
            }
        }
        None => {
            let path = redirect_path.strip_prefix("/").unwrap_or(redirect_path);
            let url = format!("http://{}:{}/{}", host, port, path);
            let redirect_url = match RedirectUrl::new(url) {
                Ok(u) => u,
                Err(e) => return Err(RequestTokenError::RedirectUrlCreation(e)),
            };
            let client = basic_client.clone().set_redirect_uri(redirect_url);
            return Ok(client);
        }
    }
}
