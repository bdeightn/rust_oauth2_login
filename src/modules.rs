use std::sync::Arc;
use headless_chrome::Tab;
use oauth2::{basic::{BasicClient, BasicTokenType}, CsrfToken, EmptyExtraTokenFields, StandardTokenResponse};
use serde::Deserialize;

use crate::errors::ApiError;



#[derive(Clone)]
pub enum Message {
    TabCreated(Arc<Tab>),
    TokenReceived(StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>),
    ApiError(ApiError),
    OtherError(String)
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TabCreated(_tab) => write!(f, "TabCreated"),
            Self::TokenReceived(token) => f.debug_tuple("TokenReceived").field(token).finish(),
            Self::ApiError(e) => f.debug_tuple("API Error").field(e).finish(),
            Self::OtherError(e) => f.debug_tuple("Other Error").field(e).finish(),
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub state_token: CsrfToken,
    pub client: BasicClient,
    pub sender: std::sync::mpsc::Sender<Message>
}


#[derive(Debug, Deserialize)]
pub struct CallbackParams {
    #[serde(flatten)]
    pub success: Option<AuthSuccessParams>,
    #[serde(flatten)]
    pub error: Option<AuthErrorParams>
}

#[derive(Debug, Deserialize)]
pub struct AuthErrorParams {
    pub error: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthSuccessParams {
    pub code: String,
    pub state: String
}
