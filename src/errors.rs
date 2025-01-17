use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;


/// Errors in handling OAuth server response.
#[derive(Debug, Error, Clone)]
pub enum ApiError {
    /// [oauth2::RequestTokenError]: Error in exchanging authorization code for request token.
    #[error("Token Error: {0}")]
    TokenError(String),

    /// Authorization error returned by the server or due to state does not match.
    #[error("AuthError: {0}")]
    AuthError(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let response = match self {
            Self::TokenError(e) => (StatusCode::INTERNAL_SERVER_ERROR, e),
            Self::AuthError(e) => (StatusCode::UNAUTHORIZED, format!("Failed to authorize. Error: {}.", e).to_string()),
        };
        response.into_response()
    }
}


/// Error returned from `request_token` function.
#[derive(Debug, Error)]
pub enum RequestTokenError {
    /// redirect path specifed in the `redirect_uri` of `basic_client` does not match that of the `options`.
    #[error("Redirect urls do not match.")]
    RedirectUrlNotMatch,

    /// RedirectUrlCreation: [url::ParseError] while creating `redirect_uri`
    #[error("Redirect url creation error: {0}")]
    RedirectUrlCreation(
        #[from] url::ParseError
    ),

    /// Login cancelled by the user by closing the authorization tab opened
    #[error("Login cancelled")]
    LoginCancelled,

    /// [ApiError]: Errors in handling server response.
    #[error("API error: {0}")]
    ApiError(ApiError),

    /// Other errors such as url parsing.
    #[error("Error: {0}")]
    Other(String),
}
