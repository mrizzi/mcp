use anyhow::Result;
use axum::{
    Router,
    extract::{Request, State},
    http::StatusCode,
    http::header::AUTHORIZATION,
    middleware,
    middleware::Next,
    response::Response,
};
use std::{env, str::FromStr, sync::Arc};
use trustify_auth::{
    auth::AuthConfigArguments,
    authenticator::{Authenticator, config::SingleAuthenticatorClientConfig},
    authorizer::Authorizer,
};

#[derive(Clone)]
struct AppState {
    authenticator: Arc<Authenticator>,
    _authorizer: Arc<Authorizer>,
}

pub fn is_auth_disabled() -> bool {
    let auth_disabled =
        bool::from_str(&env::var("AUTH_DISABLED").unwrap_or(false.to_string())).unwrap_or(false);
    if auth_disabled {
        tracing::warn!("Auth disabled");
    }
    auth_disabled
}

pub async fn protect_router(router: Router) -> Result<Router> {
    let auth_devmode = false;
    let openid_issuer_url =
        env::var("OPENID_ISSUER_URL").expect("Missing the OPENID_ISSUER_URL environment variable.");
    let open_client_id =
        env::var("OPENID_CLIENT_ID").expect("Missing the OPENID_CLIENT_ID environment variable.");
    let auth = AuthConfigArguments {
        disabled: false,
        config: None,
        clients: SingleAuthenticatorClientConfig {
            client_ids: vec![open_client_id],
            issuer_url: openid_issuer_url,
            required_audience: None,
            tls_insecure: false,
            tls_ca_certificates: vec![],
        },
    };
    let (authn, authz) = auth.split(auth_devmode)?.unzip();
    let authenticator = Arc::new(Authenticator::from_config(authn).await?.unwrap());
    let _authorizer = Arc::new(Authorizer::new(authz));
    let state = Arc::new(AppState {
        authenticator,
        _authorizer,
    });

    // Create protected SSE routes (require authorization)
    let protected_sse_router =
        router.layer(middleware::from_fn_with_state(state.clone(), authenticate));
    Ok(protected_sse_router)
}

async fn authenticate(
    State(state): State<Arc<AppState>>,
    // you can also add extractors here, e.g. the `HeaderMap` extractor
    // headers: HeaderMap,
    // but the last extractor must implement `FromRequest` which `Request` does
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if let Some(bearer) = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|auth| auth.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Bearer "))
    {
        match state.authenticator.validate_token(&bearer).await.is_ok() {
            true => Ok(next.run(request).await),
            false => Err(StatusCode::UNAUTHORIZED),
        }
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}
