use crate::jwks::{build_jwks, sign_jwt_with_private_pem};
use crate::keys::KeyStore;
use std::collections::HashMap;
use std::sync::Arc;
use warp::Filter;

// JWKS GET handler
pub fn jwks_handler (
  key_store: Arc<KeyStore>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!(".well-known" / "jwks.json")
    .and(warp::get())
    .map(move || {
      let jwks = build_jwks(&key_store.all_keys());
      warp::reply::json(&jwks)
    })
}

// Auth POST handler
pub fn auth_handler(
  key_store: Arc<KeyStore>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path("auth")
    .and(warp::post())
    .and(warp::query::<HashMap<String, String>>())
    .map(move |params: HashMap<String, String>| {
      // Check for expired query
      let expired_query = params.get("expired").is_some();

       // Respond with an expired/unexpired key
      let key = if expired_query {
        key_store
          .get_expired_key()
          .or_else(|| key_store.any_key())
      } else {
        key_store
          .get_unexpired_key()
          .or_else(|| key_store.any_key())
      };

      // Sign the jwt with the private key and serve to the client
      match key {
        Some(k) => {
          match sign_jwt_with_private_pem(&k.private_pem, &k.kid, k.expires_at) {
            Ok(token) => warp::reply::with_status(
              token,
              warp::http::StatusCode::OK,
            ),
            Err(_) => warp::reply::with_status(
              "Token generation failed".to_string(),
              warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ),
          }
        }
        None => warp::reply::with_status(
          "No Key Available".to_string(),
          warp::http::StatusCode::INTERNAL_SERVER_ERROR,
        ),
      }
    })
}