use crate::db::Database;
use crate::jwks::{build_jwks_from_keys, sign_jwt_with_private_key};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use warp::Filter;

// JWKS GET handler
pub fn jwks_handler (
  db: Arc<Mutex<Database>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!(".well-known" / "jwks.json")
    .and(warp::get())
    .map(move || {
      let db = db.lock().unwrap();
      match db.get_all_valid_keys() {
        Ok(keys) => {
          let jwks = build_jwks_from_keys(&keys);
          warp::reply::json(&jwks)
        }
        Err(_) => {
          warp::reply::json(&serde_json::json!({ "keys": [] }))
        }
      }
    })
}

// Auth POST handler
pub fn auth_handler(
  db: Arc<Mutex<Database>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path("auth")
    .and(warp::post())
    .and(warp::query::<HashMap<String, String>>())
    .map(move |params: HashMap<String, String>| {
      // DB ref
      let db = db.lock().unwrap();

      // Check for expired query
      let expired_query = params.get("expired").is_some();

       // Respond with an expired/unexpired key
      let key = if expired_query {
        db.get_expired_key()
      } else {
        db.get_valid_key()
      };

      // Sign the jwt with the private key and serve to the client
      match key {
        Ok(Some((kid, private_key, exp))) => {
          match sign_jwt_with_private_key(&private_key, &kid.to_string(), exp) {
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
        _ => warp::reply::with_status(
          "No Key Available".to_string(),
          warp::http::StatusCode::INTERNAL_SERVER_ERROR,
        ),
      }
    })
}