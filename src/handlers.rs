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

// Add this to handlers.rs

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use std::sync::{Arc, Mutex};
    use tempfile::NamedTempFile;
    use warp::http::StatusCode;
    use warp::test::request;

    fn create_test_db() -> Arc<Mutex<Database>> {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let db = Database::new(temp_file.path()).expect("Failed to create database");
        db.initialize_keys().expect("Failed to initialize keys");
        Arc::new(Mutex::new(db))
    }

    #[tokio::test]
    async fn test_jwks_handler_success() {
        let db = create_test_db();
        let filter = jwks_handler(db);

        let res = request()
            .method("GET")
            .path("/.well-known/jwks.json")
            .reply(&filter)
            .await;

        assert_eq!(res.status(), StatusCode::OK);

        let body: serde_json::Value = serde_json::from_slice(res.body()).unwrap();
        assert!(body.get("keys").is_some());
        assert!(body["keys"].is_array());
    }

    #[tokio::test]
    async fn test_jwks_handler_returns_valid_keys() {
        let db = create_test_db();
        let filter = jwks_handler(db);

        let res = request()
            .method("GET")
            .path("/.well-known/jwks.json")
            .reply(&filter)
            .await;

        assert_eq!(res.status(), StatusCode::OK);

        let body: serde_json::Value = serde_json::from_slice(res.body()).unwrap();
        let keys = body["keys"].as_array().unwrap();

        // Should have at least one valid key
        assert!(keys.len() > 0);

        // Check first key has required fields
        let key = &keys[0];
        assert!(key.get("kty").is_some());
        assert!(key.get("use").is_some());
        assert!(key.get("alg").is_some());
        assert!(key.get("kid").is_some());
        assert!(key.get("n").is_some());
        assert!(key.get("e").is_some());
    }

    #[tokio::test]
    async fn test_jwks_handler_wrong_method() {
        let db = create_test_db();
        let filter = jwks_handler(db);

        let res = request()
            .method("POST")
            .path("/.well-known/jwks.json")
            .reply(&filter)
            .await;

        assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn test_auth_handler_success() {
        let db = create_test_db();
        let filter = auth_handler(db);

        let res = request()
            .method("POST")
            .path("/auth")
            .reply(&filter)
            .await;

        assert_eq!(res.status(), StatusCode::OK);

        let body = std::str::from_utf8(res.body()).unwrap();
        // JWT should have three parts separated by dots
        assert_eq!(body.matches('.').count(), 2);
    }

    #[tokio::test]
    async fn test_auth_handler_with_expired_param() {
        let db = create_test_db();
        let filter = auth_handler(db);

        let res = request()
            .method("POST")
            .path("/auth?expired")
            .reply(&filter)
            .await;

        assert_eq!(res.status(), StatusCode::OK);

        let body = std::str::from_utf8(res.body()).unwrap();
        assert_eq!(body.matches('.').count(), 2);
    }

    #[tokio::test]
    async fn test_auth_handler_with_expired_value() {
        let db = create_test_db();
        let filter = auth_handler(db);

        let res = request()
            .method("POST")
            .path("/auth?expired=true")
            .reply(&filter)
            .await;

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_handler_wrong_method() {
        let db = create_test_db();
        let filter = auth_handler(db);

        let res = request()
            .method("GET")
            .path("/auth")
            .reply(&filter)
            .await;

        assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn test_auth_handler_no_keys_available() {
        // Create empty database without initializing keys
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let db = Database::new(temp_file.path()).expect("Failed to create database");
        let db = Arc::new(Mutex::new(db));

        let filter = auth_handler(db);

        let res = request()
            .method("POST")
            .path("/auth")
            .reply(&filter)
            .await;

        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = std::str::from_utf8(res.body()).unwrap();
        assert_eq!(body, "No Key Available");
    }

    #[tokio::test]
    async fn test_combined_routes() {
        let db = create_test_db();
        let jwks = jwks_handler(db.clone());
        let auth = auth_handler(db.clone());
        let routes = auth.or(jwks);

        // Test auth endpoint
        let res = request()
            .method("POST")
            .path("/auth")
            .reply(&routes)
            .await;
        assert_eq!(res.status(), StatusCode::OK);

        // Test JWKS endpoint
        let res = request()
            .method("GET")
            .path("/.well-known/jwks.json")
            .reply(&routes)
            .await;
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_returns_valid_jwt_format() {
        let db = create_test_db();
        let filter = auth_handler(db);

        let res = request()
            .method("POST")
            .path("/auth")
            .reply(&filter)
            .await;

        let body = std::str::from_utf8(res.body()).unwrap();
        let parts: Vec<&str> = body.split('.').collect();

        assert_eq!(parts.len(), 3);
        // Each part should be base64 encoded
        assert!(parts[0].len() > 0);
        assert!(parts[1].len() > 0);
        assert!(parts[2].len() > 0);
    }

    #[tokio::test]
    async fn test_jwks_empty_database() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let db = Database::new(temp_file.path()).expect("Failed to create database");
        let db = Arc::new(Mutex::new(db));

        let filter = jwks_handler(db);

        let res = request()
            .method("GET")
            .path("/.well-known/jwks.json")
            .reply(&filter)
            .await;

        assert_eq!(res.status(), StatusCode::OK);

        let body: serde_json::Value = serde_json::from_slice(res.body()).unwrap();
        let keys = body["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 0);
    }

    #[tokio::test]
    async fn test_auth_multiple_requests() {
        let db = create_test_db();
        let filter = auth_handler(db);

        // Make multiple requests
        for _ in 0..5 {
            let res = request()
                .method("POST")
                .path("/auth")
                .reply(&filter)
                .await;

            assert_eq!(res.status(), StatusCode::OK);
        }
    }
}