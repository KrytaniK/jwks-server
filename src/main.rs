mod handlers;
mod jwks;
mod keys;

use handlers::{auth_handler, jwks_handler};
use keys::KeyStore;
use std::sync::Arc;
use warp::Filter;

#[tokio::main]
async fn main() {
    // Initialize key store with sample keys
    let key_store = Arc::new(KeyStore::with_sample_keys());

    // Build routes
    let jwks = jwks_handler(key_store.clone());
    let auth = auth_handler(key_store.clone());
    let routes = auth.or(jwks);

    println!("Server running on http://127.0.0.1:8080");
    warp::serve(routes).run(([127, 0, 0, 1], 8080)).await;
}