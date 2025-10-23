mod handlers;
mod jwks;
mod db;

use db::Database;
use handlers::{auth_handler, jwks_handler};
use std::sync::{Arc, Mutex};
use warp::Filter;

#[tokio::main]
async fn main() {
    // Open Database
    let db = Database::new("totally_not_my_privateKeys.db")
        .expect("Failed to create/open database");

    db.initialize_keys().expect("Failed to initialize keys");

    let db = Arc::new(Mutex::new(db));

    // Build routes
    let jwks = jwks_handler(db.clone());
    let auth = auth_handler(db.clone());
    let routes = auth.or(jwks);

    println!("Server running on http://127.0.0.1:8080");
    println!("Database: totally_not_my_privateKeys.db");
    warp::serve(routes).run(([127, 0, 0, 1], 8080)).await;
}