use actix_web::{web, HttpResponse, Responder, HttpRequest, route};
use crate::keys::{KeyStore};
use crate::jwks::{build_jwks, sign_jwt_with_private_pem};

#[route("/.well-known/jwks.json", method = "GET")]
async fn jwks_get_handler(store: web::Data<KeyStore>) -> impl Responder {
    // Build an array of public keys that have not expired
    let jwks = build_jwks(&store.all_keys());
    HttpResponse::Ok().json(jwks)
}

#[route("/.well-known/jwks.json", method = "POST")]
async fn jwks_post_handler() -> impl Responder {
    HttpResponse::MethodNotAllowed().insert_header(("Allow", "GET")).body("Method not allowed")
}

#[route("/.well-known/jwks.json", method = "PUT")]
async fn jwks_put_handler() -> impl Responder {
    HttpResponse::MethodNotAllowed().insert_header(("Allow", "GET")).body("Method not allowed")
}

#[route("/.well-known/jwks.json", method = "DELETE")]
async fn jwks_delete_handler() -> impl Responder {
    HttpResponse::MethodNotAllowed().insert_header(("Allow", "GET")).body("Method not allowed")
}

#[route("/.well-known/jwks.json", method = "PATCH")]
async fn jwks_patch_handler() -> impl Responder {
    HttpResponse::MethodNotAllowed().insert_header(("Allow", "GET")).body("Method not allowed")
}

// Auth Handlers
#[route("/auth", method = "POST")]
async fn auth_post_handler(req: HttpRequest, store: web::Data<KeyStore>) -> impl Responder {
    // Check for expired query
    let expired_query = req.query_string().contains("expired");
    
    // Respond with an expired/unexpired key
    let key = if expired_query {
        store.get_expired_key().or_else(|| store.any_key())
    } else {
        store.get_unexpired_key().or_else(|| store.any_key())
    };

    // Sign the jwt with the private key and serve to the client
    match key {
        Some(k) => {
            let token = sign_jwt_with_private_pem(&k.private_pem, &k.kid, k.expires_at)
                .map_err(|e| HttpResponse::InternalServerError().body(format!("sign error: {}", e))).unwrap();
            HttpResponse::Ok().json(serde_json::json!({ "token": token }))
        }
        None => HttpResponse::InternalServerError().body("No key available"),
    }
}

#[route("/auth", method = "GET")]
async fn auth_get_handler() -> impl Responder {
    HttpResponse::MethodNotAllowed().insert_header(("Allow", "POST")).body("Method not allowed")
}

#[route("/auth", method = "PUT")]
async fn auth_put_handler() -> impl Responder {
    HttpResponse::MethodNotAllowed().insert_header(("Allow", "POST")).body("Method not allowed")
}

#[route("/auth", method = "DELETE")]
async fn auth_delete_handler() -> impl Responder {
    HttpResponse::MethodNotAllowed().insert_header(("Allow", "POST")).body("Method not allowed")
}

#[route("/auth", method = "PATCH")]
async fn auth_patch_handler() -> impl Responder {
    HttpResponse::MethodNotAllowed().insert_header(("Allow", "POST")).body("Method not allowed")
}