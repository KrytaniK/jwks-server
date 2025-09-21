mod keys; mod handlers; mod jwks;
use actix_web::{App, HttpServer, web};
use crate::keys::KeyStore;
use crate::handlers::{
    jwks_get_handler, 
    jwks_post_handler, 
    jwks_patch_handler, 
    jwks_put_handler, 
    jwks_delete_handler,
    auth_get_handler, 
    auth_post_handler, 
    auth_patch_handler, 
    auth_put_handler, 
    auth_delete_handler,
};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let key_store = KeyStore::with_sample_keys(); // build 3 keys incl 1 expired
    let data = web::Data::new(key_store);

    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .service(jwks_get_handler)
            .service(jwks_post_handler)
            .service(jwks_patch_handler)
            .service(jwks_put_handler)
            .service(jwks_delete_handler)
            .service(auth_get_handler)
            .service(auth_post_handler)
            .service(auth_patch_handler)
            .service(auth_put_handler)
            .service(auth_delete_handler)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
