use jsonwebtoken::{EncodingKey, Header, encode, Algorithm};
use serde::{Serialize, Deserialize};
use crate::keys::KeyPair;

#[derive(Serialize)]
pub struct Jwk {
    kty: &'static str,
    use_: &'static str,
    alg: String,
    kid: String,
    n: String,
    e: String,
}

#[derive(Serialize)]
pub struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Serialize, Deserialize)]
pub struct Claims {
  sub: String,
  iat: usize,
  exp: usize,
  iss: String,
}

pub fn sign_jwt_with_private_pem(pem: &str, kid: &str, expires_at: chrono::DateTime<chrono::Utc>) -> anyhow::Result<String> {
    // Grab encoding key and generate header
    let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes())?;
    let header = {
        let mut h = Header::new(Algorithm::RS256);
        h.kid = Some(kid.to_owned());
        h
    };

    // Issue a claim
    let now = chrono::Utc::now().timestamp() as usize;
    let claims = Claims {
        sub: "test-user".into(),
        iat: now,
        exp: expires_at.timestamp() as usize,
        iss: "jwks-server".into(),
    };

    // Generate the signed token
    let token = encode(&header, &claims, &encoding_key)?;
    Ok(token)
}

pub fn build_jwks(keys: &[KeyPair]) -> Jwks {
    let now = chrono::Utc::now();
    let keys: Vec<Jwk> = keys
        .iter()
        .filter(|k| k.expires_at > now)
        .map(|k| Jwk {
            kty: "RSA",
            use_: "sig",
            alg: k.alg.clone(),
            kid: k.kid.clone(),
            n: k.public_n_b64.clone(),
            e: k.public_e_b64.clone(),
        })
        .collect();
    Jwks { keys }
}