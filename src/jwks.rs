use jsonwebtoken::{EncodingKey, Header, encode, Algorithm};
use serde::{Serialize, Deserialize};
use rsa::pkcs1::{EncodeRsaPrivateKey};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};

#[derive(Serialize)]
pub struct Jwk {
    kty: &'static str,
    #[serde(rename = "use")]
    use_: &'static str,
    alg: String,
    kid: String,
    n: String,
    e: String,
}

#[derive(Serialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Serialize, Deserialize)]
pub struct Claims {
  pub sub: String,
  pub iat: usize,
  pub exp: usize,
  pub iss: String,
}

pub fn sign_jwt_with_private_key(
    private_key: &RsaPrivateKey,
    kid: &str,
    expires_at: chrono::DateTime<chrono::Utc>
) -> anyhow::Result<String> {
    // Convert to DER for jsonwebtoken v10
    let der = private_key.to_pkcs1_der()?;

    // Grab encoding key and generate header
    let encoding_key = EncodingKey::from_rsa_der(der.as_bytes());
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

/// Build JWKS from a list of (kid, public_key) tuples
pub fn build_jwks_from_keys(keys: &[(i64, RsaPublicKey)]) -> Jwks {
    let keys: Vec<Jwk> = keys
        .iter()
        .map(|(kid, pub_key)| {
            let n = base64_url::encode(&pub_key.n().to_bytes_be());
            let e = base64_url::encode(&pub_key.e().to_bytes_be());

            Jwk {
                kty: "RSA",
                use_: "sig",
                alg: "RS256".to_string(),
                kid: kid.to_string(),
                n,
                e
            }
        })
        .collect();

    Jwks { keys }
}