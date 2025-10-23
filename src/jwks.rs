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

#[derive(Serialize, Deserialize, Clone)]
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

// Add this to jwks.rs

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
    use rsa::rand_core::OsRng;
    use rsa::RsaPrivateKey;

    #[test]
    fn test_sign_jwt_with_private_key() {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let kid = "test-kid";
        let expires_at = Utc::now() + Duration::hours(1);

        let token = sign_jwt_with_private_key(&private_key, kid, expires_at);
        assert!(token.is_ok());

        let token_str = token.unwrap();
        assert!(!token_str.is_empty());
        assert!(token_str.contains('.'));
    }

    #[test]
    fn test_jwt_has_correct_kid() {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let kid = "test-kid-123";
        let expires_at = Utc::now() + Duration::hours(1);

        let token = sign_jwt_with_private_key(&private_key, kid, expires_at).unwrap();
        let header = decode_header(&token).expect("Failed to decode header");

        assert_eq!(header.kid, Some(kid.to_string()));
        assert_eq!(header.alg, jsonwebtoken::Algorithm::RS256);
    }

    #[test]
    fn test_jwt_claims() {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        let kid = "test-kid";
        let expires_at = Utc::now() + Duration::hours(1);

        let token = sign_jwt_with_private_key(&private_key, kid, expires_at).unwrap();

        // Decode and verify the token
        let n = public_key.n().to_bytes_be();
        let e = public_key.e().to_bytes_be();
        let decoding_key = DecodingKey::from_rsa_components(&base64_url::encode(&n), &base64_url::encode(&e))
            .expect("Failed to create decoding key");

        let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.validate_exp = true;

        let decoded = decode::<Claims>(&token, &decoding_key, &validation);
        assert!(decoded.is_ok());

        let claims = decoded.unwrap().claims;
        assert_eq!(claims.sub, "test-user");
        assert_eq!(claims.iss, "jwks-server");
        assert!(claims.exp > 0);
        assert!(claims.iat > 0);
    }

    #[test]
    fn test_build_jwks_from_keys_empty() {
        let keys: Vec<(i64, RsaPublicKey)> = vec![];
        let jwks = build_jwks_from_keys(&keys);

        assert_eq!(jwks.keys.len(), 0);
    }

    #[test]
    fn test_build_jwks_from_keys_single() {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        let kid = 42i64;

        let keys = vec![(kid, public_key)];
        let jwks = build_jwks_from_keys(&keys);

        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kty, "RSA");
        assert_eq!(jwks.keys[0].use_, "sig");
        assert_eq!(jwks.keys[0].alg, "RS256");
        assert_eq!(jwks.keys[0].kid, "42");
    }

    #[test]
    fn test_build_jwks_from_keys_multiple() {
        let mut rng = OsRng;

        let private_key1 = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key1 = RsaPublicKey::from(&private_key1);

        let private_key2 = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key2 = RsaPublicKey::from(&private_key2);

        let keys = vec![(1i64, public_key1), (2i64, public_key2)];
        let jwks = build_jwks_from_keys(&keys);

        assert_eq!(jwks.keys.len(), 2);
        assert_eq!(jwks.keys[0].kid, "1");
        assert_eq!(jwks.keys[1].kid, "2");
    }

    #[test]
    fn test_jwk_fields_not_empty() {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        let kid = 1i64;

        let keys = vec![(kid, public_key)];
        let jwks = build_jwks_from_keys(&keys);

        let jwk = &jwks.keys[0];
        assert!(!jwk.n.is_empty());
        assert!(!jwk.e.is_empty());
    }

    #[test]
    fn test_jwt_expiration_in_future() {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        let kid = "test-kid";
        let expires_at = Utc::now() + Duration::hours(2);

        let token = sign_jwt_with_private_key(&private_key, kid, expires_at).unwrap();

        let n = public_key.n().to_bytes_be();
        let e = public_key.e().to_bytes_be();
        let decoding_key = DecodingKey::from_rsa_components(&base64_url::encode(&n), &base64_url::encode(&e))
            .expect("Failed to create decoding key");

        let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.validate_exp = true;

        let decoded = decode::<Claims>(&token, &decoding_key, &validation);
        assert!(decoded.is_ok());

        let claims = decoded.unwrap().claims;
        assert!(claims.exp as i64 > Utc::now().timestamp());
    }

    #[test]
    fn test_jwt_with_expired_time() {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let kid = "test-kid";
        // Create an already expired token
        let expires_at = Utc::now() - Duration::hours(1);

        let token = sign_jwt_with_private_key(&private_key, kid, expires_at);
        assert!(token.is_ok());

        // Token should be created but would fail validation due to expiration
        let token_str = token.unwrap();
        assert!(!token_str.is_empty());
    }

    #[test]
    fn test_claims_serialization() {
        let claims = Claims {
            sub: "test-user".to_string(),
            iat: 1234567890,
            exp: 1234567900,
            iss: "jwks-server".to_string(),
        };

        let json = serde_json::to_string(&claims);
        assert!(json.is_ok());

        let json_str = json.unwrap();
        assert!(json_str.contains("test-user"));
        assert!(json_str.contains("jwks-server"));
    }

    #[test]
    fn test_jwk_serialization() {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        let keys = vec![(1i64, public_key)];
        let jwks = build_jwks_from_keys(&keys);

        let json = serde_json::to_string(&jwks);
        assert!(json.is_ok());

        let json_str = json.unwrap();
        assert!(json_str.contains("RSA"));
        assert!(json_str.contains("sig"));
        assert!(json_str.contains("RS256"));
    }
}