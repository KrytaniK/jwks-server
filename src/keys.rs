use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1::{EncodeRsaPrivateKey}, traits::PublicKeyParts};
use rand::rngs::OsRng;
use chrono::{Utc, Duration};
use base64::{engine::general_purpose, Engine as _};
use std::sync::{Arc, RwLock};

#[derive(Clone)]
pub struct KeyPair {
    pub kid: String,
    pub private_pem: String,
    pub public_n_b64: String,
    pub public_e_b64: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub alg: String,
}

pub struct KeyStore {
    keys: Arc<RwLock<Vec<KeyPair>>>,
}

impl KeyStore {
    /// Create an empty KeyStore
    pub fn new() -> Self {
        KeyStore {
            keys: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Generate 3 sample keys: 1 expired, 2 valid
    pub fn with_sample_keys() -> Self {
        let store = Self::new();

        // Expired key
        let expired = Self::generate_rsa_keypair("key-expired", -3600);
        store.add_key(expired.expect("Failed to generate expired key"));

        // Valid keys
        let valid1 = Self::generate_rsa_keypair("key-valid-1", 3600);
        let valid2 = Self::generate_rsa_keypair("key-valid-2", 3600 * 24);
        store.add_key(valid1.expect("Failed to generate valid key"));
        store.add_key(valid2.expect("Failed to generate valid key"));

        store
    }

    /// Generate a single RSA keypair
    pub fn generate_rsa_keypair(kid: &str, valid_secs: i64) -> anyhow::Result<KeyPair> {
        let mut rng = OsRng;
        let bits = 2048;
        let priv_key = RsaPrivateKey::new(&mut rng, bits)?;
        let pub_key = RsaPublicKey::from(&priv_key);

        let private_pem = priv_key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)?.to_string();
        let n_bytes = pub_key.n().to_bytes_be();
        let e_bytes = pub_key.e().to_bytes_be();
        let n_b64 = general_purpose::URL_SAFE_NO_PAD.encode(n_bytes);
        let e_b64 = general_purpose::URL_SAFE_NO_PAD.encode(e_bytes);

        let expires_at = Utc::now() + Duration::seconds(valid_secs);

        Ok(KeyPair {
            kid: kid.to_string(),
            private_pem,
            public_n_b64: n_b64,
            public_e_b64: e_b64,
            expires_at,
            alg: "RS256".to_string(),
        })
    }

    /// Add a KeyPair to the store
    pub fn add_key(&self, key: KeyPair) {
        let mut keys = self.keys.write().unwrap();
        keys.push(key);
    }

    /// Return all keys
    pub fn all_keys(&self) -> Vec<KeyPair> {
        let keys = self.keys.read().unwrap();
        keys.clone()
    }

    /// Return the first unexpired key
    pub fn get_unexpired_key(&self) -> Option<KeyPair> {
        let now = Utc::now();
        let keys = self.keys.read().unwrap();
        keys.iter().find(|k| k.expires_at > now).cloned()
    }

    /// Return the first expired key
    pub fn get_expired_key(&self) -> Option<KeyPair> {
        let now = Utc::now();
        let keys = self.keys.read().unwrap();
        keys.iter().find(|k| k.expires_at <= now).cloned()
    }

    /// Return any key (expired or unexpired)
    pub fn any_key(&self) -> Option<KeyPair> {
        let keys = self.keys.read().unwrap();
        keys.get(0).cloned()
    }
}