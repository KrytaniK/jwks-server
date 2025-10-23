use anyhow::Result;
use chrono::{DateTime, Utc};
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use rusqlite::{params, Connection};
use std::path::Path;

pub struct Database {
  conn: Connection,
}

impl Database {
  /// Create or open database file
  pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
    let conn = Connection::open(path)?;

    // Create the keys table if it doesn't exist
    conn.execute(
      "CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
      )",
      [],
    )?;

    Ok(Database { conn })
  }

  /// Save a private key to the database
  pub fn save_key(&self, private_key: &RsaPrivateKey, exp: DateTime<Utc>) -> Result<i64> {
    // Serialize the private key to PEM format
    let pem = private_key.to_pkcs1_pem(LineEnding::LF)?;
    let pem_bytes = pem.as_bytes();

    // Insert into database
    self.conn.execute(
      "INSERT INTO keys (key, exp) VALUES (?, ?)",
      params![pem_bytes, exp.timestamp()],
    )?;

    // Get last inserted kid
    let kid = self.conn.last_insert_rowid();

    Ok(kid)
  }

  // Get an unexpired key from the database
  pub fn get_valid_key(&self) -> Result<Option<(i64, RsaPrivateKey, DateTime<Utc>)>> {
    let now = Utc::now().timestamp();

    let mut stmt = self.conn.prepare(
      "SELECT kid, key, exp FROM keys WHERE exp > ?1 ORDER BY kid DESC LIMIT 1"
    )?;

    let result = stmt.query_row(params![now], |row| {
      let kid: i64 = row.get(0)?;
      let key_bytes: Vec<u8> = row.get(1)?;
      let exp_timestamp: i64 = row.get(2)?;
      Ok((kid, key_bytes, exp_timestamp))
    });

    match result {
      Ok((kid, key_bytes, exp_timestamp)) => {
        let pem_str = String::from_utf8(key_bytes)?;
        let private_key = RsaPrivateKey::from_pkcs1_pem(&pem_str)?;
        let exp = DateTime::from_timestamp(exp_timestamp, 0)
          .unwrap_or_else(|| Utc::now());
        Ok(Some((kid, private_key, exp)))
      }
      Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
      Err(e) => Err(e.into()),
    }
  }

   /// Get an expired key from the database
    pub fn get_expired_key(&self) -> Result<Option<(i64, RsaPrivateKey, DateTime<Utc>)>> {
        let now = Utc::now().timestamp();
        
        let mut stmt = self.conn.prepare(
            "SELECT kid, key, exp FROM keys WHERE exp <= ?1 ORDER BY kid DESC LIMIT 1"
        )?;
        
        let result = stmt.query_row(params![now], |row| {
            let kid: i64 = row.get(0)?;
            let key_bytes: Vec<u8> = row.get(1)?;
            let exp_timestamp: i64 = row.get(2)?;
            Ok((kid, key_bytes, exp_timestamp))
        });
        
        match result {
          Ok((kid, key_bytes, exp_timestamp)) => {
            let pem_str = String::from_utf8(key_bytes)?;
            let private_key = RsaPrivateKey::from_pkcs1_pem(&pem_str)?;
            let exp = DateTime::from_timestamp(exp_timestamp, 0)
              .unwrap_or_else(|| Utc::now());
            Ok(Some((kid, private_key, exp)))
          }
          Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
          Err(e) => Err(e.into()),
        }
    }

    /// Get all valid (unexpired) keys for JWKS endpoint
    pub fn get_all_valid_keys(&self) -> Result<Vec<(i64, RsaPublicKey)>> {
      let now = Utc::now().timestamp();
      
      let mut stmt = self.conn.prepare(
        "SELECT kid, key FROM keys WHERE exp > ?1"
      )?;
      
      let rows = stmt.query_map(params![now], |row| {
        let kid: i64 = row.get(0)?;
        let key_bytes: Vec<u8> = row.get(1)?;
        Ok((kid, key_bytes))
      })?;
      
      let mut keys = Vec::new();
      for row in rows {
        let (kid, key_bytes) = row?;
        let pem_str = String::from_utf8(key_bytes)?;
        let private_key = RsaPrivateKey::from_pkcs1_pem(&pem_str)?;
        let public_key = RsaPublicKey::from(&private_key);
        keys.push((kid, public_key));
      }
      
      Ok(keys)
    }

    /// Generate and save initial keys (1 expired, 1 valid)
    pub fn initialize_keys(&self) -> Result<()> {
      use rsa::rand_core::OsRng;
      
      let mut rng = OsRng;
      
      // Generate an expired key (expired 1 hour ago)
      let expired_key = RsaPrivateKey::new(&mut rng, 2048)?;
      let expired_time = Utc::now() - chrono::Duration::hours(1);
      self.save_key(&expired_key, expired_time)?;
      
      // Generate a valid key (expires in 1 hour)
      let valid_key = RsaPrivateKey::new(&mut rng, 2048)?;
      let valid_time = Utc::now() + chrono::Duration::hours(1);
      self.save_key(&valid_key, valid_time)?;
      
      Ok(())
    }
}