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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use rsa::rand_core::OsRng;
    use rsa::RsaPrivateKey;
    use tempfile::NamedTempFile;

    // Helper function to create a temporary database
    fn create_temp_db() -> (Database, NamedTempFile) {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let db = Database::new(temp_file.path()).expect("Failed to create database");
        (db, temp_file)
    }

    #[test]
    fn test_database_creation() {
        let (_db, _temp_file) = create_temp_db();
        // Database should be created successfully without panicking
        // If we got here, the database was created successfully
        assert!(true);
    }

    #[test]
    fn test_save_key() {
        let (db, _temp_file) = create_temp_db();
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let exp = Utc::now() + Duration::hours(1);

        let kid = db.save_key(&private_key, exp).expect("Failed to save key");
        assert!(kid > 0);
    }

    #[test]
    fn test_get_valid_key() {
        let (db, _temp_file) = create_temp_db();
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let exp = Utc::now() + Duration::hours(1);

        db.save_key(&private_key, exp).expect("Failed to save key");

        let result = db.get_valid_key().expect("Failed to get valid key");
        assert!(result.is_some());

        let (kid, _retrieved_key, retrieved_exp) = result.unwrap();
        assert!(kid > 0);
        assert_eq!(retrieved_exp.timestamp(), exp.timestamp());
    }

    #[test]
    fn test_get_valid_key_when_none_exist() {
        let (db, _temp_file) = create_temp_db();

        let result = db.get_valid_key().expect("Failed to query database");
        assert!(result.is_none());
    }

    #[test]
    fn test_get_expired_key() {
        let (db, _temp_file) = create_temp_db();
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let exp = Utc::now() - Duration::hours(1);

        db.save_key(&private_key, exp).expect("Failed to save key");

        let result = db.get_expired_key().expect("Failed to get expired key");
        assert!(result.is_some());

        let (kid, _retrieved_key, retrieved_exp) = result.unwrap();
        assert!(kid > 0);
        assert!(retrieved_exp < Utc::now());
    }

    #[test]
    fn test_get_expired_key_when_none_exist() {
        let (db, _temp_file) = create_temp_db();

        let result = db.get_expired_key().expect("Failed to query database");
        assert!(result.is_none());
    }

    #[test]
    fn test_get_all_valid_keys() {
        let (db, _temp_file) = create_temp_db();
        let mut rng = OsRng;

        // Add multiple valid keys
        for _ in 0..3 {
            let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
            let exp = Utc::now() + Duration::hours(1);
            db.save_key(&private_key, exp).expect("Failed to save key");
        }

        // Add an expired key (should not be returned)
        let expired_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let exp = Utc::now() - Duration::hours(1);
        db.save_key(&expired_key, exp).expect("Failed to save key");

        let keys = db.get_all_valid_keys().expect("Failed to get all valid keys");
        assert_eq!(keys.len(), 3);
    }

    #[test]
    fn test_get_all_valid_keys_when_none_exist() {
        let (db, _temp_file) = create_temp_db();

        let keys = db.get_all_valid_keys().expect("Failed to get all valid keys");
        assert_eq!(keys.len(), 0);
    }

    #[test]
    fn test_initialize_keys() {
        let (db, _temp_file) = create_temp_db();

        db.initialize_keys().expect("Failed to initialize keys");

        // Should have one valid key
        let valid = db.get_valid_key().expect("Failed to get valid key");
        assert!(valid.is_some());

        // Should have one expired key
        let expired = db.get_expired_key().expect("Failed to get expired key");
        assert!(expired.is_some());
    }

    #[test]
    fn test_multiple_valid_keys_returns_most_recent() {
        let (db, _temp_file) = create_temp_db();
        let mut rng = OsRng;

        // Add first key
        let key1 = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let exp1 = Utc::now() + Duration::hours(1);
        let _kid1 = db.save_key(&key1, exp1).expect("Failed to save key");

        // Add second key
        let key2 = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let exp2 = Utc::now() + Duration::hours(2);
        let kid2 = db.save_key(&key2, exp2).expect("Failed to save key");

        // Should return the most recent key (kid2)
        let result = db.get_valid_key().expect("Failed to get valid key");
        assert!(result.is_some());
        let (kid, _, _) = result.unwrap();
        assert_eq!(kid, kid2);
    }

    #[test]
    fn test_multiple_expired_keys_returns_most_recent() {
        let (db, _temp_file) = create_temp_db();
        let mut rng = OsRng;

        // Add first expired key
        let key1 = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let exp1 = Utc::now() - Duration::hours(2);
        let _kid1 = db.save_key(&key1, exp1).expect("Failed to save key");

        // Add second expired key
        let key2 = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let exp2 = Utc::now() - Duration::hours(1);
        let kid2 = db.save_key(&key2, exp2).expect("Failed to save key");

        // Should return the most recent expired key (kid2)
        let result = db.get_expired_key().expect("Failed to get expired key");
        assert!(result.is_some());
        let (kid, _, _) = result.unwrap();
        assert_eq!(kid, kid2);
    }

    #[test]
    fn test_database_persistence() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path().to_path_buf();

        // Create database and add a key
        {
            let db = Database::new(&path).expect("Failed to create database");
            let mut rng = OsRng;
            let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
            let exp = Utc::now() + Duration::hours(1);
            db.save_key(&private_key, exp).expect("Failed to save key");
        }

        // Reopen database and verify key exists
        {
            let db = Database::new(&path).expect("Failed to reopen database");
            let result = db.get_valid_key().expect("Failed to get valid key");
            assert!(result.is_some());
        }
    }
}