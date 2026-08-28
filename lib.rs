//! BotLog Protocol - Rust Reference Implementation
//! Tier 1 $500 Bounty - Log Validator
//! 
//! Validates log entries against spec, verifies ed25519 signatures,
//! checks hash chain integrity, timestamps, and canonical JSON.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Data Structures - matches spec v1.0
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Actor {
    #[serde(rename = "type")]
    pub actor_type: String, // "human" | "ai"
    pub id: String,
    pub public_key: String, // base64 ed25519 public key
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Action {
    #[serde(rename = "type")]
    pub action_type: String, // "propose" | "commit" | "execute" | "verify" | "dispute"
    pub description: String,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Commitment {
    #[serde(rename = "type")]
    pub commitment_type: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotLogEntry {
    pub version: String,
    pub timestamp: String,
    pub actor: Actor,
    pub action: Action,
    #[serde(default)]
    pub commitments: Vec<Commitment>,
    pub signature: String, // base64
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_hash: Option<String>,
    pub log_hash: String,
}

// For canonicalization & signing, we sign without signature and log_hash
#[derive(Serialize)]
struct SignableEntry<'a> {
    version: &'a str,
    timestamp: &'a str,
    actor: &'a Actor,
    action: &'a Action,
    commitments: &'a Vec<Commitment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_hash: &'a Option<String>,
}

// ---------------------------------------------------------------------------
// Crypto Helpers
// ---------------------------------------------------------------------------

pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

// Simple hex helper without extra dep
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }
    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if s.len() % 2 != 0 { return Err("invalid hex len".to_string()); }
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2],16).map_err(|e| e.to_string())).collect()
    }
}

pub fn sha256_hex_str(s: &str) -> String {
    sha256_hex(s.as_bytes())
}

/// RFC 8785-like canonical JSON: sorted keys, no whitespace
/// We use BTreeMap sorting via serde_json canonicalization
pub fn canonical_json(value: &serde_json::Value) -> Result<String, String> {
    // Recursively sort object keys
    fn sort_value(v: &serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(map) => {
                let mut sorted = BTreeMap::new();
                for (k, v) in map {
                    sorted.insert(k.clone(), sort_value(v));
                }
                let json_map: serde_json::Map<String, serde_json::Value> = sorted.into_iter().collect();
                serde_json::Value::Object(json_map)
            }
            serde_json::Value::Array(arr) => {
                serde_json::Value::Array(arr.iter().map(sort_value).collect())
            }
            _ => v.clone(),
        }
    }
    let sorted = sort_value(value);
    serde_json::to_string(&sorted).map_err(|e| e.to_string())
}

pub fn get_current_timestamp() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

pub fn public_key_to_base64(vk: &VerifyingKey) -> String {
    BASE64.encode(vk.to_bytes())
}

pub fn base64_to_verifying_key(b64: &str) -> Result<VerifyingKey, String> {
    let bytes = BASE64.decode(b64).map_err(|e| e.to_string())?;
    if bytes.len() != 32 { return Err("invalid pubkey len".to_string()); }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&arr).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Signing & Verification
// ---------------------------------------------------------------------------

impl BotLogEntry {
    pub fn new(
        actor: Actor,
        action: Action,
        previous_hash: Option<String>,
    ) -> Self {
        Self {
            version: "1.0".to_string(),
            timestamp: get_current_timestamp(),
            actor,
            action,
            commitments: vec![],
            signature: String::new(),
            previous_hash,
            log_hash: String::new(),
        }
    }

    fn signable_json(&self) -> Result<String, String> {
        let signable = SignableEntry {
            version: &self.version,
            timestamp: &self.timestamp,
            actor: &self.actor,
            action: &self.action,
            commitments: &self.commitments,
            previous_hash: &self.previous_hash,
        };
        let val = serde_json::to_value(&signable).map_err(|e| e.to_string())?;
        canonical_json(&val)
    }

    fn compute_log_hash(&self) -> Result<String, String> {
        // log_hash = sha256(canonical(signable) + signature)
        let signable = self.signable_json()?;
        let data = format!("{}{}", signable, self.signature);
        Ok(sha256_hex_str(&data))
    }

    pub fn sign(&mut self, signing_key: &SigningKey) -> Result<(), String> {
        let signable = self.signable_json()?;
        let sig: Signature = signing_key.sign(signable.as_bytes());
        self.signature = BASE64.encode(sig.to_bytes());
        self.log_hash = self.compute_log_hash()?;
        Ok(())
    }

    pub fn verify_signature(&self) -> Result<bool, String> {
        let vk = base64_to_verifying_key(&self.actor.public_key)?;
        let sig_bytes = BASE64.decode(&self.signature).map_err(|e| e.to_string())?;
        if sig_bytes.len() != 64 { return Err("invalid signature len".to_string()); }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&arr);
        let signable = self.signable_json()?;
        Ok(vk.verify(signable.as_bytes(), &signature).is_ok())
    }
}

// ---------------------------------------------------------------------------
// Chain Validator - matches Python verify_chain
// ---------------------------------------------------------------------------

pub fn verify_chain(chain: &[BotLogEntry]) -> Result<bool, String> {
    if chain.is_empty() { return Ok(true); }

    for (i, entry) in chain.iter().enumerate() {
        // 1. Signature must be valid
        if !entry.verify_signature()? {
            return Err(format!("Invalid signature at index {}", i));
        }

        // 2. log_hash must match computed
        let computed_hash = entry.compute_log_hash()?;
        if computed_hash != entry.log_hash {
            return Err(format!("Log hash mismatch at index {}: expected {} got {}", i, computed_hash, entry.log_hash));
        }

        // 3. Chain linking
        if i == 0 {
            if entry.previous_hash.is_some() {
                return Err("Genesis entry must have no previous_hash".to_string());
            }
        } else {
            let prev = &chain[i-1];
            if entry.previous_hash.as_deref() != Some(&prev.log_hash) {
                return Err(format!("Chain broken at index {}: previous_hash mismatch", i));
            }
            // 4. Timestamps monotonic per actor
            if entry.actor.id == prev.actor.id && entry.timestamp <= prev.timestamp {
                return Err(format!("Timestamp not monotonic at index {}", i));
            }
        }

        // 5. Basic schema validation
        if entry.version != "1.0" { return Err(format!("Invalid version at {}", i)); }
        if !["human","ai"].contains(&entry.actor.actor_type.as_str()) {
            return Err(format!("Invalid actor type at {}", i));
        }
        if !["propose","commit","execute","verify","dispute"].contains(&entry.action.action_type.as_str()) {
            return Err(format!("Invalid action type at {}", i));
        }
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain() {
        let (sk, vk) = generate_keypair();
        let pub_b64 = public_key_to_base64(&vk);

        let mut e1 = BotLogEntry::new(
            Actor { actor_type: "human".to_string(), id: "KullAxel".to_string(), public_key: pub_b64.clone() },
            Action { action_type: "propose".to_string(), description: "Launch campaign".to_string(), payload: serde_json::json!({}) },
            None,
        );
        e1.sign(&sk).unwrap();

        let mut e2 = BotLogEntry::new(
            Actor { actor_type: "human".to_string(), id: "KullAxel".to_string(), public_key: pub_b64 },
            Action { action_type: "commit".to_string(), description: "Commit".to_string(), payload: serde_json::json!({}) },
            Some(e1.log_hash.clone()),
        );
        // small delay to ensure timestamp monotonic
        std::thread::sleep(std::time::Duration::from_millis(10));
        e2.timestamp = get_current_timestamp();
        e2.sign(&sk).unwrap();

        assert!(verify_chain(&[e1, e2]).unwrap());
    }
}
