//! Example: 3-entry chain - matches Python & TypeScript examples

use botlog_rs::{BotLogEntry, Actor, Action, generate_keypair, public_key_to_base64, verify_chain, get_current_timestamp};

fn main() -> Result<(), String> {
    println!("BotLog Rust Validator - Tier 1 $500 - Demo\n");

    let (sk, vk) = generate_keypair();
    let pub_b64 = public_key_to_base64(&vk);
    println!("Public key: {}", pub_b64);

    // Entry 1 - genesis
    let mut entry1 = BotLogEntry::new(
        Actor { actor_type: "human".to_string(), id: "KullAxel".to_string(), public_key: pub_b64.clone() },
        Action { action_type: "propose".to_string(), description: "Launch BotLog feedback campaign".to_string(), payload: serde_json::json!({}) },
        None,
    );
    entry1.sign(&sk)?;
    println!("\nEntry1 hash: {}", entry1.log_hash);
    println!("Entry1 sig valid: {}", entry1.verify_signature()?);

    // Entry 2
    std::thread::sleep(std::time::Duration::from_millis(5));
    let mut entry2 = BotLogEntry::new(
        Actor { actor_type: "human".to_string(), id: "KullAxel".to_string(), public_key: pub_b64.clone() },
        Action { action_type: "commit".to_string(), description: "Commit to delivery".to_string(), payload: serde_json::json!({"deadline":"2026-02-01"}) },
        Some(entry1.log_hash.clone()),
    );
    entry2.timestamp = get_current_timestamp();
    entry2.sign(&sk)?;
    println!("\nEntry2 hash: {}", entry2.log_hash);
    println!("Entry2 previous: {:?}", entry2.previous_hash);

    // Entry 3
    std::thread::sleep(std::time::Duration::from_millis(5));
    let mut entry3 = BotLogEntry::new(
        Actor { actor_type: "human".to_string(), id: "KullAxel".to_string(), public_key: pub_b64.clone() },
        Action { action_type: "execute".to_string(), description: "Deliver feedback campaign".to_string(), payload: serde_json::json!({"result":"success"}) },
        Some(entry2.log_hash.clone()),
    );
    entry3.timestamp = get_current_timestamp();
    entry3.sign(&sk)?;
    println!("\nEntry3 hash: {}", entry3.log_hash);

    // Verify chain
    let chain = vec![entry1, entry2, entry3];
    match verify_chain(&chain) {
        Ok(true) => println!("\n✅ Chain Verified! - Matches Python & TypeScript impl"),
        Ok(false) => println!("\n❌ Chain Invalid"),
        Err(e) => println!("\n❌ Verification error: {}", e),
    }

    Ok(())
}
