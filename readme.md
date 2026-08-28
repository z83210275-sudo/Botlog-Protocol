# BotLog Rust Validator - Tier 1 $500 Bounty

Rust implementation of BotLog Protocol v1.0 - Log Validator.

Matches Python reference implementation `reference/python/botlog-mini` and TypeScript implementation `reference/typescript`.

## Features

- Ed25519 signing & verification (`ed25519-dalek` 2.0)
- SHA-256 hashing (`sha2`)
- Canonical JSON (RFC 8785-like, BTreeMap sorted keys)
- Chain verification: signature, hash chain, timestamp monotonicity, schema validation
- Pure Rust, no unsafe

## Quickstart

```bash
cd reference/rust/botlog-rs
cargo run --bin example_chain
cargo test
```

## Example

```rust
use botlog_rs::{BotLogEntry, Actor, Action, generate_keypair, public_key_to_base64, verify_chain};

let (sk, vk) = generate_keypair();
let pub_b64 = public_key_to_base64(&vk);

let mut entry1 = BotLogEntry::new(
    Actor { actor_type: "human".into(), id: "KullAxel".into(), public_key: pub_b64.clone() },
    Action { action_type: "propose".into(), description: "Launch campaign".into(), payload: json!({}) },
    None,
);
entry1.sign(&sk).unwrap();

let mut entry2 = BotLogEntry::new(
    Actor { actor_type: "human".into(), id: "KullAxel".into(), public_key: pub_b64 },
    Action { action_type: "commit".into(), description: "Commit".into(), payload: json!({}) },
    Some(entry1.log_hash.clone()),
);
entry2.sign(&sk).unwrap();

assert!(verify_chain(&[entry1, entry2]).unwrap()); // ✅ Verified!
```

## Files for PR

- `Cargo.toml` - dependencies
- `src/lib.rs` - Core validator with Ed25519 + SHA256 + Canonical JSON + verify_chain
- `src/main.rs` - 3-entry chain demo (example_chain)
- `README.md` - This file

## Payout

Polar.sh: https://polar.sh/mo-mansi

## Bounty Requirements

✅ Implements Ed25519 signing, SHA-256, chain verification
✅ Matches Python reference implementation behavior
✅ Validates: signature, previous_hash linking, log_hash integrity, timestamp monotonicity, schema
✅ `cargo test` passes
✅ `cargo run` demo shows ✅ Verified

Ready for review! 🚀
