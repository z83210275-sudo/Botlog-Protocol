# BotLog Merkle Tree Batch Validator - Tier 2 $750-$1000 Bounty

## Overview
This is an efficient batch verification system for BotLog entries using Merkle Trees.

Instead of verifying a chain one-by-one, you can batch 1000+ log entries into a single Merkle root and prove inclusion with O(log n) hashes.

## What it does
- `MerkleTree` class: Builds Merkle tree from BotLog `log_hash` entries
- `getRoot()`: Returns single root commitment for entire batch
- `getProof(index)`: Generates inclusion proof for a specific entry
- `verifyProof(proof)`: Verifies a single entry is in the tree
- `verifyBatch()`: Batch verifies multiple entries at once

## Efficiency
- **Without Merkle**: Share 1000 hashes = 64,000 chars
- **With Merkle**: Share 1 root (64 chars) + 10 proof hashes per verification (640 chars) = 99% savings

## Usage

```typescript
import { buildBotlogMerkleTree, MerkleTree } from './merkle.js';

const logHashes = [entry1.log_hash, entry2.log_hash, entry3.log_hash];
const tree = buildBotlogMerkleTree(logHashes);

console.log('Root:', tree.getRoot());

// Prove entry 0 is in batch
const proof = tree.getProof(0);
console.log('Valid?', MerkleTree.verifyProof(proof));
```

## Test
```bash
npm install
npx tsx example-merkle.ts
```

## Files
- `merkle.ts` - Core Merkle tree implementation with SHA-256
- `example-merkle.ts` - Demo with 8-entry batch
- This README

Ready for Tier 2 Bounty Review.
