# Merkle Tree Batch Validator - Tier 2 $1000 Bounty

Efficient batch verification for BotLog entries using Merkle Trees.

## Efficiency
- Without Merkle: 1000 hashes = 64,000 chars to share
- With Merkle: 1 root = 64 chars (99.9% savings)
- Proof size: O(log n) = 10 hashes for 1000 entries

## Usage
```ts
import { MerkleTree } from './merkle';
const tree = new MerkleTree(entries);
const root = tree.getRoot();
const proof = tree.getProof(2);
MerkleTree.verifyProof('', proof.proof, root, entries[2]);
```
