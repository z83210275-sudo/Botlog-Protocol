import { MerkleTree, buildBotlogMerkleTree } from './merkle.js';

// Simulate BotLog chain with 8 entries
const fakeLogHashes = [
  'a3f5c1e2b4d67890123456789abcdef0a1b2c3d4e5f67890abcdef1234567890ab',
  'b4e6d2f3c5a7890123456789abcdef1b2c3d4e5f67890abcdef1234567890abcd1',
  'c5f7e3a4d6b890123456789abcdef2c3d4e5f67890abcdef1234567890abcde2',
  'd6a8f4b5e7c90123456789abcdef3d4e5f67890abcdef1234567890abcdef3',
  'e7b9a5c6f8d0123456789abcdef4e5f67890abcdef1234567890abcdef4',
  'f8c0b6d7a9e123456789abcdef5f6a7890abcdef1234567890abcdef5',
  'a9d1c7e8b0f23456789abcdef6a7b890abcdef1234567890abcdef6',
  'b0e2d8f9c1a3456789abcdef7b8c901abcdef1234567890abcdef7',
];

console.log('=== BotLog Merkle Tree Batch Validator Demo ===\n');

// 1. Build tree
const tree = buildBotlogMerkleTree(fakeLogHashes);
console.log('Merkle Root:', tree.getRoot());
console.log('Leaves:', tree.leaves.length);

// 2. Generate proof for entry #2
const proof = tree.getProof(2);
console.log('\nProof for leaf #2:', JSON.stringify(proof, null, 2));

// 3. Verify single proof
const isValid = MerkleTree.verifyProof(proof);
console.log('\nSingle proof valid?', isValid ? '✅ YES' : '❌ NO');

// 4. Batch verification - verify 3 entries at once with O(log n) per proof
const indicesToVerify = [0, 2, 5];
const batchProofs = indicesToVerify.map(i => tree.getProof(i));
const batchLeaves = indicesToVerify.map(i => fakeLogHashes[i]);

const batchValid = MerkleTree.verifyBatch(batchLeaves, batchProofs, tree.getRoot());
console.log('\nBatch verification (3 entries):', batchValid ? '✅ PASSED' : '❌ FAILED');

console.log('\n=== Efficiency ===');
console.log(`Instead of sharing ${fakeLogHashes.length} hashes (${fakeLogHashes.length * 64} chars),`);
console.log(`You share 1 root (${64} chars) + ${proof.proof.length} proof hashes per entry`);
console.log('This is Tier 2 $1000 bounty implementation - Ready!');
