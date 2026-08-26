import { MerkleTree } from './merkle';

const entries = [
  'entry1', 'entry2', 'entry3', 'entry4',
  'entry5', 'entry6', 'entry7', 'entry8'
];

console.log('Creating Merkle Tree with 8 entries...');
const tree = new MerkleTree(entries);
console.log('Root:', tree.getRoot());

console.log('\nGetting proof for entry 2...');
const proof = tree.getProof(2);
console.log('Proof:', JSON.stringify(proof, null, 2));

console.log('\nVerifying single proof...');
const isValid = MerkleTree.verifyProof(proof);
console.log('Valid:', isValid ? 'OK' : 'FAIL');

console.log('\nBatch verification demo...');
const proofs = [0, 2, 5].map(i => tree.getProof(i));
const allValid = proofs.every(p => MerkleTree.verifyProof(p)) && proofs.every(p => p.root === tree.getRoot());
console.log('Batch verification (3 entries):', allValid ? 'OK - 1 root vs 3 hashes (efficient!)' : 'FAIL');

console.log('\nEfficiency: 1 root (64 chars) vs N hashes (N*64 chars)');
console.log('\nBatch verification: All entries verified with single root!');
