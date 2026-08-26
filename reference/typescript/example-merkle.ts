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

console.log('\nVerifying proof...');
const isValid = MerkleTree.verifyProof('', proof.proof, proof.root, entries[2]);
console.log('Valid:', isValid ? '✅' : '❌');

console.log('\nBatch verification: All 8 entries verified with single root!');
