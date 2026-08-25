import { createHash } from 'crypto';

function sha256(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

function sha256Bytes(data: Buffer): Buffer {
  return createHash('sha256').update(data).digest();
}

export interface MerkleProof {
  leaf: string;
  proof: { position: 'left' | 'right'; hash: string }[];
  root: string;
  leafIndex: number;
}

export class MerkleTree {
  public leaves: string[];
  public layers: string[][];
  public root: string;

  constructor(leaves: string[]) {
    if (leaves.length === 0) {
      throw new Error('Cannot build Merkle tree with 0 leaves');
    }
    // Hash leaves first (Botlog entries are already hashed, but we hash again for uniformity)
    this.leaves = leaves.map(l => sha256(l));
    this.layers = [this.leaves];
    this.buildTree();
    this.root = this.layers[this.layers.length - 1][0];
  }

  private buildTree() {
    let currentLayer = this.leaves;
    while (currentLayer.length > 1) {
      const nextLayer: string[] = [];
      for (let i = 0; i < currentLayer.length; i += 2) {
        const left = currentLayer[i];
        const right = i + 1 < currentLayer.length ? currentLayer[i + 1] : left; // duplicate last if odd
        const combined = Buffer.concat([Buffer.from(left, 'hex'), Buffer.from(right, 'hex')]);
        const parentHash = sha256Bytes(combined).toString('hex');
        nextLayer.push(parentHash);
      }
      this.layers.push(nextLayer);
      currentLayer = nextLayer;
    }
  }

  getRoot(): string {
    return this.root;
  }

  getProof(leafIndex: number): MerkleProof {
    if (leafIndex < 0 || leafIndex >= this.leaves.length) {
      throw new Error('Leaf index out of range');
    }
    const proof: { position: 'left' | 'right'; hash: string }[] = [];
    let index = leafIndex;
    for (let layer = 0; layer < this.layers.length - 1; layer++) {
      const currentLayer = this.layers[layer];
      const isRightNode = index % 2 === 1;
      const pairIndex = isRightNode ? index - 1 : index + 1;

      if (pairIndex < currentLayer.length) {
        proof.push({
          position: isRightNode ? 'left' : 'right',
          hash: currentLayer[pairIndex],
        });
      } else {
        // odd case, duplicated node
        proof.push({
          position: 'right',
          hash: currentLayer[index],
        });
      }
      index = Math.floor(index / 2);
    }
    return {
      leaf: this.leaves[leafIndex],
      proof,
      root: this.root,
      leafIndex,
    };
  }

  static verifyProof(proof: MerkleProof): boolean {
    let hash = proof.leaf;
    for (const p of proof.proof) {
      const combined =
        p.position === 'left'
          ? Buffer.concat([Buffer.from(p.hash, 'hex'), Buffer.from(hash, 'hex')])
          : Buffer.concat([Buffer.from(hash, 'hex'), Buffer.from(p.hash, 'hex')]);
      hash = sha256Bytes(combined).toString('hex');
    }
    return hash === proof.root;
  }

  // Batch verify multiple BotLog entry hashes at once
  static verifyBatch(leaves: string[], proofs: MerkleProof[], expectedRoot: string): boolean {
    if (leaves.length !== proofs.length) return false;
    for (let i = 0; i < leaves.length; i++) {
      const leafHash = sha256(leaves[i]);
      if (leafHash !== proofs[i].leaf) return false;
      if (proofs[i].root !== expectedRoot) return false;
      if (!MerkleTree.verifyProof(proofs[i])) return false;
    }
    return true;
  }
}

// Helper for BotLog: build tree from log_hashes
export function buildBotlogMerkleTree(logHashes: string[]): MerkleTree {
  return new MerkleTree(logHashes);
}

export function generateBotlogBatchProof(tree: MerkleTree, indices: number[]): MerkleProof[] {
  return indices.map(i => tree.getProof(i));
}
