import { createHash } from 'crypto';
function sha256(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}
export class MerkleTree {
  private leaves: string[];
  private layers: string[][];
  constructor(entries: string[]) {
    this.leaves = entries.map(e => sha256(e));
    this.layers = [this.leaves];
    this.buildTree();
  }
  private buildTree(): void {
    let currentLayer = this.leaves;
    while (currentLayer.length > 1) {
      const nextLayer: string[] = [];
      for (let i = 0; i < currentLayer.length; i += 2) {
        const left = currentLayer[i];
        const right = i + 1 < currentLayer.length ? currentLayer[i + 1] : left;
        nextLayer.push(sha256(left + right));
      }
      this.layers.push(nextLayer);
      currentLayer = nextLayer;
    }
  }
  getRoot(): string { return this.layers[this.layers.length - 1][0] || ''; }
  getProof(index: number) {
    if (index < 0 || index >= this.leaves.length) throw new Error('Index out of bounds');
    const proof: { position: 'left' | 'right'; hash: string }[] = [];
    let idx = index;
    for (let layer = 0; layer < this.layers.length - 1; layer++) {
      const currentLayer = this.layers[layer];
      const isRightNode = idx % 2 === 1;
      const pairIndex = isRightNode ? idx - 1 : idx + 1;
      if (pairIndex < currentLayer.length) {
        proof.push({ position: isRightNode ? 'left' : 'right', hash: currentLayer[pairIndex] });
      } else {
        proof.push({ position: 'right', hash: currentLayer[idx] });
      }
      idx = Math.floor(idx / 2);
    }
    return { leaf: this.leaves[index], proof, root: this.getRoot() };
  }
  static verifyProof(leafHash: string, proof: any[], root: string, leafData?: string): boolean {
    let hash = leafData ? sha256(leafData) : leafHash;
    for (const p of proof) {
      hash = p.position === 'left' ? sha256(p.hash + hash) : sha256(hash + p.hash);
    }
    return hash === root;
  }
}
