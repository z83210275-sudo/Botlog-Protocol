/**
 * BotLog Protocol - TypeScript Validator
 * Tier 1 $500 Bounty - KullAxel/Botlog-Protocol
 * 
 * Implements: Ed25519 signing, SHA-256 hash chaining, canonical JSON, chain verification
 * Spec: https://github.com/KullAxel/Botlog-Protocol
 */

import * as ed from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

// --- Types ---
export interface BotLogActor {
  type: 'human' | 'ai';
  id: string;
  public_key: string; // base64 or hex ed25519 public key
}

export interface BotLogAction {
  type: 'propose' | 'commit' | 'execute' | 'verify' | 'dispute';
  description: string;
  payload?: Record<string, any>;
}

export interface BotLogCommitment {
  type: 'zk-proof' | 'hash-commitment' | 'merkle-proof';
  value: string;
  proof?: string;
}

export interface BotLogEntryData {
  version: string;
  timestamp: string;
  actor: BotLogActor;
  action: BotLogAction;
  commitments?: BotLogCommitment[];
  previous_hash: string | null;
}

export interface BotLogEntryFull extends BotLogEntryData {
  signature: string;
  log_hash: string;
}

// --- Canonical JSON (RFC 8785 simplified) ---
function canonicalize(obj: any): string {
  if (obj === null) return 'null';
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalize).join(',') + ']';
  }
  if (typeof obj === 'object') {
    const keys = Object.keys(obj).sort();
    return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalize(obj[k])).join(',') + '}';
  }
  return JSON.stringify(obj);
}

function sha256Hex(data: string | Uint8Array): string {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  return bytesToHex(sha256(bytes));
}

// --- Key Management ---
export async function generateKeypair(): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array; publicKeyHex: string; privateKeyHex: string }> {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return {
    privateKey,
    publicKey,
    publicKeyHex: bytesToHex(publicKey),
    privateKeyHex: bytesToHex(privateKey),
  };
}

export function publicKeyToBase64(pubKey: Uint8Array): string {
  return Buffer.from(pubKey).toString('base64');
}

export function base64ToPublicKey(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

export function getCurrentTimestamp(): string {
  return new Date().toISOString();
}

// --- Core Entry ---
export class BotLogEntry {
  version: string;
  timestamp: string;
  actor: BotLogActor;
  action: BotLogAction;
  commitments: BotLogCommitment[];
  previous_hash: string | null;
  signature: string | null = null;
  log_hash: string | null = null;

  constructor(data: BotLogEntryData) {
    this.version = data.version || '1.0';
    this.timestamp = data.timestamp;
    this.actor = data.actor;
    this.action = data.action;
    this.commitments = data.commitments || [];
    this.previous_hash = data.previous_hash;
  }

  private getSignablePayload(): string {
    const payload = {
      version: this.version,
      timestamp: this.timestamp,
      actor: this.actor,
      action: this.action,
      commitments: this.commitments,
      previous_hash: this.previous_hash,
    };
    return canonicalize(payload);
  }

  async sign(privateKey: Uint8Array): Promise<void> {
    const message = this.getSignablePayload();
    const msgHash = sha256(new TextEncoder().encode(message));
    const sig = await ed.signAsync(msgHash, privateKey);
    this.signature = bytesToHex(sig);
    // log_hash is hash of (previous_hash + signature + signablePayload)
    this.log_hash = sha256Hex(this.previous_hash || '' + this.signature + message);
  }

  toJSON(): BotLogEntryFull {
    if (!this.signature || !this.log_hash) throw new Error('Entry not signed yet');
    return {
      version: this.version,
      timestamp: this.timestamp,
      actor: this.actor,
      action: this.action,
      commitments: this.commitments,
      previous_hash: this.previous_hash,
      signature: this.signature,
      log_hash: this.log_hash,
    };
  }

  static async verify(entry: BotLogEntryFull): Promise<boolean> {
    try {
      const { signature, log_hash, ...rest } = entry;
      const signable = canonicalize(rest as any);
      // We need to reconstruct signable without signature/log_hash - rest already excludes them except previous_hash is inside rest? Actually rest includes previous_hash etc
      // Our signable was version,timestamp,actor,action,commitments,previous_hash
      const payload = {
        version: (rest as any).version,
        timestamp: (rest as any).timestamp,
        actor: (rest as any).actor,
        action: (rest as any).action,
        commitments: (rest as any).commitments || [],
        previous_hash: (rest as any).previous_hash,
      };
      const canonicalPayload = canonicalize(payload);
      const msgHash = sha256(new TextEncoder().encode(canonicalPayload));

      // Resolve public key - supports hex or base64
      let pubKeyBytes: Uint8Array;
      const pkStr = (rest as any).actor.public_key;
      try {
        if (pkStr.length === 64 || pkStr.length === 128) { // hex
          pubKeyBytes = hexToBytes(pkStr);
        } else {
          pubKeyBytes = base64ToPublicKey(pkStr);
          // base64 may be hex inside base64? fallback
          if (pubKeyBytes.length !== 32) {
            pubKeyBytes = hexToBytes(pkStr);
          }
        }
      } catch {
        pubKeyBytes = hexToBytes(pkStr);
      }

      const sigBytes = hexToBytes(signature);
      const isValidSig = await ed.verifyAsync(sigBytes, msgHash, pubKeyBytes);

      const expectedHash = sha256Hex((entry.previous_hash || '') + signature + canonicalPayload);
      const isValidHash = expectedHash === log_hash;

      return isValidSig && isValidHash;
    } catch (e) {
      console.error('Verify error:', e);
      return false;
    }
  }
}

// --- Chain Validator ---
export async function verifyChain(chain: BotLogEntryFull[]): Promise<{ valid: boolean; error?: string }> {
  if (chain.length === 0) return { valid: true };
  
  // 1. Timestamps monotonically increasing per actor
  const actorTimestamps = new Map<string, string>();
  
  for (let i = 0; i < chain.length; i++) {
    const entry = chain[i];
    
    // 2. Verify signature & hash
    const sigValid = await BotLogEntry.verify(entry);
    if (!sigValid) {
      return { valid: false, error: `Invalid signature/hash at index ${i}` };
    }

    // 3. Check hash chaining
    if (i === 0) {
      if (entry.previous_hash !== null) {
        return { valid: false, error: 'Genesis entry must have previous_hash = null' };
      }
    } else {
      if (entry.previous_hash !== chain[i-1].log_hash) {
        return { valid: false, error: `Hash chain broken at index ${i}: expected ${chain[i-1].log_hash}, got ${entry.previous_hash}` };
      }
    }

    // 4. Timestamp monotonic per actor
    const actorId = entry.actor.id;
    const prevTs = actorTimestamps.get(actorId);
    if (prevTs && entry.timestamp < prevTs) {
      return { valid: false, error: `Timestamp regression for actor ${actorId} at index ${i}` };
    }
    actorTimestamps.set(actorId, entry.timestamp);
  }

  return { valid: true };
}

// --- Quick helpers for README ---
export const BotLog = {
  generateKeypair,
  publicKeyToBase64,
  getCurrentTimestamp,
  BotLogEntry,
  verifyChain,
};
