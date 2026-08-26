import { BotLogEntry, generate_keypair, public_key_to_base64, get_current_timestamp, verify_chain } from './botlog';

export class BotLogAgent {
  private sk: Uint8Array;
  private pk: string;
  chain: any[] = [];
  id: string;
  constructor(id: string) {
    const [sk, pk] = generate_keypair();
    this.sk = sk;
    this.pk = public_key_to_base64(pk);
    this.id = id;
  }
  log(type: string, desc: string, payload: any = {}) {
    const prev = this.chain.length ? this.chain[this.chain.length-1].log_hash : null;
    const e = new BotLogEntry({
      timestamp: get_current_timestamp(),
      actor: { type: 'ai', id: this.id, public_key: this.pk },
      action: { type, description: desc, payload },
      previous_hash: prev
    });
    e.sign(this.sk);
    this.chain.push(e);
    return e;
  }
  verifyAll() { return verify_chain(this.chain); }
}
