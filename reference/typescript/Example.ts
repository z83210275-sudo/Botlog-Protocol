/**
 * Demo - 3 entry chain like Python reference
 */
import { BotLogEntry, generateKeypair, publicKeyToBase64, verifyChain, getCurrentTimestamp } from './botlog.js';

async function main() {
  console.log('🚀 BotLog TypeScript Validator Demo - Tier 1 $500 Bounty\n');

  const { privateKey, publicKey } = await generateKeypair();
  const pubKeyB64 = publicKeyToBase64(publicKey);
  console.log('Generated keypair:', pubKeyB64.slice(0, 20) + '...');

  const entry1 = new BotLogEntry({
    version: '1.0',
    timestamp: getCurrentTimestamp(),
    actor: { type: 'human', id: 'KullAxel', public_key: pubKeyB64 },
    action: { type: 'propose', description: 'Launch BotLog feedback campaign', payload: {} },
    previous_hash: null,
  });
  await entry1.sign(privateKey);
  console.log('Entry 1 hash:', entry1.log_hash?.slice(0, 16) + '...');

  await new Promise(r => setTimeout(r, 10));

  const entry2 = new BotLogEntry({
    version: '1.0',
    timestamp: getCurrentTimestamp(),
    actor: { type: 'human', id: 'KullAxel', public_key: pubKeyB64 },
    action: { type: 'commit', description: 'Commit to delivery', payload: {} },
    previous_hash: entry1.log_hash,
  });
  await entry2.sign(privateKey);
  console.log('Entry 2 hash:', entry2.log_hash?.slice(0, 16) + '...');

  await new Promise(r => setTimeout(r, 10));

  const entry3 = new BotLogEntry({
    version: '1.0',
    timestamp: getCurrentTimestamp(),
    actor: { type: 'ai', id: 'ClaudeBot', public_key: pubKeyB64 },
    action: { type: 'execute', description: 'Executed TypeScript validator', payload: { lang: 'typescript' } },
    previous_hash: entry2.log_hash,
  });
  await entry3.sign(privateKey);
  console.log('Entry 3 hash:', entry3.log_hash?.slice(0, 16) + '...');

  const chain = [entry1.toJSON(), entry2.toJSON(), entry3.toJSON()];
  const result = await verifyChain(chain);
  console.log('\n✅ Chain verification:', result.valid ? 'PASSED' : 'FAILED', result.error || '');
  
  if (result.valid) {
    console.log('\n🎉 SUCCESS - Ready to claim $500 bounty!');
    console.log('Files: reference/typescript/botlog.ts');
  }
}

main();
