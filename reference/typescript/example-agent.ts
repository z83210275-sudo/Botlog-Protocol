import { BotLogAgent } from './botlog-agent';

const agent = new BotLogAgent('langchain-agent-1');
console.log('Proposing...');
agent.log('propose', 'Analyze market', { task: 'analysis' });
console.log('Committing...');
agent.log('commit', 'Commit to task', { hash: '0xabc' });
console.log('Executing...');
agent.log('execute', 'Executed', { result: 'bullish' });
console.log('Chain:', agent.chain.length, 'Verified:', agent.verifyAll());
