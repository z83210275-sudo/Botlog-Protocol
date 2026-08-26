# BotLog x LangChain Integration - Tier 2 $1000

LangChain tool that logs every agent action with Ed25519 signatures.

Files:
- botlog-agent.ts - wrapper
- example-agent.ts - demo
- readme-agent.md

Usage:
```ts
import { BotLogAgent } from './botlog-agent';
const agent = new BotLogAgent('my-agent');
agent.log('execute','did work');
```
