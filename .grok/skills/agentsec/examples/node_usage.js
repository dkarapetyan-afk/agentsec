#!/usr/bin/env node
// Run: agentsec run --clean-env --only API_KEY,DATA_DIR -- node examples/node_usage.js
const apiKey = process.env.API_KEY;
const dataDir = process.env.DATA_DIR || './data';
if (!apiKey) throw new Error('API_KEY is missing');
console.log('Required credential is available; storage location resolved.');
// Use apiKey and dataDir in the operation requiring them. Do not print either value.
