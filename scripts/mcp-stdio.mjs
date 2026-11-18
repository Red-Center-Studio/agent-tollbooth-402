#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import readline from 'node:readline';

const REMOTE_MCP_URL = process.env.TOLLBOOTH_MCP_URL ?? 'https://tollbooth.redcenterstudio.com/mcp';
const TOOLS = JSON.parse(
  readFileSync(new URL('../packages/clearinghouse-worker/mcp-tools.json', import.meta.url), 'utf8'),
);

function send(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

function localPricingQuote(args) {
  const priceMicros = Number(args?.priceMicros);
  const callsPerMonth = Number(args?.callsPerMonth);
  if (!Number.isSafeInteger(priceMicros) || priceMicros <= 0 || !Number.isSafeInteger(callsPerMonth) || callsPerMonth <= 0) {
    return { error: 'priceMicros and callsPerMonth must be positive safe integers' };
  }
  const gross = priceMicros * callsPerMonth;
  const calc = (bps) => {
    const fee = Math.round((gross * bps) / 10_000);
    return { feeBps: bps, platformFeeMicros: fee, developerNetMicros: gross - fee };
  };
  return {
    monthlyGrossMicros: gross,
    freeByoX402: calc(0),
    hybrid7Percent: calc(700),
    proPass3Percent: calc(300),
  };
}

async function forwardRemoteRpc(rpc) {
  const res = await fetch(REMOTE_MCP_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(rpc),
  });
  return res.json();
}

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });

rl.on('line', async (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;

  let rpc;
  try {
    rpc = JSON.parse(trimmed);
  } catch {
    send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }

  const { id, method, params } = rpc;
  if (method === 'notifications/initialized' || method === 'notifications/cancelled' || id === undefined) {
    return;
  }

  if (method === 'initialize') {
    const requestedVersion = typeof params?.protocolVersion === 'string' ? params.protocolVersion : '2024-11-05';
    send({
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: requestedVersion,
        capabilities: {
          tools: { listChanged: false },
          resources: { listChanged: false },
          prompts: { listChanged: false },
        },
        serverInfo: {
          name: 'agent-tollbooth-402',
          version: '1.0.0',
        },
      },
    });
    return;
  }

  if (method === 'ping') {
    send({ jsonrpc: '2.0', id, result: {} });
    return;
  }

  if (method === 'tools/list') {
    send({ jsonrpc: '2.0', id, result: { tools: TOOLS } });
    return;
  }

  if (method === 'resources/list') {
    send({ jsonrpc: '2.0', id, result: { resources: [] } });
    return;
  }

  if (method === 'resources/templates/list') {
    send({ jsonrpc: '2.0', id, result: { resourceTemplates: [] } });
    return;
  }

  if (method === 'prompts/list') {
    send({ jsonrpc: '2.0', id, result: { prompts: [] } });
    return;
  }

  if (method === 'tools/call') {
    try {
      const remote = await forwardRemoteRpc(rpc);
      send({ jsonrpc: '2.0', id, ...(remote.error ? { error: remote.error } : { result: remote.result }) });
    } catch (err) {
      if (params?.name === 'tollbooth_pricing_quote') {
        const quote = localPricingQuote(params.arguments);
        if (quote.error) {
          send({ jsonrpc: '2.0', id, error: { code: -32602, message: quote.error } });
        } else {
          send({
            jsonrpc: '2.0',
            id,
            result: { content: [{ type: 'text', text: JSON.stringify(quote) }], structuredContent: quote },
          });
        }
        return;
      }
      send({
        jsonrpc: '2.0',
        id,
        error: { code: -32000, message: `Remote clearinghouse unreachable: ${err instanceof Error ? err.message : String(err)}` },
      });
    }
    return;
  }

  send({ jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } });
});
