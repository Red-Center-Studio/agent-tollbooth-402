import { describe, expect, it, vi } from 'vitest';
import { createSandboxX402Header, withTollbooth } from '../src/index.js';

const PAY_TO = '0x209693Bc6afc0C5328bA36FaF03C514EF312287C';
const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() } as unknown as ExecutionContext;

function mcpWorker() {
  const handler = vi.fn(async () => Response.json({ jsonrpc: '2.0', id: 1, result: {} }));
  const worker = withTollbooth(
    {
      payTo: PAY_TO,
      mode: 'sandbox',
      routes: [
        {
          pattern: '/mcp',
          method: 'POST',
          priceUsd: 0.05, // tools not listed below
          mcpToolPricesUsd: { search: 0.001, analyze: '$0.02', ping: 0 },
        },
      ],
    },
    { fetch: handler },
  );
  return { worker, handler };
}

const rpc = (body: unknown, headers: Record<string, string> = {}) =>
  new Request('https://api.example.com/mcp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });

const priceOf = async (res: Response) => {
  const body = (await res.json()) as { priceMicros?: number };
  return body.priceMicros;
};

describe('MCP per-tool pricing (mcpToolPricesUsd)', () => {
  it('lets the handshake, discovery and free tools through without payment', async () => {
    const { worker, handler } = mcpWorker();
    for (const body of [
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
      { jsonrpc: '2.0', method: 'notifications/initialized' },
      { jsonrpc: '2.0', id: 2, method: 'tools/list' },
      { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'ping', arguments: {} } },
    ]) {
      const res = await worker.fetch(rpc(body), {}, ctx);
      expect(res.status, JSON.stringify(body)).toBe(200);
    }
    expect(handler).toHaveBeenCalledTimes(4);
  });

  it('charges each tool its own price, and unlisted tools the route price', async () => {
    const { worker, handler } = mcpWorker();
    const call = (name: string) => rpc({ jsonrpc: '2.0', id: 9, method: 'tools/call', params: { name, arguments: {} } });
    const search = await worker.fetch(call('search'), {}, ctx);
    expect(search.status).toBe(402);
    expect(await priceOf(search)).toBe(1_000);
    const analyze = await worker.fetch(call('analyze'), {}, ctx);
    expect(await priceOf(analyze)).toBe(20_000);
    const other = await worker.fetch(call('export_everything'), {}, ctx);
    expect(await priceOf(other)).toBe(50_000);
    expect(handler).not.toHaveBeenCalled();
  });

  it('accepts a payment for the tool price and still reaches the handler with the body intact', async () => {
    const { worker, handler } = mcpWorker();
    const body = { jsonrpc: '2.0', id: 9, method: 'tools/call', params: { name: 'search', arguments: { q: 'x' } } };
    const paid = await worker.fetch(
      rpc(body, { 'PAYMENT-SIGNATURE': createSandboxX402Header({ priceUsd: 0.001, payTo: PAY_TO }) }),
      {},
      ctx,
    );
    expect(paid.status).toBe(200);
    expect(handler).toHaveBeenCalledTimes(1);
    const received = (handler.mock.calls[0] as unknown as [Request])[0];
    expect(await received.json()).toEqual(body);
  });

  it('does not let a cheap payment cover an expensive tool', async () => {
    const { worker, handler } = mcpWorker();
    const res = await worker.fetch(
      rpc(
        { jsonrpc: '2.0', id: 9, method: 'tools/call', params: { name: 'analyze', arguments: {} } },
        { 'PAYMENT-SIGNATURE': createSandboxX402Header({ priceUsd: 0.001, payTo: PAY_TO }) },
      ),
      {},
      ctx,
    );
    expect(res.status).toBe(402);
    expect(handler).not.toHaveBeenCalled();
  });

  it('fails closed: unreadable bodies, nameless calls and batches pay the full or summed price', async () => {
    const { worker, handler } = mcpWorker();
    expect(await priceOf(await worker.fetch(rpc('not json'), {}, ctx))).toBe(50_000);
    expect(
      await priceOf(await worker.fetch(rpc({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: {} }), {}, ctx)),
    ).toBe(50_000);
    const batch = [
      { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'search' } },
      { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'analyze' } },
      { jsonrpc: '2.0', id: 3, method: 'tools/list' },
    ];
    expect(await priceOf(await worker.fetch(rpc(batch), {}, ctx))).toBe(21_000);
    expect(handler).not.toHaveBeenCalled();
  });

  it('refuses an invalid tool price instead of serving the tool for free', async () => {
    const worker = withTollbooth(
      { payTo: PAY_TO, mode: 'sandbox', routes: [{ pattern: '/mcp', mcpToolPricesUsd: { bad: 'abc' } }] },
      { fetch: async () => new Response('ok') },
    );
    await expect(worker.fetch(rpc({ jsonrpc: '2.0', id: 1, method: 'tools/list' }), {}, ctx)).rejects.toThrow();
  });
});
