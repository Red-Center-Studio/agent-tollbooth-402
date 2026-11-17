import {
  createSandboxReceipt,
  createSandboxX402Header,
  decodePaymentHeader,
  withTollbooth,
} from '../packages/edge-middleware/dist/index.js';

async function runSandboxSmokeTest() {
  const rows = [];

  const gatedWorker = withTollbooth(
    {
      priceUsd: 0.01,
      mode: 'sandbox',
    },
    async (req) => {
      return Response.json({
        ok: true,
        path: new URL(req.url).pathname,
        message: 'Paid resource unlocked in zero-config sandbox mode',
      });
    },
  );

  // 1. Unpaid JSON request -> [402 CHALLENGE]
  const unpaid = await gatedWorker.fetch(
    new Request('https://sandbox.local/api/v1/lookup', {
      headers: { Accept: 'application/json' },
    }),
  );
  const unpaidJson = await unpaid.json();
  const decodedReq = decodePaymentHeader(unpaid.headers.get('PAYMENT-REQUIRED') ?? '');
  rows.push({
    step: '1. Unpaid JSON request',
    status: unpaid.status === 402 && decodedReq.x402Version === 2 ? '[402 CHALLENGE]' : '[ACTION NEEDED]',
    details: `HTTP ${unpaid.status} | code=${unpaidJson.code} | price=$${unpaidJson.priceUsd} | hint="${unpaidJson.fix_hint}"`,
  });

  // 2. Browser HTML request -> [PASS] Industrial Charcoal/Amber/Emerald Checkout Card
  const browserRes = await gatedWorker.fetch(
    new Request('https://sandbox.local/api/v1/lookup', {
      headers: { Accept: 'text/html' },
    }),
  );
  const html = await browserRes.text();
  const htmlOk =
    browserRes.status === 402 &&
    (browserRes.headers.get('Content-Type') ?? '').includes('text/html') &&
    html.includes('#1F2937') &&
    html.includes('#D97706') &&
    html.includes('#10B981');
  rows.push({
    step: '2. Browser HTML 402 Card',
    status: htmlOk ? '[PASS]' : '[ACTION NEEDED]',
    details: `HTTP ${browserRes.status} | Content-Type=${browserRes.headers.get('Content-Type')}`,
  });

  // 3. Rail B Sandbox Receipt retry -> [200 SETTLED]
  const receipt = await createSandboxReceipt({ priceUsd: 0.01 });
  const paidRailB = await gatedWorker.fetch(
    new Request('https://sandbox.local/api/v1/lookup', {
      headers: { Authorization: `Bearer ${receipt}` },
    }),
  );
  const payResB = decodePaymentHeader(paidRailB.headers.get('PAYMENT-RESPONSE') ?? '');
  rows.push({
    step: '3. Rail B Fiat Receipt',
    status: paidRailB.status === 200 && payResB.success ? '[200 SETTLED]' : '[ACTION NEEDED]',
    details: `HTTP ${paidRailB.status} | rail=${paidRailB.headers.get('X-Tollbooth-Rail')} | tx=${payResB.transaction}`,
  });

  // 4. Nonce replay rejection -> [PASS]
  const replay = await gatedWorker.fetch(
    new Request('https://sandbox.local/api/v1/lookup', {
      headers: { Authorization: `Bearer ${receipt}` },
    }),
  );
  const replayJson = await replay.json();
  rows.push({
    step: '4. Nonce Replay Guard',
    status: replay.status === 402 && replayJson.code === 'NONCE_REPLAYED' ? '[PASS]' : '[ACTION NEEDED]',
    details: `HTTP ${replay.status} | code=${replayJson.code} | hint="${replayJson.fix_hint}"`,
  });

  // 5. Rail A Sandbox x402 V2 signature -> [200 SETTLED]
  const x402Sig = createSandboxX402Header({ priceUsd: 0.01 });
  const paidRailA = await gatedWorker.fetch(
    new Request('https://sandbox.local/api/v1/lookup', {
      headers: { 'PAYMENT-SIGNATURE': x402Sig },
    }),
  );
  const payResA = decodePaymentHeader(paidRailA.headers.get('PAYMENT-RESPONSE') ?? '');
  rows.push({
    step: '5. Rail A x402 V2 Flow',
    status: paidRailA.status === 200 && payResA.success ? '[200 SETTLED]' : '[ACTION NEEDED]',
    details: `HTTP ${paidRailA.status} | rail=${paidRailA.headers.get('X-Tollbooth-Rail')} | tx=${payResA.transaction}`,
  });

  console.log('\n| Step | Status | Details |');
  console.log('| :--- | :--- | :--- |');
  for (const r of rows) {
    console.log(`| ${r.step} | ${r.status} | ${r.details} |`);
  }

  const failed = rows.some((r) => r.status === '[ACTION NEEDED]');
  if (failed) {
    process.exit(1);
  }
}

runSandboxSmokeTest().catch((err) => {
  console.error(err);
  process.exit(1);
});
