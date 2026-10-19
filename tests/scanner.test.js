// Offline tests for the network layer using a mocked fetch (rate limits, failures, aggregation).
const test = require('node:test');
const assert = require('node:assert/strict');
const S = require('../lib/scanner.js');

const MINT_A = 'So11111111111111111111111111111111111111112';
const MINT_B = 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB';
const MINT_C = '4UAKiJ5pqdaSzUXbGETtjJ8s1HisznLZN2boCfBbNbUT';
const OWNER = '86xCnPeV69n6t3DnyGvkKobf9FdN2H9oiVDdaMpo2MMY';
const NOW = Date.UTC(2026, 9, 18);

const acct = (mint, amount, decimals) => ({ account: { data: { parsed: { info: { mint, tokenAmount: { amount, decimals } } } } } });
const res = (status, body, headers) => ({ status, ok: status >= 200 && status < 300, headers: { get: (k) => (headers || {})[k.toLowerCase()] || null }, json: async () => body });

function mockFetch(handlers) {
  const calls = [];
  const f = async (url, init) => {
    calls.push(url);
    for (const [re, fn] of handlers) if (re.test(url)) return fn(url, init, calls);
    throw new Error('unmocked ' + url);
  };
  f.calls = calls; return f;
}

test('fetchJson retries on 429 then succeeds; gives RATE_LIMIT after retries', async () => {
  let n = 0;
  const f = async () => (++n < 2 ? res(429, {}, { 'retry-after': '0' }) : res(200, { ok: 1 }));
  assert.deepEqual(await S.fetchJson({ fetch: f }, 'https://x', {}, { retries: 2 }), { ok: 1 });
  const g = async () => res(429, {}, { 'retry-after': '0' });
  await assert.rejects(() => S.fetchJson({ fetch: g }, 'https://x', {}, { retries: 1 }), (e) => e.code === 'RATE_LIMIT');
  const h = async () => { throw new TypeError('Failed to fetch'); };
  await assert.rejects(() => S.fetchJson({ fetch: h }, 'https://x', {}, { retries: 0 }), (e) => e.code === 'NETWORK');
  const b = async () => res(403, {});
  await assert.rejects(() => S.fetchJson({ fetch: b }, 'https://x', {}, { retries: 3 }), (e) => e.code === 'BLOCKED');
});

test('solana scan: aggregates accounts, hides zero balances, classifies', async () => {
  const f = mockFetch([
    [/solana\.com/, async (u, init) => {
      const b = JSON.parse(init.body);
      if (b.params[1].programId.startsWith('Tokenkeg')) return res(200, { result: { value: [acct(MINT_A, '1500000000', 9), acct(MINT_A, '500000000', 9), acct(MINT_B, '0', 6), acct(MINT_C, '42000000', 6)] } });
      return res(200, { result: { value: [] } });
    }],
    [/lite-api\.jup\.ag/, async () => res(200, [{ id: MINT_A, name: 'Wrapped SOL', symbol: 'SOL', isVerified: true, tags: ['verified'] }])],
    [/api\.dexscreener\.com/, async () => res(200, [{ chainId: 'solana', baseToken: { address: MINT_C, name: 'Claim Reward Token', symbol: 'GIFT' }, quoteToken: { address: MINT_A, name: 'Wrapped SOL', symbol: 'SOL' }, liquidity: { usd: 80 }, pairCreatedAt: NOW - 3600000 }])]
  ]);
  const r = await S.scanSolana(OWNER, { fetch: f, now: NOW, rpcUrls: ['https://api.mainnet.solana.com'] });
  assert.equal(r.tokens.length, 2);
  assert.equal(r.zeroCount, 1);
  const a = r.tokens.find((t) => t.address === MINT_A), c = r.tokens.find((t) => t.address === MINT_C);
  assert.equal(a.balance, '2'); assert.equal(a.result.category, 'known');
  assert.equal(c.balance, '42'); assert.equal(c.result.category, 'suspicious');
});

test('solana scan: Jupiter holdings API is primary (incl. Token-2022, zero balances hidden)', async () => {
  const hold = (amount, decimals, prog) => [{ account: 'acc', amount, decimals, programId: prog || 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA' }];
  const f = mockFetch([
    [/ultra\/v1\/holdings/, async () => res(200, { amount: '1', tokens: { [MINT_A]: hold('2000000000', 9), [MINT_B]: hold('0', 6), [MINT_C]: hold('7000000', 6, 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb') } })],
    [/lite-api\.jup\.ag\/tokens/, async () => res(200, [{ id: MINT_A, name: 'Wrapped SOL', symbol: 'SOL', isVerified: true, tags: [] }])],
    [/dexscreener/, async () => res(200, [])]
  ]);
  const r = await S.scanSolana(OWNER, { fetch: f, now: NOW });
  assert.equal(r.tokens.length, 2); assert.equal(r.zeroCount, 1);
  assert.equal(r.sources.rpc, 'Jupiter holdings API');
  assert.ok(!f.calls.some((u) => /solana\.com/.test(u)));
});

test('solana scan: falls back to Jupiter when custom RPC fails, and to RPC when Jupiter fails', async () => {
  const f = mockFetch([
    [/ultra\/v1\/holdings/, async () => res(500, {})],
    [/mainnet-beta/, async () => res(403, {})],
    [/api\.mainnet\.solana/, async () => res(200, { result: { value: [] } })]
  ]);
  const r = await S.scanSolana(OWNER, { fetch: f, now: NOW });
  assert.equal(r.tokens.length, 0);
  assert.ok(f.calls.some((u) => /mainnet\.solana/.test(u)));
  assert.match(r.sources.rpc, /mainnet\.solana\.com/);
});

test('solana scan: falls back to second RPC when first is blocked', async () => {
  const f = mockFetch([
    [/ultra\/v1\/holdings/, async () => res(429, {}, { 'retry-after': '0' })],
    [/mainnet-beta/, async () => res(403, {})],
    [/api\.mainnet\.solana/, async () => res(200, { result: { value: [] } })]
  ]);
  const r = await S.scanSolana(OWNER, { fetch: f, now: NOW });
  assert.equal(r.tokens.length, 0);
  assert.ok(f.calls.some((u) => /mainnet\.solana/.test(u)));
});

test('solana scan: all RPCs failing -> readable error', async () => {
  const f = mockFetch([[/solana\.com|jup\.ag/, async () => res(429, {}, { 'retry-after': '0' })]]);
  await assert.rejects(() => S.scanSolana(OWNER, { fetch: f, now: NOW }), (e) => e.code === 'RPC_FAILED' && /rate-limited/.test(e.message));
});

test('solana scan: Jupiter + DexScreener outage -> tokens shown as unknown with warnings', async () => {
  const f = mockFetch([
    [/ultra\/v1\/holdings/, async () => res(200, { tokens: { [MINT_C]: [{ amount: '5', decimals: 0, programId: 'x' }] } })],
    [/jup\.ag/, async () => res(500, {})],
    [/dexscreener/, async () => res(429, {}, { 'retry-after': '0' })]
  ]);
  const r = await S.scanSolana(OWNER, { fetch: f, now: NOW });
  assert.equal(r.tokens[0].result.category, 'unknown');
  assert.ok(r.warnings.length >= 2, r.warnings.join('|'));
});

test('evm scan: one chain failing still returns the other; both failing throws', async () => {
  const row = (addr, name, symbol, value, extra) => ({ value, token_id: null, token: Object.assign({ address_hash: addr, name, symbol, decimals: '18', type: 'ERC-20', reputation: 'ok' }, extra || {}) });
  const SPAM = '0x00000000000000000000000000000000000000aa';
  const GOOD = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
  const addr = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
  const f = mockFetch([
    [/eth\.blockscout/, async () => res(200, [row(GOOD, 'USD Coin', 'USDC', '2500000000000000000', { decimals: '6', exchange_rate: '1' }), row(SPAM, 'Visit usdc-claim.com', 'USDC', '1000000000000000000'), row('0x00000000000000000000000000000000000000bb', 'Empty', 'E', '0')])],
    [/base\.blockscout/, async () => res(403, '<html>')],
    [/zora\.engineering/, async () => res(200, { profile: { coinBalances: { edges: [], pageInfo: { hasNextPage: false, endCursor: null } } } })],
    [/dexscreener/, async () => res(200, [])]
  ]);
  const r = await S.scanEvm(addr, { fetch: f, now: NOW });
  assert.equal(r.tokens.length, 2);
  assert.equal(r.tokens.find((t) => t.address === GOOD).result.category, 'known');
  assert.equal(r.tokens.find((t) => t.address === SPAM).result.category, 'suspicious');
  assert.equal(r.tokens.find((t) => t.address === GOOD).balance, '2,500,000,000,000');
  assert.equal(r.errors.length, 1);
  const f2 = mockFetch([[/blockscout/, async () => res(429, {}, { 'retry-after': '0' })]]);
  await assert.rejects(() => S.scanEvm(addr, { fetch: f2, now: NOW }), (e) => e.code === 'EVM_FAILED');
});

/* Wallet like the one that showed false positives: Zora post coins + one tiny-liquidity token + a bait post coin. */
const WALLET = '0xb022b646724e3db39ec7b725de95b37e2a971a27';
const POST1 = '0x80bbec9baf311794d16fc2172a330b37209bd055';   // "Everything feels heavy today…" (Zora content coin)
const POST2 = '0x18d457819acbfd728d8872b74549865c5e4dd25a';   // bait-word post coin
const POST3 = '0x00000000000000000000000000000000000000c3';   // not in the Zora list (e.g. beyond the paging window)
const WGR = '0xc3c49edB33df49F8d875F326a3b735689730A749';       // Western Gold Reserve, $4.49 liquidity, not a Zora coin
const NAME1 = 'Everything feels heavy today. I know.\n\u200bBut remember: You survive';
const bsRow = (addr, name, symbol, value) => ({ value, token: { address_hash: addr, name, symbol, decimals: '18', type: 'ERC-20', reputation: 'ok' } });
const zoraNode = (addr, name, coinType, creator) => ({ node: { valuation: { marketValueUsd: '0.00' }, coin: { address: addr, name, symbol: name, coinType: coinType || 'CONTENT', chainId: 8453, platformBlocked: false, creatorAddress: creator || WALLET } } });
const baseWalletFetch = (zoraHandler) => mockFetch([
  [/eth\.blockscout/, async () => res(404, {})],
  [/base\.blockscout/, async () => res(200, [
    bsRow(POST1, NAME1, NAME1, '10000000000000000000000000'),
    bsRow(POST2, '\u200b🪂 GET READY FOR AIRDROP', '\u200b🪂 GET READY FOR AIRDROP', '10000000000000000000000000'),
    bsRow(POST3, 'Another long sentence-like post that is not in the Zora list', 'Another long sentence-like post that is not in the Zora list', '10000000000000000000000000'),
    bsRow(WGR, 'Western Gold Reserve', 'WESTERN GOLD RESERVE', '5000000000000000000')])],
  [/zora\.engineering/, zoraHandler],
  [/api\.dexscreener\.com/, async () => res(200, [
    { chainId: 'base', baseToken: { address: WGR, name: 'Western Gold Reserve', symbol: 'WESTERN GOLD RESERVE' }, quoteToken: { address: '0x4200000000000000000000000000000000000006', name: 'WETH', symbol: 'WETH' }, liquidity: { usd: 4.49 }, pairCreatedAt: NOW - 62 * 86400000 }])]
]);

test('evm scan (Base): Zora post coins are recognised via the Zora API (paged) and are not Suspicious', async () => {
  let page = 0; const urls = [];
  const f = baseWalletFetch(async (u) => {
    urls.push(u);
    page++;
    if (page === 1) return res(200, { profile: { coinBalances: { count: 2, edges: [zoraNode(POST1, NAME1)], pageInfo: { hasNextPage: true, endCursor: 'CUR1' } } } });
    return res(200, { profile: { coinBalances: { count: 2, edges: [zoraNode(POST2, '\u200b🪂 GET READY FOR AIRDROP', 'CONTENT', '0x00000000000000000000000000000000000000d4')], pageInfo: { hasNextPage: false, endCursor: null } } } });
  });
  const r = await S.scanEvm(WALLET, { fetch: f, now: NOW });
  assert.equal(urls.length, 2); assert.match(urls[1], /after=CUR1/); assert.match(urls[0], new RegExp('identifier=' + WALLET));
  const by = (a) => r.tokens.find((t) => t.address === a);
  assert.equal(by(POST1).zora.isZoraCoin, true);
  assert.equal(by(POST1).result.category, 'unknown'); assert.equal(by(POST1).result.kind, 'postcoin'); assert.match(by(POST1).result.label, /post coin/i);
  assert.equal(by(POST2).result.category, 'suspicious');                         // bait word 'AIRDROP' still flagged
  assert.equal(by(POST3).zora, null); assert.equal(by(POST3).result.kind, 'postcoin'); assert.match(by(POST3).result.label, /Likely/);   // heuristic fallback
  assert.equal(by(WGR).result.category, 'suspicious'); assert.equal(by(WGR).result.kind, 'airdropspam');    // $4.49 pool, not on any list, unsolicited-looking -> Likely airdrop spam (heuristic)
  assert.ok(!r.warnings.some((w) => /Zora/.test(w)), r.warnings.join('|'));
});

test('evm scan (Base): Zora API down -> scan still works, falls back to name heuristic with a warning', async () => {
  const f = baseWalletFetch(async () => res(500, {}));
  const r = await S.scanEvm(WALLET, { fetch: f, now: NOW });
  const by = (a) => r.tokens.find((t) => t.address === a);
  assert.equal(by(POST1).result.kind, 'postcoin'); assert.equal(by(POST1).result.category, 'unknown'); assert.match(by(POST1).result.label, /Likely/);
  assert.equal(by(POST2).result.category, 'suspicious');
  assert.ok(r.warnings.some((w) => /Zora API/.test(w)), r.warnings.join('|'));
});


/* ---------- token lists, GoPlus, effective liquidity, Coinbase assets ---------- */
const CBBTC = '0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf';
const FAKECB = '0x40faa04e00000000000000000000000000000001';
const SAL = '0x26c69e4924bd0d7d52d680b33616042ee13f621c';
const HONEY = '0x00000000000000000000000000000000000000e5';
const LISTED = '0x00000000000000000000000000000000000000f6';
const listJson = (chainId, addrs) => ({ tokens: addrs.map((a) => ({ chainId, address: a, symbol: 'X' })) });
const gpOk = (addr, rec) => ({ code: 1, result: { [addr.toLowerCase()]: rec } });

test('loadTokenLists: merges lists by chain:address, tolerates a failing list', async () => {
  const f = mockFetch([
    [/tokens\.uniswap\.org/, async () => res(200, listJson(1, [LISTED]))],
    [/optimism\.tokenlist/, async () => res(200, listJson(8453, [CBBTC]))],
    [/coingecko.*base/, async () => res(500, {})],
    [/coingecko/, async () => res(200, listJson(1, [LISTED]))]
  ]);
  const r = await S.loadTokenLists({ fetch: f });
  assert.equal(r.map.get('1:' + LISTED.toLowerCase()).uniswap, true);
  assert.equal(r.map.get('8453:' + CBBTC.toLowerCase()).superchain, true);
  assert.ok(r.failed.length >= 1); assert.equal(r.curatedLoaded, true);
  const none = await S.loadTokenLists({ fetch: mockFetch([[/./, async () => res(500, {})]]) });
  assert.equal(none.loaded.length, 0); assert.equal(none.curatedLoaded, false);
});

test('normalizeGoPlus: reads honeypot, taxes, owner powers; empty input -> null', () => {
  assert.equal(S.normalizeGoPlus(null), null);
  const n = S.normalizeGoPlus({ is_honeypot: '1', buy_tax: '0.05', sell_tax: '0.99', is_mintable: '1', owner_change_balance: '1', is_blacklisted: '0', holder_count: '4510', dex: [{ liquidity: '0.53' }] });
  assert.equal(n.honeypot, true); assert.equal(n.sellTax, 0.99); assert.equal(n.mintable, true);
  assert.equal(n.ownerChangeBalance, true); assert.equal(n.blacklist, false); assert.equal(n.holderCount, 4510); assert.equal(n.poolLiquidityUsd, 0.53);
});

test('goplusLookup: one contract per request, honours budget, stops on rate limit, never throws', async () => {
  const seen = [];
  const f = mockFetch([[/gopluslabs/, async (u) => {
    seen.push(u);
    if (seen.length === 3) return res(200, { code: 4029, message: 'too many requests' });
    const a = u.split('contract_addresses=')[1];
    return res(200, a.endsWith('1') ? { code: 1, result: {} } : gpOk(a, { is_honeypot: '0', buy_tax: '0', sell_tax: '0' }));
  }]]);
  const gate = S.createGoPlusGate({ fetch: f }, { delayMs: 0, maxCalls: 10 });
  const addrs = ['0x' + '0'.repeat(39) + '1', '0x' + '0'.repeat(39) + '2', '0x' + '0'.repeat(39) + '3', '0x' + '0'.repeat(39) + '4'];
  const r = await S.goplusLookup(gate, 8453, addrs, 6);
  assert.equal(seen.length, 3);                                   // stopped at the first refusal
  assert.equal(r.rateLimited, true);
  assert.equal(r.asked.has(addrs[0]), true); assert.equal(r.map.has(addrs[0]), false);   // asked but not indexed
  assert.equal(r.map.has(addrs[1]), true);
  const r2 = await S.goplusLookup(gate, 1, addrs, 6);              // gate is shared: stays stopped
  assert.equal(seen.length, 3); assert.equal(r2.map.size, 0);
  const g3 = S.createGoPlusGate({ fetch: mockFetch([[/./, async () => { throw new Error('reset'); }]]) }, { delayMs: 0 });
  const r3 = await S.goplusLookup(g3, 8453, addrs, 6);
  assert.equal(r3.failed, true);
});

test('goplusLookup: per-chain cap leaves budget for the other chain', async () => {
  let n = 0;
  const f = mockFetch([[/gopluslabs/, async (u) => { n++; return res(200, { code: 1, result: {} }); }]]);
  const gate = S.createGoPlusGate({ fetch: f }, { delayMs: 0, maxCalls: 5 });
  const a = Array.from({ length: 10 }, (_, i) => '0x' + String(i).padStart(40, '0'));
  await S.goplusLookup(gate, 1, a, 3);
  await S.goplusLookup(gate, 8453, a, 3);
  assert.equal(n, 5);
});

test('evm scan (Base): Coinbase assets by exact address, fake Coinbase token, listed token, honeypot, airdrop spam, hollow pool', async () => {
  const OWN = '0x1111111111111111111111111111111111111111';
  const HOLLOW = '0x00000000000000000000000000000000000000a7';
  const WETH = '0x4200000000000000000000000000000000000006';
  const dexPair = (addr, name, symbol, o) => Object.assign({ chainId: 'base', baseToken: { address: addr, name, symbol }, quoteToken: { address: WETH, name: 'WETH', symbol: 'WETH' }, priceUsd: '1', liquidity: { usd: 500000, base: 250000, quote: 100 }, volume: { h24: 5000 }, txns: { h24: { buys: 30, sells: 30 } }, fdv: 5e6, pairCreatedAt: NOW - 200 * 86400000 }, o || {});
  const f = mockFetch([
    [/eth\.blockscout/, async () => res(404, {})],
    [/base\.blockscout/, async () => res(200, [
      bsRow(CBBTC, 'Coinbase Wrapped BTC', 'cbBTC', '100000000'),
      bsRow(FAKECB, 'Coinbase Wrappped BTC', 'cbBTC', '100000000'),
      bsRow(LISTED, 'Listed Token', 'LST', '1000000000000000000'),
      bsRow(HONEY, 'Sweet Honey', 'HNY', '1000000000000000000'),
      bsRow(SAL, 'SALUKI', 'SALUKI', '25000000000000000000'),
      bsRow(HOLLOW, 'Reserve Fund', 'RSV', '1000000000000000000')])],
    [/zora\.engineering/, async () => res(200, { profile: { coinBalances: { edges: [], pageInfo: { hasNextPage: false, endCursor: null } } } })],
    [/tokens\.uniswap\.org/, async () => res(200, listJson(1, []))],
    [/optimism\.tokenlist/, async () => res(200, listJson(8453, [LISTED]))],
    [/coingecko/, async () => res(200, listJson(8453, [SAL]))],
    [/api\.dexscreener\.com/, async () => res(200, [
      dexPair(CBBTC, 'Coinbase Wrapped BTC', 'cbBTC'),
      dexPair(LISTED, 'Listed Token', 'LST'),
      dexPair(HONEY, 'Sweet Honey', 'HNY', { liquidity: { usd: 60000, base: 1, quote: 20 }, pairCreatedAt: NOW - 60 * 86400000 }),
      dexPair(HOLLOW, 'Reserve Fund', 'RSV', { liquidity: { usd: 900000, base: 900000, quote: 0.01 }, volume: { h24: 0 }, txns: { h24: { buys: 0, sells: 0 } } })])],
    [/gopluslabs/, async (u) => {
      const a = u.split('contract_addresses=')[1];
      if (a === HONEY.toLowerCase()) return res(200, gpOk(HONEY, { is_honeypot: '1', sell_tax: '1', buy_tax: '0.1' }));
      return res(200, { code: 1, result: {} });
    }]
  ]);
  const r = await S.scanEvm(OWN, { fetch: f, now: NOW, goplusDelayMs: 0 });
  const by = (a) => r.tokens.find((t) => t.address.toLowerCase() === a.toLowerCase());
  assert.equal(by(CBBTC).result.category, 'known'); assert.equal(by(CBBTC).result.kind, 'coinbase');
  assert.equal(by(FAKECB).result.category, 'suspicious'); assert.match(by(FAKECB).result.reasons.join(' '), /0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf/i);
  assert.equal(by(LISTED).result.category, 'known');
  assert.equal(by(HONEY).result.category, 'suspicious'); assert.match(by(HONEY).result.reasons.join(' '), /honeypot|cannot be sold|can't be sold|sell/i);
  assert.equal(by(SAL).result.category, 'suspicious'); assert.equal(by(SAL).result.kind, 'airdropspam');
  assert.equal(by(HOLLOW).result.category, 'suspicious'); assert.equal(by(HOLLOW).result.hollowPool, true);
  for (const t of r.tokens) { assert.ok(t.result.summary, t.symbol + ' has no summary'); assert.ok(Array.isArray(t.result.evidence)); }
});

test('evm scan: GoPlus rate-limited -> scan still completes, token marked unavailable, warning shown', async () => {
  const f = mockFetch([
    [/eth\.blockscout/, async () => res(200, [{ value: '1000000000000000000', token: { address_hash: SAL, name: 'CREDITS', symbol: 'CREDITS', decimals: '18', type: 'ERC-20', reputation: 'ok', holders_count: '4510' } }])],
    [/base\.blockscout/, async () => res(404, {})],
    [/zora\.engineering/, async () => res(200, { profile: { coinBalances: { edges: [], pageInfo: { hasNextPage: false } } } })],
    [/api\.dexscreener\.com/, async () => res(200, [])],
    [/gopluslabs/, async () => res(200, { code: 4029, message: 'too many requests' })],
    [/./, async () => res(500, {})]
  ]);
  const r = await S.scanEvm('0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045', { fetch: f, now: NOW, goplusDelayMs: 0 });
  assert.equal(r.tokens[0].result.category, 'suspicious'); assert.equal(r.tokens[0].result.kind, 'airdropspam');
  assert.ok(r.warnings.some((w) => /GoPlus/.test(w)), r.warnings.join('|'));
});

test('dexLookup: effective liquidity discounts the token-side of a hollow pool; volume and FDV captured', async () => {
  const A = '0x00000000000000000000000000000000000000a8';
  const f = mockFetch([[/dexscreener/, async () => res(200, [{ chainId: 'base', baseToken: { address: A, name: 'N', symbol: 'N' }, quoteToken: { address: '0x4200000000000000000000000000000000000006', symbol: 'WETH' }, priceUsd: '2', liquidity: { usd: 1000000, base: 499999, quote: 0.1 }, volume: { h24: 12 }, txns: { h24: { buys: 1, sells: 0 } }, fdv: 3e6, pairCreatedAt: NOW - 86400000 }])]]);
  const r = await S.dexLookup({ fetch: f }, 'base', [A], NOW);
  const d = r.result.get(A.toLowerCase());
  assert.ok(d.totalLiquidityUsd >= 1000000 - 1); assert.ok(d.effectiveLiquidityUsd < 5000);
  assert.equal(d.volume24Usd, 12); assert.equal(d.fdvUsd, 3e6);
});

test('formatUnits', () => {
  assert.equal(S.formatUnits(123456789n, 6), '123.4567');
  assert.equal(S.formatUnits(5n, 0), '5');
  assert.equal(S.formatUnits(1n, 9), '0.0000');
  assert.equal(S.formatUnits(1000000000000000000000n, 18), '1,000');
});
