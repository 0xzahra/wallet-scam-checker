/* Wallet Scam-Token Checker — network layer (read-only, keyless public APIs).
 * Works in browser (window.WSCScan) and Node 18+ (module.exports) with an injectable fetch.
 * Sends ONLY public addresses / token mints to public APIs. */
(function (root, factory) {
  const api = factory(typeof module === 'object' && module.exports ? require('./core.js') : root.WSC);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.WSCScan = api;
})(typeof self !== 'undefined' ? self : this, function (core) {
  'use strict';

  const SOLANA_RPCS = ['https://api.mainnet-beta.solana.com', 'https://api.mainnet.solana.com'];
  const TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
  const TOKEN_2022_PROGRAM = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
  const JUP_HOLDINGS = 'https://lite-api.jup.ag/ultra/v1/holdings/';
  const JUP_SEARCH = 'https://lite-api.jup.ag/tokens/v2/search?query=';
  const DEX_TOKENS = 'https://api.dexscreener.com/tokens/v1/';

  const EVM_CHAINS = [
    { id: 'ethereum', label: 'Ethereum', blockscout: 'https://eth.blockscout.com', dexChain: 'ethereum', explorer: 'https://etherscan.io/token/' },
    { id: 'base', label: 'Base', blockscout: 'https://base.blockscout.com', dexChain: 'base', explorer: 'https://basescan.org/token/' }
  ];

  const LIMITS = {
    SOLANA_MAX_MINTS: 400,   // token accounts we will look up
    EVM_MAX_DEX_LOOKUPS: 150, // per chain
    JUP_BATCH: 100,
    DEX_BATCH: 30
  };

  class ScanError extends Error {
    constructor(code, message) { super(message); this.name = 'ScanError'; this.code = code; }
  }

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  /** fetch JSON with timeout + limited retry on 429/5xx/network. Throws ScanError(code: RATE_LIMIT|BLOCKED|HTTP|NETWORK|TIMEOUT|BAD_RESPONSE). */
  async function fetchJson(ctx, url, init, opts) {
    const retries = (opts && opts.retries != null) ? opts.retries : 2;
    const timeoutMs = (opts && opts.timeoutMs) || 20000;
    let lastErr;
    for (let attempt = 0; attempt <= retries; attempt++) {
      const ac = typeof AbortController !== 'undefined' ? new AbortController() : null;
      const timer = ac ? setTimeout(() => ac.abort(), timeoutMs) : null;
      try {
        const res = await ctx.fetch(url, Object.assign({}, init || {}, ac ? { signal: ac.signal } : {}));
        if (timer) clearTimeout(timer);
        if (res.status === 429) {
          const ra = parseInt(res.headers && res.headers.get && res.headers.get('retry-after'), 10);
          lastErr = new ScanError('RATE_LIMIT', 'Rate limited (HTTP 429)');
          if (attempt < retries) { await sleep(Math.min((ra > 0 ? ra * 1000 : 1200 * (attempt + 1)), 5000)); continue; }
          throw lastErr;
        }
        if (res.status === 403) throw new ScanError('BLOCKED', 'Access refused (HTTP 403)');
        if (res.status === 404) throw new ScanError('NOT_FOUND', 'Not found (HTTP 404)');
        if (res.status >= 500) {
          lastErr = new ScanError('HTTP', 'Server error (HTTP ' + res.status + ')');
          if (attempt < retries) { await sleep(800 * (attempt + 1)); continue; }
          throw lastErr;
        }
        if (!res.ok) throw new ScanError('HTTP', 'HTTP ' + res.status);
        try { return await res.json(); } catch (e) { throw new ScanError('BAD_RESPONSE', 'Unreadable response'); }
      } catch (e) {
        if (timer) clearTimeout(timer);
        if (e instanceof ScanError) {
          if (['BLOCKED', 'NOT_FOUND', 'BAD_RESPONSE'].includes(e.code) || attempt >= retries) throw e;
          lastErr = e;
        } else {
          const isAbort = e && (e.name === 'AbortError');
          lastErr = new ScanError(isAbort ? 'TIMEOUT' : 'NETWORK', isAbort ? 'Request timed out' : 'Network error (blocked, offline or CORS)');
          if (attempt >= retries) throw lastErr;
          await sleep(600 * (attempt + 1));
        }
      }
    }
    throw lastErr || new ScanError('NETWORK', 'Network error');
  }

  async function mapLimit(items, limit, fn) {
    const results = new Array(items.length);
    let i = 0;
    const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (true) {
        const idx = i++;
        if (idx >= items.length) return;
        results[idx] = await fn(items[idx], idx);
      }
    });
    await Promise.all(workers);
    return results;
  }

  const chunk = (arr, n) => { const out = []; for (let i = 0; i < arr.length; i += n) out.push(arr.slice(i, i + n)); return out; };

  function errText(e) {
    if (!e) return 'unknown error';
    if (e.code === 'RATE_LIMIT') return 'rate limited — try again in a minute';
    if (e.code === 'BLOCKED') return 'service refused the request (HTTP 403)';
    if (e.code === 'TIMEOUT') return 'timed out';
    if (e.code === 'NETWORK') return 'network error';
    return e.message || 'error';
  }

  /* ------------------------------------------------------------------ */
  /* DexScreener aggregation (shared by Solana + EVM)                    */
  /* ------------------------------------------------------------------ */
  /** Fetch pairs for a batch of token addresses on one DexScreener chain; returns Map(lowercase address -> aggregate). */
  async function dexLookup(ctx, dexChain, addresses) {
    const result = new Map();
    const batches = chunk(addresses, LIMITS.DEX_BATCH);
    const failures = [];
    await mapLimit(batches, 3, async (batch) => {
      let pairs;
      try {
        pairs = await fetchJson(ctx, DEX_TOKENS + dexChain + '/' + batch.join(','), { headers: { accept: 'application/json' } });
      } catch (e) {
        failures.push({ batch, err: e });
        return;
      }
      if (!Array.isArray(pairs)) { failures.push({ batch, err: new ScanError('BAD_RESPONSE', 'Unexpected DexScreener response') }); return; }
      const want = new Set(batch.map((a) => a.toLowerCase()));
      for (const a of batch) result.set(a.toLowerCase(), { checked: true, pairCount: 0, totalLiquidityUsd: 0, maxLiquidityUsd: 0, oldestPairMs: null, name: null, symbol: null });
      for (const p of pairs) {
        if (!p || p.chainId !== dexChain) continue;
        for (const side of [p.baseToken, p.quoteToken]) {
          if (!side || !side.address) continue;
          const key = side.address.toLowerCase();
          if (!want.has(key)) continue;
          const agg = result.get(key);
          agg.pairCount++;
          const l = p.liquidity && Number(p.liquidity.usd);
          if (isFinite(l)) { agg.totalLiquidityUsd += l; agg.maxLiquidityUsd = Math.max(agg.maxLiquidityUsd, l); }
          if (p.pairCreatedAt && (agg.oldestPairMs == null || p.pairCreatedAt < agg.oldestPairMs)) agg.oldestPairMs = p.pairCreatedAt;
          if (!agg.name && side.name) { agg.name = side.name; agg.symbol = side.symbol; }
        }
      }
    });
    return { result, failures };
  }

  /* ------------------------------------------------------------------ */
  /* Solana                                                              */
  /* ------------------------------------------------------------------ */
  async function solRpc(ctx, rpcUrl, method, params) {
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method, params });
    const json = await fetchJson(ctx, rpcUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body }, { retries: 1 });
    if (json && json.error) {
      const msg = String(json.error.message || 'RPC error');
      if (/too many|rate|limit|429/i.test(msg)) throw new ScanError('RATE_LIMIT', msg);
      throw new ScanError('HTTP', 'RPC error: ' + msg.slice(0, 120));
    }
    return json && json.result;
  }

  function addAmounts(map, accounts) {
    for (const acc of accounts || []) {
      const info = acc && acc.account && acc.account.data && acc.account.data.parsed && acc.account.data.parsed.info;
      if (!info || !info.mint || !info.tokenAmount) continue;
      let raw;
      try { raw = BigInt(info.tokenAmount.amount); } catch (e) { continue; }
      const cur = map.get(info.mint) || { mint: info.mint, raw: 0n, decimals: info.tokenAmount.decimals, accounts: 0 };
      cur.raw += raw; cur.accounts++;
      map.set(info.mint, cur);
    }
  }

  function formatUnits(raw, decimals) {
    decimals = Number(decimals) || 0;
    const neg = raw < 0n; if (neg) raw = -raw;
    let s = raw.toString().padStart(decimals + 1, '0');
    let int = s.slice(0, s.length - decimals);
    let frac = decimals ? s.slice(-decimals).replace(/0+$/, '') : '';
    int = int.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    if (frac.length > 4) frac = frac.slice(0, 4);
    return (neg ? '-' : '') + int + (frac ? '.' + frac : '');
  }

  async function scanSolana(address, options) {
    options = options || {};
    const ctx = { fetch: options.fetch || globalThis.fetch.bind(globalThis) };
    const progress = options.onProgress || (() => {});
    const rpcs = (options.rpcUrls && options.rpcUrls.length ? options.rpcUrls : SOLANA_RPCS);
    const warnings = [];
    const now = options.now || Date.now();

    progress('Reading token balances…');
    const amounts = new Map();
    let source = null; const srcErrors = [];

    const viaRpc = async (rpc) => {
      const first = await solRpc(ctx, rpc, 'getTokenAccountsByOwner', [address, { programId: TOKEN_PROGRAM }, { encoding: 'jsonParsed' }]);
      addAmounts(amounts, first && first.value);
      try {
        const second = await solRpc(ctx, rpc, 'getTokenAccountsByOwner', [address, { programId: TOKEN_2022_PROGRAM }, { encoding: 'jsonParsed' }]);
        addAmounts(amounts, second && second.value);
      } catch (e) {
        warnings.push('Could not read Token-2022 accounts (' + errText(e) + '). Results may be missing some tokens.');
      }
    };
    const viaJupiter = async () => {
      const json = await fetchJson(ctx, JUP_HOLDINGS + address, { headers: { accept: 'application/json' } }, { retries: 1, timeoutMs: 30000 });
      if (!json || typeof json.tokens !== 'object') throw new ScanError('BAD_RESPONSE', 'Unexpected holdings response');
      for (const [mint, accs] of Object.entries(json.tokens)) {
        for (const a of Array.isArray(accs) ? accs : []) {
          let raw; try { raw = BigInt(a.amount); } catch (e) { continue; }
          const cur = amounts.get(mint) || { mint, raw: 0n, decimals: a.decimals, accounts: 0 };
          cur.raw += raw; cur.accounts++; amounts.set(mint, cur);
        }
      }
    };

    // Order: user's custom RPC (if given) -> Jupiter holdings API (browser-friendly, keyless) -> public Solana RPCs.
    // NOTE: Solana's public RPC rejects browser requests (HTTP 403) so in a browser it only works as a last resort / with a custom RPC.
    const attempts = [];
    if (options.rpcUrls && options.rpcUrls.length) options.rpcUrls.forEach((u) => attempts.push({ name: 'custom RPC', run: () => viaRpc(u) }));
    attempts.push({ name: 'Jupiter holdings API', run: viaJupiter });
    if (!(options.rpcUrls && options.rpcUrls.length)) rpcs.forEach((u) => attempts.push({ name: u.replace(/^https:\/\//, ''), run: () => viaRpc(u) }));
    for (const at of attempts) {
      try { amounts.clear(); await at.run(); source = at.name; break; } catch (e) { srcErrors.push(at.name + ': ' + errText(e)); }
    }
    if (!source) {
      throw new ScanError('RPC_FAILED', 'Could not read Solana token balances (' + srcErrors.join('; ') + '). Free public endpoints are rate-limited and Solana\'s public RPC blocks browsers — wait a minute and retry, or add your own RPC URL under "Advanced".');
    }
    const rpcUsed = source;

    let holdings = Array.from(amounts.values()).filter((h) => h.raw > 0n);
    const zeroCount = amounts.size - holdings.length;
    let truncated = false;
    if (holdings.length > LIMITS.SOLANA_MAX_MINTS) {
      truncated = true;
      warnings.push('This wallet holds ' + holdings.length + ' tokens; only the first ' + LIMITS.SOLANA_MAX_MINTS + ' were checked.');
      holdings = holdings.slice(0, LIMITS.SOLANA_MAX_MINTS);
    }
    const mints = holdings.map((h) => h.mint);
    if (!mints.length) return { chain: 'solana', address, tokens: [], warnings, zeroCount, truncated, sources: { rpc: rpcUsed } };

    progress('Checking ' + mints.length + ' tokens against Jupiter and DexScreener…');
    const jupMap = new Map();
    let jupFail = 0; let jupErr = null;
    await mapLimit(chunk(mints, LIMITS.JUP_BATCH), 2, async (batch) => {
      try {
        const arr = await fetchJson(ctx, JUP_SEARCH + batch.join(','), { headers: { accept: 'application/json' } });
        const want = new Set(batch);
        for (const t of Array.isArray(arr) ? arr : []) if (t && want.has(t.id)) jupMap.set(t.id, t);
      } catch (e) { jupFail++; jupErr = e; }
    });
    if (jupFail) warnings.push('Jupiter verified-list lookup failed for ' + jupFail + ' batch(es) (' + errText(jupErr) + '). "Verified" status may be incomplete — some known tokens may show as Unknown.');

    const dex = await dexLookup(ctx, 'solana', mints);
    const dexFailedMints = new Set();
    let dexErr = null;
    for (const f of dex.failures) { f.batch.forEach((m) => dexFailedMints.add(m.toLowerCase())); dexErr = f.err; }
    if (dex.failures.length) warnings.push('DexScreener lookup failed for ' + dexFailedMints.size + ' token(s) (' + errText(dexErr) + '). Those are shown as "not checked".');

    const tokens = holdings.map((h) => {
      const j = jupMap.get(h.mint) || null;
      const d = dex.result.get(h.mint.toLowerCase()) || null;
      const dexInfo = d || (dexFailedMints.has(h.mint.toLowerCase()) ? { checked: false, error: errText(dexErr) } : null);
      const name = (j && j.name) || (d && d.name) || null;
      const symbol = (j && j.symbol) || (d && d.symbol) || null;
      const t = {
        chain: 'solana', address: h.mint, name, symbol, decimals: h.decimals,
        nft: h.decimals === 0, type: h.decimals === 0 ? 'NFT-like (0 decimals)' : 'SPL token',
        balance: formatUnits(h.raw, h.decimals), accounts: h.accounts,
        jup: j ? { isVerified: !!j.isVerified, tags: j.tags || [], organicScoreLabel: j.organicScoreLabel, audit: j.audit || null } : null,
        dex: dexInfo
      };
      t.result = core.classifyToken(t, now);
      return t;
    });
    return { chain: 'solana', address, tokens, warnings, zeroCount, truncated, sources: { rpc: rpcUsed, jupiterMatches: jupMap.size } };
  }

  /* ------------------------------------------------------------------ */
  /* EVM (Ethereum + Base via Blockscout, DexScreener for market data)   */
  /* ------------------------------------------------------------------ */
  async function scanEvmChain(address, chain, options) {
    const ctx = { fetch: options.fetch || globalThis.fetch.bind(globalThis) };
    const now = options.now || Date.now();
    const warnings = [];
    let rows;
    try {
      rows = await fetchJson(ctx, chain.blockscout + '/api/v2/addresses/' + address + '/token-balances', { headers: { accept: 'application/json' } }, { retries: 1, timeoutMs: 30000 });
    } catch (e) {
      if (e.code === 'NOT_FOUND') return { chain: chain.id, label: chain.label, address, status: 'ok', tokens: [], warnings: ['No activity found for this address on ' + chain.label + '.'], truncated: false };
      return { chain: chain.id, label: chain.label, address, status: 'error', error: 'Blockscout (' + chain.label + ') ' + errText(e) + '.', tokens: [], warnings: [], truncated: false };
    }
    if (!Array.isArray(rows)) {
      return { chain: chain.id, label: chain.label, address, status: 'error', error: 'Blockscout (' + chain.label + ') returned an unexpected response.', tokens: [], warnings: [], truncated: false };
    }

    // Aggregate by token contract (NFTs return one row per token id).
    const byAddr = new Map();
    for (const r of rows) {
      const t = r && r.token; if (!t || !t.address_hash) continue;
      let val; try { val = BigInt(r.value || '0'); } catch (e) { continue; }
      if (val <= 0n) continue;
      const key = t.address_hash.toLowerCase();
      const cur = byAddr.get(key) || { t, val: 0n, count: 0 };
      cur.val += val; cur.count++;
      byAddr.set(key, cur);
    }
    const all = Array.from(byAddr.values());
    const isErc20 = (x) => (x.t.type || 'ERC-20') === 'ERC-20';
    const candidates = all.filter(isErc20).sort((a, b) => {
      const ra = a.t.exchange_rate ? 1 : 0, rb = b.t.exchange_rate ? 1 : 0;
      if (ra !== rb) return rb - ra;
      return (Number(b.t.holders_count || b.t.holders || 0)) - (Number(a.t.holders_count || a.t.holders || 0));
    });
    let truncated = false;
    const lookups = candidates.slice(0, LIMITS.EVM_MAX_DEX_LOOKUPS);
    if (candidates.length > lookups.length) {
      truncated = true;
      warnings.push(chain.label + ': ' + candidates.length + ' tokens held; market data was checked for the top ' + lookups.length + ' only (the rest are marked "not checked").');
    }
    const dex = await dexLookup(ctx, chain.dexChain, lookups.map((x) => x.t.address_hash));
    const failed = new Set(); let dexErr = null;
    for (const f of dex.failures) { f.batch.forEach((m) => failed.add(m.toLowerCase())); dexErr = f.err; }
    if (failed.size) warnings.push(chain.label + ': DexScreener lookup failed for ' + failed.size + ' token(s) (' + errText(dexErr) + ').');

    const tokens = all.map((x) => {
      const dec = parseInt(x.t.decimals, 10);
      const key = x.t.address_hash.toLowerCase();
      const d = dex.result.get(key) || null;
      const dexInfo = d || (failed.has(key) ? { checked: false, error: errText(dexErr) } : null);
      const nftish = !isErc20(x);
      const tok = {
        chain: chain.id, chainLabel: chain.label, address: x.t.address_hash,
        name: x.t.name || (d && d.name) || null, symbol: x.t.symbol || (d && d.symbol) || null,
        decimals: isFinite(dec) ? dec : null, type: x.t.type || 'ERC-20', nft: nftish,
        balance: nftish ? String(x.count) + (x.count === 1 ? ' item' : ' items') : (isFinite(dec) ? formatUnits(x.val, dec) : x.val.toString()),
        bs: { reputation: x.t.reputation, exchangeRate: x.t.exchange_rate, holders: x.t.holders_count || x.t.holders },
        dex: dexInfo, explorer: chain.explorer + x.t.address_hash
      };
      tok.result = core.classifyToken(tok, now);
      return tok;
    });
    return { chain: chain.id, label: chain.label, address, status: 'ok', tokens, warnings, truncated, totalHeld: all.length };
  }

  async function scanEvm(address, options) {
    options = options || {};
    const progress = options.onProgress || (() => {});
    progress('Reading token balances on Ethereum and Base (Blockscout)…');
    const chains = await Promise.all(EVM_CHAINS.map((c) => scanEvmChain(address, c, options)));
    const tokens = chains.flatMap((c) => c.tokens);
    const warnings = chains.flatMap((c) => c.warnings);
    const errors = chains.filter((c) => c.status === 'error').map((c) => c.error);
    if (errors.length === chains.length) {
      throw new ScanError('EVM_FAILED', 'Could not load balances from any chain. ' + errors.join(' ') + ' The free public explorer APIs are rate-limited and sometimes block automated requests — try again shortly.');
    }
    return { chain: 'evm', address, tokens, warnings, chains: chains.map((c) => ({ id: c.chain, label: c.label, status: c.status, error: c.error, count: c.tokens.length })), errors };
  }

  async function scan(kind, address, options) {
    return kind === 'solana' ? scanSolana(address, options) : scanEvm(address, options);
  }

  const explorerFor = (t) => t.chain === 'solana' ? 'https://solscan.io/token/' + t.address : t.explorer;

  return { scan, scanSolana, scanEvm, fetchJson, dexLookup, formatUnits, explorerFor, ScanError, EVM_CHAINS, SOLANA_RPCS, LIMITS };
});
