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
  const ZORA_BALANCES = 'https://api-sdk.zora.engineering/profileBalances';   // keyless, CORS-enabled; lists a wallet's Zora coins
  const GOPLUS = 'https://api.gopluslabs.io/api/v1/token_security/';          // keyless, CORS-enabled contract security data (rate-limited)
  const TOKEN_LISTS = [                                                       // public token lists (all CORS-enabled); matched by exact contract address
    { id: 'uniswap', kind: 'uniswap', url: 'https://tokens.uniswap.org' },
    { id: 'superchain', kind: 'superchain', url: 'https://static.optimism.io/optimism.tokenlist.json' },
    { id: 'coingecko-base', kind: 'coingecko', url: 'https://tokens.coingecko.com/base/all.json' },
    { id: 'coingecko-ethereum', kind: 'coingecko', url: 'https://tokens.coingecko.com/uniswap/all.json' }
  ];
  const BASE_APP_TOKEN_URI_HOST = 'tba-social.mypinata.cloud';               // metadata host used by Base-app-created Zora posts (inferred from Zora data)

  const EVM_CHAINS = [
    { id: 'ethereum', label: 'Ethereum', blockscout: 'https://eth.blockscout.com', dexChain: 'ethereum', explorer: 'https://etherscan.io/token/' },
    { id: 'base', label: 'Base', blockscout: 'https://base.blockscout.com', dexChain: 'base', explorer: 'https://basescan.org/token/' }
  ];

  const LIMITS = {
    SOLANA_MAX_MINTS: 400,   // token accounts we will look up
    EVM_MAX_DEX_LOOKUPS: 600, // per chain, first pass (30 per request; Zora-looking post coins are looked up last)
    EVM_EXTRA_DEX_LOOKUPS: 400, // second pass after the Zora list is known: remaining non-Zora tokens
    GOPLUS_MAX_CALLS: 12,     // per scan, shared by both chains: GoPlus keyless tier rate-limits after roughly 10 requests/minute
    GOPLUS_PER_CHAIN: 6,      // fair split so the first chain cannot starve the second
    GOPLUS_DELAY_MS: 1300,
    JUP_BATCH: 100,
    DEX_BATCH: 30,
    ZORA_MAX_PAGES: 40,         // Zora returns ~20 coins per page
    ZORA_BUDGET_MS: 45000       // stop paging after this long; anything not covered falls back to the name heuristic
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
      for (const a of batch) result.set(a.toLowerCase(), { checked: true, pairCount: 0, totalLiquidityUsd: 0, maxLiquidityUsd: 0, oldestPairMs: null, name: null, symbol: null, fdvUsd: 0, volume24Usd: 0, txns24: 0, hasActivity: false, effectiveLiquidityUsd: 0 });
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
          // DexScreener's liquidity.usd also counts the token's OWN supply valued at its own price. What you can actually sell into is the
          // quote side (ETH/USDC/…): usd - base*price. A one-sided "pool" with a huge usd figure but almost no quote side is hollow.
          let eff = isFinite(l) ? l : 0;
          if (side === p.baseToken && p.liquidity && isFinite(l) && isFinite(Number(p.liquidity.base)) && isFinite(Number(p.priceUsd))) {
            const quoteSideUsd = Math.max(0, l - Number(p.liquidity.base) * Number(p.priceUsd));
            eff = Math.min(l, 2 * quoteSideUsd);
          }
          agg.effectiveLiquidityUsd = Math.max(agg.effectiveLiquidityUsd, eff);
          const fdv = Number(p.fdv); if (side === p.baseToken && isFinite(fdv)) agg.fdvUsd = Math.max(agg.fdvUsd, fdv);   // FDV is the base token's
          const v24 = p.volume && Number(p.volume.h24); const t24 = p.txns && p.txns.h24;
          if (isFinite(v24) || t24) agg.hasActivity = true;
          if (isFinite(v24)) agg.volume24Usd += v24;
          if (t24) agg.txns24 += (Number(t24.buys) || 0) + (Number(t24.sells) || 0);
          if (!agg.name && side.name) { agg.name = side.name; agg.symbol = side.symbol; }
        }
      }
      for (const a of batch) { const agg = result.get(a.toLowerCase()); if (agg && !agg.hasActivity) { agg.volume24Usd = null; agg.txns24 = null; } }
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
  /* Zora (identifies Zora / Base-app "post coins" so they are not mistaken for scam tokens) */
  /* ------------------------------------------------------------------ */
  /** Was this Zora coin posted from the Base app? Inferred from Zora's own metadata (token URI host / media path). Informational only — never a trust signal. */
  function zoraViaBaseApp(c) {
    try {
      if (c.tokenUri && new URL(c.tokenUri).hostname === BASE_APP_TOKEN_URI_HOST) return true;
      const mu = c.mediaContent && c.mediaContent.originalUri;
      return !!(mu && /\/base-app\//.test(mu));
    } catch (e) { return false; }
  }

  /** Page through the Zora coin balances of a wallet. Returns { map: Map(lowercase address -> info), complete, error? }.
   *  Never throws: on failure returns whatever was collected plus `error`, and the classifier falls back to a name heuristic. */
  async function zoraLookup(ctx, owner, budgetMs) {
    const map = new Map();
    const started = Date.now();
    const budget = budgetMs == null ? LIMITS.ZORA_BUDGET_MS : budgetMs;
    let after = null, pages = 0, complete = false, error = null;
    try {
      while (pages < LIMITS.ZORA_MAX_PAGES) {
        const url = ZORA_BALANCES + '?identifier=' + owner + '&count=20' + (after ? '&after=' + encodeURIComponent(after) : '');
        const json = await fetchJson(ctx, url, { headers: { accept: 'application/json' } }, { retries: 2, timeoutMs: 15000 });
        const cb = json && json.profile && json.profile.coinBalances;
        if (!cb || !Array.isArray(cb.edges)) throw new ScanError('BAD_RESPONSE', 'Unexpected Zora response');
        pages++;
        for (const e of cb.edges) {
          const n = e && e.node, c = n && n.coin;
          if (!c || !c.address || Number(c.chainId || 8453) !== 8453) continue;
          const v = n.valuation && n.valuation.marketValueUsd != null ? Number(n.valuation.marketValueUsd) : null;
          map.set(String(c.address).toLowerCase(), {
            isZoraCoin: true,
            coinType: c.coinType === 'CREATOR' ? 'CREATOR' : 'CONTENT',
            platformBlocked: !!c.platformBlocked,
            valueUsd: v != null && isFinite(v) ? v : null,
            createdByWallet: !!c.creatorAddress && String(c.creatorAddress).toLowerCase() === owner.toLowerCase(),
            creatorHandle: c.creatorProfile && typeof c.creatorProfile.handle === 'string' ? c.creatorProfile.handle.slice(0, 60) : null,
            uniqueHolders: c.uniqueHolders != null && isFinite(Number(c.uniqueHolders)) ? Number(c.uniqueHolders) : null,
            volumeUsd: c.totalVolume != null && isFinite(Number(c.totalVolume)) ? Number(c.totalVolume) : null,
            createdAt: c.createdAt || null,
            viaBaseApp: zoraViaBaseApp(c)
          });
        }
        if (!cb.pageInfo || !cb.pageInfo.hasNextPage || !cb.pageInfo.endCursor) { complete = true; break; }
        after = cb.pageInfo.endCursor;
        if (Date.now() - started > budget) break;
      }
    } catch (e) { error = e; }
    return { map, complete, pages, error };
  }

  /* ------------------------------------------------------------------ */
  /* Public token lists (Uniswap default, Superchain, CoinGecko)         */
  /* ------------------------------------------------------------------ */
  const CHAIN_IDS = { ethereum: 1, base: 8453 };
  let listsCache = null;   // one load per page session
  /** Load the public token lists. Never throws. Returns { map: Map('<chainId>:<address>' -> {uniswap, superchain, coingecko}), loaded: [ids], failed: [ids], curatedLoaded: bool }. */
  async function loadTokenLists(ctx) {
    if (listsCache && ctx.cacheLists === true) return listsCache;
    const map = new Map(); const loaded = []; const failed = [];
    await Promise.all(TOKEN_LISTS.map(async (l) => {
      try {
        const json = await fetchJson(ctx, l.url, { headers: { accept: 'application/json' } }, { retries: 1, timeoutMs: 25000 });
        if (!json || !Array.isArray(json.tokens)) throw new ScanError('BAD_RESPONSE', 'Unexpected token list');
        for (const t of json.tokens) {
          if (!t || !t.address || !(t.chainId === 1 || t.chainId === 8453)) continue;
          const key = t.chainId + ':' + String(t.address).toLowerCase();
          const cur = map.get(key) || {};
          cur[l.kind] = true; map.set(key, cur);
        }
        loaded.push(l.id);
      } catch (e) { failed.push(l.id); }
    }));
    const res = { map, loaded, failed, curatedLoaded: loaded.includes('uniswap') || loaded.includes('superchain') };
    if (ctx.cacheLists === true && loaded.length) listsCache = res;
    return res;
  }

  /* ------------------------------------------------------------------ */
  /* GoPlus token security (EVM)                                         */
  /* ------------------------------------------------------------------ */
  const num = (v) => { if (v === '' || v == null) return null; const n = Number(v); return isFinite(n) ? n : null; };
  const flag = (v) => (v === '1' || v === 1 || v === true) ? true : (v === '0' || v === 0 || v === false) ? false : null;

  /** Reduce a raw GoPlus token_security record to the few fields the classifier uses. */
  function normalizeGoPlus(r) {
    if (!r || typeof r !== 'object') return null;
    let lpUsd = 0;
    for (const d of Array.isArray(r.dex) ? r.dex : []) { const l = num(d && d.liquidity); if (l != null) lpUsd += l; }
    return {
      status: 'ok',
      honeypot: flag(r.is_honeypot) === true,
      cannotSellAll: flag(r.cannot_sell_all) === true,
      cannotBuy: flag(r.cannot_buy) === true,
      buyTax: num(r.buy_tax), sellTax: num(r.sell_tax), transferTax: num(r.transfer_tax),
      mintable: flag(r.is_mintable) === true,
      hiddenOwner: flag(r.hidden_owner) === true,
      takeBackOwnership: flag(r.can_take_back_ownership) === true,
      ownerChangeBalance: flag(r.owner_change_balance) === true,
      blacklist: flag(r.is_blacklisted) === true,
      transferPausable: flag(r.transfer_pausable) === true,
      slippageModifiable: flag(r.slippage_modifiable) === true || flag(r.personal_slippage_modifiable) === true,
      openSource: flag(r.is_open_source),
      proxy: flag(r.is_proxy) === true,
      holderCount: num(r.holder_count),
      creatorPercent: num(r.creator_percent),
      poolLiquidityUsd: lpUsd
    };
  }

  /** Shared, serialised GoPlus budget for one scan. GoPlus's keyless tier answers ONE contract per request (extra addresses are ignored)
   *  and rate-limits after roughly 20 requests, so we ask about a handful of the most relevant tokens, one at a time, and stop at the first refusal. */
  function createGoPlusGate(ctx, opts) {
    opts = opts || {};
    return {
      ctx, calls: 0, maxCalls: opts.maxCalls != null ? opts.maxCalls : LIMITS.GOPLUS_MAX_CALLS,
      delayMs: opts.delayMs != null ? opts.delayMs : LIMITS.GOPLUS_DELAY_MS,
      stopped: false, rateLimited: false, failed: false, queue: Promise.resolve(), lastAt: 0
    };
  }

  /** Ask GoPlus about contracts (already ordered by importance), one request each, through the shared gate. Never throws.
   *  Returns { map: Map(lowercase address -> normalized), asked: Set(lowercase address), rateLimited, failed } */
  function goplusLookup(gate, chainId, addresses, perChainMax) {
    const map = new Map(); const asked = new Set();
    const run = async () => {
      let mine = 0;
      for (const addr of addresses) {
        if (gate.stopped || gate.calls >= gate.maxCalls || mine >= perChainMax) break;
        const wait = gate.lastAt + gate.delayMs - Date.now();
        if (wait > 0) await sleep(wait);
        gate.calls++; mine++; gate.lastAt = Date.now();
        try {
          const j = await fetchJson(gate.ctx, GOPLUS + chainId + '?contract_addresses=' + addr.toLowerCase(), { headers: { accept: 'application/json' } }, { retries: 0, timeoutMs: 15000 });
          if (j && j.code === 1 && j.result && typeof j.result === 'object') {
            asked.add(addr.toLowerCase());
            const rec = j.result[addr.toLowerCase()] || Object.values(j.result)[0];
            const n = rec && Object.keys(j.result).some((k) => k.toLowerCase() === addr.toLowerCase()) ? normalizeGoPlus(rec) : null;
            if (n) map.set(addr.toLowerCase(), n);
          } else if (j && (j.code === 4029 || /too many/i.test(String(j.message || '')))) { gate.stopped = true; gate.rateLimited = true; }
          else { gate.stopped = true; gate.failed = true; }
        } catch (e) {
          gate.stopped = true;
          if (e && e.code === 'RATE_LIMIT') gate.rateLimited = true; else gate.failed = true;
        }
      }
    };
    const p = gate.queue.then(run, run);
    gate.queue = p.catch(() => {});
    return p.then(() => ({ map, asked, rateLimited: gate.rateLimited, failed: gate.failed }));
  }

  /* ------------------------------------------------------------------ */
  /* EVM (Ethereum + Base via Blockscout, DexScreener for market data)   */
  /* ------------------------------------------------------------------ */
  async function scanEvmChain(address, chain, options, zoraPromise, listsPromise) {
    const ctx = { fetch: options.fetch || globalThis.fetch.bind(globalThis) };
    const now = options.now || Date.now();
    const progress = options.onProgress || (() => {});
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
    // Market-data order: tokens that look like ordinary tokens first; things that look like Zora post coins last (they are
    // identified by the Zora API instead and market data is not used for them).
    const postLike = (x) => chain.id === 'base' && core.looksLikePostCoinName(x.t.name, x.t.symbol) ? 1 : 0;
    const candidates = all.filter(isErc20).sort((a, b) => {
      const pa = postLike(a), pb = postLike(b);
      if (pa !== pb) return pa - pb;
      const ra = a.t.exchange_rate ? 1 : 0, rb = b.t.exchange_rate ? 1 : 0;
      if (ra !== rb) return rb - ra;
      return (Number(b.t.holders_count || b.t.holders || 0)) - (Number(a.t.holders_count || a.t.holders || 0));
    });
    let truncated = false;
    const lookups = candidates.slice(0, LIMITS.EVM_MAX_DEX_LOOKUPS);
    progress(chain.label + ': checking market data for ' + lookups.length + ' tokens (DexScreener)…');
    const dex = await dexLookup(ctx, chain.dexChain, lookups.map((x) => x.t.address_hash));
    const failed = new Set(); let dexErr = null;
    const noteFailures = (d) => { for (const f of d.failures) { f.batch.forEach((m) => failed.add(m.toLowerCase())); dexErr = f.err; } };
    noteFailures(dex);

    // Base only: which of these are Zora coins? (never blocks the scan if Zora is down)
    let zora = null;
    if (chain.id === 'base' && zoraPromise && all.length) {
      zora = await zoraPromise;
      // Second pass: anything beyond the first pass that is NOT a Zora coin still deserves market data.
      const rest = candidates.slice(lookups.length).filter((x) => !zora.map.has(x.t.address_hash.toLowerCase())).slice(0, LIMITS.EVM_EXTRA_DEX_LOOKUPS);
      if (rest.length) {
        const d2 = await dexLookup(ctx, chain.dexChain, rest.map((x) => x.t.address_hash));
        for (const [k, v] of d2.result) dex.result.set(k, v);
        noteFailures(d2);
        rest.forEach((x) => lookups.push(x));
      }
      if (zora.error && !zora.map.size) {
        warnings.push('Base: could not reach the Zora API (' + errText(zora.error) + '). Zora/Base post coins are recognised by their name pattern instead, which is less certain.');
      } else if (!zora.complete) {
        warnings.push('Base: the Zora coin list was only partly loaded' + (zora.error ? ' (' + errText(zora.error) + ')' : '') + '. Coins it did not cover are recognised by their name pattern instead.');
      }
    }

    if (failed.size) warnings.push(chain.label + ': DexScreener lookup failed for ' + failed.size + ' token(s) (' + errText(dexErr) + ').');
    const lookedUp = new Set(lookups.map((x) => x.t.address_hash.toLowerCase()));
    const unchecked = candidates.filter((x) => !lookedUp.has(x.t.address_hash.toLowerCase()) && !(zora && zora.map.has(x.t.address_hash.toLowerCase()))).length;
    if (unchecked > 0) {
      truncated = true;
      warnings.push(chain.label + ': ' + candidates.length + ' tokens held; market data was checked for ' + lookups.length + ' of them. ' + unchecked + ' non-Zora token' + (unchecked > 1 ? 's are' : ' is') + ' marked "not checked".');
    }

    // Public token lists (Uniswap default / Superchain / CoinGecko), matched by exact contract address.
    let lists = null;
    if (listsPromise) {
      lists = await listsPromise;
      if (!lists.loaded.length) warnings.push('Token lists (Uniswap / Superchain / CoinGecko) could not be loaded, so "on a verified list" checks were skipped — some known tokens may show as Unknown.');
      else if (lists.failed.length && !(chain.id === 'ethereum' && lists.failed.every((f) => f === 'coingecko-base')) && !(chain.id === 'base' && lists.failed.every((f) => f === 'coingecko-ethereum'))) {
        warnings.push('Some token lists could not be loaded (' + lists.failed.join(', ') + '); list matches may be incomplete.');
      }
    }
    const chainNum = CHAIN_IDS[chain.id];
    const listsFor = (key) => lists && lists.loaded.length ? Object.assign({ checked: true }, lists.map.get(chainNum + ':' + key) || {}) : null;

    // Pass 1: classify with everything except GoPlus.
    const build = (x, gpRec, gpAsked, gpUnavailable) => {
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
        dex: dexInfo, explorer: chain.explorer + x.t.address_hash,
        zora: zora ? zora.map.get(key) || null : null, zoraChecked: !!(zora && (zora.complete || zora.map.size)),
        lists: listsFor(key),
        gp: gpRec ? gpRec : (gpAsked ? { status: 'notIndexed' } : gpUnavailable ? { status: 'unavailable' } : null)
      };
      tok.result = core.classifyToken(tok, now);
      return tok;
    };
    const tokens = all.map((x) => build(x, null, false, false));

    // GoPlus contract security (EVM): a small budget, spent where it can change or explain the verdict — tokens that are not Zora coins,
    // NFTs, list members, canonical or Coinbase tokens. Order: (A) tokens that look OK so far but have a market (honeypot/tax checks matter
    // most there), (B) tokens flagged as airdrop spam (adds evidence), (C) the rest; within a group, most holders first.
    const byKey = new Map(all.map((x, i) => [x.t.address_hash.toLowerCase(), i]));
    const eligible = tokens.filter((t, i) => {
      const x = all[i];
      if (!isErc20(x) || !t.dex || !t.dex.checked) return false;
      if (t.zora || t.result.kind === 'postcoin') return false;
      if (t.lists && (t.lists.uniswap || t.lists.superchain)) return false;
      if (t.result.kind === 'coinbase' || (core.CANONICAL_EVM[chain.id] && core.CANONICAL_EVM[chain.id].has(t.address.toLowerCase()))) return false;
      return true;
    });
    const tier = (t) => (t.result.category !== 'suspicious' && t.dex.pairCount > 0) ? 0 : (t.result.kind === 'airdropspam' ? 1 : 2);
    eligible.sort((a, b) => (tier(a) - tier(b)) || (Number(b.bs.holders || 0) - Number(a.bs.holders || 0)));
    let gpInfo = null;
    if (eligible.length && options.goplus !== false && options.goplusGate) {
      progress(chain.label + ': running contract security checks (GoPlus)…');
      gpInfo = await goplusLookup(options.goplusGate, chainNum, eligible.map((t) => t.address), LIMITS.GOPLUS_PER_CHAIN);
      for (const t of eligible) {
        const key = t.address.toLowerCase();
        const rec = gpInfo.map.get(key) || null;
        const asked = gpInfo.asked.has(key);
        if (!rec && !asked && !(gpInfo.rateLimited || gpInfo.failed)) continue;     // never asked (budget used up): leave as "not requested"
        const i = byKey.get(key);
        tokens[i] = build(all[i], rec, asked && !rec, !asked && (gpInfo.rateLimited || gpInfo.failed));
      }
      if (gpInfo.rateLimited || gpInfo.failed) warnings.push(chain.label + ': the GoPlus security service ' + (gpInfo.rateLimited ? 'rate-limited the scan' : 'was unavailable') + ', so contract-security checks are partial (' + gpInfo.asked.size + ' tokens checked).');
      else warnings.push(chain.label + ': contract-security checks (GoPlus, free tier) were run on the ' + gpInfo.asked.size + ' most relevant of ' + eligible.length + ' eligible tokens — the rest rely on market data and lists only.');
    }
    return { chain: chain.id, label: chain.label, address, status: 'ok', tokens, warnings, truncated, totalHeld: all.length };
  }

  async function scanEvm(address, options) {
    options = options || {};
    const progress = options.onProgress || (() => {});
    progress('Reading token balances on Ethereum and Base (Blockscout), checking Zora coins and loading token lists…');
    const zctx = { fetch: options.fetch || globalThis.fetch.bind(globalThis) };
    const zoraPromise = zoraLookup(zctx, address, options.zoraBudgetMs);   // runs in parallel with the balance + market lookups
    const lctx = { fetch: options.fetch || globalThis.fetch.bind(globalThis), cacheLists: options.cacheLists === true };
    const listsPromise = options.tokenLists === false ? null : loadTokenLists(lctx);
    const evmOptions = Object.assign({}, options, { goplusGate: options.goplusGate || createGoPlusGate({ fetch: lctx.fetch }, { delayMs: options.goplusDelayMs, maxCalls: options.goplusMaxCalls }) });
    const chains = await Promise.all(EVM_CHAINS.map((c) => scanEvmChain(address, c, evmOptions, zoraPromise, listsPromise)));
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

  return { scan, scanSolana, scanEvm, fetchJson, dexLookup, zoraLookup, loadTokenLists, goplusLookup, createGoPlusGate, normalizeGoPlus, formatUnits, explorerFor, ScanError, EVM_CHAINS, SOLANA_RPCS, LIMITS };
});
