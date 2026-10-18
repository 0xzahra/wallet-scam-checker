# Wallet Scam-Token Checker

Free, no-signup, read-only, single-page static tool. Paste a **public** Solana or EVM (Ethereum + Base) address and see which tokens look
**Known / verified**, **Unknown – no liquidity data** or **Suspicious**. *This is a heuristic scan, not a guarantee.*

## Run
```bash
cd wallet-scam-checker
python3 -m http.server 8000      # then open http://localhost:8000
```
No build step, no dependencies. Any static host works (not deployed anywhere yet).

## Test
```bash
node --test tests/                       # unit + mocked-network tests (Node 18+; no network needed)
node tests/live.js <address> [...]       # optional live smoke test against the real public APIs
```

## Files
- `index.html`, `styles.css`, `app.js` – UI (strict CSP, all token text inserted via `textContent`, no token images/links rendered)
- `lib/core.js` – validators (Solana base58 / EVM + EIP-55 checksum), seed/private-key detection, name heuristics, classifier
- `lib/scanner.js` – network layer (Jupiter holdings + token search, Solana RPC fallback, Blockscout, DexScreener), retries/rate-limit handling
- `tests/` – `core.test.js`, `scanner.test.js`, `live.js`

## Data sources (all keyless)
- Solana balances: Jupiter Ultra holdings `lite-api.jup.ag/ultra/v1/holdings/<addr>`; fallback: public Solana RPC `getTokenAccountsByOwner` (Token + Token-2022); optional custom RPC.
- Solana verified status: Jupiter `lite-api.jup.ag/tokens/v2/search?query=<mints>` (`isVerified`, tags)
- Market data: DexScreener `api.dexscreener.com/tokens/v1/<chain>/<addrs>`
- EVM balances: `eth.blockscout.com` and `base.blockscout.com` `/api/v2/addresses/<addr>/token-balances`

## Classification (thresholds in `lib/core.js`)
- **Known / verified**: on Jupiter verified list, canonical contract (USDC/WETH/…), or top pool liquidity ≥ $50k **and** trading ≥ 30 days.
- **Suspicious**: link/domain, bait words (claim, airdrop, visit, reward…), money-amount bait, hidden characters, unicode look-alikes, impersonating a famous symbol, explorer reputation ≠ ok, top pool < $1k, first pool < 3 days old.
  (Domain-style or bait names on tokens with an established market only get a note; hidden chars / look-alikes still flag.)
- **Unknown**: everything else (no trading pairs, thin/young market, NFTs, or market lookup failed/skipped).
