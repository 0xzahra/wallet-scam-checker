# Wallet Scam-Token Checker

Free, no-signup, read-only, single-page static tool. Paste a **public** Solana or EVM (Ethereum + Base) address and see which tokens look
**Known / verified**, **Unknown** (incl. **social post coins** and **illiquid** tokens) or **Suspicious**. *This is a heuristic scan, not a guarantee.*

## Run
```bash
cd wallet-scam-checker
python3 -m http.server 8000      # then open http://localhost:8000
```
No build step, no dependencies. Any static host works (live: https://0xzahra.github.io/wallet-scam-checker/).

## Test
```bash
node --test tests/                       # unit + mocked-network tests (Node 18+; no network needed)
node tests/live.js <address> [...]       # optional live smoke test against the real public APIs
```

## Files
- `index.html`, `styles.css`, `app.js` – UI (strict CSP, all token text inserted via `textContent`, no token images/links rendered)
- `lib/core.js` – validators (Solana base58 / EVM + EIP-55 checksum), seed/private-key detection, name heuristics, classifier
- `lib/scanner.js` – network layer (Jupiter holdings + token search, Solana RPC fallback, Blockscout, DexScreener, Zora, token lists, GoPlus), retries/rate-limit handling
- `tests/` – `core.test.js`, `scanner.test.js`, `live.js`

## Data sources (all keyless)
- Solana balances: Jupiter Ultra holdings `lite-api.jup.ag/ultra/v1/holdings/<addr>`; fallback: public Solana RPC `getTokenAccountsByOwner` (Token + Token-2022); optional custom RPC.
- Solana verified status: Jupiter `lite-api.jup.ag/tokens/v2/search?query=<mints>` (`isVerified`, tags)
- Zora / Base-app post coins: Zora API `api-sdk.zora.engineering/profileBalances?identifier=<addr>` (keyless, paged, time-boxed; only the public wallet address is sent). Falls back to a name-pattern guess if unavailable.
- Market data: DexScreener `api.dexscreener.com/tokens/v1/<chain>/<addrs>` (liquidity, FDV, 24h volume/txns, pair age). "Effective liquidity" discounts the token's own supply that DexScreener counts at its own price, so hollow pools are detected.
- Verified lists (matched by exact contract address): Uniswap default list, Superchain token list, CoinGecko Base / Ethereum lists.
- Contract security: GoPlus `api.gopluslabs.io/api/v1/token_security/<chainId>` – honeypot, can't sell, buy/sell tax, mintable, owner can change balances, blacklist, hidden owner, holder count. The keyless tier answers one contract per request and rate-limits quickly, so only the ~6 most relevant tokens per chain are checked; the card says when GoPlus was not run / unavailable / has no record.
- EVM balances: `eth.blockscout.com` and `base.blockscout.com` `/api/v2/addresses/<addr>/token-balances`

## Classification (thresholds in `lib/core.js`)
Every verdict is a **heuristic**. Each token card shows a plain-English summary, a confidence level (low / medium / high), the evidence (risk / ok / info) and what was and wasn't checked.
- **Known / verified**: Coinbase-issued assets matched by **exact contract address** (cbBTC, cbETH, cbXRP, cbDOGE, cbLTC, cbADA… in `COINBASE_ASSETS`), canonical contracts (USDC/WETH/…), tokens on the Uniswap / Superchain lists, Jupiter-verified Solana tokens, CoinGecko-listed tokens with a real market, or established tokens (≥ $50k *effective* liquidity, ≥ 30 days old **and** actually trading).
- **Likely airdrop spam** (Suspicious): no usable market – no DexScreener pool, best pool < $1k, or a "hollow" pool (big headline figure that is only the token's own supply) – and not on a verified list, not priced by the explorer, not a Zora coin. Nobody can buy such a token, so it almost always arrived unsolicited. GoPlus data, when available, adds context (mass holder counts, unpublished source, or a clean contract meaning "worthless, probably not a trap").
- **Suspicious** (other): link/domain, bait words (claim, airdrop, visit, reward…), money-amount bait, *suspicious* hidden characters, look-alike scripts, GoPlus honeypot / can't sell / extreme tax, impersonating a famous symbol (unless it is the exact verified contract), claiming to be Coinbase (e.g. "Coinbase Wrapped BTC") without being the real contract, explorer reputation ≠ ok, Zora-blocked coin, or very new + another warning sign.
- **Unknown**: everything else, with sub-types:
  - **Social post coin** (Zora / Base app): the coin's *name is the post text*. Confirmed through the Zora API (including your own coins and coins created through the Base app), or guessed on Base from a sentence-like name that is also its symbol (labelled "Likely"). Shown as Unknown – never Suspicious for liquidity/age. Links, bait words, look-alike scripts, impersonation or a Zora platform block still make it Suspicious unless the coin has real traction (holders and volume) or is yours.
  - **Dormant pool**: a pool that looks big but has almost no trading.
  - **Unknown – illiquid**: very low liquidity and *nothing else* wrong (Solana / exempt tokens).
  - NFTs, thin/young markets, lookup failures.
- **Hidden characters** are position-aware (`findSuspiciousInvisible`): emoji ZWJ / variation selectors, newlines, normal whitespace, ZWNJ in Arabic/Indic text, RTL marks in RTL text, flag tag sequences, and a few zero-width spaces at the start/end of text or next to line breaks/emoji/symbols (how the Zora app writes posts) are fine. Flagged: a zero-width space inside a word, text-direction overrides (RLO…), isolates, stray tag characters, word joiners, invisible separators/fillers, soft hyphens, BOM, joiners/selectors outside emoji, or > 3 zero-width spaces. All invisible characters are still stripped before link/bait-word matching.
