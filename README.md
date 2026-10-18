# Wallet Scam-Token Checker

Free, no-signup, read-only, single-page static tool. Paste a **public** Solana or EVM (Ethereum + Base) address and see which tokens look
**Known / verified**, **Unknown** (incl. **social post coins** and **illiquid** tokens) or **Suspicious**. *This is a heuristic scan, not a guarantee.*

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
- Zora / Base-app post coins: Zora API `api-sdk.zora.engineering/profileBalances?identifier=<addr>` (keyless, paged ~20/page, time-boxed; only the public wallet address is sent). Falls back to a name-pattern guess if unavailable.
- Market data: DexScreener `api.dexscreener.com/tokens/v1/<chain>/<addrs>`
- EVM balances: `eth.blockscout.com` and `base.blockscout.com` `/api/v2/addresses/<addr>/token-balances`

## Classification (thresholds in `lib/core.js`)
- **Known / verified**: on Jupiter verified list, canonical contract (USDC/WETH/…), or top pool liquidity ≥ $50k **and** trading ≥ 30 days.
- **Suspicious**: link/domain, bait words (claim, airdrop, visit, reward…), money-amount bait (not "$0"), *suspicious* hidden characters, unicode look-alikes, impersonating a famous symbol, explorer reputation ≠ ok, Zora-blocked coin, or **very low liquidity (< $1k) / very new (< 3 days) combined with another warning sign**.
  (Domain-style or bait names on tokens with an established market only get a note; hidden chars / look-alikes still flag.)
- **Unknown**: everything else, with sub-types:
  - **Social post coin** (Zora / Base app): the coin's *name is the post text*. Confirmed through the Zora API, or guessed on Base from a sentence-like name that is also its symbol (labelled "Likely"). Shown as Unknown – usually harmless but illiquid — never Suspicious for liquidity/age. Links, bait words, hidden-character tricks, look-alike scripts, impersonation or a Zora platform block still make it Suspicious. Stylised unicode fonts and plain amounts in post text are only notes.
  - **Unknown – illiquid**: very low liquidity (< $1k) and *nothing else* wrong. A risk note, not proof of a scam.
  - NFTs, no trading pairs, thin/young markets, lookup failures.
- **Hidden characters** are position-aware (`findSuspiciousInvisible`): emoji ZWJ / variation selectors, newlines, normal whitespace, ZWNJ in Arabic/Indic text, RTL marks in RTL text, flag tag sequences, and a few zero-width spaces at the start/end of text or next to line breaks/emoji/symbols (how the Zora app writes posts) are fine. Flagged: a zero-width space inside a word, text-direction overrides (RLO…), isolates, stray tag characters, word joiners, invisible separators/fillers, soft hyphens, BOM, joiners/selectors outside emoji, or > 3 zero-width spaces. All invisible characters are still stripped before link/bait-word matching.
