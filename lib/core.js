/* Wallet Scam-Token Checker — core logic (pure functions, no network, no DOM).
 * Works in the browser (window.WSC) and in Node (module.exports) so it can be unit-tested.
 * Everything here is HEURISTIC. It is not a guarantee that a token is safe or a scam. */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.WSC = Object.assign(root.WSC || {}, api);
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /* ------------------------------------------------------------------ */
  /* Base58 (Bitcoin / Solana alphabet)                                  */
  /* ------------------------------------------------------------------ */
  const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  const B58_MAP = {};
  for (let i = 0; i < B58.length; i++) B58_MAP[B58[i]] = BigInt(i);

  function isBase58(str) {
    if (!str) return false;
    for (const ch of str) if (!(ch in B58_MAP)) return false;
    return true;
  }

  /** Decode base58 string to an array of bytes. Returns null if invalid. */
  function base58Decode(str) {
    if (!isBase58(str)) return null;
    let num = 0n;
    for (const ch of str) num = num * 58n + B58_MAP[ch];
    const bytes = [];
    while (num > 0n) { bytes.unshift(Number(num & 0xffn)); num >>= 8n; }
    let zeros = 0;
    while (zeros < str.length && str[zeros] === '1') zeros++;
    return new Array(zeros).fill(0).concat(bytes);
  }

  /* ------------------------------------------------------------------ */
  /* Keccak-256 (for EIP-55 checksum validation)                         */
  /* ------------------------------------------------------------------ */
  const M64 = (1n << 64n) - 1n;
  const RC = [
    0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
    0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
    0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
    0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
    0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
    0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n
  ];
  const ROTC = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];
  const PILN = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];
  const rotl = (x, n) => ((x << BigInt(n)) | (x >> BigInt(64 - n))) & M64;

  function keccakF(st) {
    const bc = new Array(5);
    for (let r = 0; r < 24; r++) {
      for (let i = 0; i < 5; i++) bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
      for (let i = 0; i < 5; i++) {
        const t = bc[(i + 4) % 5] ^ rotl(bc[(i + 1) % 5], 1);
        for (let j = 0; j < 25; j += 5) st[j + i] ^= t;
      }
      let t = st[1];
      for (let i = 0; i < 24; i++) {
        const j = PILN[i];
        const b = st[j];
        st[j] = rotl(t, ROTC[i]);
        t = b;
      }
      for (let j = 0; j < 25; j += 5) {
        for (let i = 0; i < 5; i++) bc[i] = st[j + i];
        for (let i = 0; i < 5; i++) st[j + i] ^= (~bc[(i + 1) % 5] & M64) & bc[(i + 2) % 5];
      }
      st[0] ^= RC[r];
    }
  }

  /** keccak256 of an array of bytes (or ASCII string) -> lowercase hex string. */
  function keccak256Hex(input) {
    const data = typeof input === 'string' ? Array.from(input, (c) => c.charCodeAt(0) & 0xff) : input.slice();
    const rate = 136;
    data.push(0x01);
    while (data.length % rate !== 0) data.push(0x00);
    data[data.length - 1] |= 0x80;
    const st = new Array(25).fill(0n);
    for (let off = 0; off < data.length; off += rate) {
      for (let i = 0; i < rate / 8; i++) {
        let lane = 0n;
        for (let b = 7; b >= 0; b--) lane = (lane << 8n) | BigInt(data[off + i * 8 + b]);
        st[i] ^= lane;
      }
      keccakF(st);
    }
    let out = '';
    for (let i = 0; i < 4; i++) {
      for (let b = 0; b < 8; b++) out += Number((st[i] >> BigInt(8 * b)) & 0xffn).toString(16).padStart(2, '0');
    }
    return out;
  }

  /** EIP-55: true if mixed-case address has a correct checksum. */
  function isValidEip55(address) {
    const hex = address.slice(2);
    const hash = keccak256Hex(hex.toLowerCase());
    for (let i = 0; i < 40; i++) {
      const ch = hex[i];
      if (/[a-f]/i.test(ch)) {
        const shouldUpper = parseInt(hash[i], 16) >= 8;
        if ((ch === ch.toUpperCase()) !== shouldUpper) return false;
      }
    }
    return true;
  }

  /* ------------------------------------------------------------------ */
  /* Address validation + "is this a secret?" detection                  */
  /* ------------------------------------------------------------------ */
  function isEvmAddress(s) { return /^0x[0-9a-fA-F]{40}$/.test(s); }

  function isSolanaAddress(s) {
    if (typeof s !== 'string' || s.length < 32 || s.length > 44) return false;
    const bytes = base58Decode(s);
    return !!bytes && bytes.length === 32;
  }

  function looksLikeSeedPhrase(raw) {
    const words = String(raw).trim().split(/\s+/).filter(Boolean);
    if (words.length < 4) return false;
    return words.every((w) => /^[A-Za-z]{2,10}$/.test(w));
  }

  function looksLikePrivateKey(raw) {
    const s = String(raw).trim();
    if (/^(0x)?[0-9a-fA-F]{64}$/.test(s)) return true;                       // EVM key (or a tx hash — also not an address)
    if (/^\[\s*\d{1,3}(\s*,\s*\d{1,3}){31,}\s*\]$/.test(s)) return true;     // Solana keypair JSON array
    if (/^(xprv|yprv|zprv|suiprivkey)/i.test(s)) return true;                // extended / Sui keys
    if (/^[5KLc][1-9A-HJ-NP-Za-km-z]{50,51}$/.test(s)) return true;          // Bitcoin WIF
    if (/^[1-9A-HJ-NP-Za-km-z]{80,90}$/.test(s)) {                           // Solana 64-byte secret key in base58
      const b = base58Decode(s);
      if (b && b.length === 64) return true;
    }
    return false;
  }

  /**
   * Inspect whatever the user pasted.
   * Returns { kind: 'empty'|'seed'|'privatekey'|'evm'|'solana'|'invalid', address?, message? }
   * NEVER stores or logs the raw input.
   */
  function inspectInput(raw) {
    const s = String(raw == null ? '' : raw).trim();
    if (!s) return { kind: 'empty', message: 'Paste a public wallet address to start.' };
    if (looksLikeSeedPhrase(s)) {
      return { kind: 'seed', message: 'That looks like a seed phrase (recovery words). STOP — never paste it anywhere. We did not read or send it, and we have cleared the box. Paste only your public wallet address.' };
    }
    if (looksLikePrivateKey(s)) {
      return { kind: 'privatekey', message: 'That looks like a private key (or a 64-character hash). STOP — never paste a private key anywhere. We did not read or send it, and we have cleared the box. Paste only your public wallet address.' };
    }
    if (/\s/.test(s)) return { kind: 'invalid', message: 'Please paste a single address only (no spaces).' };
    if (isEvmAddress(s)) {
      const body = s.slice(2);
      const mixed = /[a-f]/.test(body) && /[A-F]/.test(body);
      if (mixed && !isValidEip55(s)) {
        return { kind: 'invalid', message: 'This EVM address has an invalid checksum (mixed upper/lower case does not match). It may have a typo — re-copy it from your wallet.' };
      }
      return { kind: 'evm', address: s };
    }
    if (/^0x/i.test(s)) {
      return { kind: 'invalid', message: 'EVM addresses are 0x followed by exactly 40 hex characters (42 characters in total). Yours has ' + s.length + '.' };
    }
    if (/\.(eth|sol|base\.eth|crypto|bnb)$/i.test(s)) {
      return { kind: 'invalid', message: 'Name services (.eth, .sol, …) are not supported. Paste the raw address instead.' };
    }
    if (isSolanaAddress(s)) return { kind: 'solana', address: s };
    if (/[^1-9A-HJ-NP-Za-km-z]/.test(s)) {
      return { kind: 'invalid', message: 'Not a valid address. Solana addresses use only letters and digits (no 0, O, I or l); EVM addresses start with 0x.' };
    }
    return { kind: 'invalid', message: 'Not a valid address. Solana addresses are 32–44 base58 characters; EVM addresses are 0x + 40 hex characters.' };
  }

  /* ------------------------------------------------------------------ */
  /* Token-name heuristics                                               */
  /* ------------------------------------------------------------------ */
  /* Every code point that renders as nothing (or changes how text is drawn). stripInvisible() removes all of them before
   * link / bait-word matching, so none of them can be used to dodge those checks. Whether one of them is *suspicious* is
   * decided separately by findSuspiciousInvisible() (position-aware). */
  const INVISIBLE_RE = /[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\u{e0000}-\u{e007f}\u{e0100}-\u{e01ef}]/u;
  const URL_RE = /(https?:\/\/|\bwww\.|\bt\.me\/|\bbit\.ly\b|\btinyurl\b|(?<![a-z0-9-])[a-z0-9][a-z0-9-]{1,}\.(?:com|net|org|io|xyz|app|site|top|vip|club|live|online|link|click|claim|me|co|cc|gg|fi|finance|fun|info|cloud|world|tech|pro|ai|ly|to|gift|shop|store|cfd|win|bid|lol|icu|rest|pw|ru|cn|tk|ml|ga|cf|gq|ws|one|wtf|sbs|bond|today|network|exchange|farm|swap|dev|page|space|website|ink|monster)(?![a-z0-9]))/i;
  const STRONG_WORDS = /\b(claim|airdrops?|visit|rewards?|vouchers?|redeem|giveaway|whitelist(?:ed)?|bonus\s*(?:token|claim)|connect\s*wallet|swap\s*now|get\s*free|free\s*(?:mint|token|claim|eth|sol|usdt)|launch\s*now|you\s*(?:won|have\s*won)|congratulations|eligible)\b/i;
  const WEAK_WORDS = /\b(free|bonus|gift|promo|lottery|winner|prize|presale|access|verify|official\s*claim)\b/i;
  const AMOUNT_BAIT_RE = /[$€£]\s?\d[\d,.]*\s?[kKmM]?\b|\b\d[\d,.]*\s?(usdt|usdc|eth|sol|btc|bnb|usd)\b/i;
  /** True if the text advertises a NON-zero amount ("$1000", "500 USDT"). "$0" is not bait. */
  function hasAmountBait(text) {
    const re = new RegExp(AMOUNT_BAIT_RE.source, 'gi');
    let m;
    while ((m = re.exec(text))) {
      const num = parseFloat((m[0].match(/\d[\d,]*\.?\d*/) || ['0'])[0].replace(/,/g, ''));
      if (num > 0) return true;
    }
    return false;
  }

  const MAJORS = new Set(['ETH', 'WETH', 'BTC', 'WBTC', 'CBBTC', 'USDT', 'USDC', 'DAI', 'USD', 'SOL', 'WSOL', 'BNB', 'JUP', 'BONK', 'WIF', 'JTO',
    'PYTH', 'RAY', 'ORCA', 'STETH', 'WSTETH', 'MSOL', 'JITOSOL', 'LINK', 'UNI', 'AAVE', 'TETHER', 'USDCOIN', 'USDS', 'PYUSD', 'TRUMP']);

  /** Characters that are Cyrillic / Greek (the classic Latin look-alike scripts). */
  const CYR_GRK_RE = /[\u0370-\u03ff\u1f00-\u1fff\u0400-\u052f\u1c80-\u1c8f\u2de0-\u2dff\ua640-\ua69f]/;
  const LATIN_RE = /[A-Za-z]/;
  /** Fullwidth forms, math alphanumerics, enclosed alphanumerics, small caps/modifier letters used to fake Latin text. */
  const FANCY_RE = /[\uff01-\uff5e\u2460-\u24ff\u1d00-\u1dbf\u2070-\u209f\u{1d400}-\u{1d7ff}\u{1f130}-\u{1f189}]/u;

  function stripInvisible(s) { return s.replace(new RegExp(INVISIBLE_RE.source, 'gu'), ''); }

  /* ---- position-aware invisible-character check -------------------------------------------------------------------
   * Social "post coins" (Zora / Base app) use the post text as the token name, so their names legitimately contain
   * line breaks, emoji joiners (ZWJ U+200D), emoji variation selectors (VS16 U+FE0F) and — added by the Zora app — zero-width
   * spaces (U+200B) at the start/end of the text, next to line breaks, emoji, $, @ or numbers. Those are NOT tricks.
   * What IS a trick: a zero-width space hiding *inside a word* (e.g. "USD<ZWSP>C"), text-direction overrides (RLO U+202E…),
   * isolates, tag characters, word joiners, invisible fillers/separators, soft hyphens, stray joiners/selectors that are not
   * part of an emoji or a joiner-using script, or an abnormal number of zero-width spaces. */
  const PICT_RE = /\p{Extended_Pictographic}/u;
  const EMOJI_MOD_RE = /\p{Emoji_Modifier}/u;
  const WORDCH_RE = /[\p{L}\p{N}]/u;
  const RTL_RE = /[\u0590-\u08ff\ufb1d-\ufdff\ufe70-\ufefe]/;
  const JOINER_SCRIPT_RE = /[\u0590-\u08ff\u0900-\u0dff\ufb1d-\ufdff\ufe70-\ufefe]/;   // Hebrew/Arabic/Indic: ZWNJ/ZWJ are normal there
  const HAN_RE = /\p{Script=Han}/u;
  const MAX_ZWSP = 3;

  /** Returns [{ cp: 'U+200B', idx, kind: 'inword'|'bidi'|'tag'|'joiner'|'selector'|'filler'|'many' }] for truly suspicious invisibles. */
  function findSuspiciousInvisible(str) {
    const chars = Array.from(String(str == null ? '' : str));
    const bad = [];
    const hex = (cp) => 'U+' + cp.toString(16).toUpperCase().padStart(4, '0');
    const emojiLike = (c) => !!c && (PICT_RE.test(c) || EMOJI_MOD_RE.test(c) || c === '\ufe0f' || c === '\u20e3');
    const hasRtl = RTL_RE.test(chars.join(''));
    let zwsp = 0;
    for (let i = 0; i < chars.length; i++) {
      const ch = chars[i];
      if (!INVISIBLE_RE.test(ch)) continue;
      const cp = ch.codePointAt(0);
      const prev = chars[i - 1] || '', next = chars[i + 1] || '';
      const flag = (kind) => bad.push({ cp: hex(cp), idx: i, kind });
      if (cp === 0x200b) {                                   // zero-width space
        zwsp++;
        if (WORDCH_RE.test(prev) && WORDCH_RE.test(next)) flag('inword');
      } else if (cp === 0x200d) {                            // ZWJ
        const inEmoji = emojiLike(prev) && PICT_RE.test(next);
        const inScript = JOINER_SCRIPT_RE.test(prev) || JOINER_SCRIPT_RE.test(next);
        if (!inEmoji && !inScript) flag('joiner');
      } else if (cp === 0x200c) {                            // ZWNJ
        if (!(JOINER_SCRIPT_RE.test(prev) || JOINER_SCRIPT_RE.test(next))) flag('joiner');
      } else if (cp === 0xfe0f || cp === 0xfe0e) {           // emoji / text presentation selector
        const keycap = /[0-9#*]/.test(prev) && next === '\u20e3';
        if (!(PICT_RE.test(prev) || keycap)) flag('selector');
      } else if (cp >= 0xfe00 && cp <= 0xfe02) {             // CJK ideographic variation selectors
        if (!HAN_RE.test(prev)) flag('selector');
      } else if (cp === 0x200e || cp === 0x200f || cp === 0x061c) {   // LRM / RLM / ALM: only normal inside RTL text
        if (!hasRtl) flag('bidi');
      } else if ((cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069)) {   // embeddings, overrides (RLO!), isolates
        flag('bidi');
      } else if (cp >= 0xe0000 && cp <= 0xe007f) {           // tag characters: only valid as part of a subdivision flag emoji
        let j = i - 1;
        while (j >= 0 && chars[j].codePointAt(0) >= 0xe0020 && chars[j].codePointAt(0) <= 0xe007f) j--;
        if (!(j >= 0 && chars[j] === '\u{1f3f4}')) flag('tag');
      } else {                                               // word joiner, invisible operators, fillers, soft hyphen, BOM, Mongolian FVS, VS17+, …
        flag('filler');
      }
    }
    if (zwsp > MAX_ZWSP) bad.push({ cp: 'U+200B', idx: -1, kind: 'many' });
    return bad;
  }


  /** Compact comparison form for impersonation checks: uppercase letters/digits only after NFKC. */
  function compactUpper(s) {
    return stripInvisible(String(s || '')).normalize('NFKC').toUpperCase().replace(/[^A-Z0-9]/g, '');
  }

  /**
   * Analyse a token name + symbol. Returns { strong: [...], weak: [...] } of plain-English reasons.
   * strong flags make a token Suspicious on their own; weak flags only add a note.
   */
  function analyzeName(name, symbol, opts) {
    const postCoin = !!(opts && opts.postCoin);
    const strong = [];
    const kinds = [];   // parallel to `strong`: 'hidden' | 'url' | 'words' | 'amount' | 'lookalike' | 'fancy'
    const weak = [];
    const add = (kind, msg) => { kinds.push(kind); strong.push(msg); };
    const text = [name, symbol].filter(Boolean).join(' ');
    if (!text) return { strong, kinds, weak, text: '' };
    const lowered = stripInvisible(text).normalize('NFKC');
    const hid = findSuspiciousInvisible(text);
    if (hid.length) {
      if (hid.some((h) => h.kind === 'bidi')) add('hidden', 'Name contains text-direction override characters that can disguise how it reads (a common trick).');
      else if (hid.some((h) => h.kind === 'inword')) add('hidden', 'Name hides invisible characters inside words (a common trick to dodge filters).');
      else add('hidden', 'Name contains hidden/invisible characters in an unusual place (a common trick).');
    }
    if (URL_RE.test(lowered)) add('url', 'Name or symbol contains a link or website address.');
    if (STRONG_WORDS.test(lowered)) add('words', postCoin
      ? 'Post text uses bait words like "claim", "airdrop", "visit" or "reward". Scam coins use these too, so it is flagged — if you recognise the post as genuine, it is probably fine.'
      : 'Name or symbol uses bait words like "claim", "airdrop", "visit" or "reward".');
    else if (WEAK_WORDS.test(lowered)) weak.push('Name contains a word often used in bait tokens (e.g. "free", "bonus", "gift").');
    if (hasAmountBait(lowered)) {
      // In a social post, talking about money is normal; it only counts as bait when paired with other bait words.
      if (postCoin && !STRONG_WORDS.test(lowered) && !WEAK_WORDS.test(lowered)) weak.push('Post text mentions an amount of money — normal in social posts, not a scam signal on its own.');
      else add('amount', 'Name advertises an amount of money (e.g. "$1000" or "500 USDT") — classic bait.');
    }
    if (CYR_GRK_RE.test(text) && LATIN_RE.test(text)) add('lookalike', 'Name mixes Latin letters with look-alike Cyrillic/Greek letters (unicode look-alike trick).');
    if (FANCY_RE.test(text)) {
      // Stylised fonts (𝐛𝐨𝐥𝐝, 𝕏, ⒸⓄⓌ) are everywhere in social posts. impersonatesMajor() still normalises them (NFKC).
      if (postCoin) weak.push('Post text uses stylised unicode letters (common in social posts).');
      else add('lookalike', 'Name uses fancy/full-width unicode letters that imitate normal text.');
    }
    return { strong, kinds, weak, text, hidden: hid };
  }

  /** Does this name look like the text of a social post rather than a token name? (heuristic; used only when the Zora API can't confirm) */
  function looksLikePostCoinName(name, symbol) {
    const norm = (v) => stripInvisible(String(v == null ? '' : v)).replace(/\s+/g, ' ').trim();
    const n = norm(name), s = norm(symbol);
    if (!n) return false;
    // Zora content coins use the post text as BOTH name and symbol (sometimes cut off at ~32 characters).
    if (s && !(n === s || n.startsWith(s) || s.startsWith(n))) return false;
    // contact-us style names (Telegram/WhatsApp/Discord handles, "DM me") are spam adverts, not posts
    if (/\b(telegram|whats\s?app|discord|dm\s+me|contact\s+us)\b/i.test(n)) return false;
    const words = n.split(' ').length;
    return /[\r\n]/.test(String(name || '')) || n.length >= 24 || words >= 5;
  }

  /** Is this symbol/name impersonating a famous token? (caller decides whether it is the real one) */
  function impersonatesMajor(name, symbol) {
    const s = compactUpper(symbol);
    const n = compactUpper(name);
    return (s && MAJORS.has(s)) || (n && MAJORS.has(n)) ? (MAJORS.has(s) ? s : n) : null;
  }

  /** Make a token name safe to display: remove control chars, reveal hidden chars, defang links. */
  function safeDisplay(str, maxLen) {
    maxLen = maxLen || 60;
    let s = String(str == null ? '' : str);
    // Reveal only the suspicious invisibles (as ·); keep emoji joiners/selectors so emoji still render; drop harmless zero-width spaces.
    const found = findSuspiciousInvisible(s);
    const sus = new Set(found.filter((h) => h.idx >= 0).map((h) => h.idx));
    if (found.some((h) => h.kind === 'many')) Array.from(s).forEach((c, i) => { if (c === '\u200b') sus.add(i); });
    s = Array.from(s).map((c, i) => {
      if (!INVISIBLE_RE.test(c)) return c;
      if (sus.has(i)) return '·';
      return c === '\u200b' ? '' : c;
    }).join('');
    // eslint-disable-next-line no-control-regex
    s = s.replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ');
    s = s.replace(/https?:\/\//gi, (m) => (m.toLowerCase().startsWith('https') ? 'hxxps://' : 'hxxp://'));
    s = s.replace(/([a-z0-9_-]+)\.([a-z]{2,})(?![a-z0-9])/gi, '$1[.]$2');
    s = s.replace(/\s+/g, ' ').trim();
    if (s.length > maxLen) s = s.slice(0, maxLen - 1) + '…';
    return s;
  }

  /* ------------------------------------------------------------------ */
  /* Classifier                                                          */
  /* ------------------------------------------------------------------ */
  const T = {
    TINY_LIQ_USD: 1000,        // best pool below this = "tiny liquidity"
    LOW_LIQ_USD: 10000,
    KNOWN_LIQ_USD: 50000,      // established market: liquidity at least this ...
    KNOWN_AGE_DAYS: 30,        // ... and trading for at least this long
    VERY_NEW_DAYS: 3,
    IMPERSONATOR_LIQ_USD: 250000
  };

  /** Canonical EVM contracts for a few famous tokens (lowercase), used so real USDC/WETH are not flagged. */
  const CANONICAL_EVM = {
    ethereum: new Set([
      '0xdac17f958d2ee523a2206206994597c13d831ec7', // USDT
      '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', // USDC
      '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2', // WETH
      '0x6b175474e89094c44da98b954eedeac495271d0f', // DAI
      '0x2260fac5e5542a773aa44fbcfedf7c193bc2c599'  // WBTC
    ]),
    base: new Set([
      '0x4200000000000000000000000000000000000006', // WETH
      '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913', // USDC
      '0x50c5725949a6f0c72e6c4a641f24049a917db0cb', // DAI
      '0xcbb7c0000ab88b473b1f5afd9ef808440eed33bf'  // cbBTC
    ])
  };

  const WSOL_MINT = 'So11111111111111111111111111111111111111112';

  function fmtUsd(n) {
    if (n == null || !isFinite(n)) return '—';
    if (n >= 1e9) return '$' + (n / 1e9).toFixed(1) + 'B';
    if (n >= 1e6) return '$' + (n / 1e6).toFixed(1) + 'M';
    if (n >= 1e3) return '$' + (n / 1e3).toFixed(1) + 'K';
    return '$' + n.toFixed(n < 10 ? 2 : 0);
  }

  function fmtAge(days) {
    if (days == null || !isFinite(days)) return 'unknown';
    if (days < 1) return Math.max(1, Math.round(days * 24)) + ' hours';
    if (days < 60) return Math.round(days) + ' days';
    if (days < 730) return Math.round(days / 30) + ' months';
    return (days / 365).toFixed(1) + ' years';
  }

  /**
   * Classify one token.
   * token: { chain: 'solana'|'ethereum'|'base'|..., address, name, symbol, type?, decimals? ,
   *          jup?: { isVerified, tags[], organicScoreLabel, audit:{mintAuthorityDisabled, freezeAuthorityDisabled} },
   *          dex?: { checked: bool, pairCount, totalLiquidityUsd, maxLiquidityUsd, oldestPairMs },
   *          bs?: { reputation, exchangeRate, holders },
   *          zora?: { isZoraCoin: true, coinType: 'CONTENT'|'CREATOR', platformBlocked?, valueUsd?, createdByWallet? } }  (Zora API match, Base only)
   * now: ms timestamp (injectable for tests)
   * Returns { category: 'known'|'unknown'|'suspicious', kind: null|'postcoin'|'illiquid', label, reasons:[...], notes:[...], liquidityUsd, ageDays, badges:[] }
   * (`kind` is a sub-type of 'unknown': a Zora/Base social post coin, or a token whose ONLY issue is very low liquidity.)
   */
  function classifyToken(token, now) {
    now = now == null ? Date.now() : now;
    const reasons = [];   // why it landed in its category
    const notes = [];     // extra cautions
    const badges = [];

    const jup = token.jup || null;
    const dex = token.dex || null;
    const bs = token.bs || null;
    const isNft = /^ERC-(721|1155)$/.test(token.type || '') || token.nft === true;

    // Zora / Base "post coin": confirmed by the Zora API, or (fallback) a sentence-like name on Base where name == symbol.
    const zora = token.zora && token.zora.isZoraCoin ? token.zora : null;
    const postCoin = zora ? 'zora' : (!isNft && token.chain === 'base' && looksLikePostCoinName(token.name, token.symbol) ? 'heuristic' : null);
    const nameInfo = analyzeName(token.name, token.symbol, { postCoin: !!postCoin });
    const liq = dex && dex.checked ? (dex.maxLiquidityUsd || 0) : null;
    const totalLiq = dex && dex.checked ? (dex.totalLiquidityUsd || 0) : null;
    const ageDays = dex && dex.oldestPairMs ? (now - dex.oldestPairMs) / 86400000 : null;
    const pairCount = dex && dex.checked ? dex.pairCount || 0 : null;

    const addrLc = String(token.address || '').toLowerCase();
    const canonical = !!(CANONICAL_EVM[token.chain] && CANONICAL_EVM[token.chain].has(addrLc)) || token.address === WSOL_MINT;
    const jupVerified = !!(jup && (jup.isVerified || (jup.tags || []).includes('strict') || (jup.tags || []).includes('verified')));

    const out = (category, label, kind) => ({
      category, label, kind: kind || null, reasons, notes, badges,
      liquidityUsd: totalLiq, bestPoolUsd: liq, ageDays, pairCount, nameFlags: nameInfo
    });

    if (nameInfo.weak.length) notes.push(...nameInfo.weak);
    if (jup && jup.audit) {
      if (jup.audit.mintAuthorityDisabled === false) notes.push('The creator can still mint more of this token.');
      if (jup.audit.freezeAuthorityDisabled === false) notes.push('The creator can still freeze token accounts.');
    }
    if (jup && jup.organicScoreLabel === 'low') notes.push('Jupiter rates real trading activity for this token as low.');

    /* 1. Verified lists / canonical tokens win ---------------------------------- */
    if (jupVerified || canonical) {
      badges.push(canonical && !jupVerified ? 'Canonical token' : 'On Jupiter verified list');
      reasons.push(canonical && !jupVerified
        ? 'Matches a well-known official contract address.'
        : 'Listed as verified by Jupiter (a major Solana swap aggregator).');
      if (nameInfo.strong.length) notes.push('Name looks unusual for a verified token — double-check you are looking at the right one.');
      return out('known', 'Known / verified');
    }

    /* 2. Hard suspicious signals ------------------------------------------------- */
    // A token with a real, long-running market is not "suspicious" just because its name has a domain in it
    // (e.g. yearn.finance, saffron.finance). Hidden characters and unicode look-alikes still count.
    const established = !!(dex && dex.checked && pairCount > 0 && liq >= T.KNOWN_LIQ_USD && ageDays != null && ageDays >= T.KNOWN_AGE_DAYS);
    const sus = [];
    nameInfo.strong.forEach((msg, i) => {
      const kind = nameInfo.kinds[i];
      if (established && (kind === 'url' || kind === 'words' || kind === 'amount')) notes.push(msg + ' (It has an established market, so this may be a legitimate name.)');
      else sus.push(msg);
    });
    if (bs && bs.reputation && String(bs.reputation).toLowerCase() !== 'ok') {
      sus.push('The block explorer flags this token (reputation: "' + String(bs.reputation).slice(0, 20) + '").');
    }
    const major = impersonatesMajor(token.name, token.symbol);
    if (major && !canonical && !established && (liq == null || liq < T.IMPERSONATOR_LIQ_USD)) {
      sus.push('Uses the name/symbol of a famous token (' + major + ') but is not the official one. Bridged versions can be real, but fakes are common.');
    }
    if (zora && zora.platformBlocked) sus.push('Zora has blocked this coin on its own platform.');
    const tiny = !!(dex && dex.checked && pairCount > 0 && liq < T.TINY_LIQ_USD);
    const veryNew = !!(dex && dex.checked && pairCount > 0 && ageDays != null && ageDays < T.VERY_NEW_DAYS);
    // Market-shape signals never make a social post coin suspicious: post coins are usually born illiquid and brand new.
    if (!postCoin && veryNew) sus.push('Very new — first trading pool created ' + fmtAge(ageDays) + ' ago.');
    // Very low liquidity is a RISK NOTE, not proof of a scam. On its own it is "Unknown – illiquid";
    // it only counts toward Suspicious when combined with another warning sign.
    let illiquidOnly = false;
    if (tiny && !postCoin) {
      if (sus.length || nameInfo.weak.length) {
        sus.push('Very low liquidity (best pool ' + fmtUsd(liq) + ') combined with ' + (sus.length ? 'the warning signs above' : 'a bait-style word in the name') + ', so it cannot realistically be sold.');
      } else illiquidOnly = true;
    }
    if (sus.length) {
      reasons.push(...sus);
      return out('suspicious', 'Suspicious');
    }

    /* 3. Established market (liquidity + age) ----------------------------------- */
    if (established) {
      badges.push('Established market');
      reasons.push('Has real liquidity (best pool ' + fmtUsd(liq) + ') and has traded for ' + fmtAge(ageDays) + '. Not on a verified list, so still do your own research.');
      return out('known', 'Known / verified');
    }

    /* 4. Social post coins (Zora / Base app) ------------------------------------ */
    if (postCoin) {
      const mkt = tiny || pairCount === 0 || (liq != null && liq < T.LOW_LIQ_USD);
      if (zora) {
        badges.push(zora.coinType === 'CREATOR' ? 'Zora creator coin' : 'Zora post coin');
        reasons.push(zora.coinType === 'CREATOR'
          ? 'Confirmed Zora creator coin on Base (matched via the Zora API): a social token named after a creator profile.'
          : 'Confirmed Zora content coin on Base (matched via the Zora API): its name is simply the text of a social post, so it can contain line breaks, emoji and odd punctuation. That is normal for post coins.');
        if (zora.createdByWallet) reasons.push('This wallet created it.');
        if (zora.valueUsd != null && isFinite(zora.valueUsd)) notes.push('Zora values this holding at about ' + fmtUsd(Number(zora.valueUsd)) + '.');
      } else {
        badges.push('Looks like a post coin');
        reasons.push('Looks like a Zora/Base post coin (social content token): a long, sentence-like name that is also its own symbol. Not confirmed by the Zora API, so this is a name-pattern guess.');
      }
      if (mkt) notes.push('Illiquid: social post coins usually have little or no trading liquidity, so you may not be able to sell it for anything. That is a limitation, not a sign of a scam.');
      notes.push('The name is free text anyone can write — never click links in it.');
      return out('unknown', zora && zora.coinType === 'CREATOR' ? 'Social creator coin – usually harmless' : (zora ? 'Social post coin – usually harmless but illiquid' : 'Likely social post coin – usually harmless but illiquid'), 'postcoin');
    }

    /* 5. Everything else is Unknown ---------------------------------------------- */
    if (illiquidOnly) {
      reasons.push('Very low liquidity (best pool ' + fmtUsd(liq) + ')' + (ageDays != null ? ', trading for ' + fmtAge(ageDays) : '') + ', so it probably cannot be sold. That is a risk note, not proof of a scam — nothing else suspicious was found (no links, bait words, hidden characters or impersonation).');
      notes.push('Not on a verified list. If you did not buy it yourself, still ignore it.');
      return out('unknown', 'Unknown – illiquid', 'illiquid');
    }
    if (dex && dex.checked) {
      if (pairCount === 0) {
        reasons.push('No trading pairs found on DexScreener — no market data, so its value and safety cannot be judged.');
      } else {
        reasons.push('Thin or young market (best pool ' + fmtUsd(liq) + (ageDays != null ? ', ' + fmtAge(ageDays) + ' old' : '') + ') and not on a verified list.');
        if (liq < T.LOW_LIQ_USD) notes.push('Low liquidity: it may be hard or impossible to sell.');
      }
    } else if (isNft) {
      reasons.push('Collectible / NFT — not checked against market data. Unsolicited NFTs are a common scam vector.');
    } else if (dex && dex.error) {
      reasons.push('Could not check market data (' + dex.error + '). Treat as unknown.');
    } else {
      reasons.push('Not checked against market data (wallet has many tokens or the lookup was skipped). Treat as unknown.');
    }
    if (!token.name && !token.symbol) notes.push('No name or symbol could be found for this token.');
    return out('unknown', 'Unknown – no liquidity data');
  }

  function countPostCoins(classified) { return classified.filter((c) => c.kind === 'postcoin').length; }

  function summarize(classified) {
    const s = { total: classified.length, known: 0, unknown: 0, suspicious: 0 };
    for (const c of classified) s[c.category]++;
    return s;
  }

  return {
    // validators
    base58Decode, isBase58, keccak256Hex, isValidEip55, isEvmAddress, isSolanaAddress,
    looksLikeSeedPhrase, looksLikePrivateKey, inspectInput,
    // classifier
    analyzeName, findSuspiciousInvisible, looksLikePostCoinName, countPostCoins, impersonatesMajor, safeDisplay, classifyToken, summarize, fmtUsd, fmtAge, THRESHOLDS: T, WSOL_MINT
  };
});
