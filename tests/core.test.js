const test = require('node:test');
const assert = require('node:assert/strict');
const c = require('../lib/core.js');

const NOW = Date.UTC(2026, 9, 18);
const DAY = 86400000;
const dex = (o) => Object.assign({ checked: true, pairCount: 1, totalLiquidityUsd: 0, maxLiquidityUsd: 0, oldestPairMs: null }, o);
const cls = (t) => c.classifyToken(Object.assign({ chain: 'solana', address: 'X' }, t), NOW).category;

test('keccak256 + EIP-55 vectors', () => {
  assert.equal(c.keccak256Hex(''), 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
  assert.equal(c.keccak256Hex('abc'), '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45');
  for (const a of ['0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed', '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
    '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB', '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb']) assert.ok(c.isValidEip55(a), a);
  assert.ok(!c.isValidEip55('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD'));
});

test('validators: addresses', () => {
  assert.equal(c.inspectInput('86xCnPeV69n6t3DnyGvkKobf9FdN2H9oiVDdaMpo2MMY').kind, 'solana');
  assert.equal(c.inspectInput('  So11111111111111111111111111111111111111112 \n').kind, 'solana');
  assert.equal(c.inspectInput('11111111111111111111111111111111').kind, 'solana');
  assert.equal(c.inspectInput('0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045').kind, 'evm');
  assert.equal(c.inspectInput('0xd8da6bf26964af9d7eed9e03e53415d37aa96045').kind, 'evm'); // lowercase ok
  assert.equal(c.inspectInput('0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96046').kind, 'invalid'); // bad checksum
  assert.equal(c.inspectInput('0x1234').kind, 'invalid');
  assert.equal(c.inspectInput('').kind, 'empty');
  assert.equal(c.inspectInput('vitalik.eth').kind, 'invalid');
  assert.equal(c.inspectInput('toly.sol').kind, 'invalid');
  assert.equal(c.inspectInput('0OIl' + 'a'.repeat(40)).kind, 'invalid'); // forbidden base58 chars
  assert.equal(c.inspectInput('abc').kind, 'invalid');
  assert.equal(c.inspectInput('https://solscan.io/account/abc').kind, 'invalid');
  assert.equal(c.inspectInput('1 2').kind, 'invalid');
});

test('validators: seed phrases and private keys are refused', () => {
  const seed12 = 'abandon ability able about above absent absorb abstract absurd abuse access accident';
  const seed24 = (seed12 + ' ' + seed12).replace(/\s+/g, ' ');
  assert.equal(c.inspectInput(seed12).kind, 'seed');
  assert.equal(c.inspectInput(seed24).kind, 'seed');
  assert.equal(c.inspectInput('  ' + seed12.toUpperCase().replace(/ /g, '\n') + ' ').kind, 'seed');
  assert.equal(c.inspectInput('0x' + 'ab'.repeat(32)).kind, 'privatekey');
  assert.equal(c.inspectInput('ab'.repeat(32)).kind, 'privatekey');
  const sol64 = Array.from({ length: 64 }, (_, i) => (i * 7 + 3) & 255);
  assert.equal(c.inspectInput('[' + sol64.join(',') + ']').kind, 'privatekey');
  // base58 of 64 bytes (Solana secret key format)
  const A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let n = 0n; for (const b of [1, ...sol64.slice(1)]) n = n * 256n + BigInt(b);
  let s = ''; while (n > 0n) { s = A[Number(n % 58n)] + s; n /= 58n; }
  assert.equal(c.base58Decode(s).length, 64);
  assert.equal(c.inspectInput(s).kind, 'privatekey');
  assert.equal(c.inspectInput('5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ').kind, 'privatekey'); // WIF
  assert.equal(c.inspectInput('xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi').kind, 'privatekey');
  // messages never echo the secret
  assert.ok(!c.inspectInput(seed12).message.includes('abandon'));
});

test('analyzeName: links, bait words, lookalikes, hidden chars', () => {
  assert.ok(c.analyzeName('Visit https://claim-usdc.xyz to claim', 'AIRDROP').strong.length >= 2);
  assert.ok(c.analyzeName('USDC Reward', 'x').strong.length);
  assert.ok(c.analyzeName('Free $5000 Voucher', '').strong.length);
  assert.ok(c.analyzeName('t.me/scamgroup', 'SCAM').strong.length);
  assert.ok(c.analyzeName('Bonus on pepe-gift.com', 'PEPE').strong.length);
  assert.ok(c.analyzeName('USDТ', 'USDТ').strong.some((x) => /Cyrillic/.test(x))); // Cyrillic Т
  assert.ok(c.analyzeName('Ｕｓｄｃ', 'ＵＳＤＣ').strong.length);                   // fullwidth
  assert.ok(c.analyzeName('𝗨𝗦𝗗𝗖', '𝗨𝗦𝗗𝗖').strong.length);                           // math bold
  assert.ok(c.analyzeName('Rew\u200bard', 'X').strong.length);                       // zero-width space inside a word
  assert.ok(c.analyzeName('_eNFTGift.com', 'STAKE').strong.length);
  assert.ok(c.analyzeName('Reward-pepe.xyz', 'x').strong.length);
  // no false positives for normal / non-Latin names
  assert.equal(c.analyzeName('Wrapped SOL', 'SOL').strong.length, 0);
  assert.equal(c.analyzeName('Jupiter', 'JUP').strong.length, 0);
  assert.equal(c.analyzeName('比特币', 'BTC').strong.length, 0);
  assert.equal(c.analyzeName('Привет токен', 'ПТ').strong.length, 0); // pure Cyrillic is fine
  assert.equal(c.analyzeName('Bonk', 'BONK').strong.length, 0);
  assert.equal(c.analyzeName('Pepe', 'PEPE').strong.length, 0);
  assert.equal(c.analyzeName(null, null).strong.length, 0);
});

test('classifier: known / unknown / suspicious', () => {
  // verified list wins
  assert.equal(cls({ name: 'Jupiter', symbol: 'JUP', jup: { isVerified: true, tags: ['verified'] } }), 'known');
  assert.equal(cls({ name: 'x', jup: { isVerified: false, tags: ['strict'] } }), 'known');
  assert.equal(cls({ address: c.WSOL_MINT, name: 'Wrapped SOL', symbol: 'SOL' }), 'known');
  // canonical EVM
  assert.equal(c.classifyToken({ chain: 'ethereum', address: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', name: 'USD Coin', symbol: 'USDC' }, NOW).category, 'known');
  // established market
  assert.equal(cls({ name: 'Real', symbol: 'RL', dex: dex({ maxLiquidityUsd: 300000, totalLiquidityUsd: 400000, oldestPairMs: NOW - 200 * DAY }) }), 'known');
  // liquid but young-ish (10 days) -> unknown
  assert.equal(cls({ name: 'Mid', symbol: 'MID', dex: dex({ maxLiquidityUsd: 300000, oldestPairMs: NOW - 10 * DAY }) }), 'unknown');
  // no pairs -> unknown
  assert.equal(cls({ name: 'Ghost', symbol: 'GST', dex: dex({ pairCount: 0 }) }), 'unknown');
  // lookup failed -> unknown, with explicit reason
  const failed = c.classifyToken({ chain: 'solana', address: 'X', name: 'A', dex: { checked: false, error: 'rate limited' } }, NOW);
  assert.equal(failed.category, 'unknown'); assert.match(failed.reasons[0], /Could not check/);
  // tiny liquidity ALONE is a risk note -> unknown (illiquid), not suspicious (see 'low liquidity' tests below)
  assert.equal(cls({ name: 'Tiny', symbol: 'TNY', dex: dex({ maxLiquidityUsd: 120, oldestPairMs: NOW - 90 * DAY }) }), 'unknown');
  // very new -> suspicious
  assert.equal(cls({ name: 'New', symbol: 'NEW', dex: dex({ maxLiquidityUsd: 90000, oldestPairMs: NOW - 6 * 3600000 }) }), 'suspicious');
  // name bait -> suspicious even with no market data
  assert.equal(cls({ name: 'Claim your reward at reward-now.xyz', symbol: 'GIFT', dex: dex({ pairCount: 0 }) }), 'suspicious');
  assert.equal(cls({ name: 'Airdrop', symbol: 'AIR' }), 'suspicious');
  // impersonating a major token
  assert.equal(cls({ name: 'USD Coin', symbol: 'USDC', dex: dex({ pairCount: 0 }) }), 'suspicious');
  assert.equal(c.classifyToken({ chain: 'ethereum', address: '0x1111111111111111111111111111111111111111', name: 'Tether USD', symbol: 'USDT', dex: dex({ maxLiquidityUsd: 50 , oldestPairMs: NOW - 100 * DAY}) }, NOW).category, 'suspicious');
  // domain-style names with a long-running real market are not flagged (yearn.finance), but hidden chars still are
  assert.equal(cls({ name: 'yearn.finance', symbol: 'YFI', dex: dex({ maxLiquidityUsd: 900000, oldestPairMs: NOW - 900 * DAY }) }), 'known');
  assert.equal(cls({ name: 'Rew\u200bard', symbol: 'YFI', dex: dex({ maxLiquidityUsd: 900000, oldestPairMs: NOW - 900 * DAY }) }), 'suspicious');
  assert.equal(cls({ name: 'Aave', symbol: 'AAVE', dex: dex({ maxLiquidityUsd: 165000, oldestPairMs: NOW - 900 * DAY }) }), 'known');
  // explorer reputation
  assert.equal(c.classifyToken({ chain: 'base', address: '0x2', name: 'Foo', symbol: 'FOO', bs: { reputation: 'scam' } }, NOW).category, 'suspicious');
  assert.equal(c.classifyToken({ chain: 'base', address: '0x2', name: 'Foo', symbol: 'FOO', bs: { reputation: 'ok' } }, NOW).category, 'unknown');
  // NFTs unchecked -> unknown, spam NFT with link -> suspicious
  assert.equal(c.classifyToken({ chain: 'ethereum', address: '0x3', name: 'Cool Apes', symbol: 'CA', type: 'ERC-721' }, NOW).category, 'unknown');
  assert.equal(c.classifyToken({ chain: 'ethereum', address: '0x3', name: 'Visit apes-mint.com for reward', symbol: 'CA', type: 'ERC-721' }, NOW).category, 'suspicious');
  // verified token with odd name keeps "known" but adds a note
  const v = c.classifyToken({ chain: 'solana', address: 'X', name: 'pump.fun', symbol: 'PF', jup: { isVerified: true, tags: [] } }, NOW);
  assert.equal(v.category, 'known'); assert.ok(v.notes.length);
  // mint authority note
  const n = c.classifyToken({ chain: 'solana', address: 'X', name: 'A', jup: { isVerified: true, audit: { mintAuthorityDisabled: false } } }, NOW);
  assert.ok(n.notes.some((x) => /mint more/.test(x)));
});

test('safeDisplay defangs links and reveals hidden characters', () => {
  assert.equal(c.safeDisplay('Visit https://evil.xyz now'), 'Visit hxxps://evil[.]xyz now');
  assert.equal(c.safeDisplay('_eNFTGift.com'), '_eNFTGift[.]com');
  assert.equal(c.safeDisplay('a\u200bb'), 'a·b');
  assert.equal(c.safeDisplay('x'.repeat(100), 10).length, 10);
  assert.ok(!c.safeDisplay('<img src=x onerror=alert(1)>').includes('\n'));
});

test('summarize + formatting', () => {
  const s = c.summarize([{ category: 'known' }, { category: 'unknown' }, { category: 'unknown' }, { category: 'suspicious' }]);
  assert.deepEqual(s, { total: 4, known: 1, unknown: 2, suspicious: 1 });
  assert.equal(c.fmtUsd(1500000), '$1.5M'); assert.equal(c.fmtUsd(null), '—'); assert.equal(c.fmtAge(0.2), '5 hours');
});

/* ---------------------------------------------------------------------------------------------------------------- */
/* Zora / Base "post coins": names are post text. Regression tests for the false positives seen on a real wallet.   */
/* ---------------------------------------------------------------------------------------------------------------- */
const ZWSP = '\u200b', ZWJ = '\u200d', VS16 = '\ufe0f', RLO = '\u202e';
// Exact name of Zora coin 0x80bb…9bd055 as returned by the Zora API: newline followed by a zero-width space.
const POST_NAME = 'Everything feels heavy today. I know.\n' + ZWSP + 'But remember: You survive';
const hiddenFlag = (name, symbol) => c.analyzeName(name, symbol).kinds.includes('hidden');
const zoraTok = (name, extra) => Object.assign({ chain: 'base', address: '0x80bbec9baf311794d16fc2172a330b37209bd055', name, symbol: name, type: 'ERC-20',
  zora: { isZoraCoin: true, coinType: 'CONTENT', createdByWallet: false, valueUsd: 0 } }, extra);   // someone else's coin by default

test('hidden chars: legitimate post-text characters are NOT flagged', () => {
  assert.ok(!hiddenFlag(POST_NAME, POST_NAME), 'newline + ZWSP after the line break (Zora formatting)');
  assert.ok(!hiddenFlag(ZWSP + 'I DON’T CHECK CHARTS ON DECK'), 'leading ZWSP');
  assert.ok(!hiddenFlag('MEET $ZAHRAH' + ZWSP), 'trailing ZWSP');
  assert.ok(!hiddenFlag('ANNUIT BASED 🤝🟦' + ZWSP + 'FAVORED BY THE'), 'ZWSP between emoji and a letter');
  assert.ok(!hiddenFlag(ZWSP + '$1M IN 2026 IS URS ALLAH WILLING'), 'leading ZWSP before $');
  assert.ok(!hiddenFlag('Don’t you dare give up‼' + VS16), 'VS16 after ‼');
  assert.ok(!hiddenFlag('MORNING TALKS 🗣' + VS16), 'VS16 after emoji');
  assert.ok(!hiddenFlag('NEW STYLUS PEN ✍' + VS16 + '🟦'), 'VS16 mid-text');
  assert.ok(!hiddenFlag('BASEDMORNING🥶GOODMORNING😶' + ZWJ + '🌫'), 'ZWJ inside an emoji sequence');
  assert.ok(!hiddenFlag('family 👨' + ZWJ + '👩' + ZWJ + '👧' + ZWJ + '👦 post'), 'ZWJ family emoji');
  assert.ok(!hiddenFlag('coder 👩🏽' + ZWJ + '💻 here'), 'ZWJ with skin-tone modifier');
  assert.ok(!hiddenFlag('rainbow 🏳' + VS16 + ZWJ + '🌈'), 'VS16 + ZWJ');
  assert.ok(!hiddenFlag('keycap 1' + VS16 + '\u20e3 first'), 'keycap sequence');
  assert.ok(!hiddenFlag('line one\r\nline two\n\n\tindented  text   with   spaces'), 'plain newlines / tabs / spaces are not even invisible chars');
  assert.ok(!hiddenFlag('فارسی' + '\u200c' + 'می'), 'ZWNJ inside Arabic-script text');
  assert.ok(!hiddenFlag('שלום \u200f hello'), 'RLM next to Hebrew');
  assert.ok(!hiddenFlag('England 🏴\u{e0067}\u{e0062}\u{e0065}\u{e006e}\u{e0067}\u{e007f} flag'), 'tag characters inside a flag emoji');
  assert.ok(!hiddenFlag('x' + 'a '.repeat(3) + ZWSP + ZWSP + ZWSP), 'a few edge ZWSPs are fine');
});

test('hidden chars: real tricks are still flagged', () => {
  assert.ok(hiddenFlag('USD' + ZWSP + 'C', 'USDC'), 'ZWSP splitting a word');
  assert.ok(hiddenFlag('Rew' + ZWSP + 'ard'), 'ZWSP inside "Reward"');
  assert.ok(hiddenFlag('Visit' + ZWSP + '5000USDT'), 'ZWSP between letter and digit');
  assert.ok(hiddenFlag('gnp.exe' + RLO + 'txt'), 'RLO (right-to-left override)');
  assert.ok(hiddenFlag('USDC' + RLO), 'trailing RLO');
  assert.ok(hiddenFlag('abc\u202a def'), 'LRE embedding');
  assert.ok(hiddenFlag('abc\u2066def\u2069'), 'bidi isolates');
  assert.ok(hiddenFlag('Pa' + '\u2060' + 'ypal'), 'word joiner');
  assert.ok(hiddenFlag('Pay\u2063pal'), 'invisible separator');
  assert.ok(hiddenFlag('Pay\u00adpal'), 'soft hyphen');
  assert.ok(hiddenFlag('Token\u3164\u3164'), 'Hangul filler');
  assert.ok(hiddenFlag('Token\ufeffX'), 'BOM / ZWNBSP');
  assert.ok(hiddenFlag('Co' + ZWJ + 'in'), 'ZWJ between Latin letters');
  assert.ok(hiddenFlag('Coin' + VS16), 'VS16 after a plain letter');
  assert.ok(hiddenFlag('plain \u200e text'), 'LRM in text with no RTL script');
  assert.ok(hiddenFlag('t\u{e0061}\u{e0062}ag'), 'tag characters outside a flag emoji');
  assert.ok(hiddenFlag('Visit US' + ZWSP + ZWSP + ZWSP + ZWSP + ' now'), 'abnormal number of ZWSPs');
  // and hidden characters never hide bait: stripped before link / bait-word matching
  assert.ok(c.analyzeName('cl' + ZWSP + 'aim', '').kinds.includes('words'));
  assert.ok(c.analyzeName('evil' + ZWSP + '.com', '').kinds.includes('url'));
});

test('safeDisplay: keeps emoji intact, drops harmless ZWSP, reveals tricks', () => {
  assert.equal(c.safeDisplay(POST_NAME, 100), 'Everything feels heavy today. I know. But remember: You survive');
  assert.equal(c.safeDisplay(POST_NAME, 60), 'Everything feels heavy today. I know. But remember: You sur…');
  assert.equal(c.safeDisplay('😶' + ZWJ + '🌫 ok'), '😶' + ZWJ + '🌫 ok');
  assert.equal(c.safeDisplay('USD' + ZWSP + 'C'), 'USD·C');
  assert.equal(c.safeDisplay('abc' + RLO + 'def'), 'abc·def');
});

test('post coins: Zora-confirmed post text is Unknown (social post coin), never Suspicious', () => {
  const dexNew = dex({ maxLiquidityUsd: 0, totalLiquidityUsd: 0, oldestPairMs: NOW - 3600000 });   // tiny AND brand new: still fine for a post coin
  for (const d of [undefined, dexNew, dex({ pairCount: 0 }), { checked: false, error: 'rate limited' }]) {
    const r = c.classifyToken(zoraTok(POST_NAME, { dex: d }), NOW);
    assert.equal(r.category, 'unknown', JSON.stringify(r.reasons));
    assert.equal(r.kind, 'postcoin');
    assert.match(r.label, /Social post coin/);
    assert.match(r.reasons[0], /Zora content coin/);
    assert.equal(r.nameFlags.strong.length, 0);
  }
  // ZWJ / VS16 / newline / long text variants
  for (const n of ['BASEDMORNING🥶GOODMORNING😶' + ZWJ + '🌫', 'Don’t you dare give up‼' + VS16, ZWSP + '🎁' + VS16 + ' gm\n\nlong long long long long long long long long long long long long long long long long long long long long long long',
    '𝐂𝐓 𝐥𝐢𝐟𝐞 𝕏 post', 'They say nothing is free, but on Base it is $0 and a dream.', 'EARNED $15.08 ON ZORA', 'GM FROM ME AND @JESSE.BASE.ETH']) {
    assert.equal(c.classifyToken(zoraTok(n, { dex: dexNew }), NOW).category, 'unknown', n);
  }
  // creator coin gets its own wording
  const cr = c.classifyToken({ chain: 'base', address: '0x3a0f', name: 'zahrah', symbol: 'zahrah', zora: { isZoraCoin: true, coinType: 'CREATOR' } }, NOW);
  assert.equal(cr.category, 'unknown'); assert.equal(cr.kind, 'postcoin'); assert.match(cr.label, /creator coin/);
});

test('post coins: real scam signals still make them Suspicious', () => {
  const bad = (n, re) => {
    const r = c.classifyToken(zoraTok(n), NOW);
    assert.equal(r.category, 'suspicious', n);
    if (re) assert.match(r.reasons.join(' '), re);
    return r;
  };
  bad('GET READY FOR AIRDROP', /bait words/);
  bad('🪂 BASE AIRDROP STRATEGY', /bait words/);
  bad('Claim your reward now', /bait words/);
  bad('Check this out https://evil-site.xyz/free', /link or website/);
  bad('Comment your profile zora.co/zahra', /link or website/);
  bad('t.me/scamgroup join', /link or website/);
  bad('CLAIM UP TO $30,100 ON BYBIT', /bait words/);
  bad('Free $5000 giveaway today', /amount of money|bait/);
  bad('USD' + ZWSP + 'C airdrop-ish text here', /hidden|bait/);
  bad('Text that reads fine ' + RLO + 'but is reversed', /text-direction/);
  bad('Sentence with Cyrillic о and Latin letters together in one post');            // Cyrillic о mixed with Latin
  const blocked = c.classifyToken(zoraTok('A perfectly normal looking sentence here', { zora: { isZoraCoin: true, coinType: 'CONTENT', platformBlocked: true } }), NOW);
  assert.equal(blocked.category, 'suspicious'); assert.match(blocked.reasons.join(' '), /Zora has blocked/);
  // a post coin pretending to be a famous token
  assert.equal(c.classifyToken(zoraTok('USDC'), NOW).category, 'suspicious');
  assert.equal(c.classifyToken(zoraTok('𝗨𝗦𝗗𝗖'), NOW).category, 'suspicious');
});

test('post coins: name-pattern fallback when the Zora API did not confirm', () => {
  const guess = (name, extra) => c.classifyToken(Object.assign({ chain: 'base', address: '0x1', name, symbol: name, type: 'ERC-20' }, extra), NOW);
  const r = guess(POST_NAME, { dex: dex({ maxLiquidityUsd: 3, oldestPairMs: NOW - 90 * DAY }) });
  assert.equal(r.category, 'unknown'); assert.equal(r.kind, 'postcoin');
  assert.match(r.label, /Likely social post coin/); assert.match(r.reasons[0], /Looks like a Zora\/Base post coin/);
  assert.equal(guess('EVERYBODY DOESN\'T DESERVE TO BE').kind, 'postcoin');          // 31-char upper-case Zora style
  assert.equal(guess('BASEDMORNING🥶GOODMORNING😶' + ZWJ + '🌫').category, 'unknown');
  // bait / links still win over the heuristic
  assert.equal(guess('GET READY FOR AIRDROP and more text').category, 'suspicious');
  assert.equal(guess('Please look at https://evil-site.xyz for the full story').category, 'suspicious');
  // not post-like: short normal names, other chains, name != symbol, NFTs
  assert.equal(guess('Pepe').kind, null);
  assert.equal(c.classifyToken({ chain: 'base', address: '0x1', name: 'Western Gold Reserve', symbol: 'WESTERN GOLD RESERVE', type: 'ERC-20' }, NOW).kind, null);   // < 24 chars, 3 words
  assert.equal(c.classifyToken({ chain: 'ethereum', address: '0x1', name: POST_NAME, symbol: POST_NAME, type: 'ERC-20' }, NOW).kind, null);
  assert.equal(c.classifyToken({ chain: 'base', address: '0x1', name: POST_NAME, symbol: 'SHORT', type: 'ERC-20' }, NOW).kind, null);
  assert.equal(c.classifyToken({ chain: 'base', address: '0x1', name: POST_NAME, symbol: POST_NAME, type: 'ERC-721' }, NOW).kind, null);
  assert.equal(c.looksLikePostCoinName('Wrapped Ether', 'WETH'), false);
  assert.equal(c.looksLikePostCoinName('Telegram @TronVanity88_bot', 'Telegram @TronVanity88_bot'), false);   // contact-advert spam is not a post
  assert.equal(c.countPostCoins([{ kind: 'postcoin' }, { kind: null }, {}]), 1);
});

test('low liquidity: Solana / exempt tokens stay "Unknown – illiquid"; EVM tokens with no usable market become "Likely airdrop spam"', () => {
  // Solana: tiny liquidity alone is a risk note (old behaviour kept)
  const sol = c.classifyToken({ chain: 'solana', address: 'X', name: 'Western Gold Reserve', symbol: 'WGR', dex: dex({ maxLiquidityUsd: 4.49, totalLiquidityUsd: 4.49, oldestPairMs: NOW - 62 * DAY }) }, NOW);
  assert.equal(sol.category, 'unknown'); assert.equal(sol.kind, 'illiquid'); assert.equal(sol.label, 'Unknown – illiquid');
  assert.match(sol.reasons[0], /risk note, not proof of a scam/);
  // + very new / bait-style weak word / hard signal / explorer flag -> suspicious
  assert.equal(c.classifyToken({ chain: 'solana', address: 'X', name: 'WGR', symbol: 'WGR', dex: dex({ maxLiquidityUsd: 4, oldestPairMs: NOW - 3600000 }) }, NOW).category, 'suspicious');
  assert.equal(cls({ name: 'Free Gold', symbol: 'FGOLD', dex: dex({ maxLiquidityUsd: 4, oldestPairMs: NOW - 90 * DAY }) }), 'suspicious');
  const both = c.classifyToken({ chain: 'solana', address: 'X', name: 'Claim reward', symbol: 'X', dex: dex({ maxLiquidityUsd: 4, oldestPairMs: NOW - 90 * DAY }) }, NOW);
  assert.equal(both.category, 'suspicious'); assert.ok(both.reasons.some((x) => /Very low liquidity/.test(x)));
  // EVM: "Western Gold Reserve" ($4.49 pool, unsolicited, not listed) is now Likely airdrop spam (heuristic), with the evidence spelled out
  const wgr = c.classifyToken({ chain: 'base', address: '0xc3c49edB33df49F8d875F326a3b735689730A749', name: 'Western Gold Reserve', symbol: 'WESTERN GOLD RESERVE', type: 'ERC-20',
    dex: dex({ maxLiquidityUsd: 4.49, totalLiquidityUsd: 4.49, oldestPairMs: NOW - 62 * DAY }) }, NOW);
  assert.equal(wgr.category, 'suspicious'); assert.equal(wgr.kind, 'airdropspam'); assert.equal(wgr.label, 'Likely airdrop spam');
  assert.match(wgr.reasons[0], /heuristic, not proof/); assert.match(wgr.reasons[0], /\$4\.49/);
  assert.equal(wgr.confidence, 'low'); assert.ok(wgr.evidence.some((e) => e.sev === 'risk'));
  // exempt: explorer has a price for it / DeFi position names / NFTs / lookups that failed / decent thin market
  const evm = (o) => c.classifyToken(Object.assign({ chain: 'base', address: '0x5', name: 'Gold', symbol: 'G', type: 'ERC-20' }, o), NOW);
  assert.equal(evm({ bs: { exchangeRate: '0.5' }, dex: dex({ pairCount: 0 }) }).category, 'unknown');
  assert.equal(evm({ name: 'Aerodrome vAMM-USDC/WETH', symbol: 'vAMM-USDC/WETH', dex: dex({ pairCount: 0 }) }).category, 'unknown');
  assert.equal(evm({ type: 'ERC-721', dex: undefined }).category, 'unknown');
  assert.equal(evm({ dex: { checked: false, error: 'rate limited' } }).category, 'unknown');
  assert.equal(evm({ dex: dex({ maxLiquidityUsd: 5000, effectiveLiquidityUsd: 5000, oldestPairMs: NOW - 90 * DAY }) }).kind, null);
  assert.equal(evm({ dex: dex({ maxLiquidityUsd: 5000, effectiveLiquidityUsd: 5000, oldestPairMs: NOW - 90 * DAY }) }).category, 'unknown');
  // no pool at all -> spam; and a name flag adds to it rather than replacing it
  assert.equal(evm({ dex: dex({ pairCount: 0 }) }).kind, 'airdropspam');
  assert.equal(evm({ name: 'Credits', symbol: 'CREDITS', dex: dex({ pairCount: 0 }) }).label, 'Likely airdrop spam');
  const spamPlus = evm({ name: 'Claim reward', symbol: 'X', dex: dex({ pairCount: 0 }) });
  assert.equal(spamPlus.category, 'suspicious'); assert.equal(spamPlus.label, 'Suspicious');
  // Zora coins and heuristic post coins are never "airdrop spam" just because they have no market
  assert.equal(c.classifyToken(zoraTok(POST_NAME, { dex: dex({ pairCount: 0 }) }), NOW).category, 'unknown');
  // never judged when there is no market data at all
  assert.equal(evm({ dex: undefined }).category, 'unknown');
});

test('hollow pools: a huge "liquidity" figure with almost nothing on the quote side is not a real market', () => {
  // DexScreener says $732K but only ~$1.3 of ETH sits in the pool (the rest is the token valued at its own price)
  const hollow = c.classifyToken({ chain: 'base', address: '0x88Dc2910CDE113d68708f189cAe9fe6A37e624B2', name: 'Fidelity Oil Us Reserve', symbol: 'FOUR',
    dex: dex({ maxLiquidityUsd: 732015, totalLiquidityUsd: 732015, effectiveLiquidityUsd: 2.6, fdvUsd: 1006520, volume24Usd: 0.09, txns24: 9, oldestPairMs: NOW - 116 * DAY }) }, NOW);
  assert.equal(hollow.category, 'suspicious'); assert.equal(hollow.kind, 'airdropspam'); assert.equal(hollow.hollowPool, true);
  assert.match(hollow.reasons[0], /\$732\.0K pool/); assert.match(hollow.reasons[0], /own supply/);
  assert.ok(hollow.evidence.some((e) => /market cap/.test(e.text)));
  // a genuinely balanced, trading, long-running pool is still Known
  const real = c.classifyToken({ chain: 'base', address: '0x5ab000ff9b9ffe0349ce5ffa5fd86f217c3680f5', name: 'The Stonks Exchange', symbol: 'STONKEX', lists: { checked: true, coingecko: true },
    dex: dex({ maxLiquidityUsd: 312061, effectiveLiquidityUsd: 312061, volume24Usd: 56620, txns24: 418, oldestPairMs: NOW - 55 * DAY }) }, NOW);
  assert.equal(real.category, 'known');
  // big liquidity but no real volume (dormant) and not listed -> Unknown – dormant, not Known and not Suspicious
  const dormant = c.classifyToken({ chain: 'base', address: '0x3', name: 'Quiet Coin', symbol: 'QUIET', dex: dex({ maxLiquidityUsd: 400000, effectiveLiquidityUsd: 400000, volume24Usd: 1.5, txns24: 300, oldestPairMs: NOW - 200 * DAY }) }, NOW);
  assert.equal(dormant.category, 'unknown'); assert.equal(dormant.kind, 'dormant'); assert.match(dormant.label, /dormant/);
});

test('amounts: "$0" is not bait, real amounts still are', () => {
  assert.equal(c.analyzeName('it is $0 and a dream', '').strong.length, 0);
  assert.ok(c.analyzeName('Win $100 today', '').kinds.includes('amount'));
  assert.ok(c.analyzeName('1,000 USDT', '').kinds.includes('amount'));
});

/* ---------------------------------------------------------------------------------------------------------------- */
/* Zora coins created by the scanned wallet / with real traction; Coinbase-issued assets; token lists; GoPlus        */
/* ---------------------------------------------------------------------------------------------------------------- */
const own = (extra) => Object.assign({ isZoraCoin: true, coinType: 'CONTENT', createdByWallet: true, creatorHandle: 'zahrah', uniqueHolders: 2, volumeUsd: 0 }, extra);

test('Zora: a coin the scanned wallet created itself is never flagged for its own post text', () => {
  for (const text of ['\u200b🏆 CLAIM UP TO $30,100, ON BYBIT', 'HTTPS://YOUTUBE.COM/SHORTS/CBCKY', 'TEAM $5 REWARD WEEKLY', '#1 is backing creators\n\nComment your zora profile zora.co/@zahrah', 'Don’t miss out.\nI\'m live!\nhttps://vt.tiktok.com/ZSabc']) {
    const r = c.classifyToken(zoraTok(text, { zora: own() }), NOW);
    assert.equal(r.category, 'unknown', text); assert.equal(r.kind, 'postcoin'); assert.equal(r.label, 'Your own Zora post coin');
    assert.ok(r.badges.includes('Created by this wallet'));
    assert.match(r.summary, /you created yourself/);
    assert.ok(r.notes.some((n) => /created by YOUR wallet/.test(n)), 'the text flag is kept as a note so nothing is hidden');
  }
  // its own creator coin gets its own label
  const cr = c.classifyToken({ chain: 'base', address: '0x3a0f', name: 'zahrah', symbol: 'zahrah', zora: own({ coinType: 'CREATOR' }) }, NOW);
  assert.equal(cr.label, 'Your own Zora creator coin');
  // …but Zora blocking its own platform coin is still reported
  assert.equal(c.classifyToken(zoraTok('CLAIM reward now', { zora: own({ platformBlocked: true }) }), NOW).category, 'suspicious');
});

test('Zora: someone else\'s coin with link/bait text is Suspicious unless it shows real traction', () => {
  const other = (extra) => ({ isZoraCoin: true, coinType: 'CONTENT', createdByWallet: false, creatorHandle: 'someone', ...extra });
  assert.equal(c.classifyToken(zoraTok('CREATOR REWARDS', { zora: other({ uniqueHolders: 0, volumeUsd: 0 }) }), NOW).category, 'suspicious');
  assert.equal(c.classifyToken(zoraTok('CREATOR REWARDS', { zora: other({ uniqueHolders: 3, volumeUsd: 5 }) }), NOW).category, 'suspicious');
  assert.equal(c.classifyToken(zoraTok('CREATOR REWARDS', { zora: other({ uniqueHolders: 21, volumeUsd: 4.66 }) }), NOW).category, 'unknown');   // 21 holders + traded: real coin
  assert.equal(c.classifyToken(zoraTok('CREATOR REWARDS', { zora: other({ uniqueHolders: 500, volumeUsd: 0.2 }) }), NOW).category, 'suspicious'); // holders alone without volume is not enough
  // hidden-character / look-alike tricks in someone else's coin are not excused by traction
  assert.equal(c.classifyToken(zoraTok('Text that reads fine ' + RLO + 'but is reversed', { zora: other({ uniqueHolders: 99, volumeUsd: 99 }) }), NOW).category, 'suspicious');
  // impersonation by someone else's coin is still flagged; by your own coin it is not
  assert.equal(c.classifyToken(zoraTok('USDC', { zora: other() }), NOW).category, 'suspicious');
  assert.equal(c.classifyToken(zoraTok('USDC', { zora: own() }), NOW).category, 'unknown');
});

const CBBTC = '0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf';
test('Coinbase: official wrapped assets are matched by exact contract address and shown as Known', () => {
  const cb = (chain, address, name, symbol, extra) => c.classifyToken(Object.assign({ chain, chainLabel: chain, address, name, symbol, type: 'ERC-20' }, extra), NOW);
  const real = [
    ['base', CBBTC, 'Coinbase Wrapped BTC', 'cbBTC'], ['ethereum', CBBTC, 'Coinbase Wrapped BTC', 'cbBTC'],
    ['base', '0x2Ae3F1Ec7F1F5012CFEab0185bfc7aa3cf0DEc22', 'Coinbase Wrapped Staked ETH', 'cbETH'], ['ethereum', '0xBe9895146f7AF43049ca1c1AE358B0541Ea49704', 'Coinbase Wrapped Staked ETH', 'cbETH'],
    ['base', '0xcb585250f852C6c6bf90434AB21A00f02833a4af', 'Coinbase Wrapped XRP', 'cbXRP'], ['base', '0xcbD06E5A2B0C65597161de254AA074E489dEb510', 'Coinbase Wrapped DOGE', 'cbDOGE'],
    ['base', '0xcb17C9Db87B595717C857a08468793f5bAb6445F', 'Coinbase Wrapped LTC', 'cbLTC'], ['base', '0xcbADA732173e39521CDBE8bf59a6Dc85A9fc7b8c', 'Coinbase Wrapped ADA', 'cbADA']];
  for (const [chain, addr, name, sym] of real) {
    // even with no market data, no token lists, tiny liquidity or odd data, the exact contract is Known
    for (const extra of [{}, { dex: dex({ pairCount: 0 }) }, { dex: dex({ maxLiquidityUsd: 3 }) }, { dex: { checked: false, error: 'x' } }]) {
      const r = cb(chain, addr, name, sym, extra);
      assert.equal(r.category, 'known', chain + ' ' + sym); assert.equal(r.kind, 'coinbase'); assert.ok(r.badges.includes('Coinbase-issued'));
      assert.match(r.reasons[0], /Official Coinbase asset/);
    }
  }
  // the same contract is recognised case-insensitively
  assert.equal(cb('base', CBBTC.toLowerCase(), 'x', 'x').category, 'known');
  // the real cbBTC address only counts on the chains Coinbase published it for
  assert.notEqual(cb('arbitrum', CBBTC, 'Coinbase Wrapped BTC', 'cbBTC').kind, 'coinbase');
});

test('Coinbase: look-alikes with the right name but the wrong contract are flagged, with a clear reason', () => {
  // the counterfeit seen on the scanned wallet: misspelt "Wrappped", wrong contract
  const fake = c.classifyToken({ chain: 'base', chainLabel: 'Base', address: '0x40faa04e54a6f3c6f85b3114bb04890dc77b8be3', name: 'Coinbase Wrappped BTC', symbol: 'cbBTC', type: 'ERC-20', dex: dex({ pairCount: 0 }) }, NOW);
  assert.equal(fake.category, 'suspicious');
  assert.match(fake.reasons[0], /Claims to be a Coinbase asset/); assert.match(fake.reasons[0], new RegExp(CBBTC.toLowerCase()));
  assert.ok(!/Bridged versions can be real/.test(fake.reasons.join(' ')));
  // correctly spelt name, wrong address
  for (const [name, sym] of [['Coinbase Wrapped BTC', 'cbBTC'], ['Coinbase Wrapped XRP', 'cbXRP'], ['Coinbase Wrapped Staked ETH', 'cbETH'], ['Coinbase Wrapped DOGE', 'CBDOGE']]) {
    const r = c.classifyToken({ chain: 'base', address: '0x1111111111111111111111111111111111111111', name, symbol: sym, type: 'ERC-20', dex: dex({ maxLiquidityUsd: 80000, effectiveLiquidityUsd: 80000, volume24Usd: 5000, oldestPairMs: NOW - 120 * DAY }) }, NOW);
    assert.equal(r.category, 'suspicious', name); assert.match(r.reasons[0], /Coinbase/);
  }
  // a normal token that merely mentions "base" or "coin" is not a Coinbase claim
  assert.equal(c.claimsCoinbase('Base God', 'BGOD'), false); assert.equal(c.claimsCoinbase('Coinbase Fan Club', 'CBFC'), false); assert.equal(c.claimsCoinbase('Coinbase Wrapped BTC', 'x'), true);
});

test('token lists: Uniswap / Superchain membership = Known; CoinGecko alone only counts with a real market', () => {
  const t = (extra) => c.classifyToken(Object.assign({ chain: 'base', address: '0x7', name: 'Some Token', symbol: 'SOME', type: 'ERC-20' }, extra), NOW);
  const r = t({ lists: { checked: true, uniswap: true }, dex: dex({ pairCount: 0 }) });
  assert.equal(r.category, 'known'); assert.match(r.reasons[0], /Uniswap default token list/); assert.ok(r.badges.includes('On Uniswap default list'));
  assert.equal(t({ lists: { checked: true, superchain: true } }).category, 'known');
  // curated list beats a bait-looking name (kept as a note)
  const odd = t({ name: 'yearn.finance', lists: { checked: true, uniswap: true } });
  assert.equal(odd.category, 'known'); assert.ok(odd.notes.some((n) => /unusual/.test(n)));
  // CoinGecko only: dead/no market -> NOT known (the "SALUKI" case), flagged as spam with the CoinGecko caveat
  const saluki = t({ name: 'SALUKI', symbol: 'SALUKI', lists: { checked: true, coingecko: true }, dex: dex({ pairCount: 0 }) });
  assert.equal(saluki.category, 'suspicious'); assert.equal(saluki.label, 'Likely airdrop spam');
  assert.ok(saluki.notes.some((n) => /CoinGecko/.test(n)));
  // CoinGecko + live market -> Known
  const live = t({ lists: { checked: true, coingecko: true }, dex: dex({ maxLiquidityUsd: 15000, effectiveLiquidityUsd: 15000, volume24Usd: 900, oldestPairMs: NOW - 30 * DAY }) });
  assert.equal(live.category, 'known'); assert.match(live.reasons[0], /CoinGecko/);
  // CoinGecko + dormant market -> not Known
  assert.notEqual(t({ lists: { checked: true, coingecko: true }, dex: dex({ maxLiquidityUsd: 15000, effectiveLiquidityUsd: 15000, volume24Usd: 0, oldestPairMs: NOW - 30 * DAY }) }).category, 'known');
  // lists that could not be loaded never make anything Known or suspicious by themselves
  const none = t({ lists: null, dex: { checked: false, error: 'x' } });
  assert.equal(none.category, 'unknown'); assert.equal(none.checked.find((x) => x.name === 'Token lists').status, 'unavailable');
});

test('GoPlus: hard findings flag a token, soft findings are notes, missing data changes nothing', () => {
  const gp = (o) => Object.assign({ status: 'ok', honeypot: false, cannotSellAll: false, cannotBuy: false, buyTax: 0, sellTax: 0, mintable: false, hiddenOwner: false, takeBackOwnership: false, ownerChangeBalance: false,
    blacklist: false, transferPausable: false, slippageModifiable: false, openSource: true, holderCount: 100 }, o);
  const market = dex({ maxLiquidityUsd: 400000, effectiveLiquidityUsd: 400000, volume24Usd: 20000, oldestPairMs: NOW - 200 * DAY });
  const t = (g, extra) => c.classifyToken(Object.assign({ chain: 'ethereum', address: '0x9', name: 'Real Looking', symbol: 'RLK', type: 'ERC-20', dex: market, gp: g }, extra), NOW);
  assert.equal(t(undefined).category, 'known');                                                   // baseline: established market
  assert.equal(t(gp({})).category, 'known');
  assert.ok(t(gp({})).notes.some((n) => /no honeypot, tax or ownership red flags/.test(n)));
  for (const [o, re] of [[{ honeypot: true }, /honeypot/], [{ cannotSellAll: true }, /cannot sell/], [{ sellTax: 0.4 }, /40% sell tax/], [{ buyTax: 0.5 }, /buy tax/], [{ ownerChangeBalance: true }, /change holders/], [{ cannotBuy: true }, /cannot be bought/]]) {
    const r = t(gp(o)); assert.equal(r.category, 'suspicious', JSON.stringify(o)); assert.match(r.reasons.join(' '), re);
  }
  // soft findings: only notes while the market is real
  const soft = t(gp({ mintable: true, hiddenOwner: true, sellTax: 0.15, openSource: false }));
  assert.equal(soft.category, 'known'); assert.ok(soft.notes.some((n) => /unlimited minting/.test(n) && /15% sell tax/.test(n)));
  // several soft findings + no market -> suspicious by themselves
  const dead = c.classifyToken({ chain: 'ethereum', address: '0x9', name: 'Real Looking', symbol: 'RLK', type: 'ERC-20', bs: { exchangeRate: '1' }, dex: dex({ maxLiquidityUsd: 10, effectiveLiquidityUsd: 10, oldestPairMs: NOW - 99 * DAY }), gp: gp({ mintable: true, hiddenOwner: true }) }, NOW);
  assert.equal(dead.category, 'suspicious'); assert.match(dead.reasons.join(' '), /several risky contract features/);
  // GoPlus data enriches the airdrop-spam explanation (honest wording when the contract looks clean)
  const clean = c.classifyToken({ chain: 'base', address: '0xa', name: 'SALUKI', symbol: 'SALUKI', type: 'ERC-20', dex: dex({ pairCount: 0 }), gp: gp({ holderCount: 486488 }) }, NOW);
  assert.equal(clean.label, 'Likely airdrop spam'); assert.equal(clean.confidence, 'medium');
  assert.ok(clean.notes.some((n) => /486,488 holders/.test(n))); assert.ok(clean.notes.some((n) => /probably not a trap/.test(n)));
  const closed = c.classifyToken({ chain: 'ethereum', address: '0xb', name: 'CREDITS', symbol: 'CREDITS', type: 'ERC-20', dex: dex({ pairCount: 0 }), gp: gp({ openSource: false, holderCount: 4510 }) }, NOW);
  assert.equal(closed.label, 'Likely airdrop spam'); assert.ok(closed.notes.some((n) => /not published/.test(n)));
  // GoPlus findings never override a curated list / canonical / Coinbase contract
  assert.equal(c.classifyToken({ chain: 'ethereum', address: '0xdac17f958d2ee523a2206206994597c13d831ec7', name: 'Tether', symbol: 'USDT', gp: gp({ mintable: true, blacklist: true }) }, NOW).category, 'known');
  // "notIndexed"/"unavailable" are shown in "what was checked" but change nothing
  const ni = t({ status: 'notIndexed' });
  assert.equal(ni.category, 'known'); assert.equal(ni.checked.find((x) => x.name === 'GoPlus security').status, 'notIndexed');
});

test('every result explains itself: summary, confidence, evidence (risk/ok/info) and what was checked', () => {
  const samples = [
    { chain: 'base', address: '0x1', name: 'Pepe', symbol: 'PEPE', dex: dex({ pairCount: 0 }) },
    { chain: 'base', address: CBBTC, name: 'x', symbol: 'cbBTC' },
    zoraTok(POST_NAME, { zora: own() }),
    { chain: 'solana', address: 'X', name: 'Claim reward', symbol: 'C' },
    { chain: 'ethereum', address: '0x2', name: 'NFT', type: 'ERC-721' }
  ];
  for (const s of samples) {
    const r = c.classifyToken(s, NOW);
    assert.ok(r.summary && r.summary.length > 10, JSON.stringify(s));
    assert.ok(Array.isArray(r.evidence) && r.evidence.length >= 1);
    assert.ok(r.evidence.every((e) => ['risk', 'ok', 'info'].includes(e.sev) && typeof e.text === 'string' && e.text));
    assert.ok(Array.isArray(r.checked) && r.checked.length >= 1);
    assert.ok(r.reasons.every((x) => r.evidence.some((e) => e.text === x)), 'every reason is also shown as evidence');
    if (r.category === 'suspicious') assert.ok(r.evidence.some((e) => e.sev === 'risk'));
    if (r.category === 'known') assert.ok(r.evidence.some((e) => e.sev === 'ok'));
  }
});
