// Live smoke test against real public APIs (read-only). Usage: node tests/live.js <address> [more addresses…]
const core = require('../lib/core.js');
const S = require('../lib/scanner.js');
(async () => {
  const addrs = process.argv.slice(2);
  if (!addrs.length) { console.log('usage: node tests/live.js <address> …'); process.exit(1); }
  for (const a of addrs) {
    const r = core.inspectInput(a);
    console.log('\n=== ' + a + ' -> ' + r.kind);
    if (!r.address) { console.log(r.message); continue; }
    const t0 = Date.now();
    try {
      const res = await S.scan(r.kind, r.address, {});
      const sum = core.summarize(res.tokens.map((t) => t.result));
      console.log('ok in ' + (Date.now() - t0) + 'ms', sum, res.chains ? res.chains.map((c) => c.id + ':' + c.status + ':' + c.count) : '');
      (res.warnings || []).forEach((w) => console.log('  warn:', w));
      for (const cat of ['suspicious', 'unknown', 'known']) {
        res.tokens.filter((t) => t.result.category === cat).slice(0, 6).forEach((t) =>
          console.log('  [' + cat + '] ' + core.safeDisplay(t.name || '?', 40) + ' (' + core.safeDisplay(t.symbol || '', 12) + ') ' + t.address.slice(0, 8) + '… | ' + t.result.reasons[0]));
      }
    } catch (e) { console.log('FAILED in ' + (Date.now() - t0) + 'ms:', e.code, e.message); }
  }
})();
