/* Wallet Scam-Token Checker — UI. Plain JS, no build step.
 * All token text is inserted with textContent (never innerHTML) and links from token data are never rendered. */
(function () {
  'use strict';
  const core = window.WSC, scanner = window.WSCScan;
  const $ = (id) => document.getElementById(id);
  const els = { form: $('form'), addr: $('addr'), go: $('go'), msg: $('msg'), status: $('status'), statusText: $('statusText'),
    results: $('results'), warnings: $('warnings'), summary: $('summary'), filters: $('filters'), list: $('list'), more: $('more'), rpc: $('rpc') };
  const PAGE = 40;
  const ORDER = { suspicious: 0, unknown: 1, known: 2 };
  let state = { tokens: [], filter: 'all', shown: PAGE };
  let busy = false;

  function h(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  function showMsg(text, kind) {
    els.msg.hidden = !text;
    els.msg.textContent = text || '';
    els.msg.className = 'msg' + (kind ? ' ' + kind : '');
  }

  function setBusy(on, text) {
    busy = on;
    els.go.disabled = on;
    els.go.textContent = on ? 'Scanning…' : 'Scan';
    els.status.hidden = !on;
    if (text) els.statusText.textContent = text;
  }

  /* Wipe the input the instant it looks like a secret. We never read it further, store it, or send it anywhere. */
  function guardSecrets(value) {
    const r = core.inspectInput(value);
    if (r.kind === 'seed' || r.kind === 'privatekey') {
      els.addr.value = '';
      els.results.hidden = true;
      showMsg('⚠️ ' + r.message, 'danger');
      return true;
    }
    return false;
  }

  els.addr.addEventListener('input', () => { if (guardSecrets(els.addr.value)) return; if (!els.msg.hidden && !els.msg.classList.contains('danger')) showMsg(''); });
  els.addr.addEventListener('paste', (e) => {
    const txt = (e.clipboardData && e.clipboardData.getData('text')) || '';
    if (txt && guardSecrets(txt)) e.preventDefault();
  });

  function customRpc() {
    const v = els.rpc.value.trim();
    if (!v) return null;
    try { const u = new URL(v); if (u.protocol === 'https:') return u.toString(); } catch (e) { /* fallthrough */ }
    return false;
  }

  els.form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (busy) return;
    const r = core.inspectInput(els.addr.value);
    if (r.kind === 'seed' || r.kind === 'privatekey') { guardSecrets(els.addr.value); return; }
    if (r.kind === 'empty' || r.kind === 'invalid') { showMsg(r.message, 'error'); els.results.hidden = true; return; }
    const rpc = customRpc();
    if (rpc === false) { showMsg('Custom RPC must be a valid https:// URL.', 'error'); return; }
    showMsg('');
    els.results.hidden = true;
    setBusy(true, 'Starting scan…');
    try {
      const opts = { onProgress: (t) => { els.statusText.textContent = t; } };
      if (rpc) opts.rpcUrls = [rpc];
      const res = await scanner.scan(r.kind, r.address, opts);
      render(r.kind, r.address, res);
    } catch (err) {
      showMsg(err && err.message ? err.message : 'Something went wrong. Please try again.', 'error');
    } finally {
      setBusy(false);
    }
  });

  function render(kind, address, res) {
    state.tokens = res.tokens.slice().sort((a, b) => ORDER[a.result.category] - ORDER[b.result.category]);
    state.filter = state.tokens.some((t) => t.result.category === 'suspicious') ? 'suspicious' : 'all';
    state.shown = PAGE;
    const counts = core.summarize(state.tokens.map((t) => t.result));

    // warnings
    els.warnings.replaceChildren();
    (res.warnings || []).forEach((w) => els.warnings.appendChild(h('div', 'warn', '⚠️ ' + w)));
    if (res.errors && res.errors.length) res.errors.forEach((w) => els.warnings.appendChild(h('div', 'warn', '⚠️ ' + w + ' Results for that chain are missing.')));

    // summary
    els.summary.replaceChildren();
    els.summary.appendChild(h('h2', null, 'Scan result'));
    els.summary.appendChild(h('p', 'addr', (kind === 'solana' ? 'Solana · ' : 'EVM (Ethereum + Base) · ') + address));
    const stats = h('div', 'stats');
    [['suspicious', 'Suspicious', 'bad'], ['unknown', 'Unknown', 'unk'], ['known', 'Known / verified', 'ok']].forEach(([k, label, cls]) => {
      const s = h('div', 'stat ' + cls); s.appendChild(h('b', null, String(counts[k]))); s.appendChild(h('span', null, label)); stats.appendChild(s);
    });
    els.summary.appendChild(stats);
    let verdict;
    if (!counts.total) verdict = 'No tokens with a balance were found for this address.';
    else if (counts.suspicious) verdict = '🚩 ' + counts.suspicious + ' token' + (counts.suspicious > 1 ? 's look' : ' looks') + ' suspicious. Do not interact with ' + (counts.suspicious > 1 ? 'them' : 'it') + '.';
    else if (counts.unknown) verdict = 'No obvious scam patterns, but ' + counts.unknown + ' token' + (counts.unknown > 1 ? 's are' : ' is') + ' unknown. Ignore anything you did not buy yourself.';
    else verdict = '✅ Everything found looks like an established token.';
    els.summary.appendChild(h('p', 'verdict', verdict));
    if (res.chains) {
      els.summary.appendChild(h('p', 'chain-status', 'Chains: ' + res.chains.map((c) => c.label + (c.status === 'ok' ? ' ✓ (' + c.count + ')' : ' ✗ unavailable')).join(' · ') + '. Other EVM chains are not supported.'));
    }
    const extra = [];
    if (res.zeroCount) extra.push(res.zeroCount + ' empty token account' + (res.zeroCount > 1 ? 's were' : ' was') + ' hidden.');
    if (extra.length) els.summary.appendChild(h('p', 'chain-status', extra.join(' ')));

    renderFilters(counts);
    renderList();
    els.results.hidden = false;
    els.results.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
  }

  function renderFilters(counts) {
    els.filters.replaceChildren();
    [['all', 'All', counts.total], ['suspicious', 'Suspicious', counts.suspicious], ['unknown', 'Unknown', counts.unknown], ['known', 'Known / verified', counts.known]].forEach(([k, label, n]) => {
      const b = h('button', 'chip', label + ' (' + n + ')');
      b.type = 'button'; b.setAttribute('role', 'tab'); b.setAttribute('aria-selected', String(state.filter === k));
      b.addEventListener('click', () => { state.filter = k; state.shown = PAGE; renderFilters(counts); renderList(); });
      els.filters.appendChild(b);
    });
  }

  function shortAddr(a) { return a.length > 14 ? a.slice(0, 6) + '…' + a.slice(-6) : a; }

  function tokenCard(t) {
    const r = t.result;
    const flagged = r.nameFlags && r.nameFlags.strong.length;
    const card = h('article', 'token ' + r.category);
    const head = h('div', 'token-head');
    const title = h('div', 'tname', core.safeDisplay(t.name || 'Unnamed token', 60));
    if (t.symbol) title.appendChild(h('span', 'tsym', '  ' + core.safeDisplay(t.symbol, 24)));
    head.appendChild(title);
    head.appendChild(h('span', 'pill ' + r.category, r.label));
    card.appendChild(head);

    const meta = h('div', 'meta');
    meta.appendChild(h('span', null, 'Balance: ' + t.balance));
    meta.appendChild(h('span', null, (t.chainLabel || 'Solana') + ' · ' + (t.type || 'token')));
    if (r.bestPoolUsd != null && r.pairCount > 0) meta.appendChild(h('span', null, 'Top pool liquidity: ' + core.fmtUsd(r.bestPoolUsd)));
    if (r.ageDays != null) meta.appendChild(h('span', null, 'Trading for: ' + core.fmtAge(r.ageDays)));
    meta.appendChild(h('span', null, shortAddr(t.address)));
    card.appendChild(meta);

    if (r.badges.length) { const p = h('p', 'meta'); r.badges.forEach((b) => p.appendChild(h('span', 'badge', b))); card.appendChild(p); }
    if (r.reasons.length) { const ul = h('ul', 'reasons'); r.reasons.forEach((x) => ul.appendChild(h('li', null, x))); card.appendChild(ul); }
    if (r.notes.length) { const ul = h('ul', 'reasons notes'); r.notes.forEach((x) => ul.appendChild(h('li', null, x))); card.appendChild(ul); }
    if (r.category !== 'known') {
      card.appendChild(h('p', 'meta', flagged ? 'Do not click anything in this name. Do not swap, sell, claim or approve. Ignore it.' : 'Do not swap, sell, claim or approve. Ignoring it is safest.'));
    }

    const actions = h('div', 'token-actions');
    const copy = h('button', 'linkbtn', 'Copy token address'); copy.type = 'button';
    copy.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(t.address); copy.textContent = 'Copied'; } catch (e) { copy.textContent = 'Copy failed'; }
      setTimeout(() => { copy.textContent = 'Copy token address'; }, 1500);
    });
    actions.appendChild(copy);
    // Explorer link is built by us from a validated address, never from token metadata.
    const okAddr = t.chain === 'solana' ? core.isSolanaAddress(t.address) : core.isEvmAddress(t.address);
    if (okAddr) {
      const a = h('a', 'linkbtn', 'View on explorer ↗');
      a.href = scanner.explorerFor(t); a.target = '_blank'; a.rel = 'noopener noreferrer nofollow';
      actions.appendChild(a);
    }
    card.appendChild(actions);
    return card;
  }

  function renderList() {
    const items = state.tokens.filter((t) => state.filter === 'all' || t.result.category === state.filter);
    els.list.replaceChildren();
    if (!items.length) els.list.appendChild(h('p', 'empty', 'Nothing in this category.'));
    items.slice(0, state.shown).forEach((t) => els.list.appendChild(tokenCard(t)));
    const rest = items.length - state.shown;
    els.more.hidden = rest <= 0;
    els.more.textContent = 'Show more (' + Math.max(rest, 0) + ' remaining)';
  }
  els.more.addEventListener('click', () => { state.shown += PAGE; renderList(); });
})();
