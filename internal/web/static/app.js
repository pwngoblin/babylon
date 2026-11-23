'use strict';
// Babylon web UI. No frameworks, no innerHTML: every value shown comes from
// scanned hosts and is inserted as text, so it cannot inject markup.

const view = document.getElementById('view');
let timer = null;

// ---------- helpers ----------
function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k === 'class') n.className = v;
    else if (k.startsWith('on') && typeof v === 'function') n.addEventListener(k.slice(2), v);
    else if (k === 'style') n.style.cssText = v; // CSSOM: allowed by CSP (setAttribute('style') is not)
    else if (k === 'checked' || k === 'disabled' || k === 'selected') n[k] = !!v;
    else n.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    n.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return n;
}
function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }
function mount(...nodes) { clear(view); view.append(...nodes.flat().filter(n => n != null && n !== false)); }
function stopTimer() { if (timer) { clearInterval(timer); timer = null; } }
function poll(fn, ms) { stopTimer(); timer = setInterval(fn, ms); }

async function api(path, opts = {}) {
  const init = { credentials: 'same-origin', ...opts, headers: { 'X-Babylon-Request': '1', ...(opts.headers || {}) } };
  if (opts.body && typeof opts.body !== 'string') { init.body = JSON.stringify(opts.body); init.headers['Content-Type'] = 'application/json'; }
  const r = await fetch(path, init);
  let data = {};
  try { data = await r.json(); } catch (_) { /* empty body */ }
  if (!r.ok) throw new Error(data.error || (r.status + ' ' + r.statusText));
  return data;
}

function toast(msg) {
  const box = document.getElementById('toast');
  const t = el('div', { class: 't' }, msg);
  box.append(t);
  setTimeout(() => t.remove(), 4000);
}

const SEVS = ['critical', 'high', 'medium', 'low', 'info'];
// Findings table sort: key is a column id, dir is 1 (asc) or -1 (desc). Default order comes from the server (null).
let findSort = { key: null, dir: 1 };
const SORTERS = {
  sev: f => SEVS.indexOf(f.severity),
  title: f => (f.title || '').toLowerCase(),
  host: f => (f.host || '') + ':' + String(f.port || 0).padStart(5, '0'),
  cve: f => (f.cve_ids || [])[0] || '',
  cvss: f => (f.cvss_score == null ? -1 : f.cvss_score),
  engine: f => (f.engines || []).join('+'),
};
const sevChip = s => el('span', { class: 'sev sev-' + s }, s);
const badge = s => el('span', { class: 'badge s-' + s }, s);
const fmtTime = t => t ? t.replace('T', ' ').slice(0, 19) : '';
function pct(done, total) { return total ? Math.round(100 * done / total) : 0; }
function bar(done, total) { return el('div', { class: 'progress', role: 'progressbar', 'aria-valuenow': pct(done, total), 'aria-valuemin': 0, 'aria-valuemax': 100 }, el('span', { style: 'width:' + pct(done, total) + '%' })); }
function cveLink(c) { return /^CVE-\d{4}-\d{4,}$/.test(c) ? el('a', { href: 'https://nvd.nist.gov/vuln/detail/' + c, target: '_blank', rel: 'noopener noreferrer' }, c) : c; }
function errBox(e) { return el('div', { class: 'alert error', role: 'alert' }, e.message || String(e)); }

function setNav(name) {
  document.querySelectorAll('[data-nav]').forEach(a => a.classList.toggle('active', a.dataset.nav === name));
}

// ---------- router ----------
async function route() {
  stopTimer();
  const parts = location.hash.replace(/^#\/?/, '').split('/').filter(Boolean);
  try {
    if (parts[0] === 'new') { setNav('new'); await newScanView(); }
    else if (parts[0] === 'schedules') { setNav('schedules'); await schedulesView(); }
    else if (parts[0] === 'status') { setNav('status'); await statusView(); }
    else if (parts[0] === 'scan' && parts[1]) { setNav('scans'); await scanView(+parts[1], parts[2] || 'overview'); }
    else if (parts[0] === 'compare' && parts[1] && parts[2]) { setNav('scans'); await compareView(+parts[1], +parts[2]); }
    else { setNav('scans'); await scansView(); }
  } catch (e) { mount(errBox(e)); }
  view.focus({ preventScroll: true });
}
window.addEventListener('hashchange', route);

// ---------- scans list ----------
async function scansView() {
  const selected = new Set();
  const body = el('div');
  const render = async () => {
    const scans = await api('/api/scans');
    clear(body);
    if (!scans.length) {
      body.append(el('div', { class: 'card' }, el('p', {}, 'No scans yet.'), el('a', { class: 'btn primary', href: '#/new' }, 'Start your first scan')));
      return;
    }
    const cmp = el('button', { disabled: selected.size !== 2, onclick: () => {
      const [a, b] = [...selected].sort((x, y) => x - y);
      location.hash = '#/compare/' + a + '/' + b;
    } }, 'Compare selected (' + selected.size + '/2)');
    const rows = scans.map(s => {
      const chk = el('input', { type: 'checkbox', 'aria-label': 'Select scan ' + s.ID, checked: selected.has(s.ID), onclick: ev => {
        ev.stopPropagation();
        if (ev.target.checked) selected.add(s.ID); else selected.delete(s.ID);
        if (selected.size > 2) { selected.delete([...selected][0]); }
        render();
      } });
      const f = s.Findings || {};
      return el('tr', { class: 'click', onclick: () => { location.hash = '#/scan/' + s.ID; } },
        el('td', {}, chk),
        el('td', {}, el('a', { href: '#/scan/' + s.ID, onclick: e => e.stopPropagation() }, s.Name || ('Scan ' + s.ID))),
        el('td', {}, badge(s.running ? 'running' : s.Status)),
        el('td', {}, s.Template),
        el('td', { class: 'mono' }, (s.Targets || []).join(', ').slice(0, 40)),
        el('td', {}, s.JobsTotal ? el('div', {}, bar(s.JobsDone, s.JobsTotal), el('span', { class: 'muted' }, s.JobsDone + '/' + s.JobsTotal)) : '–'),
        el('td', {}, SEVS.slice(0, 4).map(k => f[k] ? el('span', { class: 'sev sev-' + k, style: 'margin-right:4px' }, f[k] + ' ' + k) : null), (!f.critical && !f.high && !f.medium && !f.low) ? el('span', { class: 'muted' }, 'none') : null),
        el('td', { class: 'muted' }, fmtTime(s.StartedAt)));
    });
    body.append(el('div', { class: 'row between', style: 'margin-bottom:10px' }, el('span', { class: 'muted' }, scans.length + ' scans stored locally'), cmp),
      el('div', { class: 'table-wrap' }, el('table', {},
        el('thead', {}, el('tr', {}, ...['', 'Scan', 'Status', 'Template', 'Targets', 'Progress', 'Findings', 'Started'].map(h => el('th', {}, h)))),
        el('tbody', {}, rows))));
    if (!scans.some(s => s.running)) stopTimer();
  };
  mount(el('div', { class: 'row between' }, el('div', {}, el('h1', {}, 'Scans'), el('p', { class: 'sub' }, 'History is kept locally; nothing is deleted unless you delete it.')),
    el('a', { class: 'btn primary', href: '#/new' }, 'New scan')), body);
  await render();
  poll(() => render().catch(() => {}), 2500);
}

// ---------- schedules ----------
const everyText = m => m % 10080 === 0 ? 'every ' + (m / 10080 === 1 ? 'week' : m / 10080 + ' weeks') : m % 1440 === 0 ? 'every ' + (m === 1440 ? 'day' : m / 1440 + ' days') : m % 60 === 0 ? 'every ' + (m === 60 ? 'hour' : m / 60 + ' hours') : 'every ' + m + ' min';
const fmtUnix = t => t ? new Date(t * 1000).toLocaleString() : '–';
async function schedulesView() {
  const body = el('div');
  const render = async () => {
    const list = await api('/api/schedules');
    clear(body);
    if (!list.length) { body.append(el('div', { class: 'card muted' }, 'No schedules yet. Choose "Repeat" when you create a scan.')); return; }
    body.append(el('div', { class: 'table-wrap' }, el('table', {},
      el('thead', {}, el('tr', {}, ...['Name', 'Repeats', 'Next run', 'Last run', 'Last scan', 'State', ''].map(h => el('th', {}, h)))),
      el('tbody', {}, list.map(s => {
        let req = {}; try { req = JSON.parse(s.request); } catch (e) { /* unreadable stored request */ }
        return el('tr', {},
          el('td', {}, s.name, el('div', { class: 'muted mono' }, (req.targets || []).join(', '))),
          el('td', {}, everyText(s.interval_min)), el('td', {}, s.enabled ? fmtUnix(s.next_run) : '–'), el('td', {}, fmtUnix(s.last_run)),
          el('td', {}, s.last_scan_id ? el('a', { href: '#/scan/' + s.last_scan_id }, '#' + s.last_scan_id) : '–', s.last_error ? el('div', { class: 'alert error' }, s.last_error) : null),
          el('td', {}, s.enabled ? 'active' : 'paused'),
          el('td', {}, el('button', { onclick: async () => { await api('/api/schedules/' + s.id + '/toggle', { method: 'POST', body: { enabled: !s.enabled } }); render(); } }, s.enabled ? 'Pause' : 'Resume'), ' ',
            el('button', { onclick: async () => { if (confirm('Delete this schedule? Past scans are kept.')) { await api('/api/schedules/' + s.id, { method: 'DELETE' }); render(); } } }, 'Delete')));
      })))));
  };
  mount(el('h1', {}, 'Schedules'), el('p', { class: 'sub' }, 'Recurring scans run while this web UI is running. Each run is a normal scan you can compare with the previous one.'), body);
  await render();
}

// ---------- new scan ----------
async function newScanView() {
  const st = await api('/api/status');
  let tpl = 'basic';
  const form = el('form', { novalidate: true });
  const err = el('div');
  const tplBox = el('div');
  const active = el('input', { type: 'checkbox', id: 'allow_active' });
  const renderTpl = () => {
    clear(tplBox);
    for (const t of st.templates) {
      const radio = el('input', { type: 'radio', name: 'template', value: t.name, checked: t.name === tpl, disabled: !t.implemented, onchange: () => { tpl = t.name; active.disabled = tpl !== 'full_unauth'; if (active.disabled) active.checked = false; } });
      tplBox.append(el('label', { class: 'tpl' + (t.implemented ? '' : ' disabled') }, el('div', { class: 'row' }, radio, el('b', {}, t.title)), el('span', {}, t.description)));
    }
  };
  renderTpl(); active.disabled = true;

  const name = el('input', { type: 'text', id: 'name', placeholder: 'e.g. Office network, weekly' });
  const targets = el('textarea', { id: 'targets', placeholder: '192.168.1.0/24\n10.0.0.5\nserver.lan', spellcheck: 'false' });
  const ports = el('input', { type: 'text', id: 'ports', placeholder: 'default for the template, or e.g. 22,80,443,8000-8100' });
  const accuracy = el('select', { id: 'accuracy' }, el('option', { value: 'normal' }, 'Normal: show unverified (version-based) findings separately'), el('option', { value: 'avoid-false-alarms' }, 'Avoid false alarms: hide unverified findings'));
  const creds = el('input', { type: 'checkbox', id: 'creds' });
  const authz = el('input', { type: 'checkbox', id: 'authz' });
  const repeat = el('select', { id: 'repeat' }, ...[['', 'Run once'], ['60', 'Repeat every hour'], ['1440', 'Repeat every day'], ['10080', 'Repeat every week'], ['43200', 'Repeat every 30 days']].map(([v, t]) => el('option', { value: v }, t)));
  const submit = el('button', { type: 'submit', class: 'primary' }, 'Start scan');

  form.append(
    el('label', { for: 'name' }, 'Name (optional)'), name,
    el('label', {}, 'Template'), tplBox,
    el('label', { for: 'targets' }, 'Targets'), targets,
    el('div', { class: 'hint' }, 'IP addresses, CIDR ranges or hostnames, one per line or separated by commas. Public addresses are refused unless you confirm authorization below.'),
    el('label', { for: 'ports' }, 'Ports (optional)'), ports,
    el('label', { for: 'accuracy' }, 'Report accuracy'), accuracy,
    el('label', { for: 'repeat' }, 'Schedule'), repeat,
    el('div', { class: 'hint' }, 'Repeated scans run while this web UI is running. Credentialed scans cannot be scheduled (credentials are never stored).'),
    el('details', { style: 'margin-top:16px' }, el('summary', {}, 'Advanced'),
      el('label', { class: 'inline' }, active, el('span', {}, 'Allow active probes (Full template only). Non-destructive, but sends more requests.')),
      el('label', { class: 'inline' }, creds, el('span', {}, 'Check default credentials. May trigger account lockouts; use only where that is acceptable.')),
      el('label', { class: 'inline' }, authz, el('span', {}, 'I am authorized to scan non-private (public) addresses.'))),
    el('div', { class: 'row', style: 'margin-top:20px' }, submit, el('a', { href: '#/', class: 'btn' }, 'Cancel')));

  form.addEventListener('submit', async ev => {
    ev.preventDefault();
    clear(err); submit.disabled = true;
    try {
      const body = {
        name: name.value.trim(), template: tpl, accuracy: accuracy.value, ports: ports.value.trim(),
        targets: targets.value.split(/[\s,]+/).map(s => s.trim()).filter(Boolean),
        allow_active: active.checked, check_default_creds: creds.checked, authorized: authz.checked,
      };
      if (repeat.value) {
        const r = await api('/api/schedules', { method: 'POST', body: { name: body.name, every_minutes: +repeat.value, scan: body } });
        toast('Schedule created; the first scan has started');
        location.hash = '#/scan/' + r.first_scan;
        return;
      }
      const r = await api('/api/scans', { method: 'POST', body });
      if (!r.started) toast(r.message || 'Scan created but not started');
      location.hash = '#/scan/' + r.id;
    } catch (e) { err.append(errBox(e)); submit.disabled = false; }
  });

  const warn = [];
  if (!st.tools.nmap) warn.push(el('div', { class: 'alert error' }, 'nmap was not found in PATH; scans cannot run.'));
  if (!st.tools.nuclei) warn.push(el('div', { class: 'alert warn' }, 'nuclei was not found in PATH; web and CVE template checks will be skipped.'));
  else if (!st.nuclei_templates.indexed) warn.push(el('div', { class: 'alert warn' }, 'No Nuclei templates are indexed yet. Run `babylon update-feeds` for full coverage.'));
  mount(el('h1', {}, 'New scan'), el('p', { class: 'sub' }, 'Checks are non-destructive. Only scan systems you own or are authorized to test.'), ...warn, el('div', { class: 'card' }, form, err));
}

// ---------- scan detail ----------
async function scanView(id, tab) {
  const head = el('div'), body = el('div');
  mount(head, body);
  let lastStatus = null, lastReport = null, filters = { sev: '', conf: '', q: '' };

  const load = async (force) => {
    const d = await api('/api/scans/' + id);
    const s = d.scan;
    const changed = s.Status !== lastStatus || s.running || force || !lastReport;
    lastStatus = s.Status;
    if (changed) lastReport = await api('/api/scans/' + id + '/report');
    renderHead(s);
    renderTab(s, d.jobs || [], lastReport);
    if (!s.running) stopTimer();
  };

  const act = async (path, method, okMsg) => {
    try { await api(path, { method }); toast(okMsg); await load(true); poll(() => load().catch(() => {}), 2000); }
    catch (e) { toast(e.message); }
  };

  function renderHead(s) {
    clear(head);
    const running = s.running;
    head.append(
      el('div', { class: 'row between' },
        el('div', {}, el('h1', {}, s.Name || ('Scan ' + s.ID)), el('p', { class: 'sub' }, s.Template + ' · ' + (s.Targets || []).join(', '))),
        el('div', { class: 'row' }, badge(running ? 'running' : s.Status),
          running ? el('button', { onclick: () => act('/api/scans/' + id + '/cancel', 'POST', 'Cancelling…') }, 'Cancel') : null,
          !running && s.Status !== 'completed' ? el('button', { class: 'primary', onclick: () => act('/api/scans/' + id + '/resume', 'POST', 'Resuming…') }, 'Resume') : null,
          el('a', { class: 'btn', href: '/api/scans/' + id + '/export?format=html' }, 'Export HTML'),
          el('a', { class: 'btn', href: '/api/scans/' + id + '/export?format=nessus' }, 'Export .nessus'),
          el('a', { class: 'btn', href: '/api/scans/' + id + '/export?format=md' }, 'MD'),
          el('a', { class: 'btn', href: '/api/scans/' + id + '/export?format=json' }, 'JSON'),
          el('a', { class: 'btn', href: '/api/scans/' + id + '/export?format=csv' }, 'CSV'),
          el('button', { class: 'danger', disabled: running, onclick: async () => {
            if (!confirm('Delete this scan and its raw output permanently?')) return;
            try { await api('/api/scans/' + id, { method: 'DELETE' }); toast('Scan deleted'); location.hash = '#/'; } catch (e) { toast(e.message); }
          } }, 'Delete'))),
      ...(s.error ? [el('div', { class: 'alert error', role: 'alert' }, 'Scan error: ' + s.error)] : []),
      el('nav', { class: 'tabs', 'aria-label': 'Scan sections' }, ...['overview', 'findings', 'hosts', 'coverage'].map(t =>
        el('a', { href: '#/scan/' + id + '/' + t, class: t === tab ? 'active' : '', 'aria-current': t === tab ? 'page' : null }, t[0].toUpperCase() + t.slice(1)))));
  }

  function renderTab(s, jobs, rep) {
    clear(body);
    if (tab === 'findings') return body.append(findingsTab(rep));
    if (tab === 'hosts') return body.append(hostsTab(rep));
    if (tab === 'coverage') return body.append(coverageTab(rep, jobs));
    body.append(overviewTab(s, jobs, rep));
  }

  function overviewTab(s, jobs, rep) {
    const by = rep.summary.findings_by_severity || {};
    const stages = {};
    for (const j of jobs) { const k = stages[j.Stage] || (stages[j.Stage] = { done: 0, total: 0, failed: 0 }); k.total++; if (j.State === 'done' || j.State === 'skipped') k.done++; if (j.State === 'failed') { k.failed++; k.done++; } }
    return el('div', {},
      (s.warnings || []).map(w => el('div', { class: 'alert warn' }, w)),
      el('div', { class: 'grid cols3' }, ...SEVS.map(k => el('div', { class: 'card count' }, el('div', { class: 'n' }, by[k] || 0), el('div', { class: 'l' }, sevChip(k))))),
      el('div', { class: 'grid cols3', style: 'margin-top:12px' },
        el('div', { class: 'card count' }, el('div', { class: 'n' }, rep.summary.hosts), el('div', { class: 'l' }, 'Live hosts')),
        el('div', { class: 'card count' }, el('div', { class: 'n' }, rep.summary.services), el('div', { class: 'l' }, 'Open services')),
        el('div', { class: 'card count' }, el('div', { class: 'n' }, rep.summary.possible_findings), el('div', { class: 'l' }, 'Possible (unverified)'))),
      s.accuracy === 'avoid-false-alarms' && rep.summary.possible_findings ? el('div', { class: 'alert warn' }, rep.summary.possible_findings + ' unverified findings are hidden by the “avoid false alarms” setting. They are stored; nothing is deleted.') : null,
      el('h2', {}, 'Progress'),
      el('div', { class: 'card' }, Object.keys(stages).length ? el('table', {}, el('thead', {}, el('tr', {}, ...['Stage', 'Progress', 'Jobs'].map(h => el('th', {}, h)))),
        el('tbody', {}, Object.entries(stages).map(([name, k]) => el('tr', {}, el('td', {}, name), el('td', {}, bar(k.done, k.total)), el('td', {}, k.done + '/' + k.total + (k.failed ? ' (' + k.failed + ' failed)' : ''))))))
        : el('span', { class: 'muted' }, 'Waiting to start…')),
      el('h2', {}, 'Details'),
      el('div', { class: 'card' }, el('table', {}, el('tbody', {},
        [['Started', fmtTime(s.StartedAt)], ['Finished', fmtTime(s.FinishedAt)], ['Report accuracy', s.accuracy], ['Targets', (s.Targets || []).join(', ')]]
          .map(([k, v]) => el('tr', {}, el('th', { style: 'width:160px' }, k), el('td', {}, v || '–')))))),
      s.ID > 1 ? el('p', {}, el('a', { href: '#/compare/' + (s.ID - 1) + '/' + s.ID }, 'Compare with scan ' + (s.ID - 1))) : null);
  }

  function findingsTab(rep) {
    const wrap = el('div'), list = el('div');
    const sevSel = el('select', { 'aria-label': 'Severity' }, el('option', { value: '' }, 'All severities'), ...SEVS.map(k => el('option', { value: k, selected: filters.sev === k }, k)));
    const confSel = el('select', { 'aria-label': 'Confidence' }, el('option', { value: '' }, 'All confidence'), el('option', { value: 'verified', selected: filters.conf === 'verified' }, 'Verified only'), el('option', { value: 'possible', selected: filters.conf === 'possible' }, 'Possible (unverified) only'));
    const q = el('input', { type: 'text', placeholder: 'Search title, host, CVE…', 'aria-label': 'Search', value: filters.q });
    const draw = () => {
      filters = { sev: sevSel.value, conf: confSel.value, q: q.value };
      const needle = q.value.trim().toLowerCase();
      const items = rep.findings.filter(f =>
        (!sevSel.value || f.severity === sevSel.value) &&
        (!confSel.value || (confSel.value === 'possible') === !!f.possible) &&
        (!needle || (f.title + ' ' + f.host + ' ' + (f.cve_ids || []).join(' ')).toLowerCase().includes(needle)));
      if (findSort.key) {
        const g = SORTERS[findSort.key], d = findSort.dir;
        items.sort((a, b) => { const x = g(a), y = g(b); return (x < y ? -1 : x > y ? 1 : 0) * d; });
      }
      clear(list);
      if (!items.length) { list.append(el('div', { class: 'card muted' }, 'No findings match.')); return; }
      const tbody = el('tbody');
      for (const f of items) {
        const detail = el('tr', { class: 'detail', hidden: true }, el('td', { colspan: 6 }, findingDetail(f)));
        const row = el('tr', { class: 'click', tabindex: 0, 'aria-expanded': 'false' },
          el('td', {}, sevChip(f.severity)),
          el('td', {}, f.title, f.possible ? el('span', { class: 'badge s-partial', style: 'margin-left:8px' }, 'possible') : null),
          el('td', { class: 'mono' }, f.host + (f.port ? ':' + f.port : '')),
          el('td', {}, (f.cve_ids || []).join(', ')),
          el('td', {}, f.cvss_score != null ? f.cvss_score.toFixed(1) : '', f.kev ? el('span', { class: 'badge s-failed', style: 'margin-left:6px', title: 'Listed in CISA Known Exploited Vulnerabilities' }, 'KEV') : null, (f.public_exploits || []).length ? el('span', { class: 'badge s-partial', style: 'margin-left:6px', title: 'Public exploit: ' + f.public_exploits.join(', ') }, 'exploit') : null, f.epss_score != null ? el('span', { class: 'muted', style: 'margin-left:6px', title: 'EPSS exploit probability' }, 'EPSS ' + (f.epss_score * 100).toFixed(1) + '%') : null),
          el('td', { class: 'muted' }, (f.engines || []).join(' + ')));
        const toggle = () => { detail.hidden = !detail.hidden; row.setAttribute('aria-expanded', String(!detail.hidden)); };
        row.addEventListener('click', toggle);
        row.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
        tbody.append(row, detail);
      }
      list.append(el('div', { class: 'table-wrap' }, el('table', {}, el('thead', {}, el('tr', {}, ...[['sev', 'Severity'], ['title', 'Finding'], ['host', 'Host'], ['cve', 'CVE'], ['cvss', 'CVSS'], ['engine', 'Found by']].map(([k, h]) => {
        const on = findSort.key === k;
        // Natural first direction: critical first for severity (index asc), highest first for CVSS, A-Z otherwise.
        const first = k === 'cvss' ? -1 : 1;
        const btn = el('button', { class: 'sortbtn', type: 'button', title: 'Sort by ' + h, onclick: () => {
          if (!on) findSort = { key: k, dir: first };
          else if (findSort.dir === first) findSort = { key: k, dir: -first };
          else findSort = { key: null, dir: 1 }; // third click: back to default order
          draw();
        } }, h + (on ? (findSort.dir === first ? ' ▼' : ' ▲') : ''));
        return el('th', { 'aria-sort': on ? (findSort.dir === 1 ? 'ascending' : 'descending') : 'none' }, btn);
      }))), tbody)));
    };
    [sevSel, confSel].forEach(c => c.addEventListener('change', draw));
    q.addEventListener('input', draw);
    wrap.append(...[rootCauses(rep)].filter(Boolean), el('div', { class: 'filters' }, el('div', {}, sevSel), el('div', {}, confSel), el('div', { style: 'flex:1;min-width:200px' }, q)), list);
    draw();
    return wrap;
  }

  // Root-cause grouping: one actionable item per outdated product, expandable to its CVEs.
  function rootCauses(rep) {
    const groups = rep.root_causes || [];
    if (!groups.length) return null;
    return el('div', { style: 'margin-bottom:20px' },
      el('h2', {}, 'Priority action plan (' + groups.length + ' root causes)'),
      el('div', { class: 'card' }, groups.map(g => {
        const detail = el('div', { hidden: true, style: 'margin-top:8px' },
          el('p', {}, g.remediation),
          el('p', { class: 'muted' }, 'Confidence of the group is that of its least certain CVE: ' + g.confidence + '.'),
          el('p', {}, ...g.cve_ids.flatMap((c, i) => [i ? ', ' : '', cveLink(c)])));
        const head = el('div', { class: 'row between click', tabindex: 0, role: 'button', 'aria-expanded': 'false' },
          el('span', {}, sevChip(g.severity), ' ', el('b', {}, g.title), el('span', { class: 'muted', style: 'margin-left:8px' }, g.host + ':' + g.port)),
          el('span', { class: 'muted' }, (g.max_cvss != null ? 'max CVSS ' + g.max_cvss.toFixed(1) : '') + (g.kev_count ? '  · ' + g.kev_count + ' KEV' : '') + (g.exploit_count ? '  · ' + g.exploit_count + ' public exploit' : '')));
        const toggle = () => { detail.hidden = !detail.hidden; head.setAttribute('aria-expanded', String(!detail.hidden)); };
        head.addEventListener('click', toggle);
        head.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
        return el('div', { style: 'padding:8px 0;border-bottom:1px solid var(--border)' }, head, detail);
      })));
  }

  function findingDetail(f) {
    const sec = (h, v) => v ? [el('h4', {}, h), el('p', {}, v)] : [];
    return el('div', {},
      ...sec('Synopsis', f.synopsis), ...sec('Description', f.description), ...sec('Remediation', f.remediation),
      el('h4', {}, 'Confidence'), el('p', {}, f.confidence + ' (' + f.detection + '-based)'),
      (f.cve_ids || []).length ? [el('h4', {}, 'CVE'), el('p', {}, ...f.cve_ids.flatMap((c, i) => [i ? ', ' : '', cveLink(c)]))] : null,
      f.evidence ? [el('h4', {}, 'Evidence'), el('pre', {}, f.evidence)] : null);
  }

  function hostsTab(rep) {
    if (!rep.hosts.length) return el('div', { class: 'card muted' }, 'No live hosts recorded.');
    return el('div', {}, rep.hosts.map(h => el('div', { class: 'card', style: 'margin-bottom:12px' },
      el('div', { class: 'row between' }, el('b', { class: 'mono' }, h.address + (h.hostnames && h.hostnames.length ? '  (' + h.hostnames.join(', ') + ')' : '')), el('span', { class: 'muted' }, h.os || '')),
      h.services.length ? el('div', { class: 'table-wrap', style: 'margin-top:8px' }, el('table', {}, el('thead', {}, el('tr', {}, ...['Port', 'Service', 'Product / version', 'TLS'].map(x => el('th', {}, x)))),
        el('tbody', {}, h.services.map(s => el('tr', {}, el('td', { class: 'mono' }, s.port + '/' + s.proto), el('td', {}, s.name || ''), el('td', {}, ((s.product || '') + ' ' + (s.version || '')).trim()),
          el('td', {}, (s.tls_issues || []).map(i => el('div', { class: 'muted' }, '⚠ ' + i)))))))) : el('p', { class: 'muted' }, 'No open services.'))));
  }

  function coverageTab(rep, jobs) {
    const c = rep.coverage, runs = c.check_runs || {};
    return el('div', {},
      el('p', { class: 'sub' }, 'Coverage shows what was and was not checked. “No findings” only means something if the relevant checks actually ran.'),
      el('div', { class: 'grid cols3' }, ['ran', 'skipped', 'error'].map(k => el('div', { class: 'card count' }, el('div', { class: 'n' }, runs[k] || 0), el('div', { class: 'l' }, 'Checks ' + k)))),
      (c.failed_jobs || []).length ? [el('h2', {}, 'Failed jobs (results may be incomplete)'), el('div', { class: 'card' }, c.failed_jobs.map(j => el('div', { class: 'alert error' }, j.stage + ' / ' + j.chunk + ': ' + j.error)))] : null,
      el('h2', {}, 'Skipped checks'),
      (c.skipped_checks || []).length ? el('div', { class: 'table-wrap' }, el('table', {}, el('thead', {}, el('tr', {}, ...['Host', 'Check', 'Reason'].map(x => el('th', {}, x)))),
        el('tbody', {}, c.skipped_checks.map(s => el('tr', {}, el('td', { class: 'mono' }, s.host), el('td', {}, s.check), el('td', { class: 'muted' }, s.reason)))))) : el('div', { class: 'card muted' }, 'Nothing was skipped.'),
      el('h2', {}, 'Jobs'),
      el('div', { class: 'table-wrap' }, el('table', {}, el('thead', {}, el('tr', {}, ...['Stage', 'Chunk', 'State', 'Attempts', 'Targets'].map(x => el('th', {}, x)))),
        el('tbody', {}, jobs.map(j => el('tr', {}, el('td', {}, j.Stage), el('td', { class: 'mono' }, j.ChunkKey), el('td', {}, badge(j.State === 'done' ? 'completed' : j.State === 'failed' ? 'failed' : j.State === 'running' ? 'running' : 'pending')), el('td', {}, j.Attempts), el('td', {}, j.Targets)))))));
  }

  await load(true);
  poll(() => load().catch(() => {}), 2000);
}

// ---------- compare ----------
async function compareView(a, b) {
  const d = await api('/api/diff?a=' + a + '&b=' + b);
  const list = (title, items, hint) => el('div', {}, el('h2', {}, title + ' (' + items.length + ')'), hint ? el('p', { class: 'sub' }, hint) : null,
    items.length ? el('div', { class: 'table-wrap' }, el('table', {}, el('thead', {}, el('tr', {}, ...['Severity', 'Finding', 'Host'].map(x => el('th', {}, x)))),
      el('tbody', {}, items.map(f => el('tr', {}, el('td', {}, sevChip(f.Severity)), el('td', {}, f.Title), el('td', { class: 'mono' }, f.Address + (f.Port ? ':' + f.Port : '')))))))
      : el('div', { class: 'card muted' }, 'None.'));
  mount(el('h1', {}, 'Compare scan ' + a + ' → ' + b), el('p', { class: 'sub' }, el('a', { href: '#/scan/' + a }, 'Scan ' + a), ' · ', el('a', { href: '#/scan/' + b }, 'Scan ' + b)),
    list('New', d.new, 'Present in the newer scan only.'),
    list('Not seen this time', d.resolved, 'Treated as resolved only if the newer scan covered the same hosts and checks; verify under Coverage.'),
    el('h2', {}, 'Persisting: ' + d.persisting.length));
}

// ---------- status ----------
async function statusView() {
  const s = await api('/api/status');
  const row = (k, v, ok) => el('tr', {}, el('th', { style: 'width:220px' }, k), el('td', {}, v, ok === true ? el('span', { class: 'badge s-completed', style: 'margin-left:8px' }, 'ok') : ok === false ? el('span', { class: 'badge s-failed', style: 'margin-left:8px' }, 'missing') : null));
  mount(el('h1', {}, 'Status'), el('p', { class: 'sub' }, 'Babylon ' + s.version),
    el('div', { class: 'card' }, el('table', {}, el('tbody', {},
      row('nmap', s.tools.nmap ? 'found' : 'not found in PATH', s.tools.nmap),
      row('nuclei', s.tools.nuclei ? 'found' : 'not found in PATH', s.tools.nuclei),
      row('trivy (optional)', s.tools.trivy ? 'found' : 'not installed'),
      row('Nuclei templates', s.nuclei_templates.indexed ? s.nuclei_templates.count + ' indexed (updated ' + s.nuclei_templates.updated.slice(0, 10) + ')' : 'not indexed. Run: babylon update-feeds', s.nuclei_templates.indexed),
      row('Privileges', s.privilege + (s.sudo_allowed ? '; sudo allowed' : '')),
      row('Data', 'All results are stored in your local database; nothing leaves this machine.')))));
}

route();
