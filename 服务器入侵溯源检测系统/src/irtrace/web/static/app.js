/* ==========================================================================
   IRT 入侵检测控制台 — 前端逻辑 (原生 JS, 无外部依赖)
   ========================================================================== */
'use strict';

const SEV = {
  critical: { label: '严重', color: '#c0392b' },
  high:     { label: '高危', color: '#e67e22' },
  medium:   { label: '中危', color: '#c9971a' },
  low:      { label: '低危', color: '#2e86c1' },
  info:     { label: '信息', color: '#7f8c8d' },
};
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

/* 时间线中值得高亮的事件标签 */
const HOT_TAGS = ['critical', 'backdoor-account', 'reverse_shell_pattern',
                  'rootkit', 'bruteforce', 'privilege-escalation',
                  'suspicious-process', 'suspicious-file', 'known_malware_name',
                  'suspicious-content', 'ssh-key'];

const state = {
  runs: [],
  current: null,      // 当前 run 的完整数据
  tab: 'findings',
  filterSev: new Set(),
  search: '',
  autoTimer: null,
};

/* ------------------------------ 工具 ------------------------------ */
const $ = (id) => document.getElementById(id);

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function fmtTime(iso, withDate = true) {
  if (!iso) return '-';
  const d = new Date(iso);
  if (isNaN(d)) return String(iso);
  const p = (n) => String(n).padStart(2, '0');
  const t = `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  if (!withDate) return t;
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${t}`;
}

function shortSha(s) { return s ? s.slice(0, 16) + '…' : '-'; }

function toast(msg) {
  const el = $('toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove('show'), 2000);
}

async function api(path, options) {
  const res = await fetch(path, options || { headers: { 'Accept': 'application/json' } });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `${res.status} ${res.statusText}`);
  return data;
}

async function postJson(path, body) {
  return api(path, {
    method: 'POST',
    headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

/* 事件标签集合 */
function tagsOf(ev) { return Array.isArray(ev.tags) ? ev.tags : []; }
function isHot(ev) { return tagsOf(ev).some((t) => HOT_TAGS.includes(t)); }

/* --------------------------- 侧栏: 记录列表 --------------------------- */
async function loadRuns(keepSelection = true) {
  try {
    const [runsRes, ov] = await Promise.all([api('/api/runs'), api('/api/overview')]);
    state.runs = runsRes.runs || [];
    $('runCount').textContent = state.runs.length;
    $('workspaceLabel').textContent = ov.workspace || '-';
    $('workspaceLabel').title = ov.workspace || '';
    renderRunList();

    if (!keepSelection || !state.current) {
      if (state.runs.length) selectRun(state.runs[0].run_id);
      else renderEmpty();
    }
  } catch (e) {
    $('runList').innerHTML = `<div class="empty-hint">加载失败：${esc(e.message)}</div>`;
  }
}

function renderRunList() {
  const box = $('runList');
  if (!state.runs.length) {
    box.innerHTML = '<div class="empty-hint">暂无分析记录<br>请先执行 <code>python -m irtrace run</code></div>';
    return;
  }
  box.innerHTML = state.runs.map((r) => {
    const sc = r.severity_counts || {};
    const worst = SEV_ORDER.find((s) => (sc[s] || 0) > 0) || 'info';
    const active = state.current && state.current.run_id === r.run_id ? ' active' : '';
    const bars = SEV_ORDER.slice(0, 4).map((s) =>
      `<i style="background:${(sc[s] || 0) > 0 ? SEV[s].color : '#dde3ea'}"></i>`).join('');
    return `
      <div class="run-item${active}" data-run="${esc(r.run_id)}"
           style="border-left-color:${SEV[worst].color}">
        <div class="r1">
          <span class="rid mono">${esc(r.run_id)}</span>
          <span class="sev-mini" title="${SEV_ORDER.map(s => SEV[s].label + ' ' + (sc[s] || 0)).join(' / ')}">${bars}</span>
        </div>
        <div class="host">${esc(r.host)}</div>
        <div class="r2">
          <span>${fmtTime(r.generated_at)}</span>
          <span>·</span>
          <span>${r.findings} 结论</span>
          <span>·</span>
          <span>${r.events} 事件</span>
        </div>
      </div>`;
  }).join('');

  box.querySelectorAll('.run-item').forEach((el) => {
    el.addEventListener('click', () => selectRun(el.dataset.run));
  });
}

function renderEmpty() {
  $('runTitle').textContent = '暂无分析记录';
  $('runMeta').textContent = '';
  $('riskBadge').textContent = '-';
  $('riskBadge').style.background = '#7c8798';
  $('stats').innerHTML = '';
  $('severityCard').style.display = 'none';
  $('timelineCard').style.display = 'none';
  $('tabs').innerHTML = '';
  $('panel').innerHTML = '<div class="empty-hint big">请先执行一次溯源分析</div>';
}

/* ------------------------------ 选择记录 ------------------------------ */
async function selectRun(runId) {
  try {
    const data = await api('/api/runs/' + encodeURIComponent(runId));
    state.current = data;
    state.filterSev.clear();
    state.search = '';
    state.tab = 'findings';
    renderRunList();
    renderRun(data);
  } catch (e) {
    toast('加载失败：' + e.message);
  }
}

/* ------------------------------ 渲染主区 ------------------------------ */
function renderRun(data) {
  const meta = data.meta || {};
  const sum = data.summary || {};
  const counts = meta.severity_counts || sum.findings_by_severity || {};

  /* 顶栏 */
  $('runTitle').textContent = `${meta.host || sum.host || '-'} 入侵溯源分析`;
  $('runMeta').innerHTML =
    `运行 ID <code>${esc(data.run_id)}</code>　·　` +
    `执行人 ${esc(meta.operator || sum.operator || '-')}　·　` +
    `生成于 ${fmtTime(meta.generated_at || sum.generated_at)}`;

  const risk = meta.risk_level || '-';
  const worst = SEV_ORDER.find((s) => (counts[s] || 0) > 0) || 'info';
  const badge = $('riskBadge');
  badge.textContent = '结论：' + risk;
  badge.style.background = SEV[worst].color;

  const link = $('rawReportLink');
  if (data.report_html) {
    link.style.display = '';
    link.href = `/api/runs/${encodeURIComponent(data.run_id)}/report.html`;
  } else { link.style.display = 'none'; }

  /* 统计卡 */
  const crit = (counts.critical || 0) + (counts.high || 0);
  const nEvents = (data.events || []).length;
  const nEvidence = (data.evidence || []).length;
  const nFindings = (data.findings || []).length;
  const nWarn = (data.warnings || []).length;
  $('stats').innerHTML = [
    stat(nEvents, '归一化事件', ''),
    stat(nFindings, '分析结论', ''),
    stat(crit, '严重 / 高危', crit ? 'danger' : 'ok'),
    stat(nEvidence, '证据条目', ''),
    stat(nWarn, '采集告警', nWarn ? 'warn' : ''),
  ].join('');

  /* 严重级别分布 */
  const total = Math.max(1, SEV_ORDER.reduce((a, s) => a + (counts[s] || 0), 0));
  $('severityCard').style.display = '';
  $('sevBars').innerHTML = SEV_ORDER.map((s) => {
    const n = counts[s] || 0;
    return `<div class="sev-row">
      <span class="sev-tag" style="background:${SEV[s].color}">${SEV[s].label}</span>
      <div class="sev-track"><div class="sev-fill"
        style="width:${(n / total * 100).toFixed(1)}%;background:${SEV[s].color}"></div></div>
      <span class="sev-num">${n} 条</span>
    </div>`;
  }).join('');

  /* 时间密度 */
  renderSpark(data.events || []);

  /* 标签页 */
  const tabs = [
    ['findings', '发现项', nFindings],
    ['timeline', '时间线', nEvents],
    ['intel', '威胁情报', null],
    ['evidence', '证据链', nEvidence],
    ['audit', '审计日志', null],
  ];
  $('tabs').innerHTML = tabs.map(([k, label, cnt]) =>
    `<button class="tab${state.tab === k ? ' active' : ''}" data-tab="${k}">
       ${label}${cnt != null ? `<span class="cnt">${cnt}</span>` : ''}
     </button>`).join('');
  $('tabs').querySelectorAll('.tab').forEach((b) =>
    b.addEventListener('click', () => { state.tab = b.dataset.tab; renderRun(state.current); }));

  renderPanel();
}

function stat(n, label, cls) {
  return `<div class="stat ${cls}"><div class="n">${n}</div><div class="l">${label}</div></div>`;
}

/* --------------------------- 事件密度图 (SVG) --------------------------- */
function renderSpark(events) {
  const withTs = events.filter((e) => e.timestamp);
  const card = $('timelineCard');
  if (withTs.length < 2) { card.style.display = 'none'; return; }
  card.style.display = '';

  const times = withTs.map((e) => new Date(e.timestamp).getTime()).filter((t) => !isNaN(t));
  const min = Math.min(...times), max = Math.max(...times);
  const span = Math.max(1, max - min);
  const BUCKETS = 72;
  const buckets = Array.from({ length: BUCKETS }, () => ({ n: 0, hot: 0 }));

  withTs.forEach((e) => {
    const t = new Date(e.timestamp).getTime();
    if (isNaN(t)) return;
    const i = Math.min(BUCKETS - 1, Math.floor((t - min) / span * BUCKETS));
    buckets[i].n++;
    if (isHot(e)) buckets[i].hot++;
  });

  const peak = Math.max(1, ...buckets.map((b) => b.n));
  const W = 1000, H = 120, bw = W / BUCKETS;
  const bars = buckets.map((b, i) => {
    if (!b.n) return '';
    const h = Math.max(3, (b.n / peak) * (H - 12));
    const color = b.hot ? '#c0392b' : '#2e86c1';
    return `<rect x="${(i * bw + 1).toFixed(1)}" y="${(H - h).toFixed(1)}"
      width="${Math.max(2, bw - 2).toFixed(1)}" height="${h.toFixed(1)}"
      fill="${color}" rx="1.5" opacity="${b.hot ? 0.95 : 0.6}">
      <title>${b.n} 个事件${b.hot ? `（${b.hot} 个高危）` : ''}</title></rect>`;
  }).join('');

  $('spark').innerHTML =
    `<line x1="0" y1="${H - 1}" x2="${W}" y2="${H - 1}" stroke="#e2e8f0" stroke-width="1"/>` + bars;
  $('sparkAxis').innerHTML =
    `<span>${fmtTime(new Date(min).toISOString())}</span>
     <span class="muted">红色 = 含高危事件　共 ${withTs.length} 个带时间戳事件</span>
     <span>${fmtTime(new Date(max).toISOString())}</span>`;
}

/* ------------------------------ 面板路由 ------------------------------ */
function renderPanel() {
  const data = state.current;
  if (!data) return;
  const fns = {
    findings: renderFindings,
    timeline: renderTimeline,
    intel: renderIntel,
    evidence: renderEvidence,
    audit: renderAudit,
  };
  (fns[state.tab] || renderFindings)(data);
}

/* ------------------------------ 发现项 ------------------------------ */
function renderFindings(data) {
  const all = data.findings || [];
  const q = state.search.trim().toLowerCase();
  const list = all.filter((f) => {
    if (state.filterSev.size && !state.filterSev.has(f.severity)) return false;
    if (!q) return true;
    return JSON.stringify(f).toLowerCase().includes(q);
  });

  const toolbar = `
    <div class="toolbar">
      <input type="search" id="fSearch" placeholder="搜索标题 / 描述 / 标签 / MITRE…"
             value="${esc(state.search)}">
      ${SEV_ORDER.map((s) => {
        const n = all.filter((f) => f.severity === s).length;
        if (!n) return '';
        return `<button class="chip${state.filterSev.has(s) ? ' on' : ''}" data-sev="${s}"
                  style="${state.filterSev.has(s) ? `background:${SEV[s].color};border-color:${SEV[s].color}` : ''}">
                  ${SEV[s].label} ${n}</button>`;
      }).join('')}
      ${state.filterSev.size || q ? '<button class="chip" id="clearFilter">清除筛选</button>' : ''}
      <span class="muted" style="font-size:12px">显示 ${list.length} / ${all.length}</span>
    </div>`;

  if (!all.length) {
    $('panel').innerHTML = '<div class="empty-hint big">未发现明显异常</div>';
    return;
  }

  const body = list.length ? list.map(renderFindingCard).join('')
    : '<div class="empty-hint big">没有符合筛选条件的结论</div>';

  $('panel').innerHTML = toolbar + body;

  const search = $('fSearch');
  search.addEventListener('input', (e) => {
    state.search = e.target.value;
    const pos = e.target.selectionStart;
    renderPanel();
    const el = $('fSearch'); el.focus(); el.setSelectionRange(pos, pos);
  });
  $('panel').querySelectorAll('[data-sev]').forEach((b) =>
    b.addEventListener('click', () => {
      const s = b.dataset.sev;
      state.filterSev.has(s) ? state.filterSev.delete(s) : state.filterSev.add(s);
      renderPanel();
    }));
  const cf = $('clearFilter');
  if (cf) cf.addEventListener('click', () => {
    state.filterSev.clear(); state.search = ''; renderPanel();
  });
}

function renderFindingCard(f) {
  const c = SEV[f.severity] || SEV.info;
  const chips = [];
  chips.push(`<span class="tag solid" style="background:${c.color}">${c.label}</span>`);
  chips.push(`<span class="tag">置信度 ${esc(f.confidence || '-')}</span>`);
  chips.push(`<span class="tag">${esc(f.category || '-')}</span>`);
  chips.push(`<span class="tag">${esc(f.analyzer || '-')}</span>`);
  (f.mitre || []).forEach((m) => chips.push(`<span class="tag mitre">${esc(m)}</span>`));
  (f.details && f.details.tags ? f.details.tags : []).slice(0, 6)
    .forEach((t) => chips.push(`<span class="tag">${esc(t)}</span>`));

  const detail = f.details
    ? `<details><summary>查看详情（${Object.keys(f.details).length} 个字段）</summary>
         <pre>${esc(JSON.stringify(f.details, null, 2))}</pre></details>`
    : '';

  return `<div class="finding" style="border-left-color:${c.color}">
      <div class="ft">${esc(f.title)}</div>
      <div class="chips">${chips.join('')}</div>
      ${f.description ? `<p class="desc">${esc(f.description)}</p>` : ''}
      ${detail}
    </div>`;
}

/* ------------------------------ 时间线 ------------------------------ */
function renderTimeline(data) {
  const q = state.search.trim().toLowerCase();
  let list = (data.events || []).slice().sort(
    (a, b) => new Date(a.timestamp || 0) - new Date(b.timestamp || 0));

  const onlyHot = state.filterSev.has('hot');
  if (onlyHot) list = list.filter(isHot);
  if (q) list = list.filter((e) => JSON.stringify(e).toLowerCase().includes(q));

  const toolbar = `
    <div class="toolbar">
      <input type="search" id="tSearch" placeholder="搜索事件（动作 / 用户 / 路径 / 描述）…"
             value="${esc(state.search)}">
      <button class="chip${onlyHot ? ' on' : ''}" id="hotChip">仅高危事件</button>
      <span class="muted" style="font-size:12px">显示 ${list.length} / ${(data.events || []).length}</span>
    </div>`;

  const rows = list.map((e) => {
    const hot = isHot(e);
    const tags = tagsOf(e).slice(0, 4)
      .map((t) => `<span class="tag">${esc(t)}</span>`).join(' ');
    const subject = e.user || e.path || (e.dst_ip ? `${e.dst_ip}${e.dst_port ? ':' + e.dst_port : ''}` : '-');
    return `<tr${hot ? ' style="background:#fdf3f1"' : ''}>
      <td class="nowrap mono">${fmtTime(e.timestamp)}</td>
      <td class="nowrap"><span class="tag">${esc(e.category || '-')}</span></td>
      <td class="nowrap mono">${esc(e.action || '-')}</td>
      <td class="nowrap mono">${esc(subject)}</td>
      <td class="truncate" title="${esc(e.message || '')}">${esc(e.message || '')}</td>
      <td class="nowrap">${tags}</td>
    </tr>`;
  }).join('');

  $('panel').innerHTML = toolbar + `<div class="table-wrap"><div class="table-scroll">
    <table><thead><tr>
      <th class="nowrap">时间</th><th class="nowrap">类别</th><th class="nowrap">动作</th>
      <th class="nowrap">主体</th><th>描述</th><th class="nowrap">标签</th>
    </tr></thead><tbody>${rows || '<tr><td colspan="6" class="muted">无匹配事件</td></tr>'}</tbody>
    </table></div></div>`;

  bindSearch('tSearch', renderPanel);
  $('hotChip').addEventListener('click', () => {
    state.filterSev.has('hot') ? state.filterSev.delete('hot') : state.filterSev.add('hot');
    renderPanel();
  });
}

function bindSearch(id, rerender) {
  const el = $(id);
  if (!el) return;
  el.addEventListener('input', (e) => {
    state.search = e.target.value;
    const pos = e.target.selectionStart;
    rerender();
    const n = $(id); n.focus(); n.setSelectionRange(pos, pos);
  });
}

/* ------------------------------ 威胁情报 ------------------------------ */
function renderIntel(data) {
  const intel = (data.stats && data.stats.intel_providers) || {};
  const providers = intel.providers || [];
  const hits = (data.stats && data.stats.intel_hits) || {};
  const ioc = (data.stats && data.stats.ioc) || {};

  const provRows = providers.map((p) => {
    const kind = p.offline ? '离线' : '在线';
    const ok = p.available;
    return `<tr>
      <td class="mono">${esc(p.name)}</td>
      <td><span class="tag">${kind}</span></td>
      <td>${ok ? '<span class="tag solid" style="background:#2e7d32">可用</span>'
               : '<span class="tag solid" style="background:#9aa5b1">不可用</span>'}</td>
      <td class="num">${p.weight}</td>
      <td class="muted">${esc(ok ? (p.supports || []).join(' / ') : (p.reason || ''))}</td>
    </tr>`;
  }).join('');

  const hitBlocks = Object.keys(hits).length
    ? Object.entries(hits).map(([name, items]) => `
        <h3><code>${esc(name)}</code> — 命中 ${items.length} 个指标</h3>
        <div class="table-wrap"><table><thead><tr>
          <th>指标</th><th class="nowrap">类型</th><th class="num">评分</th>
        </tr></thead><tbody>${items.map((i) => `
          <tr><td class="mono">${esc(i.indicator)}</td>
              <td>${esc(i.type)}</td>
              <td class="num">${i.score}</td></tr>`).join('')}
        </tbody></table></div>`).join('')
    : '<div class="empty-hint">本次分析无情报命中（或未启用情报源）</div>';

  $('panel').innerHTML = `
    <div class="card">
      <h2>情报源与查询统计</h2>
      <div class="stats" style="margin-bottom:16px">
        ${stat(providers.length, '启用情报源', '')}
        ${stat(intel.queries || 0, '情报查询次数', '')}
        ${stat(intel.cache_hits || 0, '缓存命中', '')}
        ${stat(ioc.external_peers || 0, '外部对端地址', (ioc.external_peers || 0) ? 'warn' : '')}
      </div>
      <div class="table-wrap"><table><thead><tr>
        <th>情报平台</th><th class="nowrap">类型</th><th class="nowrap">状态</th>
        <th class="num nowrap">权重</th><th>支持指标 / 不可用原因</th>
      </tr></thead><tbody>
        ${provRows || '<tr><td colspan="5" class="muted">未启用情报源</td></tr>'}
      </tbody></table></div>
    </div>
    <div class="card">
      <h2>情报源命中统计</h2>
      ${hitBlocks}
    </div>
    <div class="card">
      <h2>IOC 提取汇总</h2>
      <div class="stats" style="margin-bottom:0">
        ${stat(ioc.ips || 0, 'IP 指标', '')}
        ${stat(ioc.domains || 0, '域名指标', '')}
        ${stat(ioc.urls || 0, 'URL 指标', '')}
        ${stat(ioc.hashes || 0, '文件哈希', '')}
      </div>
    </div>`;
}

/* ------------------------------ 证据链 ------------------------------ */
async function renderEvidence(data) {
  const list = data.evidence || [];
  const q = state.search.trim().toLowerCase();
  const filtered = q
    ? list.filter((e) => JSON.stringify(e).toLowerCase().includes(q))
    : list;

  const rows = filtered.map((e, i) => `
    <tr>
      <td class="num">${i + 1}</td>
      <td class="mono nowrap">${esc(e.source)}</td>
      <td class="nowrap"><span class="tag">${esc(e.kind)}</span></td>
      <td class="mono truncate" title="${esc(e.path || '')}">${esc(e.path || '-')}</td>
      <td class="mono nowrap">${esc((e.size == null ? '-' : e.size + ' B'))}</td>
      <td class="mono nowrap" title="${esc(e.sha256 || '')}">${esc(shortSha(e.sha256))}</td>
    </tr>`).join('');

  $('panel').innerHTML = `
    <div class="toolbar">
      <input type="search" id="eSearch" placeholder="搜索证据…" value="${esc(state.search)}">
      <span class="muted" style="font-size:12px">显示 ${filtered.length} / ${list.length}</span>
      <span id="ledgerState" class="muted" style="font-size:12px">哈希链校验中…</span>
    </div>
    <div class="table-wrap"><div class="table-scroll">
      <table><thead><tr>
        <th class="num nowrap">#</th><th class="nowrap">来源</th><th class="nowrap">类型</th>
        <th>目标</th><th class="nowrap">大小</th><th class="nowrap">SHA256</th>
      </tr></thead><tbody>${rows || '<tr><td colspan="6" class="muted">无证据</td></tr>'}</tbody>
      </table></div></div>`;

  bindSearch('eSearch', renderEvidencePanel);

  /* 校验哈希链 */
  try {
    const led = await api(`/api/runs/${encodeURIComponent(data.run_id)}/ledger`);
    const el = $('ledgerState');
    if (el) {
      el.innerHTML = led.valid
        ? `<span class="good">✓ 证据哈希链完整（${led.count} 条记录）</span>`
        : '<span class="bad">✗ 证据哈希链校验失败，可能存在篡改</span>';
    }
  } catch (e) { /* 忽略 */ }
}

/* 保持输入焦点: 证据面板重绘 */
function renderEvidencePanel() { if (state.current) renderEvidence(state.current); }

/* ------------------------------ 审计日志 ------------------------------ */
async function renderAudit(data) {
  let entries = [];
  try {
    const res = await api(`/api/runs/${encodeURIComponent(data.run_id)}/audit`);
    entries = res.entries || [];
  } catch (e) { /* 忽略 */ }

  const q = state.search.trim().toLowerCase();
  const list = q ? entries.filter((e) => JSON.stringify(e).toLowerCase().includes(q)) : entries;

  const rows = list.slice().reverse().map((e) => `
    <tr>
      <td class="nowrap mono">${fmtTime(e.at)}</td>
      <td class="nowrap"><span class="tag">${esc(e.action || '-')}</span></td>
      <td class="mono truncate">${esc(e.cmd || e.run_id || '')}</td>
      <td class="num nowrap">${e.rc == null ? '-' : e.rc}</td>
    </tr>`).join('');

  $('panel').innerHTML = `
    <div class="toolbar">
      <input type="search" id="aSearch" placeholder="搜索审计日志…" value="${esc(state.search)}">
      <span class="muted" style="font-size:12px">显示 ${list.length} / ${entries.length} 条</span>
    </div>
    <div class="table-wrap"><div class="table-scroll">
      <table><thead><tr>
        <th class="nowrap">时间</th><th class="nowrap">动作</th><th>命令 / 详情</th>
        <th class="num nowrap">返回码</th>
      </tr></thead><tbody>${rows || '<tr><td colspan="4" class="muted">无审计记录</td></tr>'}</tbody>
      </table></div></div>`;

  bindSearch('aSearch', renderAuditPanel);
}

function renderAuditPanel() { if (state.current) renderAudit(state.current); }

/* ------------------------------ 自动刷新 ------------------------------ */
function setupAutoRefresh() {
  const cb = $('autoRefresh');
  cb.addEventListener('change', () => {
    clearInterval(state.autoTimer);
    if (cb.checked) {
      state.autoTimer = setInterval(async () => {
        const cur = state.current && state.current.run_id;
        await loadRuns(true);
        if (cur) {
          try { state.current = await api('/api/runs/' + encodeURIComponent(cur)); renderRun(state.current); }
          catch (e) { /* 忽略 */ }
        }
      }, 15000);
      toast('已开启自动刷新（15 秒）');
    } else {
      toast('已关闭自动刷新');
    }
  });
}

/* ------------------------------ 启动 ------------------------------ */
function init() {
  $('refreshBtn').addEventListener('click', async () => {
    const cur = state.current && state.current.run_id;
    await loadRuns(true);
    if (cur) { try { await selectRun(cur); } catch (e) { /* 忽略 */ } }
    toast('已刷新');
  });
  $('keysBtn').addEventListener('click', openKeys);
  $('keysClose').addEventListener('click', () => { $('keysModal').hidden = true; });
  $('settingsBtn').addEventListener('click', openSettings);
  $('settingsClose').addEventListener('click', () => { $('settingsModal').hidden = true; });
  $('settingsSave').addEventListener('click', saveSettings);
  $('pullBtn').addEventListener('click', pullThreats);
  setupAutoRefresh();
  loadRuns(false);
}

/* --------------------------- 情报源 Key --------------------------- */
async function openKeys() {
  $('keysModal').hidden = false;
  $('keysBody').innerHTML = '<div class="empty-hint">加载中…</div>';
  try {
    const data = await api('/api/intel/keys');
    renderKeys(data.providers || []);
  } catch (err) {
    $('keysBody').innerHTML = `<div class="empty-hint">${esc(err.message)}</div>`;
  }
}

function renderKeys(providers) {
  if (!providers.length) {
    $('keysBody').innerHTML = '<div class="empty-hint">没有可配置的在线情报源</div>';
    return;
  }
  $('keysBody').innerHTML = providers.map((p) => `
    <div class="key-row" data-name="${esc(p.name)}">
      <div class="key-name">${esc(p.name)}
        <small>${esc(p.description || '')}</small>
        ${p.configured ? `<span class="key-hint">已配置 ${esc(p.hint)}</span>` : '<small>未配置</small>'}
      </div>
      <div class="key-fields">
        <input type="password" autocomplete="new-password" data-field="api_key"
               placeholder="${p.configured ? '留空表示不修改' : 'API Key'}">
        ${p.needs_url ? `<input type="text" data-field="url" placeholder="https://misp.example.com" value="${esc(p.url || '')}">` : ''}
      </div>
      <div class="key-actions">
        <label class="switch" title="启用后参与在线查询">
          <input type="checkbox" data-field="enabled" ${p.enabled ? 'checked' : ''}>
          <span>启用</span>
        </label>
        <button class="btn" type="button" data-act="save">保存</button>
        <button class="btn btn-ghost" type="button" data-act="delete" ${p.configured ? '' : 'disabled'}>清除</button>
      </div>
    </div>`).join('');

  $('keysBody').querySelectorAll('.key-row').forEach((row) => {
    row.querySelector('[data-act="save"]').addEventListener('click', () => saveKey(row, 'save'));
    const del = row.querySelector('[data-act="delete"]');
    if (del) del.addEventListener('click', () => saveKey(row, 'delete'));
  });
}

async function saveKey(row, action) {
  const name = row.dataset.name;
  const body = {
    name,
    action,
    api_key: (row.querySelector('[data-field="api_key"]') || {}).value || '',
    enabled: !!((row.querySelector('[data-field="enabled"]') || {}).checked),
  };
  const url = row.querySelector('[data-field="url"]');
  if (url) body.url = url.value;
  try {
    const data = await postJson('/api/intel/keys', body);
    renderKeys(data.providers || []);
    toast(action === 'delete' ? '已清除 ' + name : '已保存 ' + name);
  } catch (err) {
    toast(err.message);
  }
}

async function openSettings() {
  $('settingsModal').hidden = false;
  try {
    const data = await api('/api/settings');
    $('aiEnabled').checked = !!(data.ai && data.ai.enabled);
    $('aiCross').checked = !!(data.ai && data.ai.cross_validate);
    renderThreatDb(data.threat_db);
  } catch (err) {
    toast(err.message);
  }
}

function renderThreatDb(stats) {
  const last = stats && stats.last_pull;
  const count = (stats && stats.indicators) || 0;
  $('threatDbHint').textContent = last
    ? `${count} 条，最近拉取 ${last.pulled_at}`
    : '尚未拉取。检测只使用这里已有的记录';
}

async function saveSettings() {
  try {
    const data = await postJson('/api/settings', {
      ai: {
        enabled: $('aiEnabled').checked,
        cross_validate: $('aiCross').checked,
      },
    });
    $('aiCross').checked = !!(data.ai && data.ai.cross_validate);
    toast(data.ai && data.ai.cross_validate ? '已打开在线交叉验证' : '已保存，交叉验证保持关闭');
  } catch (err) {
    toast(err.message);
  }
}

async function pullThreats() {
  $('pullBtn').disabled = true;
  toast('正在拉取在线情报…');
  try {
    const data = await postJson('/api/intel/pull', {});
    const pull = data.pull || {};
    renderThreatDb({
      indicators: pull.stored,
      last_pull: pull,
    });
    const failed = (pull.errors || []).length;
    toast(`已写入 ${pull.stored || 0} 条` + (failed ? `，${failed} 项未完成` : ''));
  } catch (err) {
    toast(err.message);
  } finally {
    $('pullBtn').disabled = false;
  }
}

document.addEventListener('DOMContentLoaded', init);
