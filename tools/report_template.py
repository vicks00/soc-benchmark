"""HTML, CSS, and JavaScript for the rendered scorecard.

Kept apart from tools/report.py so the generator stays readable. The page has no dependencies: the
data is embedded and every chart is inline SVG built at load time.
"""

from __future__ import annotations

import json

_CSS = """
:root {
  --bg: #0f1115; --panel: #171a21; --line: #262b36; --text: #e6e9ef; --muted: #8b93a7;
  --good: #4ea87a; --mid: #c8a34a; --bad: #c05c5c; --accent: #5b8dd6; --flag: #7a2f2f;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 14px/1.5 ui-sans-serif, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
main { max-width: 1240px; margin: 0 auto; padding: 32px 24px 96px; }
h1 { font-size: 22px; margin: 0 0 4px; letter-spacing: -0.01em; }
h2 { font-size: 15px; margin: 40px 0 6px; text-transform: uppercase; letter-spacing: 0.08em;
     color: var(--muted); font-weight: 600; }
p.sub { margin: 0; color: var(--muted); font-size: 13px; }
p.study { max-width: 86ch; margin: 18px 0 0; font-size: 15px; color: var(--text); }
p.note { color: var(--muted); font-size: 12.5px; margin: 6px 0 14px; max-width: 78ch; }
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 16px; }
.decision { border-left: 3px solid var(--accent); margin: 22px 0 0; }
.tag {
  display: inline-block; font-size: 11px; padding: 1px 7px; border-radius: 3px;
  letter-spacing: 0.02em; white-space: nowrap;
}
.tag-good { background: #1e3b2c; color: #9fdcbb; }
.tag-warn { background: #3a3520; color: #e0cd93; }
.tag-bad { background: #3a2226; color: #e6aeae; }
.confidence-bars { margin: 0 0 18px; }
.confidence-row {
  display: grid; grid-template-columns: minmax(160px, 240px) minmax(120px, 1fr) 52px;
  gap: 12px; align-items: center; margin: 8px 0;
}
.confidence-row .name { font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.confidence-track { height: 10px; background: #202530; border-radius: 2px; overflow: hidden; }
.confidence-fill { height: 100%; background: var(--accent); border-radius: 2px; }
.confidence-val { text-align: right; font-variant-numeric: tabular-nums; color: var(--muted); }
.decision .lead { margin: 0; font-size: 16px; }
.decision .lead strong { color: var(--accent); }
.decision ul { margin: 10px 0 0; padding-left: 18px; color: var(--muted); font-size: 13px; }
.decision li { margin: 4px 0; }
.tier { font-size: 11px; padding: 2px 7px; border-radius: 3px; white-space: nowrap; }
.tier3 { background: #1e3b2c; color: #9fdcbb; }
.tier2 { background: #3a3520; color: #e0cd93; }
.tier1 { background: #3a2226; color: #e6aeae; }
td.where { text-align: left; color: var(--muted); font-size: 12.5px; }
.methodology dl { display: grid; grid-template-columns: 210px 1fr; gap: 10px 18px; margin: 0; }
.methodology dt { font-weight: 650; }
.methodology dd { margin: 0; color: var(--muted); }
@media (max-width: 700px) {
  .methodology dl { grid-template-columns: 1fr; gap: 4px; }
  .methodology dd { margin-bottom: 10px; }
}
.controls { display: flex; gap: 20px; align-items: center; margin: 18px 0 10px; flex-wrap: wrap; }
label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; }
select {
  background: var(--panel); color: var(--text); border: 1px solid var(--line);
  border-radius: 5px; padding: 5px 8px; font: inherit; font-size: 13px; margin-left: 8px;
}
table { width: 100%; border-collapse: collapse; font-variant-numeric: tabular-nums; }
th, td { text-align: right; padding: 7px 9px; border-bottom: 1px solid var(--line); }
th:first-child, td:first-child { text-align: left; }
th { color: var(--muted); font-weight: 600; font-size: 11.5px; text-transform: uppercase;
     letter-spacing: 0.05em; cursor: pointer; user-select: none; white-space: nowrap; }
th:hover { color: var(--text); }
tr.baseline td { color: var(--muted); font-style: italic; border-bottom: 1px dashed var(--line); }
tr.disqualified td { opacity: 0.62; }
.badge {
  margin-left: 8px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em;
  background: var(--flag); color: #ffd9d9; padding: 1px 6px; border-radius: 3px;
  vertical-align: middle; white-space: nowrap;
}
td.model { font-weight: 600; white-space: nowrap; }
#leaderboard { overflow-x: auto; }
td .band { color: var(--muted); font-weight: 400; margin-left: 6px; font-size: 12px; }
.sd { color: var(--muted); font-size: 11.5px; margin-left: 3px; }
.score-cell { min-width: 126px; }
.score-number { display: inline-block; min-width: 38px; text-align: right; }
.score-track { position: relative; display: inline-block; width: 72px; height: 8px; margin-left: 7px;
               background: #202530; border-radius: 2px; vertical-align: middle; }
.score-zero { position: absolute; left: 50%; top: -2px; bottom: -2px; width: 1px; background: #8b93a7; }
.score-bar { position: absolute; top: 1px; height: 6px; border-radius: 1px; }
.score-positive { left: 50%; background: var(--accent); }
.score-negative { right: 50%; background: #d88a43; }
.mini-bar { position: relative; display: inline-block; width: 54px; height: 6px; margin-left: 6px;
            background: #202530; border-radius: 2px; vertical-align: middle; }
.mini-bar > span { display: block; height: 100%; background: var(--accent); border-radius: 2px; }
details { color: var(--muted); }
details summary { color: var(--accent); cursor: pointer; user-select: none; }
details table { margin-top: 8px; }
.stack-section { margin: 0; }
.stack-section .panel { max-width: 100%; }
.confidence-bars { max-width: 720px; }
svg text { fill: var(--muted); font-size: 10.5px; }
svg .axis line, svg .axis path { stroke: var(--line); }
footer { margin-top: 56px; color: var(--muted); font-size: 12px;
         border-top: 1px solid var(--line); padding-top: 14px; }
code { background: #10131a; padding: 1px 5px; border-radius: 3px; font-size: 12.5px; }
a { color: var(--accent); }
"""

_JS = """
const D = JSON.parse(document.getElementById("data").textContent);
const METRICS = D.run_metrics;
const LOWER = new Set(D.lower_is_better);
const state = {
  profile: D.default_profile,
  sort: "classification_score",
  sortOverride: false,
  maxCost: Infinity,
};

const fmt = (v, dp = 3) => (v === null || v === undefined ? "\\u2013" : Number(v).toFixed(dp));
const el = (tag, attrs = {}, kids = []) => {
  const node = document.createElementNS(
    tag === "svg" || SVG.has(tag) ? "http://www.w3.org/2000/svg" : "http://www.w3.org/1999/xhtml",
    tag
  );
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  for (const kid of [].concat(kids)) node.append(kid);
  return node;
};
const SVG = new Set(["svg", "g", "rect", "circle", "line", "text", "path", "polyline", "title"]);

/* Profile scores and review modes are computed once in harness/scoring.py and read from here, so
   a ranking in the HTML and a ranking in the CSVs can never disagree. */
const profileScore = (row, profileId) => row.profile_scores[profileId];
const disqualifiers = (row, profileId) => row.profile_disqualifiers[profileId] || [];
const perScenarioCost = (row) => row.cost / D.scenario_count;
const visible = () => D.summaries.filter((s) => perScenarioCost(s) <= state.maxCost);

/* Where a score sits between the fixed-answer baseline and a perfect one, mirroring
   harness.config.baseline_lift for the columns the report annotates. */
function lift(value, metric) {
  const floor = D.baseline[metric];
  if (value === null || value === undefined || floor === undefined || floor === null) return null;
  return floor >= 1 ? value : (value - floor) / (1 - floor);
}

function scoreBar(score, scale = 1) {
  const cell = el("span", { class: "score-cell" });
  cell.append(el("span", { class: "score-number" },
    score === null || score === undefined ? "\\u2013" :
      (score === 0 ? "0" : (score * 100).toFixed(1))));
  const track = el("span", { class: "score-track", "aria-hidden": "true" });
  track.append(el("span", { class: "score-zero" }));
  if (score !== null && score !== undefined && score !== 0) {
    const width = Math.min(Math.abs(score) / scale, 1) * 50;
    track.append(el("span", {
      class: `score-bar ${score > 0 ? "score-positive" : "score-negative"}`,
      style: `width:${width}%`,
    }));
  }
  cell.append(track);
  return cell;
}

function miniBar(value, maximum = 1) {
  const track = el("span", { class: "mini-bar", "aria-hidden": "true" });
  track.append(el("span", { style: `width:${Math.max(0, Math.min(value / maximum, 1)) * 100}%` }));
  return track;
}

/* ---------- leaderboard ---------- */
const COLUMNS = [
  ["classification_score", "Alert classification"],
  ["action_score", "Response action"],
  ["severity_score", "Severity utility"],
  ["severity_exact", "Severity exact"],
  ["severity_mae", "Mean levels off"],
  ["technique_score", "Technique"],
  ["evidence_precision", "Supported evidence"],
  ["observation_recall", "Important facts found"],
  ["brier", "Confidence error (Brier)"],
  ["brier_skill", "Confidence skill"],
];

function renderLeaderboard() {
  const host = document.getElementById("leaderboard");
  host.textContent = "";
  const profileId = state.profile;
  const ranked = profileId !== "none";

  const rows = visible().map((summary) => ({
    ...summary,
    _score: profileScore(summary, profileId),
    _dq: disqualifiers(summary, profileId),
  }));
  rows.sort((a, b) => {
    if (ranked && !state.sortOverride) {
      // Disqualified models sink as a group, then everything is ordered by score. Ranking on the
      // number of disqualifiers instead would reorder rows on a key the reader cannot see.
      if (!a._dq.length !== !b._dq.length) return a._dq.length ? 1 : -1;
      return (b._score ?? -1) - (a._score ?? -1);
    }
    const key = state.sort;
    const [x, y] = [a[key], b[key]];
    if (key === "model") return String(x).localeCompare(String(y));
    if (x === null || x === undefined) return 1;
    if (y === null || y === undefined) return -1;
    return LOWER.has(key) ? x - y : y - x;
  });
  const scoreScale = Math.max(0.01, ...rows.map((row) => Math.abs(row._score || 0)));

  const head = el("tr");
  head.append(el("th", { "data-key": "model" }, "Model"));
  if (ranked) head.append(el("th", { "data-key": "_score" }, "Score"));
  head.append(el("th", {}, "Recommended review mode"));
  for (const [key, label] of COLUMNS) head.append(el("th", { "data-key": key }, label));
  for (const label of [
    "Unsafe close/monitor", "False alarm", "Runs with unsupported claims", "Failures",
    "Evaluation cost/scenario (3 runs)"
  ]) {
    head.append(el("th", {}, label));
  }
  head.querySelectorAll("th[data-key]").forEach((th) => {
    th.onclick = () => {
      state.sort = th.dataset.key;
      state.sortOverride = true;
      renderLeaderboard();
    };
  });

  const body = el("tbody");
  const base = D.baseline;
  const baseRow = el("tr", { class: "baseline" });
  baseRow.append(el("td", {}, `${base.label} baseline`));
  if (ranked) {
    const baselineScore = D.profiles[profileId].baseline_relative ? 0 : null;
    baseRow.append(el("td", { class: "score-cell" }, scoreBar(baselineScore, scoreScale)));
  }
  baseRow.append(el("td", {}, "\\u2013"));
  for (const [key] of COLUMNS) baseRow.append(el("td", {}, fmt(base[key])));
  for (let i = 0; i < 5; i += 1) baseRow.append(el("td", {}, "\\u2013"));
  body.append(baseRow);

  for (const row of rows) {
    const tr = el("tr", row._dq.length ? { class: "disqualified" } : {});
    const name = el("td", { class: "model" }, row.model);
    name.append(el("span", { class: "band" }, `${row.provider} \\u00b7 ${row.band}`));
    if (row._dq.length) {
      const reasons = row._dq.map((counter) => `${counter.replace(/_/g, " ")} ${row[counter]}`);
      name.append(el("span", { class: "badge", title: reasons.join("; ") }, reasons.join(" \\u00b7 ")));
    }
    tr.append(name);
    if (ranked) {
      // Zero is the fixed-policy baseline; negative bars extend left.
      tr.append(el("td", { class: "score-cell" }, scoreBar(row._score, scoreScale)));
    }
    const tier = el("td", {}, el("span", { class: `tier tier${row.review_mode.tier}`, title: row.review_mode.reason },
      row.review_mode.label));
    tr.append(tier);
    for (const [key] of COLUMNS) {
      const cell = el("td", {}, fmt(row[key]));
      const sd = row[`${key}_sd`];
      if (sd !== null && sd !== undefined) cell.append(el("span", { class: "sd" }, `\\u00b1${fmt(sd, 2)}`));
      const over = lift(row[key], key);
      if (over !== null) cell.setAttribute("title", `${fmt(over, 2)} of the way from baseline to perfect`);
      tr.append(cell);
    }
    tr.append(el("td", {}, String(row.unsafe_close_or_monitor_runs)));
    tr.append(el("td", {}, String(row.false_alarms)));
    tr.append(el("td", {}, String(row.unsupported_claim_runs)));
    const failures = row.refusal_runs + row.timeout_runs + row.invalid_output_runs +
      row.provider_error_runs + row.missing_result_runs;
    tr.append(el("td", {}, String(failures)));
    tr.append(el("td", {}, `$${(row.cost / D.scenario_count).toFixed(3)}`));
    body.append(tr);
  }

  const table = el("table");
  table.append(el("thead", {}, head), body);
  host.append(table);
  document.getElementById("profile-label").textContent = D.profiles[profileId].label;
}

/* ---------- decision header ---------- */
function renderDecision() {
  const host = document.getElementById("decision");
  host.textContent = "";
  const rows = D.summaries.filter((s) => s.classification_score !== null);
  const above = rows.filter((s) => lift(s.classification_score, "classification_score") > 0);
  const candidates = rows.filter((s) => s.review_mode.tier === 3);
  const best = rows.slice().sort((a, b) =>
    (b.profile_scores[D.default_profile] ?? -9) - (a.profile_scores[D.default_profile] ?? -9))[0];

  const lead = el("p", { class: "lead" });
  if (best) {
    lead.append(el("strong", {}, best.model));
    lead.append(` scores ${(best.profile_scores[D.default_profile] * 100).toFixed(1)} of 100 ` +
      `at $${perScenarioCost(best).toFixed(3)} per evaluated scenario (three runs).`);
  }
  host.append(lead);
  if (best) {
    const singleRunCost = best.cost / (D.scenario_count * 3);
    host.append(el("p", { class: "sub" },
      `Approximately $${(singleRunCost * 1000).toFixed(2)} per 1,000 alerts for one batch ` +
      `triage run, assuming similar telemetry volume and token usage.`));
  }

  const facts = el("ul");
  facts.append(el("li", {}, `${above.length} of ${rows.length} configurations classify better than ` +
    `the conservative fixed policy, which already scores ` +
    `${fmt(D.baseline.classification_score, 3)} on classification.`));
  facts.append(el("li", {}, candidates.length
    ? `${candidates.length} of ${rows.length} qualifies for controlled-autonomy testing: ` +
      `${candidates.map((s) => s.model).join(", ")}.`
    : `No configuration cleared the bar for acting without review.`));
  host.append(facts);
}

/* ---------- scenario heatmap ---------- */
function renderHeatmap() {
  const host = document.getElementById("heatmap");
  host.textContent = "";
  const scenarios = [...new Set(D.cells.map((c) => c.scenario))].sort();
  const models = D.summaries.map((s) => s.model);
  const byKey = new Map(D.cells.map((c) => [`${c.model}|${c.scenario}`, c]));
  const refClass = new Map(D.cells.map((c) => [c.scenario, c.reference_class]));

  const left = 190, top = 92, cw = 62, ch = 30;
  const svg = el("svg", {
    width: left + scenarios.length * cw + 16,
    height: top + models.length * ch + 20,
    viewBox: `0 0 ${left + scenarios.length * cw + 16} ${top + models.length * ch + 20}`,
  });

  scenarios.forEach((scenario, i) => {
    const parts = scenario.replace(/^scenario_/, "").split("_");
    const short = `${parts[0]} ${parts.slice(1).join("_").slice(0, 14)}`;
    const x = left + i * cw + cw / 2;
    const label = el("text", {
      x, y: top - 34, transform: `rotate(-40 ${x} ${top - 34})`, "text-anchor": "start",
    }, short);
    label.append(el("title", {}, scenario));
    svg.append(label);
    svg.append(el("text", { x, y: top - 8, "text-anchor": "middle", "font-size": "9" },
      (refClass.get(scenario) || "").slice(0, 4).toUpperCase()));
  });

  models.forEach((model, r) => {
    svg.append(el("text", { x: left - 10, y: top + r * ch + ch / 2 + 4, "text-anchor": "end" }, model));
    scenarios.forEach((scenario, c) => {
      const cell = byKey.get(`${model}|${scenario}`);
      const value = cell ? cell.classification_score : null;
      const fill = value === null ? "#20242e"
        : value >= 0.95 ? "#2f6f9f" : value >= 0.7 ? "#4f91bf"
        : value >= 0.4 ? "#c98b43" : "#a8572a";
      const rect = el("rect", {
        x: left + c * cw + 2, y: top + r * ch + 2, width: cw - 4, height: ch - 4,
        rx: 3, fill,
      });
      rect.append(el("title", {}, `${model}\\n${scenario}\\nclassification ${fmt(value)}`));
      svg.append(rect);
      svg.append(el("text", {
        x: left + c * cw + cw / 2, y: top + r * ch + ch / 2 + 4,
        "text-anchor": "middle", fill: "#e6e9ef",
      }, value === null ? "\\u2013" : value.toFixed(2)));
    });
  });
  host.append(svg);
}

/* Nudge overlapping SVG labels apart vertically. Cheap enough for the handful of points here,
   and it keeps model names legible when several score similarly. */
function deCollide(nodes) {
  for (let pass = 0; pass < 10; pass += 1) {
    let moved = false;
    for (let i = 0; i < nodes.length; i += 1) {
      for (let j = i + 1; j < nodes.length; j += 1) {
        const a = nodes[i].getBBox(), b = nodes[j].getBBox();
        const overlap = a.x < b.x + b.width && b.x < a.x + a.width &&
                        a.y < b.y + b.height && b.y < a.y + a.height;
        if (!overlap) continue;
        const shift = (Math.min(a.y + a.height, b.y + b.height) - Math.max(a.y, b.y)) / 2 + 1;
        const [up, down] = a.y <= b.y ? [nodes[i], nodes[j]] : [nodes[j], nodes[i]];
        up.setAttribute("y", parseFloat(up.getAttribute("y")) - shift);
        down.setAttribute("y", parseFloat(down.getAttribute("y")) + shift);
        moved = true;
      }
    }
    if (!moved) return;
  }
}

/* ---------- score against cost ---------- */
function renderScatter() {
  const host = document.getElementById("scatter");
  host.textContent = "";
  const profileId = state.profile;
  const ranked = profileId !== "none";
  const metric = ranked ? profileId
    : (state.sort in D.summaries[0] && !LOWER.has(state.sort) ? state.sort : "classification_score");
  const points = visible()
    .map((s) => ({
      model: s.model,
      x: perScenarioCost(s),
      y: ranked ? profileScore(s, profileId) : s[metric],
    }))
    .filter((p) => p.y !== null && p.y !== undefined);
  if (!points.length) { host.append(el("p", { class: "note" }, "No models under this cost.")); return; }

  const W = 980, H = 360, pad = { l: 58, r: 28, t: 28, b: 52 };
  const xs = points.map((p) => p.x), ys = points.map((p) => p.y);
  const xMin = Math.min(...xs, 0.03) * 0.8;
  const xMax = Math.max(...xs, 1) * 1.2;
  const logMin = Math.log10(xMin), logMax = Math.log10(xMax);
  const yMin = Math.min(...ys, 0) - 0.06;
  const yMax = Math.max(...ys, 0) + 0.08;
  const sx = (v) => pad.l +
    ((Math.log10(v) - logMin) / (logMax - logMin)) * (W - pad.l - pad.r);
  const sy = (v) => H - pad.b - ((v - yMin) / (yMax - yMin || 1)) * (H - pad.t - pad.b);

  const svg = el("svg", { width: "100%", viewBox: `0 0 ${W} ${H}` });
  for (const tick of [0.03, 0.1, 0.3, 1]) {
    if (tick < xMin || tick > xMax) continue;
    const x = sx(tick);
    svg.append(el("line", { x1: x, x2: x, y1: pad.t, y2: H - pad.b, stroke: "#262b36" }));
    svg.append(el("text", { x, y: H - pad.b + 17, "text-anchor": "middle" },
      `$${tick.toFixed(2)}`));
  }
  for (const tick of [-0.25, 0, 0.25, 0.5, 0.75, 1]) {
    if (tick < yMin || tick > yMax) continue;
    const y = sy(tick);
    svg.append(el("line", { x1: pad.l, x2: W - pad.r, y1: y, y2: y, stroke: "#262b36" }));
    svg.append(el("text", { x: pad.l - 7, y: y + 4, "text-anchor": "end" },
      ranked ? (tick * 100).toFixed(0) : tick.toFixed(2)));
  }
  svg.append(el("line", { x1: pad.l, y1: H - pad.b, x2: W - pad.r, y2: H - pad.b, stroke: "#596171" }));
  svg.append(el("line", { x1: pad.l, y1: pad.t, x2: pad.l, y2: H - pad.b, stroke: "#596171" }));

  const labels = [];
  const baseline = ranked ? (D.profiles[profileId].baseline_relative ? 0 : null) : D.baseline[metric];
  if (baseline !== undefined && baseline !== null) {
    svg.append(el("line", {
      x1: pad.l, x2: W - pad.r, y1: sy(baseline), y2: sy(baseline),
      stroke: "#8b93a7", "stroke-dasharray": "4 4", "stroke-width": 1,
    }));
    const caption = el("text", { x: pad.l + 4, y: sy(baseline) - 6 },
      ranked ? `${D.baseline.label} baseline` : `${D.baseline.label} baseline ${fmt(baseline, 2)}`);
    svg.append(caption);
    labels.push(caption);
  }

  const sorted = points.slice().sort((a, b) => a.x - b.x);
  const frontier = [];
  let best = -Infinity;
  for (const point of sorted) {
    if (point.y > best) {
      frontier.push(point);
      best = point.y;
    }
  }
  if (frontier.length > 1) {
    svg.append(el("polyline", {
      points: frontier.map((point) => `${sx(point.x)},${sy(point.y)}`).join(" "),
      fill: "none", stroke: "#4ea87a", "stroke-width": 2,
    }));
  }

  sorted.forEach((point, index) => {
    const onFrontier = frontier.includes(point);
    const dot = el("circle", {
      cx: sx(point.x), cy: sy(point.y), r: onFrontier ? 6 : 5, fill: "#5b8dd6",
      stroke: onFrontier ? "#9fdcbb" : "none", "stroke-width": onFrontier ? 2 : 0,
    });
    dot.append(el("title", {}, `${point.model}\\n${metric} ${fmt(point.y)}\\n$${point.x.toFixed(3)}/scenario`));
    svg.append(dot);
    const label = el("text", {
      x: sx(point.x), y: sy(point.y) + (index % 2 ? 19 : -10), "text-anchor": "middle",
    }, point.model);
    svg.append(label);
    labels.push(label);
  });
  svg.append(el("text", { x: (W) / 2, y: H - 8, "text-anchor": "middle" },
    "evaluation cost per scenario, three runs (USD, log scale)"));
  svg.append(el("text", { x: 12, y: pad.t + 8 },
    ranked ? "SOC triage score" : metric.replace(/_/g, " ")));
  svg.append(el("line", { x1: W - 142, x2: W - 116, y1: 15, y2: 15,
    stroke: "#4ea87a", "stroke-width": 2 }));
  svg.append(el("text", { x: W - 110, y: 19 }, "Pareto frontier"));
  host.append(svg);
  deCollide(labels);
}

/* ---------- confidence quality (replaces reliability diagram) ---------- */
function renderConfidence() {
  const host = document.getElementById("confidence");
  host.textContent = "";
  const byModel = new Map();
  for (const run of D.runs) {
    if (!run.valid || run.confidence === null || run.correct === null) continue;
    if (!byModel.has(run.model)) byModel.set(run.model, []);
    byModel.get(run.model).push(run);
  }
  const rows = D.summaries
    .map((summary) => {
      const runs = byModel.get(summary.model) || [];
      if (!runs.length || summary.brier_skill === null || summary.brier_skill === undefined) {
        return null;
      }
      const accuracy = runs.filter((run) => run.correct).length / runs.length;
      const avgConf = runs.reduce((total, run) => total + run.confidence, 0) / runs.length;
      const sure = runs.filter((run) => run.confidence >= 0.9);
      const sureAccuracy = sure.length
        ? sure.filter((run) => run.correct).length / sure.length
        : null;
      const gap = avgConf - accuracy;
      let reading = "Well matched";
      let tag = "tag-good";
      if (gap > 0.08) {
        reading = "Overconfident";
        tag = "tag-bad";
      } else if (gap < -0.08) {
        reading = "Underconfident";
        tag = "tag-warn";
      }
      return {
        model: summary.model,
        skill: summary.brier_skill,
        brier: summary.brier,
        accuracy,
        avgConf,
        sureAccuracy,
        sureN: sure.length,
        reading,
        tag,
      };
    })
    .filter(Boolean)
    .sort((a, b) => b.skill - a.skill);

  if (!rows.length) {
    host.append(el("p", { class: "note" }, "No confidence data to plot."));
    return;
  }

  const bars = el("div", { class: "confidence-bars" });
  bars.append(el("p", { class: "note" },
    "Confidence skill (higher is better). 0 matches a flat 25% guess; 1 is perfect. " +
    "Use this to see whose probability estimates you can trust."));
  for (const row of rows) {
    const line = el("div", { class: "confidence-row" });
    line.append(el("div", { class: "name", title: row.model }, row.model));
    const track = el("div", { class: "confidence-track" });
    const width = Math.max(0, Math.min(row.skill, 1)) * 100;
    track.append(el("div", {
      class: "confidence-fill",
      style: `width:${width}%`,
      title: `skill ${fmt(row.skill, 2)} · Brier ${fmt(row.brier, 3)}`,
    }));
    line.append(track);
    line.append(el("div", { class: "confidence-val" }, fmt(row.skill, 2)));
    bars.append(line);
  }
  host.append(bars);

  const table = el("table");
  const head = el("tr");
  for (const label of [
    "Model", "Correct rate", "Avg certainty claimed", "When ≥90% sure", "Reading",
  ]) {
    head.append(el("th", {}, label));
  }
  const body = el("tbody");
  for (const row of rows) {
    const tr = el("tr");
    tr.append(el("td", { class: "model" }, row.model));
    tr.append(el("td", {}, `${(row.accuracy * 100).toFixed(0)}%`));
    tr.append(el("td", {}, `${(row.avgConf * 100).toFixed(0)}%`));
    tr.append(el("td", {}, row.sureAccuracy === null
      ? "\\u2013"
      : `${(row.sureAccuracy * 100).toFixed(0)}% (${row.sureN} runs)`));
    const reading = el("td", {});
    reading.append(el("span", { class: `tag ${row.tag}` }, row.reading));
    tr.append(reading);
    body.append(tr);
  }
  table.append(el("thead", {}, head), body);
  host.append(table);
}

/* ---------- where the unsafe actions happened ---------- */
function renderSafety() {
  const host = document.getElementById("safety");
  host.textContent = "";
  const offenders = D.summaries.filter((s) => s.unsafe_close_or_monitor_runs)
    .sort((a, b) => b.unsafe_close_or_monitor_runs - a.unsafe_close_or_monitor_runs);
  if (!offenders.length) {
    host.append(el("p", { class: "note" },
      "No configuration recommended Close or Continue Monitoring when active handling was required."));
    return;
  }

  const table = el("table");
  const head = el("tr");
  for (const label of ["Model", "Unsafe close/monitor", "Where"]) head.append(el("th", {}, label));
  const body = el("tbody");
  for (const summary of offenders) {
    const where = D.cells
      .filter((c) => c.model === summary.model && c.unsafe_close_or_monitor_runs)
      .map((c) => `${c.scenario.replace(/^scenario_/, "")} (${c.unsafe_close_or_monitor_runs})`);
    const tr = el("tr");
    tr.append(el("td", { class: "model" }, summary.model));
    tr.append(el("td", {}, String(summary.unsafe_close_or_monitor_runs)));
    tr.append(el("td", { class: "where" }, where.join(", ")));
    body.append(tr);
  }
  table.append(el("thead", {}, head), body);
  host.append(table);
}

/* ---------- severity ---------- */
function renderSeverity() {
  const host = document.getElementById("severity");
  host.textContent = "";
  const rows = D.summaries.slice().sort((a, b) =>
    (b.severity_score ?? -1) - (a.severity_score ?? -1));
  const table = el("table");
  const head = el("tr");
  for (const label of [
    "Model", "Ordinal utility", "Exact", "Mean levels off", "Undercalls", "Severe undercalls"
  ]) head.append(el("th", {}, label));
  const body = el("tbody");
  for (const row of rows) {
    const tr = el("tr");
    tr.append(el("td", { class: "model" }, row.model));
    const utility = el("td", {}, fmt(row.severity_score));
    utility.append(miniBar(row.severity_score));
    tr.append(utility);
    tr.append(el("td", {}, fmt(row.severity_exact)));
    tr.append(el("td", {}, fmt(row.severity_mae, 2)));
    tr.append(el("td", {}, String(row.severity_undercalls)));
    tr.append(el("td", {}, String(row.severe_undercalls)));
    body.append(tr);
  }
  table.append(el("thead", {}, head), body);
  host.append(table);
}

/* ---------- leave-one-scenario-out stability ---------- */
function renderStability() {
  const host = document.getElementById("stability");
  host.textContent = "";
  const rows = D.summaries.slice().sort((a, b) => (b.soc_triage_score ?? -9) - (a.soc_triage_score ?? -9));
  const table = el("table");
  const head = el("tr");
  for (const label of [
    "Model", "Full score", "Score without any one scenario", "Rank range", "Winner changes"
  ]) head.append(el("th", {}, label));
  const body = el("tbody");
  for (const row of rows) {
    const sensitivity = row.leave_one_out;
    const tr = el("tr");
    tr.append(el("td", { class: "model" }, row.model));
    tr.append(el("td", {}, row.soc_triage_score === null ? "\\u2013" : (row.soc_triage_score * 100).toFixed(1)));
    tr.append(el("td", {}, sensitivity.score_min === null ? "\\u2013" :
      `${(sensitivity.score_min * 100).toFixed(1)} to ${(sensitivity.score_max * 100).toFixed(1)}`));
    tr.append(el("td", {}, sensitivity.rank_min === null ? "\\u2013" :
      `${sensitivity.rank_min} to ${sensitivity.rank_max}`));
    tr.append(el("td", {}, String(sensitivity.winner_changes)));
    body.append(tr);
  }
  table.append(el("thead", {}, head), body);
  host.append(table);
}

/* ---------- scenario families ---------- */
function renderFamilies() {
  const host = document.getElementById("families");
  host.textContent = "";
  const table = el("table");
  const head = el("tr");
  for (const label of [
    "Family", "Scenarios", "Best model", "Best family score", "Unsafe close/monitor"
  ]) {
    head.append(el("th", {}, label));
  }
  const body = el("tbody");
  for (const [family, count] of Object.entries(D.suite_health.family_counts)) {
    const candidates = D.summaries
      .map((summary) => ({ model: summary.model, ...summary.family_scores[family] }))
      .filter((item) => item.soc_triage_score !== null && item.soc_triage_score !== undefined)
      .sort((a, b) => b.soc_triage_score - a.soc_triage_score);
    const best = candidates[0];
    const tr = el("tr");
    tr.append(el("td", {}, family.replace(/_/g, " ")));
    tr.append(el("td", {}, String(count)));
    tr.append(el("td", { class: "model" }, best ? best.model : "\\u2013"));
    tr.append(el("td", { class: "score-cell" },
      best ? scoreBar(best.soc_triage_score, 1) : "\\u2013"));
    tr.append(el("td", {}, best ? String(best.unsafe_close_or_monitor_runs) : "\\u2013"));
    body.append(tr);
  }
  table.append(el("thead", {}, head), body);
  host.append(table);
}

function renderAll() {
  renderLeaderboard();
  renderScatter();
}

document.getElementById("profile").onchange = (event) => {
  state.profile = event.target.value;
  state.sortOverride = false;
  renderAll();
};
document.getElementById("maxcost").onchange = (event) => {
  state.maxCost = event.target.value === "any" ? Infinity : Number(event.target.value);
  renderAll();
};
document.getElementById("profile").value = state.profile;
renderDecision();
renderLeaderboard();
renderHeatmap();
renderScatter();
renderConfidence();
renderSafety();
renderSeverity();
renderStability();
renderFamilies();
"""


def _report_payload(data: dict) -> dict:
    """Keep only fields the interactive page reads.

    scorecard.json remains the complete research artifact. The embedded browser payload carries
    enough run detail for confidence quality without duplicating every score column.
    """
    run_fields = {
        "valid",
        "confidence",
        "correct",
        "model",
    }
    cell_fields = {
        "scenario",
        "model",
        "reference_class",
        "classification_score",
        "unsafe_close_or_monitor_runs",
    }
    payload = dict(data)
    payload["runs"] = [
        {key: value for key, value in row.items() if key in run_fields}
        for row in data.get("runs", [])
    ]
    payload["cells"] = [
        {key: value for key, value in row.items() if key in cell_fields}
        for row in data.get("cells", [])
    ]
    payload.pop("alternative_catalog", None)
    return payload


def render(data: dict) -> str:
    sweeps = ", ".join(data.get("sweeps") or ["unlabelled"])
    total_cost = sum(summary["cost"] for summary in data["summaries"])
    options = "".join(
        f'<option value="{profile_id}">{profile["label"]}</option>'
        for profile_id, profile in data["profiles"].items()
    )
    grounding_explanation = (
        "The share of factual evidence claims supported by the supplied telemetry. An independent "
        "language-model judge evaluates semantic grounding and required-fact coverage."
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SOC alert triage benchmark {sweeps}</title>
<style>{_CSS}</style>
</head>
<body>
<!-- provenance: collection {data["instrument_version"]}; scoring
{data.get("scoring_version", data["instrument_version"])}; judge {data["judge_version"]} -->
<main>
  <h1>SOC alert triage benchmark</h1>
  <p class="sub">
    sweep {sweeps} &middot; {len(data["summaries"])} configurations &middot;
    {data["scenario_count"]} scenarios &middot; {len(data["runs"])} runs &middot;
    ${total_cost:.2f}
  </p>
  <p class="sub">Evidence grounding by an independent language-model judge over the supplied telemetry.</p>
  <p class="study">
    {len(data["summaries"])} model configurations triaged {data["scenario_count"]} security alerts
    three times each using the same frozen telemetry. Compare decision quality, safety, confidence
    honesty, and batch cost to choose a configuration for a controlled pilot.
  </p>

  <div class="panel decision" id="decision"></div>

  <h2>Results</h2>
  <p class="note">
    Pick a weighting, then read the score as lift over a fixed escalate-everything policy
    (baseline = 0). Higher is better. Prefer models with a strong score, low unsafe close/monitor
    count, and a review mode that matches how much human oversight you can afford. Click a column
    to sort. Values show the spread across scenarios in grey.
  </p>
  <div class="controls">
    <label>Weighting
      <select id="profile">{options}</select>
    </label>
    <label>Max cost
      <select id="maxcost">
        <option value="any">Any price</option>
        <option value="0.05">$0.05 per scenario</option>
        <option value="0.10">$0.10 per scenario</option>
        <option value="0.25">$0.25 per scenario</option>
        <option value="0.50">$0.50 per scenario</option>
        <option value="1.00">$1.00 per scenario</option>
      </select>
    </label>
    <span class="sub" id="profile-label"></span>
  </div>
  <div class="panel" id="leaderboard"></div>

  <h2>Per scenario</h2>
  <p class="note">
    Classification score by model and alert. Darker blue is better. A weak column means every model
    struggled on that alert; a single weak cell points at that model.
  </p>
  <div class="panel" id="heatmap" style="overflow-x:auto"></div>

  <div class="stack-section">
    <h2>Score against cost</h2>
    <p class="note">
      Up = better triage score under the selected weighting. Right = more expensive per scenario
      (3 runs). The green line is the efficient frontier: best score at each cost. Below the dashed
      baseline adds less value than a fixed escalate-everything policy.
    </p>
    <div class="panel" id="scatter"></div>
  </div>

  <div class="stack-section">
    <h2>Confidence quality</h2>
    <p class="note">
      Longer bars mean the model's stated probabilities better match how often it is actually
      right. The table compares how sure it claimed to be versus how often it was correct—useful
      when deciding whether to trust a high-confidence auto-disposition.
    </p>
    <div class="panel" id="confidence"></div>
  </div>

  <h2>Unsafe close or monitor recommendations</h2>
  <p class="note">
    These are the deal-breakers for unsupervised use: the model recommended closing or downgrading
    an alert that still needed active handling. Zero is required for controlled-autonomy testing.
  </p>
  <div class="panel" id="safety"></div>

  <h2>Severity performance</h2>
  <p class="note">
    How accurately each model rates urgency. Exact matches are best; undercalls matter because they
    can push a real incident down the queue.
  </p>
  <div class="panel" id="severity"></div>

  <h2>Ranking stability</h2>
  <p class="note">
    How much the leaderboard depends on a single alert. If removing one scenario changes the winner,
    treat the ranking as provisional.
  </p>
  <div class="panel" id="stability"></div>

  <h2>Scenario families</h2>
  <p class="note">
    Best model within each alert type. Family sizes are small, so use this as a check for blind
    spots—not as a second leaderboard.
  </p>
  <div class="panel" id="families"></div>

  <h2>How to read this evaluation</h2>
  <div class="panel methodology">
    <dl>
      <dt>SOC score</dt>
      <dd>A declared weighted score combining response action, alert classification, confidence
        skill, supported evidence, important-fact coverage, and severity utility. Decision metrics
        are measured as lift over the conservative fixed policy shown in the baseline row.</dd>
      <dt>Conservative fixed policy</dt>
      <dd>Classify every alert as <strong>{data["baseline"].get("policy", {}).get("classification", "Malicious")}</strong>,
        assign <strong>{data["baseline"].get("policy", {}).get("severity", "High")}</strong> severity,
        and <strong>{data["baseline"].get("policy", {}).get("recommended_action", "Escalate for Investigation")}</strong>.
        A model matching this policy adds no decision value.</dd>
      <dt>Confidence skill</dt>
      <dd>How well the model's probability distribution matches outcomes. Zero matches a uniform
        25% guess across the four classes; one is perfect. Overconfident models claim high certainty
        more often than they are correct.</dd>
      <dt>Supported evidence</dt>
      <dd>{grounding_explanation}</dd>
      <dt>Important facts found</dt>
      <dd>The share of required reference observations covered by the candidate submission.</dd>
      <dt>Unsafe close/monitor</dt>
      <dd>A recommendation to Close or Continue Monitoring when the reference requires escalation
        or containment. Those actions end active workflow, so any such recommendation requires
        supervised review.</dd>
      <dt>Recommended review mode</dt>
      <dd>Candidate for controlled autonomy testing requires zero unsafe close/monitor actions, zero
        false alarms, and Brier at or below 0.15. Ten scenarios cannot authorise deployment.</dd>
      <dt>Evaluation cost/scenario (3 runs)</dt>
      <dd>Actual batch API cost divided by the number of scenarios. Each scenario was run three
        times, so this is an evaluation cost and not the expected cost of one production alert.</dd>
    </dl>
  </div>

  <footer>
    Generated {data["generated"]} from scorecard.json.
  </footer>
</main>
<script id="data" type="application/json">{json.dumps(_report_payload(data))}</script>
<script>{_JS}</script>
</body>
</html>
"""
