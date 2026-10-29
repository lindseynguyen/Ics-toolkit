/* ics-ctf-toolkit local interface - vanilla JS, no build step. */
"use strict";

const state = {
  files: [],
  selected: [],
  artefact: null,
  tools: [],
  glossary: {},
};

const $ = (sel) => document.querySelector(sel);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
};

function toast(msg, ms = 2600) {
  const t = $("#toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { t.hidden = true; }, ms);
}

function bytes(n) {
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  if (n < 1073741824) return (n / 1048576).toFixed(1) + " MB";
  return (n / 1073741824).toFixed(2) + " GB";
}

async function api(path, opts) {
  const res = await fetch(path, opts);
  let data;
  try { data = await res.json(); } catch (e) { data = { error: "bad response" }; }
  if (!res.ok || data.error) throw new Error(data.error || ("HTTP " + res.status));
  return data;
}

/* ------------------------------------------------------------------ files */
async function refreshFiles() {
  const data = await api("/api/files");
  state.files = data.files;
  $("#ws-path").textContent = "workspace: " + data.workspace;
  renderFiles();
  renderExpertFiles();
  if (state.selected.length > 1) planGroup();
  else $("#group-steps").innerHTML = "";
}

function renderFiles() {
  const list = $("#file-list");
  list.innerHTML = "";
  if (!state.files.length) {
    const li = el("li");
    li.style.cursor = "default";
    li.append(el("span", "hint", "No artefacts yet."));
    list.append(li);
    return;
  }
  for (const f of state.files) {
    const li = el("li", state.selected.includes(f.name) ? "sel" : "");
    li.append(el("span", "nm", f.name), el("span", "sz", bytes(f.size)));
    const x = el("button", "x", "×");
    x.title = "Remove from the workspace";
    x.onclick = async (ev) => {
      ev.stopPropagation();
      if (!confirm("Remove " + f.name + " from the workspace folder?")) return;
      await api("/api/delete", { method: "POST", body: JSON.stringify({ name: f.name }) });
      state.selected = state.selected.filter((n) => n !== f.name);
      refreshFiles();
    };
    li.append(x);
    li.onclick = (ev) => {
      if (ev.metaKey || ev.ctrlKey) {
        state.selected = state.selected.includes(f.name)
          ? state.selected.filter((n) => n !== f.name)
          : state.selected.concat(f.name);
      } else {
        state.selected = [f.name];
      }
      renderFiles();
      if (state.selected.length === 1) identify(state.selected[0]);
      if (state.selected.length > 1) planGroup();
      else $("#group-steps").innerHTML = "";
    };
    list.append(li);
  }
}

function renderExpertFiles() {
  const sel = $("#expert-files");
  const keep = new Set(Array.from(sel.selectedOptions).map((o) => o.value));
  sel.innerHTML = "";
  for (const f of state.files) {
    const o = el("option", "", f.name + "  (" + bytes(f.size) + ")");
    o.value = f.name;
    if (keep.has(f.name) || state.selected.includes(f.name)) o.selected = true;
    sel.append(o);
  }
}

/* ----------------------------------------------------------------- upload */
async function uploadFile(file) {
  if (file.size > 512 * 1024 * 1024) {
    toast("That file is larger than 512 MB - copy it into the workspace folder instead.");
    return;
  }
  toast("Reading " + file.name + " …", 60000);
  const data = await api("/api/upload?name=" + encodeURIComponent(file.name), {
    method: "PUT", body: file,
  });
  toast(file.name + " added");
  state.selected = [file.name];
  await refreshFiles();
  if (data.artefact) showArtefact(data.artefact);
  else identify(file.name);
}

function wireDrop() {
  const drop = $("#drop");
  const stop = (e) => { e.preventDefault(); e.stopPropagation(); };
  ["dragenter", "dragover"].forEach((t) =>
    drop.addEventListener(t, (e) => { stop(e); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach((t) =>
    drop.addEventListener(t, (e) => { stop(e); drop.classList.remove("over"); }));
  drop.addEventListener("drop", async (e) => {
    for (const f of e.dataTransfer.files) {
      try { await uploadFile(f); } catch (err) { toast("Failed: " + err.message); }
    }
  });
  document.addEventListener("dragover", (e) => e.preventDefault());
  document.addEventListener("drop", (e) => e.preventDefault());
  $("#file-input").addEventListener("change", async (e) => {
    for (const f of e.target.files) {
      try { await uploadFile(f); } catch (err) { toast("Failed: " + err.message); }
    }
    e.target.value = "";
  });
  $("#path-add").addEventListener("click", async () => {
    const p = $("#path-input").value.trim();
    if (!p) return;
    try {
      const data = await api("/api/add-path", {
        method: "POST", body: JSON.stringify({ path: p }),
      });
      $("#path-input").value = "";
      state.selected = [data.artefact.name];
      await refreshFiles();
      showArtefact(data.artefact);
    } catch (err) { toast(err.message); }
  });
}

/* --------------------------------------------------------------- identify */
async function identify(name) {
  try {
    const art = await api("/api/identify", {
      method: "POST", body: JSON.stringify({ name }),
    });
    showArtefact(art);
  } catch (err) { toast(err.message); }
}

function showArtefact(art) {
  state.artefact = art;
  setMode("guided");
  const box = $("#artefact");
  box.className = "card ident";
  box.innerHTML = "";
  box.append(el("h2", "", art.name));
  const dl = el("dl", "kv");
  const add = (k, v) => { dl.append(el("dt", "", k), el("dd", "", v)); };
  add("What it is", art.summary);
  add("Size", bytes(art.size));
  if (art.details.length) add("Notes", art.details.join(" · "));
  box.append(dl);
  if (art.protocols.length) {
    const tags = el("div", "tags");
    art.protocols.forEach((p) => tags.append(el("span", "tag", p)));
    box.append(tags);
  }
  art.warnings.forEach((w) => box.append(el("div", "warn", "⚠ " + w)));

  const steps = $("#steps");
  steps.innerHTML = "";
  if (!art.steps.length) {
    steps.append(el("p", "hint",
      "No automated decoding applies to this file - open it and read it directly."));
    return;
  }
  const h = el("h2", "", "2 · Suggested steps, in order");
  steps.append(h);
  const list = el("div", "steplist");
  art.steps.forEach((s, i) => list.append(stepCard(s, i + 1, art.name)));
  steps.append(list);
}

function stepCard(step, n, fileName) {
  const card = el("div", "step" + (step.primary ? " primary" : ""));
  const top = el("div", "top");
  top.append(el("span", "n", String(n)), el("span", "lbl", step.label));
  if (step.primary) top.append(el("span", "badge", "start here"));
  const run = el("button", "btn " + (step.primary ? "primary" : ""), "Run");
  run.onclick = () => runStep(step, fileName, step.label, run);
  top.append(run);
  card.append(top);
  if (step.why) card.append(el("p", "why", step.why));
  card.append(el("div", "cmd", "$ python3 tools/" + step.tool +
    " \"" + fileName + "\"" + (step.args.length ? " " + step.args.join(" ") : "")));
  return card;
}

async function planGroup() {
  const box = $("#group-steps");
  box.innerHTML = "";
  try {
    const data = await api("/api/plan-group", {
      method: "POST", body: JSON.stringify({ names: state.selected }),
    });
    if (!data.steps.length) return;
    box.append(el("h2", "", "Multiple files selected"));
    const list = el("div", "steplist");
    data.steps.forEach((s) => {
      const card = el("div", "step primary");
      const top = el("div", "top");
      top.append(el("span", "lbl", s.label));
      const b = el("button", "btn primary", "Run");
      b.onclick = () => runTool(s.tool, state.selected, s.args, s.label, b,
        { __out__: "merged.pcap" });
      top.append(b);
      card.append(top, el("p", "why", s.why));
      list.append(card);
    });
    box.append(list);
  } catch (err) { /* nothing to suggest */ }
}

/* -------------------------------------------------------------------- run */
function runStep(step, fileName, title, btn) {
  return runTool(step.tool, [fileName], step.args, title, btn, {});
}

async function runTool(tool, files, args, title, btn, flags) {
  const card = el("div", "result");
  const head = el("header");
  head.append(el("span", "spin"), el("span", "t", title + " — running…"));
  card.append(head);
  $("#results").prepend(card);
  card.scrollIntoView({ behavior: "smooth", block: "nearest" });
  if (btn) { btn.disabled = true; }
  try {
    const data = await api("/api/run", {
      method: "POST",
      body: JSON.stringify({ tool, files, args: args || [], flags: flags || {} }),
    });
    renderResult(card, title, data);
  } catch (err) {
    card.innerHTML = "";
    const h = el("header");
    h.append(el("span", "t", title + " — failed"));
    card.append(h);
    const b = el("div", "body");
    b.append(el("div", "warn", err.message));
    card.append(b);
  } finally {
    if (btn) btn.disabled = false;
    refreshFiles();
  }
}

function renderResult(card, title, data) {
  card.innerHTML = "";
  const head = el("header");
  head.append(el("span", "t", title));
  if (data.returncode !== 0) head.append(el("span", "tag", "exit " + data.returncode));
  const copy = el("button", "btn tiny", "Copy command");
  copy.onclick = () => {
    navigator.clipboard.writeText(data.command).then(
      () => toast("Command copied"),
      () => toast("Copy failed - select the text manually"));
  };
  head.append(copy);
  const hide = el("button", "btn tiny", "Dismiss");
  hide.onclick = () => card.remove();
  head.append(hide);
  card.append(head);

  const body = el("div", "body");
  const cmd = el("div", "cmdline");
  cmd.append(el("code", "", data.command));
  body.append(cmd);

  if (data.notes && data.notes.length) {
    body.append(el("h3", "", "What this means"));
    const ul = el("ul", "means");
    data.notes.forEach((n) => ul.append(el("li", "", n)));
    body.append(ul);
  }
  const gl = data.glossary || {};
  const keys = Object.keys(gl);
  if (keys.length) {
    const det = el("details", "raw");
    det.append(el("summary", "", "Terms used here (" + keys.length + ")"));
    const g = el("div", "gloss");
    keys.sort().forEach((k) => {
      const d = el("div");
      d.append(el("b", "", k + " — "), el("span", "", gl[k]));
      g.append(d);
    });
    det.append(g);
    body.append(det);
  }

  const det = el("details", "raw");
  det.open = true;
  det.append(el("summary", "", "Full report"));
  det.append(el("pre", "out", data.output || "(no output)"));
  body.append(det);
  card.append(body);
}

/* ----------------------------------------------------------------- expert */
async function loadTools() {
  const data = await api("/api/tools");
  state.tools = data.tools;
  const sel = $("#tool-select");
  sel.innerHTML = "";
  data.tools.forEach((t) => {
    const o = el("option", "", t.title + "  (" + t.tool + ")");
    o.value = t.tool;
    sel.append(o);
  });
  sel.onchange = renderToolForm;
  renderToolForm();
}

function currentTool() {
  const name = $("#tool-select").value;
  return state.tools.find((t) => t.tool === name);
}

function renderToolForm() {
  const t = currentTool();
  if (!t) return;
  $("#tool-blurb").textContent = t.blurb;
  const vs = $("#view-select");
  vs.innerHTML = "";
  const views = t.views && t.views.length ? t.views : [["", "Default"]];
  views.forEach(([flag, label]) => {
    const o = el("option", "", label);
    o.value = flag;
    vs.append(o);
  });
  const box = $("#flag-fields");
  box.innerHTML = "";
  Object.entries(t.flags || {}).forEach(([flag, kind]) => {
    const lab = el("label", "", flag);
    const inp = el("input");
    inp.type = kind === "int" ? "number" : "text";
    inp.dataset.flag = flag;
    inp.placeholder = kind;
    lab.append(inp);
    box.append(lab);
  });
}

function wireExpert() {
  $("#expert-run").onclick = () => {
    const t = currentTool();
    const files = Array.from($("#expert-files").selectedOptions).map((o) => o.value);
    if (!files.length) { toast("Select at least one file"); return; }
    const flags = {};
    $("#flag-fields").querySelectorAll("input").forEach((i) => {
      if (i.value.trim()) flags[i.dataset.flag] = i.value.trim();
    });
    if (t.output_first) flags.__out__ = "merged.pcap";
    const view = $("#view-select").value;
    const args = view ? [view] : [];
    const label = t.title + ($("#view-select").selectedOptions[0]
      ? " — " + $("#view-select").selectedOptions[0].textContent : "");
    runTool(t.tool, files, args, label, $("#expert-run"), flags);
  };
}

/* -------------------------------------------------------------- help/mode */
async function loadGlossary() {
  const data = await api("/api/glossary");
  state.glossary = data.glossary;
  const box = $("#glossary");
  box.innerHTML = "";
  Object.keys(data.glossary).sort().forEach((k) => {
    const d = el("div");
    d.append(el("b", "", k + " — "), el("span", "", data.glossary[k]));
    box.append(d);
  });
}

function setMode(mode) {
  const map = { guided: "#view-guided", expert: "#view-expert", help: "#view-help" };
  Object.entries(map).forEach(([m, sel]) => { $(sel).hidden = m !== mode; });
  ["guided", "expert", "help"].forEach((m) =>
    $("#mode-" + m).classList.toggle("active", m === mode));
}

function wireModes() {
  $("#mode-guided").onclick = () => setMode("guided");
  $("#mode-expert").onclick = () => { setMode("expert"); renderExpertFiles(); };
  $("#mode-help").onclick = () => setMode("help");
}

/* -------------------------------------------------------------------- init */
(async function init() {
  wireDrop();
  wireModes();
  wireExpert();
  try {
    await refreshFiles();
    await loadTools();
    await loadGlossary();
  } catch (err) {
    toast("Could not reach the local server: " + err.message, 8000);
  }
})();
