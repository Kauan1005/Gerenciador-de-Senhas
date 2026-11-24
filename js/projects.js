/* ==========================================================
   PROJECTS: guarda de projetos (onde estão e como instalar)
   ==========================================================
   Cada projeto é UM registro cifrado no navegador (AES-256-GCM, AAD
   ligando ao usuário e ao id) com:
     - dados gerais (nome, descrição, repositório, etiquetas, notas)
     - BANCO DE DADOS: onde o projeto guarda os dados (provedor,
       identificador, endereço, painel, conta, região, notas, senhas
       ligadas do cofre)
     - HOSPEDAGEM: onde o projeto foi publicado (provedor, site,
       endereço, painel, domínio, como publica, conta, notas, senhas)
     - ARQUIVOS: instaladores/.zip/.apk cifrados no Storage (files.js)

   O servidor (Supabase) só enxerga blobs cifrados. Tudo que vem do
   cofre é desenhado com textContent (sem innerHTML), e links só
   abrem se forem http(s) (safeHttpUrl).
   ========================================================== */

const MAX_PROJECTS = 500;
const MAX_ENTRIES = 50;
const MAX_FILES = 100;
const MAX_JSON_BYTES = 200 * 1024;
const STORAGE_QUOTA_BYTES = 1024 * 1024 * 1024; // plano gratuito do Supabase: ~1 GB

const DB_FIELDS = [
  { k: "provider", label: "Provedor", list: "db-providers", placeholder: "Supabase, Firebase, Neon…", wide: false },
  { k: "name", label: "Nome do banco / projeto no provedor", placeholder: "Ex.: Financeiro" },
  { k: "ref", label: "Identificador (ref, ID ou host)", placeholder: "Ex.: drtrifievfcjhvgjepcq" },
  { k: "url", label: "Endereço (API ou host)", url: true, placeholder: "https://…" },
  { k: "dashboardUrl", label: "Painel de administração", url: true, placeholder: "https://…" },
  { k: "account", label: "Conta do provedor (e-mail)", placeholder: "voce@exemplo.com" },
  { k: "region", label: "Região", placeholder: "Ex.: São Paulo" },
  { k: "notes", label: "Notas", textarea: true, wide: true }
];

const HOST_FIELDS = [
  { k: "provider", label: "Provedor", list: "host-providers", placeholder: "Netlify, Vercel…" },
  { k: "name", label: "Nome do site / serviço", placeholder: "Ex.: gerenciadorml" },
  { k: "url", label: "Endereço público", url: true, placeholder: "https://…" },
  { k: "dashboardUrl", label: "Painel de administração", url: true, placeholder: "https://…" },
  { k: "domain", label: "Domínio próprio", placeholder: "Ex.: cofre.minhaempresa.com.br" },
  { k: "deploy", label: "Como publica", select: ["", "Git automático", "Arrastar e soltar", "Linha de comando", "Manual no servidor", "Outro"] },
  { k: "account", label: "Conta do provedor (e-mail)", placeholder: "voce@exemplo.com" },
  { k: "notes", label: "Notas", textarea: true, wide: true }
];

let allProjects = [];
let groupBy = "project";
let current = null; // projeto aberto no editor (cópia de trabalho)
let currentIsNew = false;
let originalFileIds = new Set();
let uploadedNow = []; // arquivos enviados nesta edição (apagados se cancelar)
let removedNow = []; // arquivos marcados para remover ao salvar
let activeTab = "general";

/* ---------- dados ---------- */

async function fetchProjects() {
  const { data, error } = await sb
    .from("vault_projects")
    .select("id, encrypted_data, iv, version, created_at, updated_at")
    .eq("user_id", VaultSession.userId)
    .order("updated_at", { ascending: false });
  if (error) throw error;
  const out = [];
  for (const row of data) {
    try {
      const aad = CryptoUtil.aadFor(row.version || 2, VaultSession.userId, "project", row.id);
      const p = await CryptoUtil.decryptJSON(VaultSession.key, row.encrypted_data, row.iv, aad);
      out.push(normalizeProject({ ...p, id: row.id }));
    } catch (err) {
      console.error("Falha ao decifrar projeto", row.id);
    }
  }
  return out;
}

function normalizeProject(p) {
  return {
    id: p.id,
    name: p.name || "",
    description: p.description || "",
    repoUrl: p.repoUrl || "",
    tags: Array.isArray(p.tags) ? p.tags : [],
    notes: p.notes || "",
    database: Array.isArray(p.database) ? p.database : [],
    hosting: Array.isArray(p.hosting) ? p.hosting : [],
    files: Array.isArray(p.files) ? p.files : []
  };
}

async function persistProject(p) {
  const { id, ...payload } = p;
  const json = JSON.stringify(payload);
  if (new TextEncoder().encode(json).length > MAX_JSON_BYTES) throw new Error("Projeto grande demais (muitas notas ou entradas).");
  const aad = CryptoUtil.aadFor(2, VaultSession.userId, "project", id);
  const { ciphertext, iv } = await CryptoUtil.encryptJSON(VaultSession.key, payload, aad);
  const { error } = await sb
    .from("vault_projects")
    .upsert({ id, user_id: VaultSession.userId, encrypted_data: ciphertext, iv, version: 2, updated_at: new Date().toISOString() }, { onConflict: "id" });
  if (error) throw error;
}

async function removeProject(p) {
  try {
    await FileStore.remove(p.files);
  } catch (err) {
    console.error("Alguns arquivos não puderam ser removidos do Storage", err);
  }
  const { error } = await sb.from("vault_projects").delete().eq("id", p.id).eq("user_id", VaultSession.userId);
  if (error) throw error;
}

async function reloadProjects() {
  allProjects = await fetchProjects();
  renderProjects();
}

/* ---------- lista ---------- */

const norm = (s) => String(s || "").trim();
const providerKey = (s) => norm(s).toLowerCase();

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(0)} KB`;
  if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MB`;
  return `${(n / 1073741824).toFixed(2)} GB`;
}

function projectCard(p) {
  const card = el("article", "proj-card");
  card.tabIndex = 0;
  card.setAttribute("role", "button");
  card.setAttribute("aria-label", `Abrir o projeto ${p.name}`);
  card.append(el("h3", "proj-card__title", p.name));
  if (p.description) card.append(el("p", "proj-card__desc", p.description));

  const chips = el("div", "proj-card__chips");
  for (const d of p.database) chips.append(el("span", "chip chip--db", `Banco: ${d.provider || "?"}${d.name ? " · " + d.name : ""}`));
  for (const h of p.hosting) chips.append(el("span", "chip chip--host", `Hospedagem: ${h.provider || "?"}${h.name ? " · " + h.name : ""}`));
  if (p.files.length) chips.append(el("span", "chip chip--file", `${p.files.length} arquivo(s) · ${formatBytes(p.files.reduce((a, f) => a + (f.size || 0), 0))}`));
  if (!chips.children.length) chips.append(el("span", "chip chip--empty", "Sem banco, hospedagem ou arquivos ainda"));
  card.append(chips);

  const open = () => openProject(p);
  card.addEventListener("click", open);
  card.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); }
  });
  return card;
}

function matchesSearch(p, term) {
  if (!term) return true;
  const hay = [p.name, p.description, p.repoUrl, p.tags.join(" "), p.notes]
    .concat(p.database.flatMap((d) => [d.provider, d.name, d.ref, d.url, d.account]))
    .concat(p.hosting.flatMap((h) => [h.provider, h.name, h.url, h.domain, h.account]))
    .concat(p.files.map((f) => f.name));
  return hay.filter(Boolean).some((v) => String(v).toLowerCase().includes(term));
}

function renderProjects() {
  const list = document.getElementById("projects-list");
  const empty = document.getElementById("projects-empty");
  const none = document.getElementById("projects-noresults");
  const term = document.getElementById("search-input").value.trim().toLowerCase();
  list.replaceChildren();

  updateStorageMeter();
  empty.hidden = allProjects.length > 0;
  const shown = allProjects.filter((p) => matchesSearch(p, term));
  none.hidden = !(allProjects.length > 0 && shown.length === 0);
  if (!shown.length) return;

  if (groupBy === "project") {
    const grid = el("div", "proj-grid");
    shown.forEach((p) => grid.append(projectCard(p)));
    list.append(grid);
    return;
  }

  // visão por banco de dados ou por hospedagem: um grupo por provedor
  const key = groupBy === "database" ? "database" : "hosting";
  const groups = new Map();
  for (const p of shown) {
    const providers = [...new Set(p[key].map((e) => norm(e.provider)).filter(Boolean))];
    if (!providers.length) providers.push("");
    for (const prov of providers) {
      const k = providerKey(prov);
      if (!groups.has(k)) groups.set(k, { label: prov, items: [] });
      groups.get(k).items.push(p);
    }
  }
  const emptyLabel = key === "database" ? "Sem banco de dados informado" : "Sem hospedagem informada";
  [...groups.values()]
    .sort((a, b) => (a.label === "" ? 1 : b.label === "" ? -1 : a.label.localeCompare(b.label, "pt-BR")))
    .forEach((g) => {
      const section = el("section", "proj-group");
      const head = el("h2", "proj-group__title", g.label || emptyLabel);
      head.append(el("span", "proj-group__count", String(g.items.length)));
      const grid = el("div", "proj-grid");
      g.items.forEach((p) => grid.append(projectCard(p)));
      section.append(head, grid);
      list.append(section);
    });
}

function updateStorageMeter() {
  const used = allProjects.reduce((a, p) => a + p.files.reduce((b, f) => b + (f.size || 0), 0), 0);
  const meter = document.getElementById("storage-meter");
  if (!meter) return;
  meter.textContent = `Arquivos guardados: ${formatBytes(used)} de ~${formatBytes(STORAGE_QUOTA_BYTES)} (plano gratuito)`;
  meter.hidden = used === 0 && allProjects.length === 0;
}

/* ---------- editor ---------- */

function blankProject() {
  return normalizeProject({ id: CryptoUtil.newId() });
}

function openProject(p) {
  currentIsNew = !p;
  current = p ? structuredClone(p) : blankProject();
  originalFileIds = new Set((p ? p.files : []).map((f) => f.id));
  uploadedNow = [];
  removedNow = [];
  activeTab = "general";
  document.getElementById("project-title").textContent = p ? "Editar projeto" : "Novo projeto";
  document.getElementById("btn-delete-project").hidden = !p;
  document.getElementById("project-error").hidden = true;
  document.getElementById("project-modal").hidden = false;
  renderEditor();
  document.getElementById("project-modal").querySelector("input")?.focus();
}

async function closeProject(save) {
  if (!save) {
    // cancelou: o que foi enviado nesta edição e não foi salvo sai do Storage
    const orphans = uploadedNow.filter((f) => !originalFileIds.has(f.id));
    if (orphans.length) FileStore.remove(orphans).catch(console.error);
  }
  document.getElementById("project-modal").hidden = true;
  current = null;
  uploadedNow = [];
  removedNow = [];
}

function tabButton(id, label, count) {
  const b = el("button", "ptab" + (activeTab === id ? " is-active" : ""), count ? `${label} (${count})` : label);
  b.type = "button";
  b.setAttribute("role", "tab");
  b.setAttribute("aria-selected", String(activeTab === id));
  b.addEventListener("click", () => { activeTab = id; renderEditor(); });
  return b;
}

function renderEditor() {
  const tabs = document.getElementById("project-tabs");
  const body = document.getElementById("project-body");
  tabs.replaceChildren(
    tabButton("general", "Geral"),
    tabButton("database", "Banco de dados", current.database.length),
    tabButton("hosting", "Hospedagem", current.hosting.length),
    tabButton("files", "Arquivos", current.files.length)
  );
  body.replaceChildren();
  if (activeTab === "general") body.append(generalTab());
  else if (activeTab === "files") body.append(filesTab());
  else body.append(entriesTab(activeTab));
}

function inputFor(spec, obj, onChange) {
  let input;
  if (spec.textarea) {
    input = el("textarea");
    input.rows = 2;
  } else if (spec.select) {
    input = el("select");
    spec.select.forEach((o) => input.append(Object.assign(el("option", "", o || "—"), { value: o })));
  } else {
    input = el("input");
    input.type = spec.url ? "url" : "text";
    if (spec.list) input.setAttribute("list", spec.list);
    if (spec.placeholder) input.placeholder = spec.placeholder;
  }
  input.maxLength = spec.textarea ? 4000 : 300;
  input.value = obj[spec.k] || "";
  input.addEventListener("input", () => { obj[spec.k] = input.value; if (onChange) onChange(); });
  const label = el("label", "field" + (spec.wide ? " field--wide" : ""));
  label.append(el("span", "field__label", spec.label), input);
  return label;
}

function generalTab() {
  const wrap = el("div", "form-grid");
  wrap.append(
    inputFor({ k: "name", label: "Nome do projeto *", placeholder: "Ex.: Gerenciador de Senhas" }, current),
    inputFor({ k: "repoUrl", label: "Repositório (Git)", url: true, placeholder: "https://github.com/…" }, current),
    inputFor({ k: "description", label: "Descrição", textarea: true, wide: true }, current)
  );
  const tags = { tags: current.tags.join(", ") };
  const tagField = inputFor({ k: "tags", label: "Etiquetas (separadas por vírgula)", placeholder: "web, interno, cliente-x", wide: true }, tags);
  tagField.querySelector("input").addEventListener("input", (e) => {
    current.tags = e.target.value.split(",").map((t) => t.trim()).filter(Boolean).slice(0, 20);
  });
  wrap.append(tagField, inputFor({ k: "notes", label: "Notas gerais", textarea: true, wide: true }, current));
  return wrap;
}

/* ---- abas Banco de dados e Hospedagem: mesma mecânica, campos diferentes ---- */

function entriesTab(kind) {
  const fields = kind === "database" ? DB_FIELDS : HOST_FIELDS;
  const list = current[kind];
  const wrap = el("div", "entries");
  wrap.append(
    el("p", "hint", kind === "database"
      ? "Onde os dados deste projeto estão guardados. Pode haver mais de um (ex.: produção e testes)."
      : "Onde este projeto foi publicado. Pode haver mais de uma (ex.: site e API).")
  );

  list.forEach((entry, index) => {
    const box = el("fieldset", "entry");
    const legend = el("legend", "", `${kind === "database" ? "Banco de dados" : "Hospedagem"} ${index + 1}${entry.provider ? " · " + entry.provider : ""}`);
    box.append(legend);
    const grid = el("div", "form-grid");
    fields.forEach((spec) => grid.append(inputFor(spec, entry, () => { legend.textContent = `${kind === "database" ? "Banco de dados" : "Hospedagem"} ${index + 1}${entry.provider ? " · " + entry.provider : ""}`; })));
    box.append(grid, linkedCredentials(entry), entryLinks(entry));

    const remove = el("button", "btn btn--ghost btn--small btn--danger-text", "Remover esta entrada");
    remove.type = "button";
    remove.addEventListener("click", () => {
      current[kind].splice(index, 1);
      renderEditor();
    });
    box.append(remove);
    wrap.append(box);
  });

  const add = el("button", "btn btn--ghost", kind === "database" ? "+ Adicionar banco de dados" : "+ Adicionar hospedagem");
  add.type = "button";
  add.disabled = list.length >= MAX_ENTRIES;
  add.addEventListener("click", () => {
    list.push({ id: CryptoUtil.newId(), credentialIds: [] });
    renderEditor();
    document.getElementById("project-body").querySelector("fieldset:last-of-type input")?.focus();
  });
  wrap.append(add);
  return wrap;
}

function entryLinks(entry) {
  const row = el("div", "entry__links");
  for (const [label, url] of [["Abrir endereço", entry.url], ["Abrir painel", entry.dashboardUrl]]) {
    const href = safeHttpUrl(url);
    if (!href) continue;
    const a = el("a", "btn btn--ghost btn--small", label);
    a.href = href;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    row.append(a);
  }
  return row;
}

// Senhas do cofre ligadas a esta entrada (guardadas só como ids; o conteúdo continua no cofre).
function linkedCredentials(entry) {
  entry.credentialIds = Array.isArray(entry.credentialIds) ? entry.credentialIds : [];
  const details = el("details", "linked");
  const summary = el("summary", "", `Senhas do cofre ligadas (${entry.credentialIds.length})`);
  details.append(summary);

  const body = el("div", "linked__body");
  if (!allCredentials.length) body.append(el("p", "hint", "Nenhuma senha no cofre ainda. Cadastre em \"Senhas\" e volte aqui para ligar."));
  allCredentials.forEach((c) => {
    const row = el("label", "linked__item");
    const cb = el("input");
    cb.type = "checkbox";
    cb.checked = entry.credentialIds.includes(c.id);
    cb.addEventListener("change", () => {
      entry.credentialIds = cb.checked ? [...new Set([...entry.credentialIds, c.id])] : entry.credentialIds.filter((id) => id !== c.id);
      summary.textContent = `Senhas do cofre ligadas (${entry.credentialIds.length})`;
      renderChips();
    });
    row.append(cb, el("span", "", `${c.title}${c.username ? " · " + c.username : ""}`));
    body.append(row);
  });

  const chips = el("div", "linked__chips");
  function renderChips() {
    chips.replaceChildren();
    for (const id of entry.credentialIds) {
      const c = allCredentials.find((x) => x.id === id);
      const b = el("button", "chip chip--key", c ? `Copiar senha: ${c.title}` : "Senha removida do cofre");
      b.type = "button";
      b.disabled = !c;
      if (c) b.addEventListener("click", () => copySecret(c.password, `Senha de "${c.title}" copiada`));
      chips.append(b);
    }
  }
  renderChips();
  details.append(body);
  const wrap = el("div", "");
  wrap.append(details, chips);
  return wrap;
}

/* ---- aba Arquivos ---- */

function filesTab() {
  const wrap = el("div", "files");
  const maxMb = (FileStore.limitBytes() / 1048576).toFixed(0);
  wrap.append(el("p", "hint", `Instaladores, .zip, .apk e outros arquivos do projeto. São cifrados aqui no navegador antes de subir (limite de ${maxMb} MB por arquivo). Para uma pasta, compacte em .zip.`));

  const drop = el("label", "dropzone");
  drop.append(el("span", "dropzone__title", "Escolher arquivos"), el("span", "hint", "ou solte aqui"));
  const input = el("input");
  input.type = "file";
  input.multiple = true;
  input.hidden = true;
  input.id = "project-file-input";
  drop.append(input);
  ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("is-over"); }));
  ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("is-over"); }));
  drop.addEventListener("drop", (e) => addFiles([...e.dataTransfer.files]));
  input.addEventListener("change", () => { addFiles([...input.files]); input.value = ""; });
  wrap.append(drop);

  const status = el("p", "hint", "");
  status.id = "file-status";
  status.setAttribute("role", "status");
  wrap.append(status);

  const table = el("div", "file-list");
  current.files.forEach((f, i) => table.append(fileRow(f, i)));
  wrap.append(table);
  return wrap;
}

function fileRow(f, index) {
  const row = el("div", "file-row");
  const main = el("div", "file-row__main");
  main.append(el("strong", "", f.name), el("span", "hint", `${formatBytes(f.size || 0)} · SHA-256 ${String(f.sha256 || "").slice(0, 12)}… · ${f.uploadedAt ? new Date(f.uploadedAt).toLocaleDateString("pt-BR") : ""}`));
  const version = el("input");
  version.type = "text";
  version.placeholder = "Versão (ex.: 1.2.0)";
  version.maxLength = 40;
  version.value = f.version || "";
  version.setAttribute("aria-label", `Versão de ${f.name}`);
  version.addEventListener("input", () => { f.version = version.value; });
  const notes = el("input");
  notes.type = "text";
  notes.placeholder = "Como instalar / observações";
  notes.maxLength = 300;
  notes.value = f.notes || "";
  notes.setAttribute("aria-label", `Observações de ${f.name}`);
  notes.addEventListener("input", () => { f.notes = notes.value; });
  main.append(version, notes);

  const actions = el("div", "file-row__actions");
  const dl = el("button", "btn btn--ghost btn--small", "Baixar");
  dl.type = "button";
  dl.addEventListener("click", () => downloadFile(f, dl));
  const rm = el("button", "btn btn--ghost btn--small btn--danger-text", "Remover");
  rm.type = "button";
  rm.addEventListener("click", () => {
    if (!window.confirm(`Remover "${f.name}" deste projeto? O arquivo será apagado do armazenamento ao salvar.`)) return;
    const [gone] = current.files.splice(index, 1);
    if (originalFileIds.has(gone.id)) removedNow.push(gone);
    else FileStore.remove([gone]).catch(console.error); // enviado nesta edição e já descartado
    uploadedNow = uploadedNow.filter((u) => u.id !== gone.id);
    renderEditor();
  });
  actions.append(dl, rm);
  row.append(main, actions);
  return row;
}

async function addFiles(files) {
  const status = () => document.getElementById("file-status");
  for (const file of files) {
    if (current.files.length >= MAX_FILES) { toast(`Máximo de ${MAX_FILES} arquivos por projeto.`); break; }
    try {
      if (status()) status().textContent = `Cifrando e enviando "${file.name}"…`;
      const meta = await FileStore.upload(file, current.id, (p) => { if (status()) status().textContent = `"${file.name}": ${(p * 100).toFixed(0)}%`; });
      current.files.push(meta);
      uploadedNow.push(meta);
      renderEditor();
      toast(`"${file.name}" enviado e cifrado. Clique em Salvar para guardar o projeto.`);
    } catch (err) {
      console.error(err);
      toast(err && err.message && /limite|MB/.test(err.message) ? err.message : `Não foi possível enviar "${file.name}".`);
      if (status()) status().textContent = "";
    }
  }
}

async function downloadFile(f, button) {
  button.disabled = true;
  try {
    toast(`Baixando e decifrando "${f.name}"…`);
    const blob = await FileStore.fetchPlain(f, current.id);
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = f.name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast(`"${f.name}" baixado. SHA-256 conferido.`);
  } catch (err) {
    console.error(err);
    toast(err && /SHA-256/.test(err.message) ? err.message : "Não foi possível baixar este arquivo.");
  } finally {
    button.disabled = false;
  }
}

/* ---------- salvar / excluir ---------- */

function validateProject(p) {
  if (!norm(p.name)) return "Dê um nome ao projeto (aba Geral).";
  for (const [label, url] of [["Repositório", p.repoUrl]]) {
    if (url && !safeHttpUrl(url)) return `${label}: use um endereço http:// ou https://.`;
  }
  for (const kind of ["database", "hosting"]) {
    for (const e of p[kind]) {
      for (const f of ["url", "dashboardUrl"]) {
        if (e[f] && !safeHttpUrl(e[f])) return `${kind === "database" ? "Banco de dados" : "Hospedagem"}: endereço inválido (use http:// ou https://).`;
      }
    }
  }
  return null;
}

function cleanForSave(p) {
  const trimEntries = (list) => list.map((e) => {
    const out = {};
    for (const [k, v] of Object.entries(e)) out[k] = typeof v === "string" ? v.trim() : v;
    return out;
  });
  return { ...p, name: norm(p.name), database: trimEntries(p.database), hosting: trimEntries(p.hosting) };
}

async function saveCurrent() {
  const errorEl = document.getElementById("project-error");
  errorEl.hidden = true;
  const problem = validateProject(current);
  if (problem) {
    errorEl.textContent = problem;
    errorEl.hidden = false;
    return;
  }
  if (currentIsNew && allProjects.length >= MAX_PROJECTS) {
    errorEl.textContent = `Máximo de ${MAX_PROJECTS} projetos.`;
    errorEl.hidden = false;
    return;
  }
  const saveBtn = document.getElementById("btn-save-project");
  saveBtn.disabled = true;
  try {
    await persistProject(cleanForSave(current));
    if (removedNow.length) await FileStore.remove(removedNow).catch(console.error);
    uploadedNow = []; // agora fazem parte do projeto salvo
    removedNow = [];
    document.getElementById("project-modal").hidden = true;
    current = null;
    toast("Projeto salvo.");
    await reloadProjects();
  } catch (err) {
    console.error(err);
    errorEl.textContent = err && /grande demais/.test(err.message) ? err.message : "Erro ao salvar o projeto. Tente novamente.";
    errorEl.hidden = false;
  } finally {
    saveBtn.disabled = false;
  }
}

async function deleteCurrent() {
  const p = allProjects.find((x) => x.id === current.id);
  if (!p) return;
  if (!window.confirm(`Excluir o projeto "${p.name}" e os ${p.files.length} arquivo(s) guardados nele? Essa ação não pode ser desfeita.`)) return;
  try {
    await removeProject(p);
    document.getElementById("project-modal").hidden = true;
    current = null;
    toast("Projeto excluído.");
    await reloadProjects();
  } catch (err) {
    console.error(err);
    toast("Erro ao excluir o projeto.");
  }
}

/* ---------- avisos ---------- */

function showSchemaMissing() {
  const banner = document.getElementById("upgrade-banner");
  banner.textContent = "O banco ainda não tem a tabela de projetos nem o armazenamento de arquivos. Rode o arquivo supabase/schema.sql no Supabase (README, seção 5) e recarregue esta página.";
  banner.hidden = false;
  document.getElementById("btn-new-project").disabled = true;
}

/* ---------- inicialização ---------- */

document.addEventListener("DOMContentLoaded", async () => {
  const ok = await guardSession();
  if (!ok) return;

  document.getElementById("account-email").textContent = VaultSession.email || "";
  AutoLockModule.init();
  await detectSchema();

  // Senhas do cofre: só para o usuário ligar a bancos/hospedagens (continuam no cofre).
  try {
    allCredentials = await fetchAndDecryptAll();
  } catch (err) {
    console.error(err);
  }

  if (!VaultSchema.projects) showSchemaMissing();
  else reloadProjects().catch((err) => { console.error(err); toast("Erro ao carregar os projetos."); });

  document.getElementById("search-input").addEventListener("input", renderProjects);
  document.querySelectorAll("[data-group]").forEach((b) =>
    b.addEventListener("click", () => {
      groupBy = b.dataset.group;
      document.querySelectorAll("[data-group]").forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
      renderProjects();
    })
  );

  document.getElementById("btn-new-project").addEventListener("click", () => openProject(null));
  document.getElementById("project-close").addEventListener("click", () => closeProject(false));
  document.getElementById("btn-cancel-project").addEventListener("click", () => closeProject(false));
  document.getElementById("project-modal").addEventListener("click", (e) => { if (e.target.id === "project-modal") closeProject(false); });
  document.getElementById("btn-save-project").addEventListener("click", saveCurrent);
  document.getElementById("btn-delete-project").addEventListener("click", deleteCurrent);

  // menu da conta
  const menuTrigger = document.getElementById("account-menu-trigger");
  const menuPanel = document.getElementById("account-menu-panel");
  menuTrigger.addEventListener("click", () => {
    const isOpen = !menuPanel.hidden;
    menuPanel.hidden = isOpen;
    menuTrigger.setAttribute("aria-expanded", String(!isOpen));
  });
  document.addEventListener("click", (e) => {
    if (!menuTrigger.contains(e.target) && !menuPanel.contains(e.target)) {
      menuPanel.hidden = true;
      menuTrigger.setAttribute("aria-expanded", "false");
    }
  });
  document.getElementById("btn-logout").addEventListener("click", async () => {
    await sb.auth.signOut();
    VaultSession.clear();
    window.location.href = "index.html";
  });
});

// Ao bloquear, tudo que estava decifrado sai da memória e da tela.
document.addEventListener("vault:locked", () => {
  allProjects = [];
  allCredentials = [];
  current = null;
  document.getElementById("projects-list")?.replaceChildren();
  const modal = document.getElementById("project-modal");
  if (modal) modal.hidden = true;
});
document.addEventListener("vault:unlocked", async () => {
  try {
    allCredentials = await fetchAndDecryptAll();
    if (VaultSchema.projects) await reloadProjects();
  } catch (err) {
    console.error(err);
  }
});
document.addEventListener("vault:rekeyed", () => {
  if (VaultSchema.projects) reloadProjects().catch(console.error);
});
