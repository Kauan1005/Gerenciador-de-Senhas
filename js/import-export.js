/* ==========================================================
   IMPORT / EXPORT (CSV e Excel)
   ==========================================================
   - CSV: leitor/escritor próprios (sem biblioteca): aceita "," e ";",
     campos entre aspas e quebras de linha dentro do campo.
   - Excel (.xlsx/.xls): SheetJS 0.20.3, servido por vendor/ (a versão
     0.18.5 usada antes tinha falhas conhecidas de poluição de protótipo
     e ReDoS). Fórmulas e HTML das células são ignorados na leitura.

   A exportação é SEMPRE em texto puro: por isso exige confirmar a
   senha mestra de novo. Células que começariam com = + - @ ganham um
   apóstrofo na frente para não virarem fórmula ao abrir no Excel.

   Colunas: Site, Usuário, Senha, URL, Notas (aceita variações comuns
   de cabeçalho, com ou sem acento, em português ou inglês).
   ========================================================== */

const IMPORT_MAX_BYTES = 5 * 1024 * 1024;
const IMPORT_MAX_ROWS = 5000;
const FIELD_MAX = { title: 200, username: 300, password: 1000, url: 500, notes: 5000 };

const FIELD_ALIASES = {
  title: ["site", "titulo", "nome", "servico", "title", "name"],
  username: ["usuario", "username", "user", "email", "e-mail", "login"],
  password: ["senha", "password", "pass"],
  url: ["url", "link", "endereco", "site url", "login_uri", "website"],
  notes: ["notas", "nota", "observacoes", "notes", "note"]
};

function normalizeHeader(h) {
  return h.toString().trim().toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "");
}

function mapRowToCredential(row) {
  const normalizedRow = {};
  for (const [key, value] of Object.entries(row)) normalizedRow[normalizeHeader(key)] = value;

  const result = { title: "", username: "", password: "", url: "", notes: "" };
  for (const field of Object.keys(FIELD_ALIASES)) {
    for (const alias of FIELD_ALIASES[field]) {
      if (normalizedRow[alias] !== undefined && normalizedRow[alias] !== "") {
        let v = String(normalizedRow[alias]).trim();
        if (/^'[=+\-@]/.test(v)) v = v.slice(1); // desfaz o apóstrofo de proteção da exportação
        result[field] = v.slice(0, FIELD_MAX[field]);
        break;
      }
    }
  }
  return result;
}

/* ---------- CSV ---------- */

function parseCsv(text) {
  const clean = text.replace(/^﻿/, "");
  const firstLine = clean.split(/\r?\n/, 1)[0] || "";
  const delimiter = (firstLine.match(/;/g) || []).length > (firstLine.match(/,/g) || []).length ? ";" : ",";
  const rows = [];
  let row = [];
  let cell = "";
  let quoted = false;
  for (let i = 0; i < clean.length; i++) {
    const c = clean[i];
    if (quoted) {
      if (c === '"') {
        if (clean[i + 1] === '"') { cell += '"'; i++; } else quoted = false;
      } else cell += c;
    } else if (c === '"') quoted = true;
    else if (c === delimiter) { row.push(cell); cell = ""; }
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && clean[i + 1] === "\n") i++;
      row.push(cell); cell = "";
      if (row.some((v) => v !== "")) rows.push(row);
      row = [];
    } else cell += c;
  }
  row.push(cell);
  if (row.some((v) => v !== "")) rows.push(row);
  if (rows.length < 2) return [];
  const header = rows[0];
  return rows.slice(1).map((r) => Object.fromEntries(header.map((h, i) => [h, r[i] ?? ""])));
}

function csvCell(value) {
  let v = String(value ?? "");
  if (/^[=+\-@\t\r]/.test(v)) v = "'" + v; // evita injeção de fórmula na planilha
  return /[",;\n\r]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
}

function toCsv(items) {
  const lines = [["Site", "Usuário", "Senha", "URL", "Notas"].join(",")];
  for (const it of items) lines.push([it.title, it.username, it.password, it.url || "", it.notes || ""].map(csvCell).join(","));
  return "﻿" + lines.join("\r\n") + "\r\n"; // BOM: o Excel abre os acentos certo
}

/* ---------- exportação ---------- */

function download(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function exportPlain(format) {
  if (!allCredentials || allCredentials.length === 0) {
    toast("Não há credenciais para exportar.");
    return;
  }
  const ok = await reauth("O arquivo exportado terá as senhas em texto puro, sem criptografia. Confirme sua senha mestra para continuar.");
  if (!ok) return;

  const day = new Date().toISOString().slice(0, 10);
  if (format === "csv") {
    download(new Blob([toCsv(allCredentials)], { type: "text/csv;charset=utf-8" }), `cofre-export-${day}.csv`);
  } else {
    const rows = allCredentials.map((item) => ({
      Site: csvSafe(item.title),
      "Usuário": csvSafe(item.username),
      Senha: csvSafe(item.password),
      URL: csvSafe(item.url || ""),
      Notas: csvSafe(item.notes || "")
    }));
    const workbook = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(workbook, XLSX.utils.json_to_sheet(rows), "Cofre");
    XLSX.writeFile(workbook, `cofre-export-${day}.xlsx`);
  }
  toast("Exportação concluída. O arquivo NÃO está criptografado: guarde com cuidado e apague depois de usar.");
}

function csvSafe(v) {
  const s = String(v ?? "");
  return /^[=+\-@\t\r]/.test(s) ? "'" + s : s;
}

/* ---------- importação ---------- */

async function readRows(file) {
  if (file.size > IMPORT_MAX_BYTES) throw new Error("Arquivo grande demais (máximo 5 MB).");
  if (/\.csv$/i.test(file.name) || file.type === "text/csv") return parseCsv(await file.text());
  const workbook = XLSX.read(await file.arrayBuffer(), { type: "array", cellFormula: false, cellHTML: false });
  const sheet = workbook.Sheets[workbook.SheetNames[0]];
  return XLSX.utils.sheet_to_json(sheet, { defval: "" });
}

async function handleImportFile(file) {
  try {
    const rows = await readRows(file);
    if (rows.length === 0) return toast("A planilha está vazia.");
    if (rows.length > IMPORT_MAX_ROWS) return toast(`Muitas linhas (máximo ${IMPORT_MAX_ROWS}). Divida o arquivo.`);

    await detectSchema();
    const version = VaultSchema.itemVersion ? 2 : 1;
    const seen = new Set(allCredentials.map((c) => `${c.title}|${c.username}|${c.url || ""}`.toLowerCase()));
    const records = [];
    let skipped = 0;
    let duplicated = 0;

    for (const row of rows) {
      const cred = mapRowToCredential(row);
      if (!cred.title || !cred.password) { skipped++; continue; }
      const sig = `${cred.title}|${cred.username}|${cred.url}`.toLowerCase();
      if (seen.has(sig)) { duplicated++; continue; }
      seen.add(sig);
      const id = CryptoUtil.newId();
      const { ciphertext, iv } = await CryptoUtil.encryptJSON(VaultSession.key, cred, CryptoUtil.aadFor(version, VaultSession.userId, "item", id));
      const rec = { id, user_id: VaultSession.userId, encrypted_data: ciphertext, iv };
      if (VaultSchema.itemVersion) rec.version = version;
      records.push(rec);
    }

    for (let i = 0; i < records.length; i += 100) {
      const { error } = await sb.from("vault_items").insert(records.slice(i, i + 100));
      if (error) throw error;
    }

    await refreshList();
    toast(`Importação concluída: ${records.length} adicionada(s), ${duplicated} já existiam, ${skipped} ignorada(s).`);
  } catch (err) {
    console.error(err);
    toast(err && /grande demais/.test(err.message) ? err.message : "Erro ao ler o arquivo. Verifique se é um .csv/.xlsx válido.");
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const importBtn = document.getElementById("btn-import");
  const importInput = document.getElementById("import-file-input");

  document.getElementById("btn-export-csv")?.addEventListener("click", () => exportPlain("csv"));
  document.getElementById("btn-export")?.addEventListener("click", () => exportPlain("xlsx"));

  if (importBtn && importInput) {
    importBtn.addEventListener("click", () => importInput.click());
    importInput.addEventListener("change", (e) => {
      const file = e.target.files[0];
      if (file) handleImportFile(file);
      importInput.value = ""; // permite selecionar o mesmo arquivo de novo depois
    });
  }
});
