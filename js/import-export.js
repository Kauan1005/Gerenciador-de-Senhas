/* ==========================================================
   IMPORT / EXPORT MODULE (Excel)
   ==========================================================
   Usa a biblioteca SheetJS (window.XLSX, carregada via CDN em
   vault.html) para ler/gerar arquivos .xlsx no navegador —
   nada passa pelo servidor durante a conversão.

   Colunas usadas: Site, Usuário, Senha, URL, Notas.
   A importação aceita variações comuns de cabeçalho (com ou
   sem acento, en/pt) para ser tolerante a planilhas externas.
   ========================================================== */

const FIELD_ALIASES = {
  title: ["site", "titulo", "nome", "servico", "title"],
  username: ["usuario", "username", "user", "email", "e-mail", "login"],
  password: ["senha", "password", "pass"],
  url: ["url", "link", "endereco", "site url"],
  notes: ["notas", "nota", "observacoes", "notes", "note"]
};

function normalizeHeader(h) {
  return h
    .toString()
    .trim()
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "");
}

function mapRowToCredential(row) {
  const normalizedRow = {};
  for (const [key, value] of Object.entries(row)) {
    normalizedRow[normalizeHeader(key)] = value;
  }

  const result = { title: "", username: "", password: "", url: "", notes: "" };
  for (const field of Object.keys(FIELD_ALIASES)) {
    for (const alias of FIELD_ALIASES[field]) {
      if (normalizedRow[alias] !== undefined && normalizedRow[alias] !== "") {
        result[field] = String(normalizedRow[alias]).trim();
        break;
      }
    }
  }
  return result;
}

/* ---------- exportação ---------- */

async function exportToExcel() {
  if (!allCredentials || allCredentials.length === 0) {
    toast("Não há credenciais para exportar.");
    return;
  }

  const rows = allCredentials.map((item) => ({
    Site: item.title,
    "Usuário": item.username,
    Senha: item.password,
    URL: item.url || "",
    Notas: item.notes || ""
  }));

  const worksheet = XLSX.utils.json_to_sheet(rows);
  const workbook = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(workbook, worksheet, "Cofre");

  const filename = `cofre-export-${new Date().toISOString().slice(0, 10)}.xlsx`;
  XLSX.writeFile(workbook, filename);
  toast("Exportação concluída. O arquivo NÃO está criptografado — guarde-o com cuidado.");
}

/* ---------- importação ---------- */

async function handleImportFile(file) {
  try {
    const data = await file.arrayBuffer();
    const workbook = XLSX.read(data, { type: "array" });
    const sheetName = workbook.SheetNames[0];
    const sheet = workbook.Sheets[sheetName];
    const rows = XLSX.utils.sheet_to_json(sheet, { defval: "" });

    if (rows.length === 0) {
      toast("A planilha está vazia.");
      return;
    }

    let imported = 0;
    let skipped = 0;

    for (const row of rows) {
      const cred = mapRowToCredential(row);
      if (!cred.title || !cred.password) {
        skipped++;
        continue;
      }
      try {
        await addCredential(cred);
        imported++;
      } catch (err) {
        console.error("Erro ao importar linha", row, err);
        skipped++;
      }
    }

    await refreshList();
    toast(`Importação concluída: ${imported} adicionada(s), ${skipped} ignorada(s).`);
  } catch (err) {
    console.error(err);
    toast("Erro ao ler o arquivo. Verifique se é um .xlsx/.csv válido.");
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const exportBtn = document.getElementById("btn-export");
  const importBtn = document.getElementById("btn-import");
  const importInput = document.getElementById("import-file-input");

  if (exportBtn) {
    exportBtn.addEventListener("click", () => {
      const confirmed = window.confirm(
        "O arquivo exportado conterá as senhas em texto puro (sem criptografia). Deseja continuar?"
      );
      if (confirmed) exportToExcel();
    });
  }

  if (importBtn && importInput) {
    importBtn.addEventListener("click", () => importInput.click());
    importInput.addEventListener("change", (e) => {
      const file = e.target.files[0];
      if (file) handleImportFile(file);
      importInput.value = ""; // permite selecionar o mesmo arquivo de novo depois
    });
  }
});