/* ==========================================================
   SESSION MODULE (compartilhado por Senhas e Projetos)
   ==========================================================
   - toast(): aviso rápido na tela
   - guardSession(): garante login + chave em memória; se a chave
     sumiu (recarregou a página), pede a senha mestra de novo
   - reauth(): pede a senha mestra antes de ações sensíveis
     (ex.: exportar senhas em texto puro)
   - detectSchema(): descobre se o banco já tem as tabelas/colunas
     novas, para o app continuar funcionando com o banco antigo
   ========================================================== */

function toast(message) {
  const el = document.getElementById("toast");
  if (!el) return;
  el.textContent = message;
  el.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { el.hidden = true; }, 3500);
}

/* ---------- passagem da chave entre páginas (login -> cofre -> projetos) ----------
   A chave AES é NÃO exportável: o navegador a guarda no IndexedDB sem expor os bytes.
   Ela fica lá por no máximo 20 s e é APAGADA assim que a página seguinte a lê.
   Recarregar a página (F5) não passa pela troca e continua pedindo a senha mestra. */

const HANDOFF_TTL_MS = 20000;

function handoffDb() {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open("cofre-handoff", 1);
    open.onupgradeneeded = () => open.result.createObjectStore("h");
    open.onsuccess = () => resolve(open.result);
    open.onerror = () => reject(open.error);
  });
}

async function handoffPut() {
  try {
    if (!VaultSession.key || !VaultSession.userId) return;
    const db = await handoffDb();
    await new Promise((resolve, reject) => {
      const tx = db.transaction("h", "readwrite");
      tx.objectStore("h").put({ key: VaultSession.key, userId: VaultSession.userId, at: Date.now() }, "k");
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
    });
    db.close();
  } catch (_) { /* sem IndexedDB: a próxima página só pede a senha mestra */ }
}

async function handoffTake() {
  try {
    const db = await handoffDb();
    const value = await new Promise((resolve, reject) => {
      const tx = db.transaction("h", "readwrite");
      const store = tx.objectStore("h");
      const get = store.get("k");
      get.onsuccess = () => { store.delete("k"); resolve(get.result); };
      get.onerror = () => reject(get.error);
    });
    db.close();
    if (value && Date.now() - value.at <= HANDOFF_TTL_MS) return value;
  } catch (_) { /* ignora */ }
  return null;
}

async function guardSession() {
  // Já tem chave em memória (ex.: navegação dentro da mesma aba)
  if (window.VaultSession && VaultSession.key && VaultSession.userId) return true;

  const { data: { session } } = await sb.auth.getSession();
  if (!session) {
    window.location.href = "index.html";
    return false;
  }
  VaultSession.userId = session.user.id;
  VaultSession.email = session.user.email;

  const passed = await handoffTake();
  if (passed && passed.userId === session.user.id) {
    try {
      const config = await AuthModule.fetchVaultConfig(session.user.id);
      if (config) {
        VaultSession.key = passed.key;
        VaultSession.config = config;
        return true;
      }
    } catch (_) { /* cai no pedido da senha mestra */ }
  }
  return await promptUnlock();
}

// Links de navegação entre páginas do cofre levam a chave junto (por até 20 s).
document.addEventListener("click", async (e) => {
  const link = e.target.closest && e.target.closest("a[data-nav]");
  if (!link || e.defaultPrevented || e.ctrlKey || e.metaKey || e.shiftKey) return;
  e.preventDefault();
  await handoffPut();
  window.location.href = link.href;
});

function promptUnlock() {
  return new Promise((resolve) => {
    const overlay = document.getElementById("lock-overlay");
    const form = document.getElementById("unlock-form");
    const input = document.getElementById("unlock-password");
    const errorEl = document.getElementById("unlock-error");
    const logoutBtn = document.getElementById("btn-unlock-logout");

    errorEl.hidden = true;
    overlay.hidden = false;
    input.value = "";
    input.focus();

    async function onSubmit(e) {
      e.preventDefault();
      e.stopImmediatePropagation(); // o desbloqueio do auto-bloqueio ainda não está ativo nesta fase
      errorEl.hidden = true;
      try {
        const config = await AuthModule.fetchVaultConfig(VaultSession.userId);
        if (!config) {
          errorEl.textContent = "Configuração do cofre não encontrada.";
          errorEl.hidden = false;
          return;
        }
        const key = await AuthModule.unlockWithConfig(input.value, config);
        if (!key) {
          errorEl.textContent = "Senha mestra incorreta.";
          errorEl.hidden = false;
          return;
        }
        VaultSession.key = key;
        VaultSession.config = config;
        input.value = "";
        cleanup();
        overlay.hidden = true;
        resolve(true);
      } catch (err) {
        console.error(err);
        errorEl.textContent = "Erro ao desbloquear. Tente novamente.";
        errorEl.hidden = false;
      }
    }

    function onLogout() {
      cleanup();
      sb.auth.signOut().finally(() => {
        VaultSession.clear();
        window.location.href = "index.html";
      });
      resolve(false);
    }

    function cleanup() {
      form.removeEventListener("submit", onSubmit, true);
      logoutBtn.removeEventListener("click", onLogout);
    }

    form.addEventListener("submit", onSubmit, true);
    logoutBtn.addEventListener("click", onLogout);
  });
}

/* ---------- confirmação da senha mestra para ações sensíveis ---------- */

function reauth(reason) {
  return new Promise((resolve) => {
    const dlg = document.getElementById("reauth-modal");
    if (!dlg) { resolve(false); return; }
    const form = document.getElementById("reauth-form");
    const input = document.getElementById("reauth-password");
    const err = document.getElementById("reauth-error");
    document.getElementById("reauth-reason").textContent = reason || "Confirme sua senha mestra para continuar.";
    err.hidden = true;
    input.value = "";
    dlg.hidden = false;
    input.focus();

    const done = (ok) => {
      form.removeEventListener("submit", onSubmit);
      document.getElementById("reauth-cancel").removeEventListener("click", onCancel);
      input.value = "";
      dlg.hidden = true;
      resolve(ok);
    };
    const onCancel = () => done(false);
    const onSubmit = async (e) => {
      e.preventDefault();
      try {
        const config = await AuthModule.fetchVaultConfig(VaultSession.userId);
        const key = config && (await AuthModule.unlockWithConfig(input.value, config));
        if (key) return done(true);
      } catch (_) { /* cai na mensagem abaixo */ }
      err.textContent = "Senha mestra incorreta.";
      err.hidden = false;
    };
    form.addEventListener("submit", onSubmit);
    document.getElementById("reauth-cancel").addEventListener("click", onCancel);
  });
}

/* ---------- compatibilidade com o banco ---------- */

// Descobre uma vez o que o banco já tem. Erros "coluna/tabela não existe" viram false.
const VaultSchema = { checked: false, itemVersion: false, projects: false, authVersion: false };

async function detectSchema() {
  if (VaultSchema.checked) return VaultSchema;
  const missing = (error) => !!error && (/42703|42P01|PGRST20[45]|PGRST202/.test(String(error.code)) || /does not exist|not find|schema cache/i.test(error.message || ""));
  const probe = async (query) => !missing((await query).error);
  VaultSchema.itemVersion = await probe(sb.from("vault_items").select("version").limit(1));
  VaultSchema.authVersion = await probe(sb.from("vault_config").select("auth_version").limit(1));
  VaultSchema.projects = await probe(sb.from("vault_projects").select("id").limit(1));
  VaultSchema.checked = true;
  return VaultSchema;
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}

// Só aceita http(s) para links vindos do cofre: "javascript:" e similares nunca viram link.
function safeHttpUrl(raw) {
  if (!raw) return null;
  const text = String(raw).trim();
  const withScheme = /^[a-z][a-z0-9+.-]*:/i.test(text) ? text : `https://${text}`;
  try {
    const u = new URL(withScheme);
    return u.protocol === "https:" || u.protocol === "http:" ? u.href : null;
  } catch (_) {
    return null;
  }
}

// Cria um elemento com texto (textContent: nunca interpreta HTML).
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

window.el = el;
window.toast = toast;
window.escapeHtml = escapeHtml;
window.safeHttpUrl = safeHttpUrl;
