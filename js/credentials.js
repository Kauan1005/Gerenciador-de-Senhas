/* ==========================================================
   CREDENTIALS MODULE
   ==========================================================
   Controla a tela vault.html inteira: busca a lista cifrada
   no Supabase, decifra em memória, renderiza, e implementa
   criar/editar/excluir. Também cuida do "guarda de sessão":
   se a chave não estiver em memória (reload, aba nova, link
   direto), mas ainda existir uma sessão válida no Supabase,
   pede a senha mestra novamente (overlay de bloqueio) para
   re-derivar a chave, sem exigir novo login. Se não houver
   sessão nenhuma, manda de volta para o login.
   ========================================================== */

let allCredentials = []; // cache em memória, já decifrada

function toast(message) {
  const el = document.getElementById("toast");
  if (!el) return;
  el.textContent = message;
  el.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { el.hidden = true; }, 2500);
}

async function guardSession() {
  // Já tem chave em memória (ex.: navegação dentro da mesma aba)
  if (window.VaultSession && VaultSession.key && VaultSession.userId) {
    return true;
  }

  // Sem chave em memória: verifica se ainda existe sessão válida no Supabase
  const { data: { session } } = await sb.auth.getSession();
  if (!session) {
    window.location.href = "index.html";
    return false;
  }

  // Sessão existe, mas a chave derivada se perdeu (reload / navegação) -> pede senha mestra
  VaultSession.userId = session.user.id;
  VaultSession.email = session.user.email;
  return await promptUnlock();
}

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
      form.removeEventListener("submit", onSubmit);
      logoutBtn.removeEventListener("click", onLogout);
    }

    form.addEventListener("submit", onSubmit);
    logoutBtn.addEventListener("click", onLogout);
  });
}

/* ---------- CRUD ---------- */

async function fetchAndDecryptAll() {
  const { data, error } = await sb
    .from("vault_items")
    .select("id, encrypted_data, iv, created_at")
    .eq("user_id", VaultSession.userId)
    .order("created_at", { ascending: false });

  if (error) throw error;

  const decrypted = [];
  for (const row of data) {
    try {
      const item = await CryptoUtil.decryptJSON(VaultSession.key, row.encrypted_data, row.iv);
      decrypted.push({ id: row.id, ...item });
    } catch (err) {
      // linha corrompida ou cifrada com outra chave — não trava a lista inteira
      console.error("Falha ao decifrar item", row.id, err);
    }
  }
  return decrypted;
}

async function addCredential(payload) {
  const { ciphertext, iv } = await CryptoUtil.encryptJSON(VaultSession.key, payload);
  const { data, error } = await sb
    .from("vault_items")
    .insert({ user_id: VaultSession.userId, encrypted_data: ciphertext, iv })
    .select("id, created_at")
    .single();
  if (error) throw error;
  return { id: data.id, ...payload };
}

async function updateCredential(id, payload) {
  const { ciphertext, iv } = await CryptoUtil.encryptJSON(VaultSession.key, payload);
  const { error } = await sb
    .from("vault_items")
    .update({ encrypted_data: ciphertext, iv })
    .eq("id", id)
    .eq("user_id", VaultSession.userId);
  if (error) throw error;
  return { id, ...payload };
}

async function deleteCredential(id) {
  const { error } = await sb
    .from("vault_items")
    .delete()
    .eq("id", id)
    .eq("user_id", VaultSession.userId);
  if (error) throw error;
}

/* ---------- render ---------- */

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}

function renderList(items) {
  const list = document.getElementById("credentials-list");
  const emptyState = document.getElementById("empty-state");
  const noResults = document.getElementById("no-results");

  list.innerHTML = "";

  if (allCredentials.length === 0) {
    emptyState.hidden = false;
    noResults.hidden = true;
    return;
  }
  emptyState.hidden = true;

  if (items.length === 0) {
    noResults.hidden = false;
    return;
  }
  noResults.hidden = true;

  for (const item of items) {
    const card = document.createElement("article");
    card.className = "cred-card";
    card.dataset.id = item.id;

    card.innerHTML = `
      <div class="cred-card__main">
        <h3 class="cred-card__title">${escapeHtml(item.title)}</h3>
        <p class="cred-card__username">${escapeHtml(item.username)}</p>
      </div>
      <div class="cred-card__actions">
        ${item.url ? `<button class="icon-btn" data-action="open-url" title="Abrir URL e copiar login e senha" aria-label="Abrir URL e copiar login e senha">&#128279;</button>` : ""}
        <button class="icon-btn" data-action="edit" title="Editar credencial" aria-label="Editar credencial">&#9998;</button>
        <button class="icon-btn" data-action="delete" title="Excluir credencial" aria-label="Excluir credencial">&#128465;</button>
      </div>
    `;

    card.querySelector('[data-action="open-url"]')?.addEventListener("click", () => {
      openCredentialUrl(item);
    });
    card.querySelector('[data-action="edit"]').addEventListener("click", () => {
      openModal(item);
    });
    card.querySelector('[data-action="delete"]').addEventListener("click", () => {
      confirmDelete(item);
    });

    list.appendChild(card);
  }
}

function applyFilter() {
  const term = document.getElementById("search-input").value.trim().toLowerCase();
  if (!term) {
    renderList(allCredentials);
    return;
  }
  const filtered = allCredentials.filter((item) =>
    [item.title, item.username, item.url]
      .filter(Boolean)
      .some((field) => field.toLowerCase().includes(term))
  );
  renderList(filtered);
}

async function refreshList() {
  allCredentials = await fetchAndDecryptAll();
  applyFilter();
}

/* ---------- ações auxiliares ---------- */

// Abre a URL cadastrada em nova aba e, junto, copia login e senha para a
// área de transferência (com o separador " e " entre eles), já que não há
// como preencher automaticamente os campos de um site de terceiros a
// partir daqui — só uma extensão de navegador com permissão de autofill
// faria isso.
function openCredentialUrl(item) {
  if (!item || !item.url) return;
  const href = /^https?:\/\//i.test(item.url) ? item.url : `https://${item.url}`;
  window.open(href, "_blank", "noopener,noreferrer");

  const seconds = (window.APP_CONFIG && window.APP_CONFIG.CLIPBOARD_CLEAR_SECONDS) || 20;
  const combined = `${item.username} e ${item.password}`;
  ClipboardModule.copy(combined).then((ok) => {
    toast(
      ok
        ? `Site aberto. Login e senha copiados (Ctrl+V) — limpos em ${seconds}s.`
        : "Site aberto. Não foi possível copiar login/senha."
    );
  });
}

function confirmDelete(item) {
  if (!window.confirm(`Excluir a credencial "${item.title}"? Essa ação não pode ser desfeita.`)) {
    return;
  }
  deleteCredential(item.id)
    .then(() => {
      toast("Credencial excluída.");
      refreshList();
    })
    .catch((err) => {
      console.error(err);
      toast("Erro ao excluir. Tente novamente.");
    });
}

/* ---------- modal ---------- */

function openModal(item) {
  const modal = document.getElementById("credential-modal");
  const title = document.getElementById("modal-title");
  const deleteBtn = document.getElementById("btn-delete-credential");
  const error = document.getElementById("credential-error");

  document.getElementById("credential-form").reset();
  error.hidden = true;

  if (item) {
    title.textContent = "Editar credencial";
    document.getElementById("cred-id").value = item.id;
    document.getElementById("cred-title").value = item.title;
    document.getElementById("cred-username").value = item.username;
    document.getElementById("cred-password").value = item.password;
    document.getElementById("cred-url").value = item.url || "";
    document.getElementById("cred-notes").value = item.notes || "";
    deleteBtn.hidden = false;
    deleteBtn.onclick = () => {
      closeModal();
      confirmDelete(item);
    };
  } else {
    title.textContent = "Nova credencial";
    document.getElementById("cred-id").value = "";
    deleteBtn.hidden = true;
  }

  modal.hidden = false;
  document.getElementById("cred-title").focus();
}

function closeModal() {
  document.getElementById("credential-modal").hidden = true;
}

async function handleCredentialSubmit(e) {
  e.preventDefault();
  const errorEl = document.getElementById("credential-error");
  errorEl.hidden = true;

  const id = document.getElementById("cred-id").value;
  const payload = {
    title: document.getElementById("cred-title").value.trim(),
    username: document.getElementById("cred-username").value.trim(),
    password: document.getElementById("cred-password").value,
    url: document.getElementById("cred-url").value.trim(),
    notes: document.getElementById("cred-notes").value.trim()
  };

  const saveBtn = document.getElementById("btn-save-credential");
  saveBtn.disabled = true;
  try {
    if (id) {
      await updateCredential(id, payload);
      toast("Credencial atualizada.");
    } else {
      await addCredential(payload);
      toast("Credencial salva.");
    }
    closeModal();
    await refreshList();
  } catch (err) {
    console.error(err);
    errorEl.textContent = "Erro ao salvar. Tente novamente.";
    errorEl.hidden = false;
  } finally {
    saveBtn.disabled = false;
  }
}

/* ---------- inicialização ---------- */

document.addEventListener("DOMContentLoaded", async () => {
  const ok = await guardSession();
  if (!ok) return;

  document.getElementById("account-email").textContent = VaultSession.email || "";

  refreshList().catch((err) => {
    console.error(err);
    toast("Erro ao carregar o cofre.");
  });

  document.getElementById("search-input").addEventListener("input", applyFilter);

  document.getElementById("btn-new-credential").addEventListener("click", () => openModal(null));
  document.getElementById("modal-close").addEventListener("click", closeModal);
  document.getElementById("btn-cancel-credential").addEventListener("click", closeModal);
  document.getElementById("credential-modal").addEventListener("click", (e) => {
    if (e.target.id === "credential-modal") closeModal();
  });
  document.getElementById("credential-form").addEventListener("submit", handleCredentialSubmit);

  document.querySelectorAll(".field__toggle").forEach((btn) => {
    btn.addEventListener("click", () => {
      const input = document.getElementById(btn.dataset.toggleFor);
      if (!input) return;
      const isPassword = input.type === "password";
      input.type = isPassword ? "text" : "password";
      btn.setAttribute("aria-label", isPassword ? "Ocultar senha" : "Mostrar senha");
    });
  });

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

  // Gerador de senha, cópia com limpeza automática, importar/exportar Excel,
  // backup/restauração, bloqueio automático e troca de senha mestra são
  // ligados pelos respectivos módulos (generator.js, clipboard.js,
  // import-export.js, backup.js, autolock.js, settings.js), carregados
  // depois deste arquivo em vault.html.
});