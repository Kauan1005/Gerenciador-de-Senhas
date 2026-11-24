/* ==========================================================
   CREDENTIALS MODULE (tela vault.html)
   ==========================================================
   Só a interface: lista, busca, modal e ações. O acesso aos dados
   (buscar/gravar cifrado) está em vault-data.js; a guarda de sessão
   (pedir senha mestra) está em session.js.
   ========================================================== */

/* ---------- render ---------- */

function iconButton(action, label, glyph) {
  const b = el("button", "icon-btn");
  b.type = "button";
  b.dataset.action = action;
  b.title = label;
  b.setAttribute("aria-label", label);
  b.innerHTML = glyph; // glifo constante (entidade HTML), nunca dado do usuário
  return b;
}

function renderList(items) {
  const list = document.getElementById("credentials-list");
  const emptyState = document.getElementById("empty-state");
  const noResults = document.getElementById("no-results");

  list.replaceChildren();

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
    const card = el("article", "cred-card");
    card.dataset.id = item.id;

    const main = el("div", "cred-card__main");
    main.append(el("h3", "cred-card__title", item.title), el("p", "cred-card__username", item.username));

    const actions = el("div", "cred-card__actions");
    const copyUser = iconButton("copy-user", "Copiar usuário", "&#128100;");
    const copyPass = iconButton("copy-pass", "Copiar senha", "&#128273;");
    actions.append(copyUser, copyPass);
    if (safeHttpUrl(item.url)) actions.append(iconButton("open-url", "Abrir o site e copiar login e senha", "&#128279;"));
    actions.append(iconButton("edit", "Editar credencial", "&#9998;"), iconButton("delete", "Excluir credencial", "&#128465;"));

    copyUser.addEventListener("click", () => copySecret(item.username, "Usuário copiado"));
    copyPass.addEventListener("click", () => copySecret(item.password, "Senha copiada"));
    actions.querySelector('[data-action="open-url"]')?.addEventListener("click", () => openCredentialUrl(item));
    actions.querySelector('[data-action="edit"]').addEventListener("click", () => openModal(item));
    actions.querySelector('[data-action="delete"]').addEventListener("click", () => confirmDelete(item));

    card.append(main, actions);
    list.appendChild(card);
  }
}

function applyFilter() {
  const term = document.getElementById("search-input").value.trim().toLowerCase();
  if (!term) {
    renderList(allCredentials);
    return;
  }
  renderList(
    allCredentials.filter((item) =>
      [item.title, item.username, item.url].filter(Boolean).some((field) => field.toLowerCase().includes(term))
    )
  );
}

async function refreshList() {
  allCredentials = await fetchAndDecryptAll();
  applyFilter();
}

/* ---------- ações auxiliares ---------- */

// Abre a URL cadastrada em nova aba e copia login e senha (separados por " e ").
// Não há como preencher campos de um site de terceiros daqui: só uma extensão faria isso.
function openCredentialUrl(item) {
  const href = safeHttpUrl(item && item.url);
  if (!href) return;
  window.open(href, "_blank", "noopener,noreferrer");
  copySecret(`${item.username} e ${item.password}`, "Site aberto. Login e senha copiados (Ctrl+V)");
}

function confirmDelete(item) {
  if (!window.confirm(`Excluir a credencial "${item.title}"? Essa ação não pode ser desfeita.`)) return;
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
  document.getElementById("credential-form").reset(); // não deixa a senha digitada no formulário
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

/* ---------- avisos de atualização do banco / da criptografia ---------- */

function showUpgradeBanner() {
  const banner = document.getElementById("upgrade-banner");
  if (!banner) return;
  const messages = [];
  if (!VaultSchema.projects || !VaultSchema.itemVersion || !VaultSchema.rotateRpc) {
    messages.push("O banco ainda não tem as atualizações de segurança e de projetos. Rode o arquivo supabase/schema.sql no Supabase (README, seção 5).");
  }
  if (AuthModule.needsKdfUpgrade(VaultSession.config)) {
    messages.push("Seu cofre usa uma derivação de chave mais fraca que a atual. Use \"Reforçar criptografia\" no menu da conta.");
    document.getElementById("btn-upgrade-kdf")?.removeAttribute("hidden");
  }
  if (messages.length) {
    banner.textContent = messages.join(" ");
    banner.hidden = false;
  }
  if (sessionStorage.getItem("cofre-migrated") === "1") {
    sessionStorage.removeItem("cofre-migrated");
    toast("Login atualizado: sua senha mestra agora não é mais enviada ao servidor.");
  }
}

/* ---------- inicialização ---------- */

document.addEventListener("DOMContentLoaded", async () => {
  const ok = await guardSession();
  if (!ok) return;

  document.getElementById("account-email").textContent = VaultSession.email || "";
  AutoLockModule.init(); // só agora a chave existe
  await detectSchema();
  showUpgradeBanner();

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

  // Gerador de senha, cópia com limpeza automática, importar/exportar, backup,
  // bloqueio automático e troca de senha mestra são ligados pelos demais módulos.
});
