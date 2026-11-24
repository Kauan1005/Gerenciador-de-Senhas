/* ==========================================================
   SETTINGS MODULE: alterar senha mestra / reforçar criptografia
   ==========================================================
   Passo a passo:
   1) Confere a senha atual decifrando o verificador.
   2) Gera sal novo, deriva a chave nova e prepara TODOS os registros
      (credenciais e projetos) re-cifrados em memória.
   3) Atualiza o segredo de login no Supabase Auth.
   4) Grava tudo de uma vez numa única transação do banco
      (função rotate_vault): ou muda tudo, ou não muda nada.
      Se este passo falhar, o segredo de login volta ao anterior.

   Arquivos de projeto NÃO são re-cifrados: cada arquivo tem a própria
   chave, guardada dentro do registro do projeto (que é re-cifrado).

   Sem a função rotate_vault no banco (schema.sql ainda não rodado), cai
   no método antigo, que NÃO é atômico: por isso o app pede um backup
   antes e avisa para não fechar a janela.
   ========================================================== */

async function reencryptTable(table, kind, oldKey, newKey, targetVersion) {
  const cols = VaultSchema.itemVersion || table !== "vault_items" ? "id, encrypted_data, iv, version" : "id, encrypted_data, iv";
  const { data: rows, error } = await sb.from(table).select(cols).eq("user_id", VaultSession.userId);
  if (error) throw error;

  const out = [];
  for (const row of rows) {
    const oldVersion = row.version || 1;
    const plain = await CryptoUtil.decryptJSON(oldKey, row.encrypted_data, row.iv, CryptoUtil.aadFor(oldVersion, VaultSession.userId, kind, row.id));
    const { ciphertext, iv } = await CryptoUtil.encryptJSON(newKey, plain, CryptoUtil.aadFor(targetVersion, VaultSession.userId, kind, row.id));
    out.push({ id: row.id, encrypted_data: ciphertext, iv, version: targetVersion });
  }
  return out;
}

async function rotateMasterKey(currentPassword, newPassword) {
  await detectSchema();
  const config = await AuthModule.fetchVaultConfig(VaultSession.userId);
  if (!config) throw new Error("Configuração do cofre não encontrada.");

  const oldKey = await AuthModule.unlockWithConfig(currentPassword, config);
  if (!oldKey) return { wrongPassword: true };

  const newSalt = CryptoUtil.generateSaltBase64();
  const iterations = window.APP_CONFIG.KDF_ITERATIONS || CryptoUtil.DEFAULT_KDF_ITERATIONS;
  const newKey = await CryptoUtil.deriveKey(newPassword, newSalt, iterations);
  const { verifier, verifier_iv } = await CryptoUtil.createVerifier(newKey);

  const itemVersion = VaultSchema.itemVersion ? 2 : 1;
  const items = await reencryptTable("vault_items", "item", oldKey, newKey, itemVersion);
  const projects = VaultSchema.projects ? await reencryptTable("vault_projects", "project", oldKey, newKey, 2) : [];

  const newConfig = { salt: newSalt, kdf_iterations: iterations, verifier, verifier_iv };
  if (VaultSchema.authVersion) newConfig.auth_version = 2;

  // 3) segredo de login (só muda se a senha mestra mudou)
  const email = VaultSession.email;
  const passwordChanged = newPassword !== currentPassword;
  const newSecret = await CryptoUtil.deriveAuthSecret(newPassword, email);
  const oldSecret = config.auth_version >= 2 ? await CryptoUtil.deriveAuthSecret(currentPassword, email) : currentPassword;
  if (passwordChanged || config.auth_version < 2) {
    const { error: authError } = await sb.auth.updateUser({ password: newSecret });
    if (authError) throw authError;
  }

  try {
    if (VaultSchema.rotateRpc) {
      const { error } = await sb.rpc("rotate_vault", { p_config: newConfig, p_items: items, p_projects: projects });
      if (error) throw error;
    } else {
      // método antigo (não atômico): primeiro os itens, depois a configuração
      for (const row of items) {
        const patch = { encrypted_data: row.encrypted_data, iv: row.iv };
        if (VaultSchema.itemVersion) patch.version = row.version;
        const { error } = await sb.from("vault_items").update(patch).eq("id", row.id).eq("user_id", VaultSession.userId);
        if (error) throw error;
      }
      const { error } = await sb.from("vault_config").update(newConfig).eq("user_id", VaultSession.userId);
      if (error) throw error;
    }
  } catch (err) {
    if (passwordChanged || config.auth_version < 2) {
      await sb.auth.updateUser({ password: oldSecret }).catch(() => {}); // desfaz o segredo de login
    }
    throw err;
  }

  VaultSession.key = newKey;
  VaultSession.config = { ...config, ...newConfig };
  return { ok: true, count: items.length + projects.length };
}

async function handleChangeMasterPassword(currentPassword, newPassword, newPasswordConfirm) {
  const errorEl = document.getElementById("change-master-error");
  errorEl.hidden = true;
  const fail = (msg) => {
    errorEl.textContent = msg;
    errorEl.hidden = false;
  };

  if (newPassword !== newPasswordConfirm) return fail("As novas senhas não coincidem.");
  const problem = CryptoUtil.masterPasswordProblem(newPassword, window.APP_CONFIG.MIN_MASTER_LENGTH || CryptoUtil.MIN_MASTER_LENGTH);
  if (problem) return fail(problem);
  if (newPassword === currentPassword) return fail("A nova senha precisa ser diferente da atual.");

  const saveBtn = document.getElementById("btn-save-change-master");
  saveBtn.disabled = true;
  try {
    await detectSchema();
    if (!VaultSchema.rotateRpc && !window.confirm("O banco ainda não tem a troca atômica de senha. Se a conexão cair no meio, parte dos registros pode ficar ilegível. Baixe um backup antes. Continuar mesmo assim?")) return;
    const r = await rotateMasterKey(currentPassword, newPassword);
    if (r.wrongPassword) return fail("Senha mestra atual incorreta.");
    closeChangeMasterModal();
    document.dispatchEvent(new CustomEvent("vault:rekeyed"));
    if (typeof refreshList === "function") await refreshList();
    toast(`Senha mestra alterada. ${r.count} registro(s) re-criptografado(s).`);
  } catch (err) {
    console.error(err);
    fail("Erro ao alterar a senha mestra. Nada foi alterado. Tente novamente.");
  } finally {
    saveBtn.disabled = false;
  }
}

// "Reforçar criptografia": mesma senha, derivação com mais iterações e sal novo.
async function handleUpgradeKdf() {
  if (!AuthModule.needsKdfUpgrade(VaultSession.config)) {
    toast("Sua criptografia já está no nível atual.");
    return;
  }
  if (!window.confirm("Vamos baixar um backup (cifrado) e depois reforçar a criptografia do cofre com a mesma senha mestra. Continuar?")) return;
  // a senha é pedida uma vez, usada só para derivar a chave nova e não é guardada em lugar nenhum
  const password = await askPasswordValue();
  if (!password) return;
  try {
    await createBackup();
    const r = await rotateMasterKey(password, password);
    if (r.wrongPassword) return toast("Senha mestra incorreta.");
    toast("Criptografia reforçada.");
    document.getElementById("btn-upgrade-kdf")?.setAttribute("hidden", "");
    document.getElementById("upgrade-banner").hidden = true;
  } catch (err) {
    console.error(err);
    toast("Não foi possível reforçar agora. Nada foi alterado.");
  }
}

// Pede a senha mestra por um campo do próprio app (reaproveita o diálogo de confirmação).
function askPasswordValue() {
  return new Promise((resolve) => {
    const dlg = document.getElementById("reauth-modal");
    const form = document.getElementById("reauth-form");
    const input = document.getElementById("reauth-password");
    document.getElementById("reauth-reason").textContent = "Digite a senha mestra mais uma vez para gerar a nova chave.";
    document.getElementById("reauth-error").hidden = true;
    input.value = "";
    dlg.hidden = false;
    input.focus();
    const finish = (v) => {
      form.removeEventListener("submit", onSubmit, true);
      document.getElementById("reauth-cancel").removeEventListener("click", onCancel);
      input.value = "";
      dlg.hidden = true;
      resolve(v);
    };
    const onCancel = () => finish(null);
    const onSubmit = (e) => {
      e.preventDefault();
      e.stopImmediatePropagation();
      finish(input.value);
    };
    form.addEventListener("submit", onSubmit, true);
    document.getElementById("reauth-cancel").addEventListener("click", onCancel);
  });
}

function openChangeMasterModal() {
  document.getElementById("change-master-form").reset();
  document.getElementById("change-master-error").hidden = true;
  document.getElementById("change-master-modal").hidden = false;
}

function closeChangeMasterModal() {
  document.getElementById("change-master-modal").hidden = true;
  document.getElementById("change-master-form").reset();
}

document.addEventListener("DOMContentLoaded", () => {
  const openBtn = document.getElementById("btn-change-master");
  const closeBtn = document.getElementById("change-master-close");
  const cancelBtn = document.getElementById("btn-cancel-change-master");
  const modal = document.getElementById("change-master-modal");
  const form = document.getElementById("change-master-form");

  document.getElementById("btn-upgrade-kdf")?.addEventListener("click", handleUpgradeKdf);

  if (!openBtn) return;

  openBtn.addEventListener("click", openChangeMasterModal);
  closeBtn.addEventListener("click", closeChangeMasterModal);
  cancelBtn.addEventListener("click", closeChangeMasterModal);
  modal.addEventListener("click", (e) => {
    if (e.target.id === "change-master-modal") closeChangeMasterModal();
  });

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    handleChangeMasterPassword(
      document.getElementById("current-master-password").value,
      document.getElementById("new-master-password").value,
      document.getElementById("new-master-password-confirm").value
    );
  });
});
