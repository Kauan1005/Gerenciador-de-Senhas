/* ==========================================================
   SETTINGS MODULE: alterar senha mestra / reforçar criptografia
   ==========================================================
   O cofre usa uma chave aleatória (DEK) que cifra tudo; a senha mestra
   só "embrulha" essa DEK. Por isso trocar a senha mestra NÃO re-cifra
   credenciais, projetos nem arquivos: a mesma DEK é embrulhada de novo
   com uma KEK nova (uma única linha de vault_config muda).

   Passo a passo:
   1) Desembrulha a DEK com a senha atual (se falhar, a senha está errada).
   2) Gera sal novo, deriva a KEK nova e embrulha a MESMA DEK.
   3) Atualiza o segredo de login no Supabase Auth.
   4) Grava o novo sal e a DEK embrulhada em vault_config. Se este passo
      falhar, o segredo de login volta ao anterior.

   A chave de recuperação continua valendo depois da troca (ela embrulha
   a mesma DEK, que não muda).
   ========================================================== */

async function rotateMasterKey(currentPassword, newPassword) {
  const config = await AuthModule.fetchVaultConfig(VaultSession.userId);
  if (!config) throw new Error("Configuração do cofre não encontrada.");

  const dekBuf = await AuthModule.unwrapDek(currentPassword, config);
  if (!dekBuf) return { wrongPassword: true };

  const newSalt = CryptoUtil.generateSaltBase64();
  const iterations = window.APP_CONFIG.KDF_ITERATIONS || CryptoUtil.DEFAULT_KDF_ITERATIONS;
  const newKek = await CryptoUtil.deriveKey(newPassword, newSalt, iterations);
  const { wrapped, iv } = await CryptoUtil.wrapBytes(newKek, dekBuf);
  const newConfig = { salt: newSalt, kdf_iterations: iterations, wrapped_dek: wrapped, wrapped_dek_iv: iv };

  // segredo de login (só muda se a senha mestra mudou ou se a conta ainda era do formato antigo)
  const email = VaultSession.email;
  const legacyAuth = !(config.auth_version >= 2);
  const passwordChanged = newPassword !== currentPassword;
  const touchAuth = passwordChanged || legacyAuth;
  const newSecret = await CryptoUtil.deriveAuthSecret(newPassword, email);
  const oldSecret = legacyAuth ? currentPassword : await CryptoUtil.deriveAuthSecret(currentPassword, email);
  if (touchAuth) {
    const { error: authError } = await sb.auth.updateUser({ password: newSecret });
    if (authError) throw authError;
    if (VaultSchema.authVersion) newConfig.auth_version = 2;
  }

  try {
    const { error } = await sb.from("vault_config").update(newConfig).eq("user_id", VaultSession.userId);
    if (error) throw error;
  } catch (err) {
    if (touchAuth) await sb.auth.updateUser({ password: oldSecret }).catch(() => {}); // desfaz o segredo de login
    throw err;
  }

  VaultSession.config = { ...config, ...newConfig };
  return { ok: true };
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
    const r = await rotateMasterKey(currentPassword, newPassword);
    if (r.wrongPassword) return fail("Senha mestra atual incorreta.");
    closeChangeMasterModal();
    toast("Senha mestra alterada. A chave de recuperação continua valendo.");
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
  if (!window.confirm("Vamos reforçar a criptografia do cofre com a mesma senha mestra. Suas credenciais não são alteradas. Continuar?")) return;
  // a senha é pedida uma vez, usada só para derivar a chave nova e não é guardada em lugar nenhum
  const password = await askPasswordValue();
  if (!password) return;
  try {
    await detectSchema();
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
function askPasswordValue(reason) {
  return new Promise((resolve) => {
    const dlg = document.getElementById("reauth-modal");
    const form = document.getElementById("reauth-form");
    const input = document.getElementById("reauth-password");
    document.getElementById("reauth-reason").textContent = reason || "Digite a senha mestra mais uma vez para gerar a nova chave.";
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
