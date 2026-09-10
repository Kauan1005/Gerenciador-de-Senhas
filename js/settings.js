/* ==========================================================
   SETTINGS MODULE — alterar senha mestra
   ==========================================================
   Passo a passo:
   1) Confere a senha atual decifrando o verificador (checkVerifier).
   2) Gera um salt novo e deriva a nova chave.
   3) Decifra cada credencial com a chave antiga e re-cifra com a nova.
   4) Grava o novo salt/verificador em vault_config.
   5) Atualiza a senha de login no Supabase Auth para a mesma senha
      mestra nova (mantendo login e senha mestra sincronizados).

   Limitação conhecida: os passos 3 e 4 não são atômicos (o Supabase
   via REST não nos dá uma transação client-side). Se a conexão cair
   no meio da re-criptografia, alguns itens podem ficar com a chave
   nova e outros com a antiga. Por isso o aviso na tela pedindo para
   não fechar a janela durante o processo — para um cofre pessoal
   isso é um risco aceitável, mas é bom saber que existe.
   ========================================================== */

async function reencryptAllItems(oldKey, newKey) {
  const { data: items, error } = await sb
    .from("vault_items")
    .select("id, encrypted_data, iv")
    .eq("user_id", VaultSession.userId);
  if (error) throw error;

  for (const row of items) {
    const plain = await CryptoUtil.decryptJSON(oldKey, row.encrypted_data, row.iv);
    const { ciphertext, iv } = await CryptoUtil.encryptJSON(newKey, plain);
    const { error: updateError } = await sb
      .from("vault_items")
      .update({ encrypted_data: ciphertext, iv })
      .eq("id", row.id)
      .eq("user_id", VaultSession.userId);
    if (updateError) throw updateError;
  }
  return items.length;
}

async function handleChangeMasterPassword(currentPassword, newPassword, newPasswordConfirm) {
  const errorEl = document.getElementById("change-master-error");
  errorEl.hidden = true;

  if (newPassword !== newPasswordConfirm) {
    errorEl.textContent = "As novas senhas não coincidem.";
    errorEl.hidden = false;
    return;
  }
  if (newPassword.length < 8) {
    errorEl.textContent = "A nova senha mestra precisa ter pelo menos 8 caracteres.";
    errorEl.hidden = false;
    return;
  }
  if (newPassword === currentPassword) {
    errorEl.textContent = "A nova senha precisa ser diferente da atual.";
    errorEl.hidden = false;
    return;
  }

  const saveBtn = document.getElementById("btn-save-change-master");
  saveBtn.disabled = true;
  try {
    const config = await AuthModule.fetchVaultConfig(VaultSession.userId);
    if (!config) throw new Error("Configuração do cofre não encontrada.");

    const oldKey = await AuthModule.unlockWithConfig(currentPassword, config);
    if (!oldKey) {
      errorEl.textContent = "Senha mestra atual incorreta.";
      errorEl.hidden = false;
      return;
    }

    const newSalt = CryptoUtil.generateSaltBase64();
    const iterations = window.APP_CONFIG.KDF_ITERATIONS;
    const newKey = await CryptoUtil.deriveKey(newPassword, newSalt, iterations);

    const count = await reencryptAllItems(oldKey, newKey);

    const { verifier, verifier_iv } = await CryptoUtil.createVerifier(newKey);
    const { error: configUpdateError } = await sb
      .from("vault_config")
      .update({ salt: newSalt, kdf_iterations: iterations, verifier, verifier_iv })
      .eq("user_id", VaultSession.userId);
    if (configUpdateError) throw configUpdateError;

    // mantém a senha de login do Supabase Auth sincronizada com a senha mestra
    const { error: authUpdateError } = await sb.auth.updateUser({ password: newPassword });
    if (authUpdateError) throw authUpdateError;

    VaultSession.key = newKey;
    closeChangeMasterModal();
    await refreshList();
    toast(`Senha mestra alterada. ${count} credencial(is) re-criptografada(s).`);
  } catch (err) {
    console.error(err);
    errorEl.textContent = "Erro ao alterar a senha mestra. Tente novamente.";
    errorEl.hidden = false;
  } finally {
    saveBtn.disabled = false;
  }
}

function openChangeMasterModal() {
  document.getElementById("change-master-form").reset();
  document.getElementById("change-master-error").hidden = true;
  document.getElementById("change-master-modal").hidden = false;
}

function closeChangeMasterModal() {
  document.getElementById("change-master-modal").hidden = true;
}

document.addEventListener("DOMContentLoaded", () => {
  const openBtn = document.getElementById("btn-change-master");
  const closeBtn = document.getElementById("change-master-close");
  const cancelBtn = document.getElementById("btn-cancel-change-master");
  const modal = document.getElementById("change-master-modal");
  const form = document.getElementById("change-master-form");

  if (!openBtn) return;

  openBtn.addEventListener("click", openChangeMasterModal);
  closeBtn.addEventListener("click", closeChangeMasterModal);
  cancelBtn.addEventListener("click", closeChangeMasterModal);
  modal.addEventListener("click", (e) => {
    if (e.target.id === "change-master-modal") closeChangeMasterModal();
  });

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const current = document.getElementById("current-master-password").value;
    const next = document.getElementById("new-master-password").value;
    const confirm = document.getElementById("new-master-password-confirm").value;
    handleChangeMasterPassword(current, next, confirm);
  });
});