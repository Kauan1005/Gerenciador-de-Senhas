/* ==========================================================
   RECOVERY: recovery.html
   ==========================================================
   Chega aqui quem clicou no link de redefinição enviado por e-mail
   (sb.auth.resetPasswordForEmail): o Supabase já autenticou a pessoa
   como dona do e-mail. Falta provar que ela TAMBÉM tem a chave de
   recuperação, que desembrulha a DEK (chave real do cofre). A mesma DEK
   é então embrulhada com a nova senha mestra: nenhum registro é re-cifrado.
   O segredo de login passa a ser o derivado da nova senha (nunca a senha).
   ========================================================== */

document.addEventListener("DOMContentLoaded", async () => {
  const form = document.getElementById("recovery-form");
  const noSessionEl = document.getElementById("recovery-no-session");
  const errorEl = document.getElementById("recovery-error");
  const fail = (msg) => {
    errorEl.textContent = msg;
    errorEl.hidden = false;
  };

  // o Supabase lê o token da URL (detectSessionInUrl): espera a sessão aparecer
  let session = null;
  for (let i = 0; i < 20 && !session; i++) {
    ({ data: { session } } = await sb.auth.getSession());
    if (!session) await new Promise((r) => setTimeout(r, 150));
  }
  if (!session) {
    noSessionEl.hidden = false;
    form.hidden = true;
    return;
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    errorEl.hidden = true;

    const code = document.getElementById("recovery-code-input").value.trim();
    const newPassword = document.getElementById("recovery-new-password").value;
    const newPasswordConfirm = document.getElementById("recovery-new-password-confirm").value;

    if (newPassword !== newPasswordConfirm) return fail("As senhas não coincidem.");
    const problem = CryptoUtil.masterPasswordProblem(newPassword, window.APP_CONFIG.MIN_MASTER_LENGTH || CryptoUtil.MIN_MASTER_LENGTH);
    if (problem) return fail(problem);

    const submitBtn = document.getElementById("recovery-submit");
    submitBtn.disabled = true;
    try {
      const userId = session.user.id;
      const config = await AuthModule.fetchVaultConfig(userId);
      if (!config || !config.recovery_wrapped_dek) return fail("Este cofre não tem uma chave de recuperação configurada.");

      const recoveryKeyBytes = CryptoUtil.recoveryCodeToKeyBytes(code);
      if (!recoveryKeyBytes) return fail("Chave de recuperação em formato inválido.");

      const recoveryKek = await CryptoUtil.importRawAesKey(recoveryKeyBytes, false);
      const dekBuf = await CryptoUtil.unwrapBytes(recoveryKek, config.recovery_wrapped_dek, config.recovery_wrapped_dek_iv);
      if (!dekBuf) return fail("Chave de recuperação incorreta.");

      // embrulha a MESMA DEK com a KEK da nova senha mestra
      const newSalt = CryptoUtil.generateSaltBase64();
      const iterations = window.APP_CONFIG.KDF_ITERATIONS || CryptoUtil.DEFAULT_KDF_ITERATIONS;
      const newKek = await CryptoUtil.deriveKey(newPassword, newSalt, iterations);
      const { wrapped, iv } = await CryptoUtil.wrapBytes(newKek, dekBuf);

      // segredo de login derivado da nova senha (o servidor nunca recebe a senha)
      const secret = await CryptoUtil.deriveAuthSecret(newPassword, session.user.email);
      const { error: authError } = await sb.auth.updateUser({ password: secret });
      if (authError) throw authError;

      const patch = { salt: newSalt, kdf_iterations: iterations, wrapped_dek: wrapped, wrapped_dek_iv: iv, auth_version: 2 };
      let { error: updateError } = await sb.from("vault_config").update(patch).eq("user_id", userId);
      if (updateError && /auth_version|42703/.test(updateError.code + updateError.message)) {
        delete patch.auth_version;
        ({ error: updateError } = await sb.from("vault_config").update(patch).eq("user_id", userId));
      }
      if (updateError) throw updateError;

      VaultSession.key = await CryptoUtil.importRawAesKey(dekBuf, false);
      VaultSession.userId = userId;
      VaultSession.email = session.user.email;
      VaultSession.config = { ...config, ...patch };
      await handoffPut();
      window.location.href = "vault.html";
    } catch (err) {
      console.error(err);
      fail("Erro ao recuperar o cofre. Tente novamente.");
    } finally {
      submitBtn.disabled = false;
    }
  });
});
