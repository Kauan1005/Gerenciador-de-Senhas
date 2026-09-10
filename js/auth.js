/* ==========================================================
   AUTH MODULE
   ==========================================================
   Estado do cofre em memória (nunca em localStorage/cookie):
     VaultSession.key    -> CryptoKey AES-GCM derivada da senha mestra
     VaultSession.userId -> uuid do usuário no Supabase
     VaultSession.email  -> e-mail (só para exibir na UI)

   Regra de ouro: se a aba fechar ou der reload, a chave some.
   É assim mesmo — é o que garante que a senha mestra não fica
   "guardada" em lugar nenhum além da cabeça do usuário.
   ========================================================== */

const VaultSession = {
  key: null,
  userId: null,
  email: null,
  clear() {
    this.key = null;
    this.userId = null;
    this.email = null;
  }
};
window.VaultSession = VaultSession;

const AuthModule = (() => {
  function showError(elId, message) {
    const el = document.getElementById(elId);
    if (!el) return;
    el.textContent = message;
    el.hidden = false;
  }

  function hideError(elId) {
    const el = document.getElementById(elId);
    if (!el) return;
    el.hidden = true;
  }

  async function fetchVaultConfig(userId) {
    const { data, error } = await sb
      .from("vault_config")
      .select("salt, kdf_iterations, verifier, verifier_iv")
      .eq("user_id", userId)
      .maybeSingle();
    if (error) throw error;
    return data;
  }

  // Gera salt novo, deriva a chave e grava o verificador cifrado no Supabase.
  // Usado tanto no cadastro quanto no primeiro login após confirmação de e-mail.
  async function createVaultConfig(userId, masterPassword) {
    const salt = CryptoUtil.generateSaltBase64();
    const iterations = window.APP_CONFIG.KDF_ITERATIONS;
    const key = await CryptoUtil.deriveKey(masterPassword, salt, iterations);
    const { verifier, verifier_iv } = await CryptoUtil.createVerifier(key);

    const { error } = await sb.from("vault_config").insert({
      user_id: userId,
      salt,
      kdf_iterations: iterations,
      verifier,
      verifier_iv
    });
    if (error) throw error;
    return key;
  }

  async function unlockWithConfig(masterPassword, config) {
    const key = await CryptoUtil.deriveKey(
      masterPassword,
      config.salt,
      config.kdf_iterations
    );
    const ok = await CryptoUtil.checkVerifier(key, config.verifier, config.verifier_iv);
    return ok ? key : null;
  }

  function translateAuthError(err) {
    const msg = (err && err.message) || "";
    if (msg.includes("Invalid login credentials")) return "E-mail ou senha mestra incorretos.";
    if (msg.includes("User already registered")) return "Já existe um cofre com esse e-mail.";
    if (msg.includes("Password should be at least")) return "Senha mestra muito curta.";
    if (msg.includes("Email not confirmed")) return "Confirme seu e-mail antes de entrar.";
    return msg || "Não foi possível concluir a operação. Tente novamente.";
  }

  async function handleSignUp(email, password, passwordConfirm) {
    hideError("signup-error");

    if (password !== passwordConfirm) {
      showError("signup-error", "As senhas não coincidem.");
      return;
    }
    if (password.length < 8) {
      showError("signup-error", "A senha mestra precisa ter pelo menos 8 caracteres.");
      return;
    }

    const submitBtn = document.getElementById("signup-submit");
    submitBtn.disabled = true;
    try {
      const { data, error } = await sb.auth.signUp({
          email,
          password,
          options: {
          emailRedirectTo: window.location.origin + "/index.html"
          }
        });
      if (error) throw error;

      if (data.session && data.user) {
        // Confirmação de e-mail desativada no projeto: já há sessão, configura agora.
        const key = await createVaultConfig(data.user.id, password);
        VaultSession.key = key;
        VaultSession.userId = data.user.id;
        VaultSession.email = email;
        window.location.href = "vault.html";
      } else {
        showError(
          "signup-error",
          "Cofre criado! Confirme seu e-mail e depois volte aqui para entrar."
        );
      }
    } catch (err) {
      showError("signup-error", translateAuthError(err));
    } finally {
      submitBtn.disabled = false;
    }
  }

  async function handleLogin(email, password) {
    hideError("login-error");
    const submitBtn = document.getElementById("login-submit");
    submitBtn.disabled = true;
    try {
      const { data, error } = await sb.auth.signInWithPassword({ email, password });
      if (error) throw error;

      const userId = data.user.id;
      const config = await fetchVaultConfig(userId);

      let key;
      if (!config) {
        // Primeiro login após confirmar e-mail: finaliza a configuração do cofre agora.
        key = await createVaultConfig(userId, password);
      } else {
        key = await unlockWithConfig(password, config);
        if (!key) {
          await sb.auth.signOut();
          showError("login-error", "Senha mestra incorreta.");
          return;
        }
      }

      VaultSession.key = key;
      VaultSession.userId = userId;
      VaultSession.email = email;
      window.location.href = "vault.html";
    } catch (err) {
      showError("login-error", translateAuthError(err));
    } finally {
      submitBtn.disabled = false;
    }
  }

  return { handleSignUp, handleLogin, fetchVaultConfig, unlockWithConfig };
})();
window.AuthModule = AuthModule;

document.addEventListener("DOMContentLoaded", () => {
  const loginForm = document.getElementById("panel-login");
  const signupForm = document.getElementById("panel-signup");

  if (loginForm) {
    loginForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const email = document.getElementById("login-email").value.trim();
      const password = document.getElementById("login-password").value;
      AuthModule.handleLogin(email, password);
    });
  }

  if (signupForm) {
    signupForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const email = document.getElementById("signup-email").value.trim();
      const password = document.getElementById("signup-password").value;
      const passwordConfirm = document.getElementById("signup-password-confirm").value;
      AuthModule.handleSignUp(email, password, passwordConfirm);
    });
  }
});