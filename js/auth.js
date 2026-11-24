/* ==========================================================
   AUTH MODULE
   ==========================================================
   Estado do cofre em memória (nunca em localStorage/cookie):
     VaultSession.key    -> CryptoKey AES-GCM derivada da senha mestra
     VaultSession.userId -> uuid do usuário no Supabase
     VaultSession.email  -> e-mail (só para exibir na UI)
     VaultSession.config -> linha de vault_config (sal, iterações...)

   Login v2: o que vai ao Supabase Auth NÃO é a senha mestra, e sim um
   segredo derivado dela (CryptoUtil.deriveAuthSecret). A senha mestra
   fica só no navegador.

   Contas antigas (v1) tinham a senha mestra como senha do Supabase.
   Enquanto APP_CONFIG.LEGACY_LOGIN for true, o login tenta o método
   novo e, se falhar, o antigo; ao entrar pelo antigo, a conta é
   migrada na hora para o novo. Depois que todas as contas migrarem,
   coloque LEGACY_LOGIN: false em config.js.
   ========================================================== */

const VaultSession = {
  key: null,
  userId: null,
  email: null,
  config: null,
  clear() {
    this.key = null;
    this.userId = null;
    this.email = null;
    this.config = null;
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
    if (el) el.hidden = true;
  }

  const isMissingColumn = (error) => !!error && (error.code === "42703" || /auth_version|does not exist/i.test(error.message || ""));

  async function fetchVaultConfig(userId) {
    let q = await sb
      .from("vault_config")
      .select("salt, kdf_iterations, verifier, verifier_iv, auth_version")
      .eq("user_id", userId)
      .maybeSingle();
    if (isMissingColumn(q.error)) {
      // banco ainda sem a coluna nova: segue com o formato antigo
      q = await sb.from("vault_config").select("salt, kdf_iterations, verifier, verifier_iv").eq("user_id", userId).maybeSingle();
    }
    if (q.error) throw q.error;
    return q.data;
  }

  // Gera sal novo, deriva a chave e grava o verificador cifrado no Supabase.
  async function createVaultConfig(userId, masterPassword) {
    const salt = CryptoUtil.generateSaltBase64();
    const iterations = window.APP_CONFIG.KDF_ITERATIONS || CryptoUtil.DEFAULT_KDF_ITERATIONS;
    const key = await CryptoUtil.deriveKey(masterPassword, salt, iterations);
    const { verifier, verifier_iv } = await CryptoUtil.createVerifier(key);
    const row = { user_id: userId, salt, kdf_iterations: iterations, verifier, verifier_iv, auth_version: 2 };
    let { error } = await sb.from("vault_config").insert(row);
    if (isMissingColumn(error)) {
      delete row.auth_version;
      ({ error } = await sb.from("vault_config").insert(row));
    }
    if (error) throw error;
    return { key, config: { salt, kdf_iterations: iterations, verifier, verifier_iv, auth_version: 2 } };
  }

  async function unlockWithConfig(masterPassword, config) {
    const key = await CryptoUtil.deriveKey(masterPassword, config.salt, config.kdf_iterations);
    const ok = await CryptoUtil.checkVerifier(key, config.verifier, config.verifier_iv);
    return ok ? key : null;
  }

  // O cofre foi criado com menos iterações do que o padrão atual?
  function needsKdfUpgrade(config) {
    const target = window.APP_CONFIG.KDF_ITERATIONS || CryptoUtil.DEFAULT_KDF_ITERATIONS;
    return !!config && config.kdf_iterations < target;
  }

  function translateAuthError(err) {
    const msg = (err && err.message) || "";
    if (msg.includes("Invalid login credentials")) return "E-mail ou senha mestra incorretos.";
    if (msg.includes("User already registered")) return "Já existe um cofre com esse e-mail.";
    if (msg.includes("Password should be at least")) return "Senha mestra muito curta.";
    if (msg.includes("Email not confirmed")) return "Confirme seu e-mail antes de entrar.";
    if (/rate limit|too many/i.test(msg)) return "Muitas tentativas. Aguarde um pouco e tente de novo.";
    if (/signups? (not allowed|disabled)/i.test(msg)) return "A criação de novos cofres está desativada neste site.";
    return msg || "Não foi possível concluir a operação. Tente novamente.";
  }

  /* ---------- freio contra tentativas em sequência (no navegador) ---------- */

  const attempts = { count: 0, until: 0 };
  function throttleWait() {
    const left = Math.ceil((attempts.until - Date.now()) / 1000);
    return left > 0 ? left : 0;
  }
  function registerFailure() {
    attempts.count += 1;
    if (attempts.count >= 3) attempts.until = Date.now() + Math.min(60, 2 ** (attempts.count - 2)) * 1000;
  }
  function registerSuccess() {
    attempts.count = 0;
    attempts.until = 0;
  }

  /* ---------- cadastro ---------- */

  async function handleSignUp(email, password, passwordConfirm) {
    hideError("signup-error");

    if (password !== passwordConfirm) {
      showError("signup-error", "As senhas não coincidem.");
      return;
    }
    const minLen = window.APP_CONFIG.MIN_MASTER_LENGTH || CryptoUtil.MIN_MASTER_LENGTH;
    const problem = CryptoUtil.masterPasswordProblem(password, minLen);
    if (problem) {
      showError("signup-error", problem);
      return;
    }

    const submitBtn = document.getElementById("signup-submit");
    submitBtn.disabled = true;
    try {
      const secret = await CryptoUtil.deriveAuthSecret(password, email);
      const { data, error } = await sb.auth.signUp({
        email,
        password: secret,
        options: { emailRedirectTo: window.location.origin + "/index.html" }
      });
      if (error) throw error;

      if (data.session && data.user) {
        // Confirmação de e-mail desativada no projeto: já há sessão, configura agora.
        const { key, config } = await createVaultConfig(data.user.id, password);
        VaultSession.key = key;
        VaultSession.config = config;
        VaultSession.userId = data.user.id;
        VaultSession.email = email;
        await handoffPut();
        window.location.href = "vault.html";
      } else {
        showError("signup-error", "Cofre criado! Confirme seu e-mail e depois volte aqui para entrar.");
      }
    } catch (err) {
      showError("signup-error", translateAuthError(err));
    } finally {
      submitBtn.disabled = false;
    }
  }

  /* ---------- login ---------- */

  const isBadCredentials = (error) => !!error && /Invalid login credentials/i.test(error.message || "");

  async function handleLogin(email, password) {
    hideError("login-error");

    const wait = throttleWait();
    if (wait) {
      showError("login-error", `Muitas tentativas seguidas. Aguarde ${wait}s para tentar de novo.`);
      return;
    }

    const submitBtn = document.getElementById("login-submit");
    submitBtn.disabled = true;
    try {
      const secret = await CryptoUtil.deriveAuthSecret(password, email);
      let { data, error } = await sb.auth.signInWithPassword({ email, password: secret });

      let legacy = false;
      if (isBadCredentials(error) && window.APP_CONFIG.LEGACY_LOGIN !== false) {
        // conta antiga: a senha do Supabase ainda é a própria senha mestra
        ({ data, error } = await sb.auth.signInWithPassword({ email, password }));
        legacy = !error;
      }
      if (error) throw error;

      const userId = data.user.id;
      const config = await fetchVaultConfig(userId);

      let key;
      let usedConfig = config;
      if (!config) {
        // Primeiro login após confirmar e-mail: finaliza a configuração do cofre agora.
        ({ key, config: usedConfig } = await createVaultConfig(userId, password));
      } else {
        key = await unlockWithConfig(password, config);
        if (!key) {
          await sb.auth.signOut();
          registerFailure();
          showError("login-error", "Senha mestra incorreta.");
          return;
        }
      }

      if (legacy) await migrateLegacyLogin(userId, secret);

      registerSuccess();
      VaultSession.key = key;
      VaultSession.config = usedConfig;
      VaultSession.userId = userId;
      VaultSession.email = email;
      await handoffPut();
        window.location.href = "vault.html";
    } catch (err) {
      registerFailure();
      showError("login-error", translateAuthError(err));
    } finally {
      submitBtn.disabled = false;
    }
  }

  // Troca a senha do Supabase (que era a senha mestra) pelo segredo derivado.
  // Se falhar, nada se perde: o login antigo continua valendo e a migração tenta de novo no próximo.
  async function migrateLegacyLogin(userId, secret) {
    try {
      const { error } = await sb.auth.updateUser({ password: secret });
      if (error) throw error;
      const { error: cfgError } = await sb.from("vault_config").update({ auth_version: 2 }).eq("user_id", userId);
      if (cfgError && !isMissingColumn(cfgError)) throw cfgError;
      sessionStorage.setItem("cofre-migrated", "1");
    } catch (err) {
      console.warn("[Cofre] Migração do login para o método novo adiada:", err && err.message);
    }
  }

  return { handleSignUp, handleLogin, fetchVaultConfig, unlockWithConfig, needsKdfUpgrade, createVaultConfig };
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
