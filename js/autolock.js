/* ==========================================================
   AUTO-LOCK MODULE
   ==========================================================
   "Bloquear" aqui significa de verdade apagar a chave AES da
   memória (VaultSession.key = null) e avisar as páginas
   (evento "vault:locked") para limparem o que já estava decifrado.
   Não é só cobrir a tela com um overlay: sem a chave, nada pode
   ser lido, mesmo inspecionando a página. A sessão do Supabase
   continua válida, então desbloquear pede só a senha mestra.

   IMPORTANTE: init() precisa ser chamado DEPOIS de guardSession()
   (a chave só existe depois dela). Na versão anterior o init era
   tentado cedo demais e o bloqueio por inatividade nunca chegava
   a ser ligado.
   ========================================================== */

const AutoLockModule = (() => {
  let timer = null;
  let started = false;
  const minutes = () => (window.APP_CONFIG && window.APP_CONFIG.AUTO_LOCK_MINUTES) || 180;
  let lastResume = 0;

  function resetTimer() {
    if (!window.VaultSession || !VaultSession.key) return; // já bloqueado
    clearTimeout(timer);
    timer = setTimeout(lock, minutes() * 60 * 1000);
    // renova a validade da chave guardada para o F5 (no máximo 1 vez por minuto)
    if (Date.now() - lastResume > 60000 && typeof resumePut === "function") {
      lastResume = Date.now();
      resumePut();
    }
  }

  function lock() {
    if (!window.VaultSession || !VaultSession.key) return; // já bloqueado
    VaultSession.key = null;
    clearTimeout(timer);
    document.dispatchEvent(new CustomEvent("vault:locked"));
    const overlay = document.getElementById("lock-overlay");
    if (overlay) overlay.hidden = false;
    document.getElementById("unlock-password")?.focus();
  }

  async function unlock(password) {
    const errorEl = document.getElementById("unlock-error");
    errorEl.hidden = true;
    try {
      const config = await AuthModule.fetchVaultConfig(VaultSession.userId);
      if (!config) throw new Error("Configuração do cofre não encontrada.");

      const key = await AuthModule.unlockWithConfig(password, config);
      if (!key) {
        errorEl.textContent = "Senha mestra incorreta.";
        errorEl.hidden = false;
        return;
      }

      VaultSession.key = key;
      VaultSession.config = config;
      lastResume = 0;
      document.getElementById("lock-overlay").hidden = true;
      resetTimer();
      document.dispatchEvent(new CustomEvent("vault:unlocked"));
    } catch (err) {
      console.error(err);
      errorEl.textContent = "Erro ao desbloquear. Tente novamente.";
      errorEl.hidden = false;
    }
  }

  function init() {
    if (started) return;
    started = true;

    ["mousemove", "keydown", "click", "scroll", "touchstart"].forEach((evt) => {
      document.addEventListener(evt, resetTimer, { passive: true });
    });
    // aba escondida por muito tempo também bloqueia ao voltar
    let hiddenAt = 0;
    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState === "hidden") hiddenAt = Date.now();
      else if (hiddenAt && Date.now() - hiddenAt > minutes() * 60 * 1000) lock();
    });
    resetTimer();

    document.getElementById("btn-lock-now")?.addEventListener("click", lock);

    const unlockForm = document.getElementById("unlock-form");
    if (unlockForm) {
      unlockForm.addEventListener("submit", (e) => {
        e.preventDefault();
        const passwordInput = document.getElementById("unlock-password");
        unlock(passwordInput.value).then(() => {
          passwordInput.value = "";
        });
      });
    }

    document.getElementById("btn-unlock-logout")?.addEventListener("click", async () => {
      await sb.auth.signOut();
      VaultSession.clear();
      if (typeof resumeClear === "function") await resumeClear();
      window.location.href = "index.html";
    });
  }

  return { init, lock, resetTimer };
})();
window.AutoLockModule = AutoLockModule;

// A lista de credenciais decifradas some da memória e da tela quando o cofre bloqueia.
document.addEventListener("vault:locked", () => {
  if (typeof allCredentials !== "undefined") allCredentials = [];
  document.getElementById("credentials-list")?.replaceChildren();
});
document.addEventListener("vault:unlocked", () => {
  if (typeof refreshList === "function") refreshList().catch(console.error);
});
