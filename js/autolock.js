/* ==========================================================
   AUTO-LOCK MODULE
   ==========================================================
   "Bloquear" aqui significa de verdade apagar a chave AES da
   memória (VaultSession.key = null) e limpar a lista de
   credenciais já decifrada — não é só cobrir a tela com um
   overlay. Sem a chave, nada pode ser lido, mesmo inspecionando
   a página. A sessão do Supabase Auth continua válida, então
   desbloquear pede só a senha mestra, não e-mail de novo.
   ========================================================== */

const AutoLockModule = (() => {
  let timer = null;
  const minutes = (window.APP_CONFIG && window.APP_CONFIG.AUTO_LOCK_MINUTES) || 5;

  function resetTimer() {
    if (!window.VaultSession || !VaultSession.key) return; // já bloqueado
    clearTimeout(timer);
    timer = setTimeout(lock, minutes * 60 * 1000);
  }

  function lock() {
    if (!window.VaultSession || !VaultSession.key) return; // já bloqueado
    VaultSession.key = null;

    if (typeof allCredentials !== "undefined") {
      allCredentials = [];
    }
    const list = document.getElementById("credentials-list");
    if (list) list.innerHTML = "";

    showOverlay();
  }

  function showOverlay() {
    const overlay = document.getElementById("lock-overlay");
    if (overlay) overlay.hidden = false;
    clearTimeout(timer);
  }

  function hideOverlay() {
    const overlay = document.getElementById("lock-overlay");
    if (overlay) overlay.hidden = true;
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
      hideOverlay();
      resetTimer();
      await refreshList();
    } catch (err) {
      console.error(err);
      errorEl.textContent = "Erro ao desbloquear. Tente novamente.";
      errorEl.hidden = false;
    }
  }

  function init() {
    ["mousemove", "keydown", "click", "scroll", "touchstart"].forEach((evt) => {
      document.addEventListener(evt, resetTimer, { passive: true });
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
      window.location.href = "index.html";
    });
  }

  return { init, lock, resetTimer };
})();
window.AutoLockModule = AutoLockModule;

document.addEventListener("DOMContentLoaded", () => {
  if (!window.VaultSession || !VaultSession.key) return; // guardSession já deve redirecionar
  AutoLockModule.init();
});