/* ==========================================================
   CLIPBOARD MODULE
   ==========================================================
   Copia texto e agenda a limpeza automática da área de
   transferência depois de N segundos (configurável em
   config.js). Antes de limpar, confere se o conteúdo ainda é
   o mesmo que copiamos — assim não apagamos por engano algo
   que o usuário copiou de outro lugar nesse meio-tempo. Se o
   navegador não permitir ler a área de transferência, limpa
   mesmo assim: em dúvida, prefira errar para o lado seguro.
   ========================================================== */

const ClipboardModule = (() => {
  let timer = null;

  async function copy(value) {
    try {
      await navigator.clipboard.writeText(value);
    } catch (err) {
      console.error("Falha ao copiar para a área de transferência", err);
      return false;
    }

    if (timer) clearTimeout(timer);
    const seconds =
      (window.APP_CONFIG && window.APP_CONFIG.CLIPBOARD_CLEAR_SECONDS) || 20;
    timer = setTimeout(() => clearIfUnchanged(value), seconds * 1000);

    return true;
  }

  async function clearIfUnchanged(expectedValue) {
    try {
      const current = await navigator.clipboard.readText();
      if (current === expectedValue) {
        await navigator.clipboard.writeText("");
      }
    } catch (err) {
      // sem permissão para ler a área de transferência: limpa por precaução
      try {
        await navigator.clipboard.writeText("");
      } catch (_) {
        /* nada mais a fazer */
      }
    } finally {
      timer = null;
    }
  }

  return { copy };
})();
window.ClipboardModule = ClipboardModule;