/* ==========================================================
   THEME MODULE
   ==========================================================
   Aplica o tema salvo ANTES do body renderizar (evita "flash"
   do tema errado ao carregar a página) e liga qualquer botão
   marcado com [data-theme-toggle] para trocar entre claro/escuro.
   Preferência salva em localStorage (não é dado sensível).
   ========================================================== */

(function applyStoredTheme() {
  const stored = localStorage.getItem("cofre-theme");
  const theme = stored === "light" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", theme);
})();

document.addEventListener("DOMContentLoaded", () => {
  function updateLabel(btn) {
    const current = document.documentElement.getAttribute("data-theme") || "dark";
    btn.textContent = current === "dark" ? "Tema claro" : "Tema escuro";
  }

  const toggles = document.querySelectorAll("[data-theme-toggle]");
  toggles.forEach((btn) => {
    updateLabel(btn);
    btn.addEventListener("click", () => {
      const current = document.documentElement.getAttribute("data-theme") || "dark";
      const next = current === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      localStorage.setItem("cofre-theme", next);
      toggles.forEach(updateLabel);
    });
  });
});