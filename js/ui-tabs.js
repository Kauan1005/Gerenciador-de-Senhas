/* ==========================================================
   UI — TELA DE ACESSO
   Só interação visual. Nenhuma chamada ao Supabase aqui.
   ========================================================== */

document.addEventListener("DOMContentLoaded", () => {
  // ---- alternância de abas Entrar / Criar cofre ----
  const tabs = document.querySelectorAll(".tab");
  const panels = {
    "panel-login": document.getElementById("panel-login"),
    "panel-signup": document.getElementById("panel-signup")
  };

  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      tabs.forEach((t) => {
        t.classList.remove("is-active");
        t.setAttribute("aria-selected", "false");
      });
      tab.classList.add("is-active");
      tab.setAttribute("aria-selected", "true");

      Object.entries(panels).forEach(([id, panel]) => {
        if (!panel) return;
        const isTarget = id === tab.dataset.target;
        panel.hidden = !isTarget;
        panel.classList.toggle("is-active", isTarget);
      });
    });
  });

  // ---- mostrar/ocultar senha ----
  document.querySelectorAll(".field__toggle").forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetId = btn.dataset.toggleFor;
      const input = document.getElementById(targetId);
      if (!input) return;
      const isPassword = input.type === "password";
      input.type = isPassword ? "text" : "password";
      btn.setAttribute("aria-label", isPassword ? "Ocultar senha" : "Mostrar senha");
    });
  });

  // ---- barra de força da senha mestra (cadastro) ----
  const signupPassword = document.getElementById("signup-password");
  const strengthBar = document.getElementById("strength-bar");
  const strengthLabel = document.getElementById("strength-label");
  const labels = ["Muito fraca", "Fraca", "Razoável", "Boa", "Forte", "Muito forte"];
  const colors = ["var(--danger)", "var(--danger)", "var(--warn)", "var(--warn)", "var(--success)", "var(--success)"];

  if (signupPassword && strengthBar && strengthLabel) {
    signupPassword.addEventListener("input", () => {
      const value = signupPassword.value;
      if (!value) {
        strengthBar.style.width = "0%";
        strengthLabel.textContent = "\u00A0";
        return;
      }
      const score = CryptoUtil.passwordStrengthScore(value); // 0..5
      const pct = (score / 5) * 100;
      strengthBar.style.width = pct + "%";
      strengthBar.style.background = colors[score];
      strengthLabel.textContent = labels[score];
    });
  }
});