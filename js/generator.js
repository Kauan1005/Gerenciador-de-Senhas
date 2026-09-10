/* ==========================================================
   GENERATOR MODULE
   ==========================================================
   Gera senhas aleatórias usando crypto.getRandomValues (nunca
   Math.random, que não é seguro para isso). Usa rejeição de
   amostragem para evitar viés de módulo.
   ========================================================== */

function secureRandomInt(maxExclusive) {
  const range = 256 - (256 % maxExclusive);
  let byte;
  do {
    byte = crypto.getRandomValues(new Uint8Array(1))[0];
  } while (byte >= range);
  return byte % maxExclusive;
}

function generateSecurePassword(options) {
  const pools = [];
  if (options.upper) pools.push("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
  if (options.lower) pools.push("abcdefghijklmnopqrstuvwxyz");
  if (options.numbers) pools.push("0123456789");
  if (options.symbols) pools.push("!@#$%^&*()-_=+[]{};:,.<>/?");

  if (pools.length === 0) {
    // nunca gera com pool vazia — cai para um padrão mínimo seguro
    pools.push("abcdefghijklmnopqrstuvwxyz0123456789");
  }

  const allChars = pools.join("");
  const length = Math.max(8, Math.min(64, options.length || 16));

  const chars = [];
  // garante ao menos 1 caractere de cada categoria marcada
  for (const pool of pools) {
    chars.push(pool[secureRandomInt(pool.length)]);
  }
  while (chars.length < length) {
    chars.push(allChars[secureRandomInt(allChars.length)]);
  }

  // embaralha (Fisher-Yates com fonte segura)
  for (let i = chars.length - 1; i > 0; i--) {
    const j = secureRandomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }

  return chars.slice(0, length).join("");
}

document.addEventListener("DOMContentLoaded", () => {
  const lengthInput = document.getElementById("generator-length");
  const lengthValue = document.getElementById("generator-length-value");
  const toggleBtn = document.getElementById("btn-toggle-generator-options");
  const optionsPanel = document.getElementById("generator-options");
  const generateBtn = document.getElementById("btn-generate-password");
  const copyBtn = document.getElementById("btn-copy-generated");
  const passwordInput = document.getElementById("cred-password");

  if (!generateBtn || !passwordInput) return; // página sem o modal de credencial

  lengthInput.addEventListener("input", () => {
    lengthValue.textContent = lengthInput.value;
  });

  toggleBtn.addEventListener("click", () => {
    const isHidden = optionsPanel.hidden;
    optionsPanel.hidden = !isHidden;
    toggleBtn.setAttribute("aria-expanded", String(isHidden));
  });

  generateBtn.addEventListener("click", () => {
    const options = {
      length: parseInt(lengthInput.value, 10),
      upper: document.getElementById("generator-upper").checked,
      lower: document.getElementById("generator-lower").checked,
      numbers: document.getElementById("generator-numbers").checked,
      symbols: document.getElementById("generator-symbols").checked
    };
    passwordInput.type = "text";
    passwordInput.value = generateSecurePassword(options);
  });

  copyBtn.addEventListener("click", () => {
    if (!passwordInput.value) return;
    const seconds = (window.APP_CONFIG && window.APP_CONFIG.CLIPBOARD_CLEAR_SECONDS) || 20;
    ClipboardModule.copy(passwordInput.value).then((ok) => {
      toast(ok ? `Senha copiada. Será limpa em ${seconds}s.` : "Não foi possível copiar.");
    });
  });
});