/* ==========================================================
   CRYPTO UTIL
   ==========================================================
   Tudo aqui roda 100% no navegador via Web Crypto API.
   A senha mestra nunca é enviada a lugar nenhum — só entra
   como matéria-prima para derivar uma chave AES-256, que fica
   apenas na memória da aba enquanto o cofre está desbloqueado.

   Fluxo:
   1) deriveKey(senha, salt)  -> chave AES-GCM (não exportável)
   2) createVerifier(chave)   -> cifra uma string conhecida
                                  (guardada no Supabase para,
                                  no próximo login, confirmar
                                  que a senha digitada é a certa)
   3) encryptJSON / decryptJSON -> usados para cada credencial
   ========================================================== */

const CryptoUtil = (() => {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  // String fixa usada apenas para validar a senha mestra no login.
  // Não é segredo — o segredo é a chave, não este texto.
  const VERIFIER_PLAINTEXT = "COFRE_VERIFICADO_v1";

  function bufToBase64(buf) {
    const bytes = new Uint8Array(buf);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }

  function base64ToBuf(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  function generateSaltBase64() {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    return bufToBase64(salt);
  }

  function generateIvBase64() {
    // 12 bytes é o tamanho recomendado de IV para AES-GCM
    const iv = crypto.getRandomValues(new Uint8Array(12));
    return bufToBase64(iv);
  }

  async function deriveKey(masterPassword, saltBase64, iterations) {
    const saltBuf = base64ToBuf(saltBase64);
    const baseKey = await crypto.subtle.importKey(
      "raw",
      encoder.encode(masterPassword),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: saltBuf,
        iterations: iterations,
        hash: "SHA-256"
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false, // chave não-exportável: nem o próprio código consegue extrair os bytes dela
      ["encrypt", "decrypt"]
    );
  }

  async function encryptText(key, plaintext) {
    const ivBase64 = generateIvBase64();
    const ivBuf = base64ToBuf(ivBase64);
    const ciphertextBuf = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: ivBuf },
      key,
      encoder.encode(plaintext)
    );
    return { ciphertext: bufToBase64(ciphertextBuf), iv: ivBase64 };
  }

  async function decryptText(key, ciphertextBase64, ivBase64) {
    const ciphertextBuf = base64ToBuf(ciphertextBase64);
    const ivBuf = base64ToBuf(ivBase64);
    const plainBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ivBuf },
      key,
      ciphertextBuf
    );
    return decoder.decode(plainBuf);
  }

  async function encryptJSON(key, obj) {
    return encryptText(key, JSON.stringify(obj));
  }

  async function decryptJSON(key, ciphertextBase64, ivBase64) {
    const text = await decryptText(key, ciphertextBase64, ivBase64);
    return JSON.parse(text);
  }

  async function createVerifier(key) {
    const { ciphertext, iv } = await encryptText(key, VERIFIER_PLAINTEXT);
    return { verifier: ciphertext, verifier_iv: iv };
  }

  // Retorna true/false — nunca lança erro para quem chamou.
  async function checkVerifier(key, verifierBase64, verifierIvBase64) {
    try {
      const text = await decryptText(key, verifierBase64, verifierIvBase64);
      return text === VERIFIER_PLAINTEXT;
    } catch (err) {
      // AES-GCM falha na tag de autenticação quando a chave está errada
      return false;
    }
  }

  // Heurística simples só para feedback visual da barra de força.
  // Não é uma medição formal de entropia.
  function passwordStrengthScore(password) {
    let score = 0;
    if (password.length >= 8) score++;
    if (password.length >= 12) score++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
    if (/\d/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;
    return Math.min(score, 5);
  }

  return {
    generateSaltBase64,
    generateIvBase64,
    deriveKey,
    encryptText,
    decryptText,
    encryptJSON,
    decryptJSON,
    createVerifier,
    checkVerifier,
    passwordStrengthScore
  };
})();