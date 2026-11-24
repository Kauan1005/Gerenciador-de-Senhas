/* ==========================================================
   CRYPTO UTIL
   ==========================================================
   Tudo aqui roda 100% no navegador via Web Crypto API.
   A senha mestra nunca é enviada a lugar nenhum: dela saem DUAS
   coisas independentes, derivadas com sais diferentes:

     1) chave de cifra (AES-256-GCM, não exportável) = PBKDF2(senha, sal do cofre)
        -> cifra credenciais e projetos. Fica só na memória da aba.
     2) segredo de login = PBKDF2(senha, sal fixo do e-mail)
        -> é ISTO que vai ao Supabase Auth no lugar da senha.

   Assim o servidor nunca recebe a senha mestra (versão antiga do app
   enviava a própria senha ao fazer login).

   Formato dos dados cifrados:
     versão 1: AES-GCM sem dados associados (AAD)  [contas antigas]
     versão 2: AES-GCM com AAD = "cofre/v2|<usuário>|<tipo>|<id>"
               -> um blob não pode ser trocado de lugar (outro registro
                  ou outro usuário) sem a decifragem falhar.
   ========================================================== */

const CryptoUtil = (() => {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  // String fixa usada apenas para validar a senha mestra no login.
  const VERIFIER_PLAINTEXT = "COFRE_VERIFICADO_v1";

  // Piso de iterações aceito vindo do servidor: impede que um servidor
  // comprometido "enfraqueça" a derivação devolvendo um número pequeno.
  const MIN_KDF_ITERATIONS = 100000;
  const DEFAULT_KDF_ITERATIONS = 600000;
  const MIN_MASTER_LENGTH = 12;

  const FILE_MAGIC = [0x43, 0x46, 0x52, 0x31]; // "CFR1"
  const FILE_HEADER_BYTES = 16;
  const FILE_CHUNK_BYTES = 1024 * 1024; // 1 MiB de texto claro por bloco
  const GCM_TAG_BYTES = 16;

  /* ---------- base64 ---------- */

  function bufToBase64(buf) {
    const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let binary = "";
    const step = 0x8000;
    for (let i = 0; i < bytes.byteLength; i += step) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + step));
    }
    return btoa(binary);
  }

  function base64ToBuf(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  function generateSaltBase64() {
    return bufToBase64(crypto.getRandomValues(new Uint8Array(16)));
  }

  function generateIvBase64() {
    // 12 bytes é o tamanho recomendado de IV para AES-GCM
    return bufToBase64(crypto.getRandomValues(new Uint8Array(12)));
  }

  function newId() {
    return crypto.randomUUID();
  }

  /* ---------- derivação ---------- */

  function assertIterations(iterations) {
    if (!Number.isInteger(iterations) || iterations < MIN_KDF_ITERATIONS) {
      throw new Error("Configuração do cofre com custo de derivação inseguro.");
    }
  }

  async function pbkdf2Base(masterPassword) {
    return crypto.subtle.importKey("raw", encoder.encode(masterPassword), { name: "PBKDF2" }, false, [
      "deriveKey",
      "deriveBits"
    ]);
  }

  // Chave de cifra do cofre (AES-GCM 256, não exportável).
  async function deriveKey(masterPassword, saltBase64, iterations) {
    assertIterations(iterations);
    const baseKey = await pbkdf2Base(masterPassword);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: base64ToBuf(saltBase64), iterations, hash: "SHA-256" },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false, // nem o próprio código consegue extrair os bytes da chave
      ["encrypt", "decrypt"]
    );
  }

  // Segredo de login (vai ao Supabase Auth no lugar da senha mestra).
  // O sal é público e determinístico (derivado do e-mail) porque precisa existir
  // ANTES do login; ele só separa este segredo da chave de cifra do cofre.
  async function deriveAuthSecret(masterPassword, email, iterations = DEFAULT_KDF_ITERATIONS) {
    assertIterations(iterations);
    const normalized = String(email || "").trim().toLowerCase();
    const salt = await crypto.subtle.digest("SHA-256", encoder.encode("cofre/auth/v2|" + normalized));
    const baseKey = await pbkdf2Base(masterPassword);
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
      baseKey,
      256
    );
    return bufToBase64(bits);
  }

  /* ---------- AES-GCM ---------- */

  // AAD da versão 2. kind: "item" | "project" | "verifier".
  function aadFor(version, userId, kind, id) {
    if (version < 2) return undefined;
    return encoder.encode(`cofre/v2|${userId}|${kind}|${id || ""}`);
  }

  async function encryptText(key, plaintext, aad) {
    const ivBase64 = generateIvBase64();
    const params = { name: "AES-GCM", iv: base64ToBuf(ivBase64) };
    if (aad) params.additionalData = aad;
    const ciphertextBuf = await crypto.subtle.encrypt(params, key, encoder.encode(plaintext));
    return { ciphertext: bufToBase64(ciphertextBuf), iv: ivBase64 };
  }

  async function decryptText(key, ciphertextBase64, ivBase64, aad) {
    const params = { name: "AES-GCM", iv: base64ToBuf(ivBase64) };
    if (aad) params.additionalData = aad;
    const plainBuf = await crypto.subtle.decrypt(params, key, base64ToBuf(ciphertextBase64));
    return decoder.decode(plainBuf);
  }

  async function encryptJSON(key, obj, aad) {
    return encryptText(key, JSON.stringify(obj), aad);
  }

  async function decryptJSON(key, ciphertextBase64, ivBase64, aad) {
    return JSON.parse(await decryptText(key, ciphertextBase64, ivBase64, aad));
  }

  async function createVerifier(key) {
    const { ciphertext, iv } = await encryptText(key, VERIFIER_PLAINTEXT);
    return { verifier: ciphertext, verifier_iv: iv };
  }

  // Retorna true/false: nunca lança erro para quem chamou.
  async function checkVerifier(key, verifierBase64, verifierIvBase64) {
    try {
      return (await decryptText(key, verifierBase64, verifierIvBase64)) === VERIFIER_PLAINTEXT;
    } catch (err) {
      return false; // a tag de autenticação falha quando a chave está errada
    }
  }

  /* ---------- arquivos (projetos instaláveis) ---------- */

  // Cada arquivo tem a sua própria chave (FEK). A FEK fica DENTRO do registro cifrado
  // do projeto: trocar a senha mestra só re-cifra o registro, nunca os arquivos.
  async function generateFileKey() {
    const raw = crypto.getRandomValues(new Uint8Array(32));
    return bufToBase64(raw);
  }

  async function importFileKey(rawBase64) {
    return crypto.subtle.importKey("raw", base64ToBuf(rawBase64), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  }

  function chunkIv(prefix, index) {
    const iv = new Uint8Array(12);
    iv.set(prefix, 0);
    new DataView(iv.buffer).setBigUint64(4, BigInt(index), false);
    return iv;
  }

  function chunkAad(aadBase, index, isLast) {
    return encoder.encode(`${aadBase}|${index}|${isLast ? 1 : 0}`);
  }

  /**
   * Cifra um Blob/File em blocos de 1 MiB (AES-256-GCM, IV por bloco, AAD com posição e "último bloco":
   * reordenar, repetir ou truncar blocos faz a decifragem falhar). Devolve { blob, sha256, size }.
   * aadBase identifica o arquivo (ex.: "cofre/v2|<usuário>|file|<projeto>/<arquivo>").
   */
  async function encryptFile(file, fileKey, aadBase, onProgress) {
    const prefix = crypto.getRandomValues(new Uint8Array(4));
    const header = new Uint8Array(FILE_HEADER_BYTES);
    header.set(FILE_MAGIC, 0);
    new DataView(header.buffer).setUint32(4, FILE_CHUNK_BYTES, false);
    header.set(prefix, 8);

    const parts = [header];
    const hash = [];
    const total = file.size;
    const chunks = Math.max(1, Math.ceil(total / FILE_CHUNK_BYTES));
    for (let i = 0; i < chunks; i++) {
      const plain = await file.slice(i * FILE_CHUNK_BYTES, Math.min(total, (i + 1) * FILE_CHUNK_BYTES)).arrayBuffer();
      hash.push(plain);
      const ct = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: chunkIv(prefix, i), additionalData: chunkAad(aadBase, i, i === chunks - 1) },
        fileKey,
        plain
      );
      parts.push(new Uint8Array(ct));
      if (onProgress) onProgress((i + 1) / chunks);
    }
    return { blob: new Blob(parts, { type: "application/octet-stream" }), sha256: await sha256Hex(new Blob(hash)), size: total };
  }

  /** Decifra o que encryptFile gerou. Lança erro se qualquer bloco foi alterado, reordenado ou cortado. */
  async function decryptFile(encBlob, fileKey, aadBase, mimeType, onProgress) {
    const head = new Uint8Array(await encBlob.slice(0, FILE_HEADER_BYTES).arrayBuffer());
    if (head.length < FILE_HEADER_BYTES || FILE_MAGIC.some((b, i) => head[i] !== b)) {
      throw new Error("Arquivo cifrado inválido.");
    }
    const chunkSize = new DataView(head.buffer).getUint32(4, false);
    if (chunkSize < 1024 || chunkSize > 16 * 1024 * 1024) throw new Error("Arquivo cifrado inválido.");
    const prefix = head.slice(8, 12);
    const body = encBlob.size - FILE_HEADER_BYTES;
    const step = chunkSize + GCM_TAG_BYTES;
    const chunks = Math.max(1, Math.ceil(body / step));
    const out = [];
    for (let i = 0; i < chunks; i++) {
      const start = FILE_HEADER_BYTES + i * step;
      const ct = await encBlob.slice(start, Math.min(encBlob.size, start + step)).arrayBuffer();
      const plain = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: chunkIv(prefix, i), additionalData: chunkAad(aadBase, i, i === chunks - 1) },
        fileKey,
        ct
      );
      out.push(new Uint8Array(plain));
      if (onProgress) onProgress((i + 1) / chunks);
    }
    return new Blob(out, { type: mimeType || "application/octet-stream" });
  }

  async function sha256Hex(blobOrBuf) {
    const buf = blobOrBuf instanceof Blob ? await blobOrBuf.arrayBuffer() : blobOrBuf;
    const d = new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
    return Array.from(d, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  /* ---------- senha mestra ---------- */

  const COMMON = ["123456789012", "senha1234567", "password1234", "qwertyuiop12", "administrador", "1q2w3e4r5t6y", "abcdefghijkl"];

  // Heurística só para a barra de força; não é medição formal de entropia.
  function passwordStrengthScore(password) {
    let score = 0;
    if (password.length >= 12) score++;
    if (password.length >= 16) score++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
    if (/\d/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;
    if (new Set(password).size < Math.min(6, password.length)) score = Math.min(score, 1);
    return Math.min(score, 5);
  }

  // Devolve o motivo (texto) se a senha mestra não serve, ou null se serve.
  function masterPasswordProblem(password, minLength = MIN_MASTER_LENGTH) {
    if (password.length < minLength) return `A senha mestra precisa ter pelo menos ${minLength} caracteres.`;
    if (new Set(password).size < 5) return "A senha mestra é repetitiva demais. Misture mais caracteres.";
    if (COMMON.includes(password.toLowerCase())) return "Essa senha é conhecida demais. Escolha outra.";
    return null;
  }

  const api = {
    MIN_KDF_ITERATIONS,
    DEFAULT_KDF_ITERATIONS,
    MIN_MASTER_LENGTH,
    FILE_CHUNK_BYTES,
    bufToBase64,
    base64ToBuf,
    generateSaltBase64,
    generateIvBase64,
    newId,
    deriveKey,
    deriveAuthSecret,
    aadFor,
    encryptText,
    decryptText,
    encryptJSON,
    decryptJSON,
    createVerifier,
    checkVerifier,
    generateFileKey,
    importFileKey,
    encryptFile,
    decryptFile,
    sha256Hex,
    passwordStrengthScore,
    masterPasswordProblem
  };

  if (typeof module !== "undefined" && module.exports) module.exports = api; // testes em Node
  return api;
})();
