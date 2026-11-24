/* ==========================================================
   GOOGLE DRIVE: os arquivos de projeto ficam no Drive de CADA pessoa
   ==========================================================
   Cada usuário conecta a PRÓPRIA conta Google e os arquivos cifrados vão
   para o Drive dele (a cota gratuita é dele, ~15 GB, e não do projeto).

   - Escopo: só "drive.file" = o app enxerga APENAS os arquivos que ele
     mesmo criou. Não consegue listar nem ler o resto do Drive.
   - Os arquivos já chegam cifrados (AES-256-GCM, files.js) e com nome
     aleatório (<uuid>.arca) dentro da pasta "Arca (arquivos cifrados)":
     o Google só vê blobs ilegíveis.
   - Login: abre a janela de consentimento do Google (OAuth 2.0 para
     aplicações de navegador) SEM carregar nenhum script do Google no
     site. O token (validade ~1 h) fica só na memória: bloquear o cofre,
     sair ou fechar a aba o descarta. "Desconectar" também o revoga.
   - O token é conferido (aud = o seu Client ID, escopo, validade) antes
     de ser aceito, e a resposta só vale se o "state" bater.

   Se um dia o Google desativar este fluxo, só este arquivo precisa ser
   trocado (por exemplo, pelo Google Identity Services).
   ========================================================== */

const GoogleDrive = (() => {
  const SCOPE = "https://www.googleapis.com/auth/drive.file";
  const FOLDER_NAME = "Arca (arquivos cifrados)";
  const CHANNEL = "arca-google";
  const HINT_KEY = "arca-google-hint";
  const API = "https://www.googleapis.com/drive/v3";
  const UPLOAD = "https://www.googleapis.com/upload/drive/v3/files";

  let token = null;
  let expiresAt = 0;
  let account = null; // { email, name, free, limit }
  let folderId = null;

  const clientId = () => (window.APP_CONFIG && window.APP_CONFIG.GOOGLE_CLIENT_ID) || "";
  const enabled = () => !!clientId();
  const connected = () => !!token && Date.now() < expiresAt - 30000;
  const getAccount = () => (connected() ? account : null);
  const hint = () => { try { return localStorage.getItem(HINT_KEY) || ""; } catch { return ""; } };

  function clear() {
    token = null;
    expiresAt = 0;
    account = null;
    folderId = null;
  }

  const randomState = () => {
    const b = crypto.getRandomValues(new Uint8Array(16));
    return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  };

  /* ---------- conectar ---------- */

  // Abre a janela do Google e espera o token chegar pelo BroadcastChannel (a página de retorno é do próprio site).
  // Precisa ser chamado por um clique (senão o navegador bloqueia a janela).
  function connect() {
    return new Promise((resolve, reject) => {
      if (!enabled()) return reject(new Error("Google não configurado."));
      const state = randomState();
      const redirect = location.origin + "/google-callback.html";
      const params = new URLSearchParams({
        client_id: clientId(),
        redirect_uri: redirect,
        response_type: "token",
        scope: SCOPE,
        state,
        include_granted_scopes: "false",
        prompt: "select_account"
      });
      if (hint()) params.set("login_hint", hint());

      const channel = new BroadcastChannel(CHANNEL);
      let finished = false;
      const finish = (fn, value) => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        channel.close();
        fn(value);
      };
      const timer = setTimeout(() => finish(reject, new Error("Tempo esgotado esperando o Google.")), 3 * 60 * 1000);

      channel.onmessage = async (ev) => {
        const m = ev.data || {};
        if (m.type !== "token" || m.state !== state) return; // resposta de outra tentativa: ignora
        if (m.error || !m.access_token) return finish(reject, new Error(m.error === "access_denied" ? "Você não autorizou o acesso." : "O Google recusou a conexão."));
        try {
          const info = await fetch("https://oauth2.googleapis.com/tokeninfo?access_token=" + encodeURIComponent(m.access_token)).then((r) => (r.ok ? r.json() : Promise.reject(new Error("token"))));
          if (info.aud !== clientId() || !String(info.scope || "").split(" ").includes(SCOPE) || !(Number(info.expires_in) > 60)) {
            throw new Error("Token do Google não confere com este app.");
          }
          token = m.access_token;
          expiresAt = Date.now() + Math.min(Number(info.expires_in), 3600) * 1000;
          account = await loadAccount();
          try { localStorage.setItem(HINT_KEY, account.email); } catch { /* sem armazenamento */ }
          finish(resolve, account);
        } catch (err) {
          clear();
          finish(reject, err);
        }
      };

      const win = window.open("https://accounts.google.com/o/oauth2/v2/auth?" + params.toString(), "arca-google", "popup,width=520,height=700");
      if (!win) finish(reject, new Error("O navegador bloqueou a janela do Google. Permita pop-ups para este site e tente de novo."));
    });
  }

  async function loadAccount() {
    const r = await api("/about?fields=user(emailAddress,displayName),storageQuota(limit,usage)");
    const j = await r.json();
    const limit = Number(j.storageQuota && j.storageQuota.limit);
    const usage = Number(j.storageQuota && j.storageQuota.usage) || 0;
    return {
      email: (j.user && j.user.emailAddress) || "",
      name: (j.user && j.user.displayName) || "",
      limit: Number.isFinite(limit) && limit > 0 ? limit : null, // contas sem limite (Workspace ilimitado) não trazem "limit"
      free: Number.isFinite(limit) && limit > 0 ? Math.max(0, limit - usage) : null
    };
  }

  /* ---------- API do Drive ---------- */

  async function api(path, init = {}) {
    if (!connected()) throw Object.assign(new Error("Conecte sua conta Google."), { needsGoogle: true });
    const base = path.startsWith("http") ? "" : API;
    const r = await fetch(base + path, { ...init, headers: { ...(init.headers || {}), Authorization: "Bearer " + token } });
    if (r.status === 401) {
      clear();
      throw Object.assign(new Error("A conexão com o Google expirou. Conecte de novo."), { needsGoogle: true });
    }
    if (!r.ok && r.status !== 404) throw new Error("Google Drive respondeu " + r.status);
    return r;
  }

  // Pasta própria do app (o escopo drive.file só enxerga o que o app criou).
  async function ensureFolder() {
    if (folderId) return folderId;
    const q = `name='${FOLDER_NAME}' and mimeType='application/vnd.google-apps.folder' and trashed=false`;
    const found = await (await api("/files?fields=files(id)&spaces=drive&q=" + encodeURIComponent(q))).json();
    if (found.files && found.files.length) return (folderId = found.files[0].id);
    const made = await (await api("/files?fields=id", {
      method: "POST",
      headers: { "Content-Type": "application/json; charset=UTF-8" },
      body: JSON.stringify({ name: FOLDER_NAME, mimeType: "application/vnd.google-apps.folder" })
    })).json();
    return (folderId = made.id);
  }

  /** Envia um blob JÁ CIFRADO. Devolve o id do arquivo no Drive. */
  async function upload(blob, onProgress) {
    const parent = await ensureFolder();
    const name = crypto.randomUUID() + ".arca"; // nome sem significado: o Google não aprende nada
    const start = await api(UPLOAD + "?uploadType=resumable&fields=id", {
      method: "POST",
      headers: {
        "Content-Type": "application/json; charset=UTF-8",
        "X-Upload-Content-Type": "application/octet-stream",
        "X-Upload-Content-Length": String(blob.size)
      },
      body: JSON.stringify({ name, parents: [parent], mimeType: "application/octet-stream", appProperties: { app: "arca" } })
    });
    const session = start.headers.get("Location");
    if (!session) throw new Error("O Drive não abriu a sessão de envio.");
    const result = await new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("PUT", session);
      xhr.setRequestHeader("Content-Type", "application/octet-stream");
      xhr.upload.onprogress = (e) => { if (onProgress && e.lengthComputable) onProgress(e.loaded / e.total); };
      xhr.onload = () => (xhr.status >= 200 && xhr.status < 300 ? resolve(JSON.parse(xhr.responseText)) : reject(new Error("Envio ao Drive falhou (" + xhr.status + ").")));
      xhr.onerror = () => reject(new Error("Envio ao Drive falhou."));
      xhr.send(blob);
    });
    return result.id;
  }

  async function download(id) {
    const r = await api("/files/" + encodeURIComponent(id) + "?alt=media");
    if (r.status === 404) throw new Error("O arquivo não está mais no seu Google Drive (foi apagado ou movido).");
    return r.blob();
  }

  async function remove(id) {
    await api("/files/" + encodeURIComponent(id), { method: "DELETE" }); // 404 = já tinha sumido: ok
  }

  /** Desconecta e REVOGA a autorização no Google (o acesso só volta se a pessoa autorizar de novo). */
  async function disconnect() {
    const t = token;
    clear();
    if (t) {
      try { await fetch("https://oauth2.googleapis.com/revoke?token=" + encodeURIComponent(t), { method: "POST" }); } catch { /* sem rede: o token expira sozinho */ }
    }
  }

  return { enabled, connected, getAccount, hint, connect, disconnect, clear, upload, download, remove, FOLDER_NAME };
})();
window.GoogleDrive = GoogleDrive;

// O token vive só enquanto o cofre estiver aberto.
document.addEventListener("vault:locked", () => GoogleDrive.clear());
