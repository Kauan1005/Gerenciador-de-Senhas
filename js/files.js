/* ==========================================================
   FILES: arquivos de projetos (instaladores, .zip, .apk...)
   ==========================================================
   Cada arquivo é cifrado NO NAVEGADOR (AES-256-GCM em blocos de
   1 MiB, com chave própria) antes de sair daqui. Onde ele fica:

     - GOOGLE_CLIENT_ID configurado  -> no Google Drive da PRÓPRIA pessoa
       (google-drive.js): cota gratuita individual, projetos pessoais.
     - sem Google configurado        -> Supabase Storage (bucket privado,
       cota de ~1 GB compartilhada por todos), como nas versões anteriores.

   Cada arquivo guarda no seu registro de projeto onde está (store:
   "drive" ou "supabase"), então arquivos antigos continuam abrindo.
   O armazenamento (Google ou Supabase) só vê um blob opaco com nome
   aleatório. A chave do arquivo (FEK), o nome real, o tamanho e o SHA-256
   ficam DENTRO do registro cifrado do projeto. Ao baixar, o app decifra e
   confere o SHA-256: se alguém alterou o arquivo, o download é recusado.
   ========================================================== */

const FileStore = (() => {
  const BUCKET = "project-files";
  const cfg = () => window.APP_CONFIG || {};
  const useDrive = () => GoogleDrive.enabled();
  const maxBytes = () => (useDrive() ? cfg().MAX_FILE_MB_DRIVE || 200 : cfg().MAX_FILE_MB || 50) * 1024 * 1024;

  const aadBase = (projectId, fileId) => `cofre/v2|${VaultSession.userId}|file|${projectId}/${fileId}`;
  const pathOf = (projectId, fileId) => `${VaultSession.userId}/${projectId}/${fileId}.bin`;
  const storeOf = (meta) => (meta.store === "drive" ? "drive" : "supabase");

  function limitBytes() {
    return maxBytes();
  }

  /** Cifra e envia. Devolve os metadados que vão dentro do registro do projeto. */
  async function upload(file, projectId, onProgress) {
    if (file.size > maxBytes()) {
      throw new Error(`"${file.name}" tem ${(file.size / 1048576).toFixed(1)} MB. O limite é ${(maxBytes() / 1048576).toFixed(0)} MB por arquivo.`);
    }
    if (useDrive() && !GoogleDrive.connected()) throw Object.assign(new Error("Conecte sua conta Google."), { needsGoogle: true });

    const fileId = CryptoUtil.newId();
    const fek = await CryptoUtil.generateFileKey();
    const key = await CryptoUtil.importFileKey(fek);
    const { blob, sha256 } = await CryptoUtil.encryptFile(file, key, aadBase(projectId, fileId), (p) => onProgress && onProgress(p * 0.4));

    const meta = {
      id: fileId,
      name: file.name.slice(0, 200),
      type: file.type || "application/octet-stream",
      size: file.size,
      sha256,
      fek,
      version: "",
      notes: "",
      uploadedAt: new Date().toISOString()
    };
    if (useDrive()) {
      meta.store = "drive";
      meta.driveId = await GoogleDrive.upload(blob, (p) => onProgress && onProgress(0.4 + p * 0.6));
    } else {
      meta.store = "supabase";
      meta.path = pathOf(projectId, fileId);
      const { error } = await sb.storage.from(BUCKET).upload(meta.path, blob, { contentType: "application/octet-stream", upsert: false });
      if (error) throw error;
    }
    if (onProgress) onProgress(1);
    return meta;
  }

  /** Baixa, decifra e confere a integridade. Devolve um Blob com o conteúdo original. */
  async function fetchPlain(meta, projectId, onProgress) {
    let data;
    if (storeOf(meta) === "drive") {
      data = await GoogleDrive.download(meta.driveId);
    } else {
      const res = await sb.storage.from(BUCKET).download(meta.path);
      if (res.error) throw res.error;
      data = res.data;
    }
    const key = await CryptoUtil.importFileKey(meta.fek);
    const plain = await CryptoUtil.decryptFile(data, key, aadBase(projectId, meta.id), meta.type, onProgress);
    const digest = await CryptoUtil.sha256Hex(plain);
    if (digest !== meta.sha256) throw new Error("O arquivo não confere com o SHA-256 guardado. Download recusado.");
    return plain;
  }

  /** Apaga arquivos. Nunca lança erro: devolve { failed } com o que NÃO foi apagado (ex.: Google desconectado). */
  async function remove(metas) {
    const failed = [];
    const sup = metas.filter((m) => storeOf(m) === "supabase" && m.path);
    if (sup.length) {
      const { error } = await sb.storage.from(BUCKET).remove(sup.map((m) => m.path));
      if (error) failed.push(...sup);
    }
    for (const m of metas.filter((x) => storeOf(x) === "drive" && x.driveId)) {
      try {
        await GoogleDrive.remove(m.driveId);
      } catch (err) {
        failed.push(m);
      }
    }
    return { failed };
  }

  /** Algum destes arquivos está no Google Drive (e portanto exige a conta conectada para apagar/baixar)? */
  const needsGoogle = (metas) => metas.some((m) => storeOf(m) === "drive");

  return { BUCKET, limitBytes, upload, fetchPlain, remove, needsGoogle, storeOf };
})();
window.FileStore = FileStore;
