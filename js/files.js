/* ==========================================================
   FILES: arquivos de projetos (instaladores, .zip, .apk...)
   ==========================================================
   Cada arquivo é cifrado NO NAVEGADOR (AES-256-GCM em blocos de
   1 MiB, com chave própria) antes de ir para o Supabase Storage.
   O servidor só vê um blob opaco com nome aleatório:
       <usuário>/<projeto>/<arquivo>.bin
   A chave do arquivo (FEK), o nome real, o tamanho e o SHA-256 ficam
   dentro do registro cifrado do projeto. Ao baixar, o app decifra e
   confere o SHA-256: se alguém alterou o arquivo no servidor, o
   download é recusado.
   ========================================================== */

const FileStore = (() => {
  const BUCKET = "project-files";
  const maxBytes = () => ((window.APP_CONFIG && window.APP_CONFIG.MAX_FILE_MB) || 50) * 1024 * 1024;

  const aadBase = (projectId, fileId) => `cofre/v2|${VaultSession.userId}|file|${projectId}/${fileId}`;
  const pathOf = (projectId, fileId) => `${VaultSession.userId}/${projectId}/${fileId}.bin`;

  function limitBytes() {
    return maxBytes();
  }

  /** Cifra e envia. Devolve os metadados que vão dentro do registro do projeto. */
  async function upload(file, projectId, onProgress) {
    if (file.size > maxBytes()) {
      throw new Error(`"${file.name}" tem ${(file.size / 1048576).toFixed(1)} MB. O limite é ${(maxBytes() / 1048576).toFixed(0)} MB por arquivo.`);
    }
    const fileId = CryptoUtil.newId();
    const fek = await CryptoUtil.generateFileKey();
    const key = await CryptoUtil.importFileKey(fek);
    const { blob, sha256 } = await CryptoUtil.encryptFile(file, key, aadBase(projectId, fileId), (p) => onProgress && onProgress(p * 0.5));
    if (onProgress) onProgress(0.5);
    const path = pathOf(projectId, fileId);
    const { error } = await sb.storage.from(BUCKET).upload(path, blob, { contentType: "application/octet-stream", upsert: false });
    if (error) throw error;
    if (onProgress) onProgress(1);
    return {
      id: fileId,
      name: file.name.slice(0, 200),
      type: file.type || "application/octet-stream",
      size: file.size,
      sha256,
      fek,
      path,
      version: "",
      notes: "",
      uploadedAt: new Date().toISOString()
    };
  }

  /** Baixa, decifra e confere a integridade. Devolve um Blob com o conteúdo original. */
  async function fetchPlain(meta, projectId, onProgress) {
    const { data, error } = await sb.storage.from(BUCKET).download(meta.path);
    if (error) throw error;
    const key = await CryptoUtil.importFileKey(meta.fek);
    const plain = await CryptoUtil.decryptFile(data, key, aadBase(projectId, meta.id), meta.type, onProgress);
    const digest = await CryptoUtil.sha256Hex(plain);
    if (digest !== meta.sha256) throw new Error("O arquivo não confere com o SHA-256 guardado. Download recusado.");
    return plain;
  }

  async function remove(metas) {
    const paths = metas.map((m) => m.path).filter(Boolean);
    if (!paths.length) return;
    const { error } = await sb.storage.from(BUCKET).remove(paths);
    if (error) throw error;
  }

  return { BUCKET, limitBytes, upload, fetchPlain, remove };
})();
window.FileStore = FileStore;
