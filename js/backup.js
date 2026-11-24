/* ==========================================================
   BACKUP MODULE
   ==========================================================
   O backup baixa exatamente o que está no Supabase: os blobs já
   cifrados (credenciais e projetos), mais o sal e a chave do cofre
   embrulhada (DEK). Nada é decifrado para gerar o arquivo: ele continua
   seguro se cair em outras mãos, mas só abre com a senha mestra (ou a
   chave de recuperação) do cofre que o gerou.

   Formato 2 ("cofre-backup", version 2): guarda também os ids, a
   versão de cada registro e o dono (user_id). Restaurar é idempotente
   (mesmo id = atualiza, não duplica). Arquivos de projeto (Storage)
   NÃO vão dentro do backup: ficam guardados no próprio Supabase; o
   backup leva só os registros que apontam para eles.
   ========================================================== */

async function createBackup() {
  try {
    await detectSchema();
    const { data: configRow, error: configError } = await sb
      .from("vault_config")
      .select("salt, kdf_iterations, wrapped_dek, wrapped_dek_iv, recovery_wrapped_dek, recovery_wrapped_dek_iv")
      .eq("user_id", VaultSession.userId)
      .maybeSingle();
    if (configError) throw configError;

    const { data: items, error: itemsError } = await sb
      .from("vault_items")
      .select(VaultSchema.itemVersion ? "id, encrypted_data, iv, version, created_at" : "id, encrypted_data, iv, created_at")
      .eq("user_id", VaultSession.userId);
    if (itemsError) throw itemsError;

    let projects = [];
    if (VaultSchema.projects) {
      const res = await sb.from("vault_projects").select("id, encrypted_data, iv, version, created_at").eq("user_id", VaultSession.userId);
      if (res.error) throw res.error;
      projects = res.data;
    }

    const backup = {
      format: "cofre-backup",
      version: 2,
      exported_at: new Date().toISOString(),
      user_id: VaultSession.userId,
      email: VaultSession.email,
      vault_config: configRow,
      items,
      projects
    };

    const blob = new Blob([JSON.stringify(backup, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cofre-backup-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);

    toast("Backup criado. Os dados dentro do arquivo continuam criptografados.");
    return true;
  } catch (err) {
    console.error(err);
    toast("Erro ao criar backup.");
    return false;
  }
}

// Decifra uma lista do backup e re-cifra para o usuário atual (outro usuário = ids novos).
async function convertBackupRows(rows, kind, backup, backupKey, targetVersion) {
  const sameUser = backup.user_id === VaultSession.userId;
  const out = [];
  for (const row of rows) {
    const version = row.version || 1;
    const aad = CryptoUtil.aadFor(version, backup.user_id, kind, row.id);
    const plain = await CryptoUtil.decryptJSON(backupKey, row.encrypted_data, row.iv, aad);
    const id = sameUser && row.id ? row.id : CryptoUtil.newId();
    const enc = await CryptoUtil.encryptJSON(VaultSession.key, plain, CryptoUtil.aadFor(targetVersion, VaultSession.userId, kind, id));
    const rec = { id, user_id: VaultSession.userId, encrypted_data: enc.ciphertext, iv: enc.iv };
    if (kind === "project" || VaultSchema.itemVersion) rec.version = targetVersion;
    out.push(rec);
  }
  return out;
}

async function restoreBackup(file) {
  try {
    await detectSchema();
    const backup = JSON.parse(await file.text());

    if (backup.format !== "cofre-backup" || !Array.isArray(backup.items)) {
      toast("Arquivo de backup inválido.");
      return;
    }

    // Qual chave abre o backup? A DEK atual, se for a mesma do cofre que o gerou; senão a DEK do backup,
    // desembrulhada com a senha mestra que valia quando ele foi feito.
    let backupKey = VaultSession.key;
    const sample = backup.items[0] || (backup.projects || [])[0];
    if (sample) {
      const kind = backup.items[0] ? "item" : "project";
      const aad = CryptoUtil.aadFor(sample.version || 1, backup.user_id, kind, sample.id);
      const opens = await CryptoUtil.decryptJSON(VaultSession.key, sample.encrypted_data, sample.iv, aad).then(() => true, () => false);
      if (!opens) {
        const cfg = backup.vault_config;
        if (!cfg || !cfg.wrapped_dek) {
          toast("Este backup é de outro cofre e não traz a chave dele.");
          return;
        }
        const password = await askPasswordValue("Este backup é de outro cofre. Digite a senha mestra que valia quando ele foi feito.");
        if (!password) return;
        const dekBuf = await AuthModule.unwrapDek(password, cfg);
        if (!dekBuf) {
          toast("A senha mestra informada não abre este backup.");
          return;
        }
        backupKey = await CryptoUtil.importRawAesKey(dekBuf, false);
      }
    }

    const itemVersion = VaultSchema.itemVersion ? 2 : 1;
    const items = await convertBackupRows(backup.items, "item", backup, backupKey, itemVersion);
    const projects = VaultSchema.projects && Array.isArray(backup.projects) ? await convertBackupRows(backup.projects, "project", backup, backupKey, 2) : [];

    if (items.length === 0 && projects.length === 0) {
      toast("Backup lido (o arquivo não continha registros).");
      return;
    }

    if (items.length) {
      const { error } = await sb.from("vault_items").upsert(items, { onConflict: "id" });
      if (error) throw error;
    }
    if (projects.length) {
      const { error } = await sb.from("vault_projects").upsert(projects, { onConflict: "id" });
      if (error) throw error;
    }

    if (typeof refreshList === "function") await refreshList();
    document.dispatchEvent(new CustomEvent("vault:rekeyed"));
    toast(`Backup restaurado: ${items.length} credencial(is) e ${projects.length} projeto(s).`);
  } catch (err) {
    console.error(err);
    toast("Erro ao restaurar backup. Verifique se o arquivo é válido e se a senha mestra é a do backup.");
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const backupBtn = document.getElementById("btn-backup");
  const restoreBtn = document.getElementById("btn-restore");
  const restoreInput = document.getElementById("restore-file-input");

  if (backupBtn) backupBtn.addEventListener("click", createBackup);

  if (restoreBtn && restoreInput) {
    restoreBtn.addEventListener("click", () => restoreInput.click());
    restoreInput.addEventListener("change", (e) => {
      const file = e.target.files[0];
      if (file) restoreBackup(file);
      restoreInput.value = "";
    });
  }
});
