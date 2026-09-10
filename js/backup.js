/* ==========================================================
   BACKUP MODULE
   ==========================================================
   O backup baixa exatamente o que está no Supabase: os blobs
   já cifrados (encrypted_data + iv) de vault_items, mais o
   salt/verificador de vault_config. Nada é decifrado para
   gerar o backup — por isso o arquivo .json continua seguro
   mesmo que caia em outras mãos, mas SÓ pode ser lido de volta
   com a mesma senha mestra que o gerou.
   ========================================================== */

async function createBackup() {
  try {
    const { data: configRow, error: configError } = await sb
      .from("vault_config")
      .select("salt, kdf_iterations, verifier, verifier_iv")
      .eq("user_id", VaultSession.userId)
      .maybeSingle();
    if (configError) throw configError;

    const { data: items, error: itemsError } = await sb
      .from("vault_items")
      .select("encrypted_data, iv, created_at")
      .eq("user_id", VaultSession.userId);
    if (itemsError) throw itemsError;

    const backup = {
      format: "cofre-backup",
      version: 1,
      exported_at: new Date().toISOString(),
      email: VaultSession.email,
      vault_config: configRow,
      items
    };

    const blob = new Blob([JSON.stringify(backup, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cofre-backup-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);

    toast("Backup criado. Os dados dentro do arquivo continuam criptografados.");
  } catch (err) {
    console.error(err);
    toast("Erro ao criar backup.");
  }
}

async function restoreBackup(file) {
  try {
    const text = await file.text();
    const backup = JSON.parse(text);

    if (backup.format !== "cofre-backup" || !Array.isArray(backup.items)) {
      toast("Arquivo de backup inválido.");
      return;
    }

    const { data: currentConfig, error: configError } = await sb
      .from("vault_config")
      .select("salt")
      .eq("user_id", VaultSession.userId)
      .maybeSingle();
    if (configError) throw configError;

    if (!currentConfig && backup.vault_config) {
      // recuperação total: a configuração do cofre também foi perdida
      const { error: insertConfigError } = await sb.from("vault_config").insert({
        user_id: VaultSession.userId,
        salt: backup.vault_config.salt,
        kdf_iterations: backup.vault_config.kdf_iterations,
        verifier: backup.vault_config.verifier,
        verifier_iv: backup.vault_config.verifier_iv
      });
      if (insertConfigError) throw insertConfigError;
    } else if (
      currentConfig &&
      backup.vault_config &&
      currentConfig.salt !== backup.vault_config.salt
    ) {
      const proceed = window.confirm(
        "Este backup foi feito com uma senha mestra diferente da atual. Os itens restaurados podem ficar ilegíveis. Restaurar mesmo assim?"
      );
      if (!proceed) return;
    }

    if (backup.items.length === 0) {
      toast("Backup restaurado (o arquivo não continha credenciais).");
      return;
    }

    const rows = backup.items.map((item) => ({
      user_id: VaultSession.userId,
      encrypted_data: item.encrypted_data,
      iv: item.iv
    }));

    const { error: insertError } = await sb.from("vault_items").insert(rows);
    if (insertError) throw insertError;

    await refreshList();
    toast(`Backup restaurado: ${rows.length} credencial(is) adicionada(s).`);
  } catch (err) {
    console.error(err);
    toast("Erro ao restaurar backup. Verifique se o arquivo é válido.");
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