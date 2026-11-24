/* ==========================================================
   VAULT DATA: acesso às credenciais (usado por Senhas e Projetos)
   ==========================================================
   Formato dos registros (coluna "version" de vault_items):
     1 = AES-GCM sem AAD (contas/dados antigos)
     2 = AES-GCM com AAD ligando o blob ao usuário e ao id da linha
   Registros antigos continuam abrindo; qualquer edição grava na
   versão 2 (se o banco já tem a coluna).
   ========================================================== */

let allCredentials = []; // cache em memória, já decifrada

function itemWriteVersion() {
  return VaultSchema.itemVersion ? 2 : 1;
}

async function fetchAndDecryptAll() {
  await detectSchema();
  const cols = VaultSchema.itemVersion ? "id, encrypted_data, iv, version, created_at" : "id, encrypted_data, iv, created_at";
  const { data, error } = await sb
    .from("vault_items")
    .select(cols)
    .eq("user_id", VaultSession.userId)
    .order("created_at", { ascending: false });
  if (error) throw error;

  const decrypted = [];
  for (const row of data) {
    try {
      const version = row.version || 1;
      const aad = CryptoUtil.aadFor(version, VaultSession.userId, "item", row.id);
      const item = await CryptoUtil.decryptJSON(VaultSession.key, row.encrypted_data, row.iv, aad);
      decrypted.push({ id: row.id, ...item });
    } catch (err) {
      // linha corrompida ou cifrada com outra chave: não trava a lista inteira
      console.error("Falha ao decifrar item", row.id);
    }
  }
  return decrypted;
}

async function addCredential(payload) {
  await detectSchema();
  const version = itemWriteVersion();
  const id = CryptoUtil.newId(); // o id faz parte do AAD, então é definido antes de gravar
  const aad = CryptoUtil.aadFor(version, VaultSession.userId, "item", id);
  const { ciphertext, iv } = await CryptoUtil.encryptJSON(VaultSession.key, payload, aad);
  const row = { id, user_id: VaultSession.userId, encrypted_data: ciphertext, iv };
  if (VaultSchema.itemVersion) row.version = version;
  const { error } = await sb.from("vault_items").insert(row);
  if (error) throw error;
  return { id, ...payload };
}

async function updateCredential(id, payload) {
  await detectSchema();
  const version = itemWriteVersion();
  const aad = CryptoUtil.aadFor(version, VaultSession.userId, "item", id);
  const { ciphertext, iv } = await CryptoUtil.encryptJSON(VaultSession.key, payload, aad);
  const patch = { encrypted_data: ciphertext, iv };
  if (VaultSchema.itemVersion) patch.version = version;
  const { error } = await sb.from("vault_items").update(patch).eq("id", id).eq("user_id", VaultSession.userId);
  if (error) throw error;
  return { id, ...payload };
}

async function deleteCredential(id) {
  const { error } = await sb.from("vault_items").delete().eq("id", id).eq("user_id", VaultSession.userId);
  if (error) throw error;
}

// Copia com limpeza automática da área de transferência.
function copySecret(value, okMessage) {
  const seconds = (window.APP_CONFIG && window.APP_CONFIG.CLIPBOARD_CLEAR_SECONDS) || 20;
  ClipboardModule.copy(value).then((ok) => {
    toast(ok ? `${okMessage}. Será limpo em ${seconds}s.` : "Não foi possível copiar.");
  });
}
