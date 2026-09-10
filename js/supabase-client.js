/* ==========================================================
   SUPABASE CLIENT
   ==========================================================
   Cria uma única instância do cliente Supabase, reaproveitada
   por auth.js, credentials.js, backup.js, etc.
   Depende de:
     - window.supabase (carregado via CDN no index.html/vault.html)
     - window.APP_CONFIG (definido em config.js)
   ========================================================== */

if (!window.APP_CONFIG || window.APP_CONFIG.SUPABASE_URL.includes("SEU-PROJETO")) {
  console.warn(
    "[Cofre] Configure SUPABASE_URL e SUPABASE_ANON_KEY em js/config.js antes de usar o app."
  );
}

const sb = window.supabase.createClient(
  window.APP_CONFIG.SUPABASE_URL,
  window.APP_CONFIG.SUPABASE_ANON_KEY,
  {
    auth: {
      persistSession: true,
      autoRefreshToken: true,
      detectSessionInUrl: true
    }
  }
);