/* ==========================================================
   SUPABASE CLIENT
   ==========================================================
   Cria uma única instância do cliente Supabase, reaproveitada
   pelos demais módulos. Depende de:
     - window.supabase (vendor/supabase-js-*.umd.js, servido pelo próprio site)
     - window.APP_CONFIG (js/config.js)

   Sessão: por padrão fica só na ABA (sessionStorage). Fechar a aba
   encerra o login, coerente com o cofre apagar a chave da memória.
   Para manter o login entre aberturas do navegador, use
   SESSION_STORE: "browser" em config.js.
   ========================================================== */

if (!window.APP_CONFIG || String(window.APP_CONFIG.SUPABASE_URL).includes("SEU-PROJETO")) {
  console.warn("[Cofre] Configure SUPABASE_URL e SUPABASE_ANON_KEY em js/config.js antes de usar o app.");
}

const sb = window.supabase.createClient(window.APP_CONFIG.SUPABASE_URL, window.APP_CONFIG.SUPABASE_ANON_KEY, {
  auth: {
    persistSession: true,
    autoRefreshToken: true,
    detectSessionInUrl: true,
    storage: window.APP_CONFIG.SESSION_STORE === "browser" ? window.localStorage : window.sessionStorage
  }
});
