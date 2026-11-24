// Copie para js/config.js (arquivo ignorado pelo git) e preencha.
// Em produção (Netlify) este arquivo é gerado por scripts/build.mjs a partir das variáveis de ambiente.
window.APP_CONFIG = {
  SUPABASE_URL: "https://SEU-PROJETO.supabase.co",
  SUPABASE_ANON_KEY: "sua-chave-PUBLICA-anon-aqui", // nunca a service_role / secret

  KDF_ITERATIONS: 600000,       // custo do PBKDF2 na derivação da chave (mínimo aceito: 100000)
  AUTO_LOCK_MINUTES: 5,         // bloqueio automático por inatividade
  CLIPBOARD_CLEAR_SECONDS: 20,  // limpeza automática da área de transferência
  MAX_FILE_MB: 50,              // limite por arquivo de projeto (teto do plano gratuito do Supabase)
  MIN_MASTER_LENGTH: 5,         // tamanho mínimo da senha mestra (cadastro e troca)
  SESSION_STORE: "tab",         // "tab" = login só na aba (padrão) | "browser" = persiste no navegador
  LEGACY_LOGIN: true            // aceita contas antigas (login com a própria senha mestra) e as migra; use false depois de migrar
};
