# Relatório de segurança da Arca

Revisão feita sobre o código do repositório, o site publicado e o projeto Supabase, **somente com a
chave pública do próprio site** (leitura e escrita anônimas negadas; nenhum dado foi lido ou criado no seu banco).
Método: revisão de código com a skill `security-review` (OWASP), rastreando o caminho dos dados antes de apontar cada achado, mais testes
automatizados de cada correção (`tests/`).

## O que já estava bom

- AES-256-GCM e PBKDF2-SHA256 (600.000 iterações) pela Web Crypto API; chave **não exportável**; IV aleatório por registro.
- Gerador de senhas com `crypto.getRandomValues` e rejeição de amostragem.
- Limpeza automática da área de transferência (só se o conteúdo ainda for o copiado).
- Conteúdo do cofre desenhado com `escapeHtml`/`textContent` (sem XSS pelos dados); URLs com esquema `http(s)` forçado.
- **RLS ativa no banco publicado**: leitura anônima de `vault_items` devolve `[]` e escrita anônima responde `401`.

## Achados e correções

| # | Gravidade | Achado | Correção | Teste |
|---|---|---|---|---|
| 1 | **Alta** | A senha mestra era **enviada ao Supabase** no cadastro e no login (era a senha do Auth). O README afirmava o contrário. Um servidor ou painel comprometido a recebia em texto. | Login **v2**: o Auth recebe um **segredo derivado** (PBKDF2 com sal do e-mail), não a senha. Contas antigas migram sozinhas no primeiro login. | e2e: `passwordsSeen` nunca contém a senha |
| 2 | **Alta** | Site sem **CSP** e sem proteção contra clickjacking (só HSTS). Um XSS num cofre de senhas é o pior cenário. | `_headers`: CSP `script-src 'self'`, `frame-ancestors 'none'`, `connect-src` só o seu Supabase, `nosniff`, `no-referrer`, Permissions-Policy, COOP/CORP. | e2e: cabeçalhos presentes; script inline injetado é bloqueado |
| 3 | **Alta** | JavaScript de **CDN sem versão fixa nem SRI** (`supabase-js@2`) e **SheetJS 0.18.5** (CVE-2023-30533, poluição de protótipo; CVE-2024-22363, ReDoS). | Bibliotecas servidas pelo próprio site (`vendor/`), versão fixa, **SRI**; SheetJS 0.20.3. | crypto: SRI confere; nenhuma página carrega JS de fora |
| 4 | Média | O **bloqueio automático por inatividade nunca era ligado** (o `init` rodava antes da chave existir). | `init()` chamado depois da guarda de sessão; também bloqueia ao voltar de uma aba escondida por muito tempo. | e2e com relógio simulado |
| 5 | Média | Blobs sem **AAD**: um servidor malicioso poderia trocar blobs entre linhas ou usuários sem a decifragem falhar. | Formato v2 com AAD (usuário + tipo + id). v1 continua abrindo. | crypto: 4 trocas recusadas |
| 6 | Média | **Troca de senha mestra não atômica** (falha no meio deixava registros ilegíveis). | `rotate_vault()`: uma transação que confere que **todos** os registros foram re-cifrados; o segredo de login volta ao anterior se falhar. | e2e: falha simulada não muda nada |
| 7 | Média | Servidor podia devolver `kdf_iterations` baixo e enfraquecer a derivação; README (250 mil) e config (600 mil) divergiam. | Piso de 100.000 no cliente; aviso e ação "Reforçar criptografia" para cofres antigos; README corrigido. | crypto: piso recusado |
| 8 | Média | Exportar para Excel gerava **texto puro** com um clique; células com `=`, `+`, `-`, `@` viravam **fórmula** (injeção em planilha). | Exige **reconfirmar a senha mestra**; prefixo `'` nas células perigosas; CSV nativo. | e2e |
| 9 | Baixa | Senha mestra mínima de 8 caracteres e sem checagem de senhas conhecidas. | Mínimo de **5** caracteres (**escolha do dono**), recusa um único caractere repetido e senhas muito conhecidas, e barra de força. Veja o risco 3 abaixo. | crypto, e2e |
| 10 | Baixa | O site publicava a **raiz inteira** (`README.md`, `config.example.js`...). | Publica só `dist/`, montado por `scripts/build.mjs`; o build recusa chave `service_role`. | e2e: servidor não entrega README/SQL |
| 11 | Baixa | Sessão do Supabase em `localStorage` (sobrevive ao fechar o navegador). | Padrão: `sessionStorage` (só na aba). Opção `SESSION_STORE: "browser"`. | e2e |
| 12 | Baixa | O **esquema e a RLS não estavam no repositório** (o README citava um `schema.sql` que não existia). | `supabase/schema.sql` idempotente: redefine RLS removendo regras antigas, `anon` sem acesso, limites de tamanho. | revisado; **aplicar no banco é um passo seu** |
| 13 | Baixa | Botão principal com texto escuro sobre vinho (contraste ~2:1). | Texto branco (~9:1). | visual |
| 14 | Baixa | Restaurar backup criava **duplicatas** a cada vez. | Backup v2 guarda ids; restauração é idempotente e re-cifra para o usuário atual. | e2e |

## Riscos que restam (decisões suas)

1. **Cadastro aberto a qualquer pessoa, sem confirmação de e-mail (decisão do dono).** O Auth do projeto está com
   `disable_signup: false` e `mailer_autoconfirm: true`, e assim fica: não há restrição para criar um cofre. Isso **não expõe os
   dados de ninguém** (a RLS isola cada usuário e tudo é cifrado), mas todos os cofres dividem a **mesma cota gratuita** do Supabase
   (~1 GB de arquivos, banco e tráfego). Uma conta que suba muitos arquivos grandes pode esgotar a cota de todos; nesse caso o
   Supabase bloqueia novos envios até renovar o ciclo. Sinais para acompanhar: Supabase > Reports/Usage (Storage e Database).
   Se um dia isso incomodar, as saídas que **não** fecham o cadastro são: limitar o tamanho/quantidade por usuário (via SQL) ou
   reduzir `MAX_FILE_MB` em `config.js`. Fechar o cadastro continua sendo só um interruptor no painel, se você mudar de ideia.
2. **Sem segundo fator no login do Supabase.** Como tudo é cifrado no cliente, quem entrar no Auth só leva blobs ilegíveis; ainda assim,
   o MFA (TOTP, gratuito) dificulta ataques de força bruta contra a senha mestra. Opcional.
3. **A senha mestra continua sendo o ponto único, e o mínimo é só 5 caracteres (decisão do dono).** Quem tiver os blobs (por exemplo, um
   acesso indevido ao banco) pode tentar adivinhá-la offline, e o custo de 600.000 iterações **não compensa** uma senha curta: uma de
   5 caracteres cai em horas ou menos. Para dados que valem a pena proteger, use uma frase longa; o mínimo de 5 só vale para o que você
   aceitar arriscar. Não há recuperação se a senha for esquecida.
4. **`LEGACY_LOGIN: true` durante a migração.** Enquanto ligado, uma senha errada pode ser enviada ao servidor numa segunda tentativa
   (compatibilidade com contas antigas). Desligue assim que todas as contas migrarem (README, seção 10).
5. **Onde ficam os arquivos de projeto.** Com `GOOGLE_CLIENT_ID` (README, seção 11), no **Google Drive de cada pessoa**: cota individual, e
   o risco de uma conta esgotar a cota dos outros some para arquivos. O app pede só `drive.file` (vê apenas o que criou), recebe o token por
   janela própria, o guarda só em memória, confere `state`/`aud`/escopo e o revoga ao desconectar; a CSP só libera os hosts do Google quando ele
   está ligado. Os arquivos chegam cifrados (nome `<uuid>.arca`). Resíduos: quem controla a conta Google da pessoa pode apagar ou trocar o blob
   (o download é recusado se o SHA-256 não bater, mas o arquivo se perde); o fluxo OAuth implícito é o mais simples sem servidor, porém o Google o
   considera legado para novos apps de servidor (para web "sem back-end" segue disponível). **Sem Google configurado**, os arquivos ficam no
   Storage do Supabase (~1 GB compartilhado, ver item 1). Não testado contra o Google real.
6. **Não foi possível testar contra o seu Supabase real** (as credenciais são suas). Os testes usam um simulado fiel ao uso do app, e o SQL
   foi escrito para ser seguro, mas rode-o e confira com as consultas ao final do `schema.sql`.

## Como verificar você mesmo

- Cabeçalhos: `curl -I https://SEU-SITE.netlify.app/` deve mostrar `content-security-policy`, `x-frame-options: DENY`.
- Rede: no DevTools > Network, o login deve enviar um `password` de 44 caracteres (base64), nunca a senha que você digitou.
- Banco: no Supabase > Table Editor, `encrypted_data` deve ser uma sequência base64 sem nada legível.
