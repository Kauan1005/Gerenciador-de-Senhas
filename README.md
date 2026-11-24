# Arca: gerenciador de senhas e de projetos

HTML/CSS/JS puro (sem bundler no site), com **Supabase** como banco e login, e deploy estático no **Netlify**.
Tudo o que é sensível é **cifrado no navegador** antes de sair: o servidor só guarda blobs ilegíveis.

Duas seções:

- **Senhas**: credenciais (site, usuário, senha, URL, notas), gerador de senhas, importar/exportar CSV e Excel, backup cifrado.
- **Projetos**: guarda onde cada projeto está e como instalá-lo de novo. Cada projeto tem **Banco de dados** (onde os dados ficam), **Hospedagem** (onde foi publicado) e **Arquivos** instaláveis (cifrados). Veja a seção 7.

> Relatório de segurança, com o que foi encontrado e corrigido: [`SECURITY.md`](SECURITY.md).

---

## 1. Arquitetura

```
Navegador (HTML/CSS/JS puro)
   │
   ├─ Web Crypto API  → PBKDF2 (derivação) + AES-256-GCM (cifra). 100% local.
   │                    A senha mestra NUNCA é enviada.
   │
   └─ Supabase (supabase-js servido pelo próprio site, versão fixa + SRI)
        ├─ Auth      → login com um SEGREDO DERIVADO da senha mestra (não ela)
        ├─ Postgres  → só blobs já cifrados + RLS (cada usuário só vê o que é seu)
        └─ Storage   → bucket privado com arquivos já cifrados
```

## 2. Como funciona a criptografia

Da senha mestra saem **duas coisas independentes**, com sais diferentes:

1. **Chave de cifra** (AES-256-GCM, não exportável) = PBKDF2-SHA256(senha, sal aleatório do cofre, 600.000 iterações).
   Cifra credenciais e projetos. Fica só na memória da aba.
2. **Segredo de login** = PBKDF2-SHA256(senha, sal derivado do e-mail, 600.000 iterações).
   É isto (e não a senha) que vai ao Supabase Auth.

Cada registro é um blob AES-GCM com IV aleatório. No formato **v2**, o blob carrega um **AAD** que o prende ao usuário, ao tipo
e ao id da linha: copiar um blob para outra linha ou outro usuário faz a decifragem falhar. Registros antigos (v1, sem AAD) continuam
abrindo e sobem para v2 quando editados.

**Arquivos de projeto**: cada arquivo tem a própria chave (FEK), é cifrado em blocos de 1 MiB (AES-GCM, IV por bloco, AAD com a posição
do bloco e "é o último?"): reordenar, repetir ou cortar blocos é detectado. A FEK, o nome, o tamanho e o SHA-256 ficam **dentro** do
registro cifrado do projeto. Trocar a senha mestra re-cifra só os registros, nunca os arquivos.

Reload da página, fechar a aba ou o bloqueio automático apagam a chave da memória. É proposital. Ao navegar entre Senhas e Projetos
a chave (não exportável) passa pelo IndexedDB por no máximo 20 segundos e é apagada assim que a página seguinte a lê.

## 3. Estrutura

```
index.html  vault.html  projects.html     telas: login, senhas, projetos
css/                                      estilos (style, vault, projects)
js/
  config.js                  URL e chave PÚBLICA do Supabase (local; fora do git)
  config.example.js          modelo do config.js
  supabase-client.js         cliente (sessão só na aba por padrão)
  crypto.js                  PBKDF2, AES-GCM com AAD, arquivos em blocos
  auth.js                    cadastro e login v2 (+ migração de contas antigas)
  session.js                 sessão, pedir senha mestra, passagem da chave entre páginas
  vault-data.js              acesso às credenciais cifradas
  credentials.js             tela de senhas
  projects.js  files.js      tela de projetos e arquivos cifrados
  google-drive.js            arquivos no Google Drive de cada pessoa (+ google-callback.html/.js)
  import-export.js           CSV e Excel
  backup.js  settings.js     backup/restauração e troca de senha mestra (atômica)
  autolock.js  clipboard.js  generator.js  theme.js  ui-tabs.js
vendor/                      bibliotecas locais (supabase-js 2.119.0, SheetJS 0.20.3) + SRI.txt
supabase/schema.sql          banco: tabelas, RLS, bucket de arquivos
scripts/build.mjs            monta dist/ (só o que vai para o ar)
_headers  netlify.toml       cabeçalhos de segurança (CSP...) e build do Netlify
tests/                       testes (criptografia e ponta a ponta)
```

## 4. Rodar localmente

1. Copie `js/config.example.js` para `js/config.js` e preencha `SUPABASE_URL` e `SUPABASE_ANON_KEY`
   (Supabase > Project Settings > API: use a chave **anon/publishable**, **nunca** a `service_role`/secret).
2. Sirva a pasta por HTTP (o Web Crypto precisa de contexto seguro; `localhost` serve), por exemplo
   `npx serve .` ou `python -m http.server 8080`, e abra `http://localhost:8080`.

## 5. Banco de dados: rodar o `schema.sql` (uma vez)

Os recursos novos (Projetos, troca de senha atômica, formato v2) precisam de tabelas e funções que o `supabase/schema.sql` cria.

1. Supabase > **SQL Editor** > **New query**.
2. Cole o conteúdo inteiro de `supabase/schema.sql` e clique **Run**.

Ele é **idempotente e não apaga dados**: pode rodar sobre o banco que já tem credenciais e pode ser repetido. Além de criar o que falta,
ele **redefine as regras de acesso (RLS)** das tabelas do cofre (removendo qualquer regra antiga mais frouxa) e cria o bucket privado
`project-files` (50 MB por arquivo). Sem rodá-lo, o app **continua funcionando no formato antigo** e mostra um aviso.

Conferência (opcional, no SQL Editor): as três últimas linhas comentadas do arquivo listam tabelas, regras e o bucket.

**Antes de rodar em um cofre com dados: crie um backup** (menu da conta > Criar backup). O arquivo continua cifrado.

## 6. Publicar no Netlify

O site publica a pasta **`dist/`**, montada por `scripts/build.mjs`, e não a raiz do repositório. Assim o README, os scripts, o SQL e os
testes nunca vão para o ar (o site antigo servia o `README.md` e o `config.example.js`).

**Com Git (recomendado):** Netlify > Site configuration:
- Build command: `node scripts/build.mjs`  ·  Publish directory: `dist` (já estão no `netlify.toml`)
- Environment variables: `SUPABASE_URL` e `SUPABASE_ANON_KEY` (a chave **pública**)
- Opcional: `GOOGLE_CLIENT_ID` (seção 11) e `LEGACY_LOGIN=false` (seção 10)

O build **recusa** uma chave `service_role`/`sb_secret_` por engano e troca o host do Supabase dentro da CSP.

**Arrastar e soltar:** crie o `js/config.js` local, rode `node scripts/build.mjs` e arraste a pasta `dist/` no Netlify.

Cabeçalhos aplicados (arquivo `_headers`): CSP restritiva (só JS/CSS do próprio site e conexão só com o seu Supabase), `X-Frame-Options: DENY`,
`nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, COOP/CORP e HSTS.

> **Importante:** a nova versão grava registros no formato v2. Depois de usar a nova versão, o site antigo não consegue ler o que foi
> salvo ou editado por ela. Troque o site inteiro de uma vez.

## 7. Projetos

Menu **Projetos**. Cada projeto tem quatro abas:

- **Geral**: nome, descrição, repositório, etiquetas, notas.
- **Banco de dados** (uma ou mais entradas): provedor (Supabase, Firebase, Neon…), nome no provedor, identificador, endereço, painel,
  conta, região, notas, e **senhas do cofre ligadas** (guardadas só como ids; o conteúdo continua no cofre, com atalho para copiar).
- **Hospedagem** (uma ou mais): provedor (Netlify, Vercel…), nome do site, endereço público, painel, domínio, como publica, conta, notas, senhas ligadas.
- **Arquivos**: instaladores, `.zip`, `.apk`… cifrados no navegador antes de subir; versão e observações de instalação por arquivo;
  "Baixar" decifra e confere o SHA-256 (arquivo adulterado no servidor é recusado). Onde ficam os arquivos:
  - **Com `GOOGLE_CLIENT_ID` configurado (recomendado): no Google Drive de cada pessoa** (seção 11). Cada um conecta a própria conta
    Google, usa a própria cota gratuita (~15 GB) e os arquivos são pessoais. Limite padrão de 200 MB por arquivo (`MAX_FILE_MB_DRIVE`).
  - **Sem Google configurado:** no Storage do Supabase (limite de 50 MB por arquivo; ~1 GB no total, dividido por todos os usuários).
  Arquivos já guardados num lugar continuam abrindo mesmo se você mudar de modo (cada arquivo lembra onde está).

A lista pode ser organizada **por projeto**, **por banco de dados** ou **por hospedagem** (um grupo por provedor). A busca olha nome,
descrição, provedores, endereços, contas e nomes de arquivo, sempre localmente.

## 8. Segurança, em resumo

- A senha mestra nunca sai do navegador (login com segredo derivado), e não é recuperável: perdeu, perdeu os dados. O mínimo é de 5 caracteres (configurável em `MIN_MASTER_LENGTH`), mas uma senha curta enfraquece muito a proteção: prefira uma frase longa.
- Servidor sem texto puro: credenciais, projetos e arquivos são blobs AES-256-GCM.
- RLS em todas as tabelas e no Storage: cada usuário só alcança o que é seu.
- Sem JavaScript de terceiros; CSP; SRI; sem scripts inline; conteúdo do cofre sempre desenhado como texto.
- Bloqueio por inatividade (5 min), cópia com limpeza automática da área de transferência, gerador com `crypto.getRandomValues`.
- Exportar em texto puro exige reconfirmar a senha mestra; CSV/Excel protegidos contra injeção de fórmula.
- Troca de senha mestra em uma única transação (tudo ou nada).

Detalhes e riscos restantes em [`SECURITY.md`](SECURITY.md).

## 9. Testes

```
cd tests
npm install        # só desenvolvimento (playwright-core); o site não usa npm
npm test           # criptografia (Node) + build + ponta a ponta (navegador) + Google Drive simulado
```

Os testes ponta a ponta usam um **Supabase simulado** (`tests/fake-supabase.js`): não tocam no banco real. Servem o site com os
mesmos cabeçalhos do Netlify e conferem, entre outras coisas, que a senha mestra não chega ao servidor, que nada fica em texto
puro, que a CSP bloqueia script injetado, que arquivos adulterados são recusados e que contas antigas continuam abrindo.
Precisam do Edge ou do Chrome instalados (ou `PW_BROWSER=caminho`).

## 10. Contas antigas (migração do login)

Contas criadas antes desta versão tinham a **própria senha mestra** como senha do Supabase. Com `LEGACY_LOGIN: true` (padrão), o login
tenta o método novo e, se falhar, o antigo; ao entrar pelo antigo, a conta é **migrada na hora** (a senha do Supabase passa a ser o
segredo derivado) e o app avisa. Os dados não são tocados nessa migração.

Quando **todas** as contas tiverem entrado uma vez com a versão nova, ponha `LEGACY_LOGIN: false` (variável `LEGACY_LOGIN=false` no
Netlify). Aí uma senha errada deixa de ser enviada ao servidor numa segunda tentativa.

Cofres criados com menos de 600.000 iterações mostram o aviso **"Reforçar criptografia"** no menu da conta (re-deriva a chave com o
custo atual, com backup automático antes).

## 11. Google Drive pessoal (arquivos de projeto)

Para cada pessoa guardar os arquivos no **próprio** Google Drive (cota gratuita individual, projetos pessoais), crie um cliente OAuth uma vez:

1. [Google Cloud Console](https://console.cloud.google.com/) > novo projeto (qualquer nome).
2. **APIs e serviços > Biblioteca**: ative a **Google Drive API**.
3. **Tela de permissão OAuth**: tipo *Externo*; nome do app (ex.: Arca); e-mail de suporte; em *Escopos* adicione só
   `.../auth/drive.file`. Para o app abrir para qualquer pessoa, publique-o (*Em produção*). `drive.file` não é escopo restrito,
   então normalmente não exige a auditoria de segurança do Google; enquanto estiver em *Teste*, só os e-mails de teste entram.
4. **Credenciais > Criar credenciais > ID do cliente OAuth > Aplicativo da Web**.
   - *Origens JavaScript autorizadas*: `https://SEU-SITE.netlify.app` (e `http://localhost:8080` se for testar local).
   - *URIs de redirecionamento autorizados*: `https://SEU-SITE.netlify.app/google-callback.html`.
5. Copie o **ID do cliente** (`123...apps.googleusercontent.com`) e defina `GOOGLE_CLIENT_ID` no Netlify (ou no `js/config.js` local).
   **Nunca** use o "segredo do cliente": o build recusa um valor que não tenha o formato de ID.

Como funciona e o que isso garante:

- Cada pessoa clica em **Conectar conta Google** na aba Arquivos. O app só recebe o escopo `drive.file`: enxerga **apenas** o que ele mesmo criou
  (a pasta "Arca (arquivos cifrados)"), nunca o resto do Drive.
- Os arquivos já saem cifrados do navegador e têm nomes sem significado (`<uuid>.arca`): o Google só guarda blobs ilegíveis.
- O token do Google (validade de ~1 h) fica **só na memória**: bloquear o cofre, sair ou fechar a aba o descarta; **Desconectar** também o revoga.
  O app confere o `state`, o `aud` (seu Client ID) e o escopo antes de aceitar o token. Nenhum script do Google é carregado no site; a CSP libera
  apenas `www.googleapis.com` e `oauth2.googleapis.com` (e só quando `GOOGLE_CLIENT_ID` está definido).
- Para baixar ou apagar um arquivo é preciso estar com a conta Google dona dele conectada. Se um projeto for apagado sem a conta
  conectada, os arquivos ficam no Drive da pessoa (o app avisa); ela apaga a pasta quando quiser.

**Limites e o que NÃO foi verificado:** os testes usam um Google **simulado** (`tests/drive.e2e.test.mjs`); o fluxo real depende do seu Client ID
e das telas do Google, e não pôde ser exercitado aqui. Se ao conectar o Google mostrar `redirect_uri_mismatch`, confira o passo 4. O fluxo usado
(OAuth "implícito" em janela própria) é suportado pelo Google para apps web hoje; se um dia for descontinuado, só `js/google-drive.js` precisa trocar.

## 12. Chave de recuperação e "esqueci a senha mestra"

O cofre usa uma chave aleatória (DEK) que cifra tudo. Ela fica guardada **embrulhada** de duas formas: pela sua senha mestra e por uma
**chave de recuperação** de 256 bits, mostrada **uma única vez** no cadastro (anote ou guarde num lugar seguro; não fica salva no servidor em texto).

- **Esqueci a senha mestra:** na tela de login, clique em *Esqueci minha senha mestra*. O Supabase manda um link para o seu e-mail, que abre
  `recovery.html`; ali você informa a chave de recuperação e escolhe uma nova senha mestra. Nada é re-cifrado e nada se perde.
- **Trocar a senha mestra** (menu da conta) também só re-embrulha a DEK e é instantâneo. A chave de recuperação continua valendo.
- Sem a senha mestra **e** sem a chave de recuperação, os dados não podem ser lidos por ninguém.
- No Supabase, em *Authentication > URL Configuration*, o **Site URL** deve ser o endereço do site e `https://SEU-SITE/recovery.html` precisa estar
  em *Redirect URLs*, senão o link do e-mail não volta para a tela de recuperação.
