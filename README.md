# Cofre — gerenciador de senhas

Gerenciador de senhas 100% HTML/CSS/JS, com Supabase como backend e deploy estático no Netlify.

---

## 1. Arquitetura

```
Navegador (HTML/CSS/JS puro, sem bundler)
   │
   ├─ Web Crypto API   → PBKDF2 (derivação de chave) + AES-256-GCM (cifra)
   │                      100% local. A senha mestra nunca é enviada.
   │
   └─ Supabase JS SDK (via CDN)
        ├─ Auth       → login/sessão (e-mail + senha mestra)
        └─ Postgres   → guarda só dados JÁ CIFRADOS + RLS por usuário
```

**Por que sem build/bundler?** Todo o código roda com `<script>` simples,
sem webpack/vite/npm install. Isso evita qualquer atrito com antivírus
corporativos (CrowdStrike, Kaspersky) — não há binários, não há
`node_modules`, não há execução de scripts de instalação.

**Por que a senha mestra também é a senha de login?** Para manter só
1 senha para lembrar. O Supabase Auth nunca guarda essa senha em texto
puro — só um hash bcrypt irreversível, que é o padrão de qualquer
sistema de login. A chave de criptografia do cofre é derivada
**localmente**, a partir da mesma senha mais um salt próprio que nunca
sai do navegador em forma útil para decifrar nada sem a senha.

---

## 2. Como funciona a criptografia

1. **Cadastro:** você escolhe uma senha mestra. O navegador gera um
   `salt` aleatório e deriva uma chave AES-256 com PBKDF2 (250.000
   iterações, SHA-256). Essa chave cifra um texto fixo conhecido
   (`"COFRE_VERIFICADO_v1"`) e o resultado (`verifier`) vai para o
   Supabase, junto com o `salt`. **A senha em si nunca é enviada.**
2. **Login:** o navegador busca seu `salt`, deriva a chave de novo a
   partir da senha que você digitou, e tenta decifrar o `verifier`.
   Se bater com o texto esperado, a senha estava certa — e a chave
   fica só na memória da aba.
3. **Cada credencial** (site, usuário, senha, URL, notas) é cifrada
   como um blob único (AES-256-GCM, IV aleatório por item) antes de
   ir para o Supabase. O Postgres nunca vê texto puro.
4. **Reload da página, fechar a aba, ou bloqueio automático** apagam
   a chave da memória. É proposital — ninguém além de quem sabe a
   senha mestra consegue ler o cofre.

---

## 3. Estrutura de arquivos

```
vault-app/
├── index.html              tela de login / criar cofre
├── vault.html               tela principal (cofre)
├── css/
│   ├── style.css            tokens visuais + tela de login
│   └── vault.css             estilos da tela principal
├── js/
│   ├── config.js             URL e chave do Supabase (você edita)
│   ├── supabase-client.js    inicialização do cliente Supabase
│   ├── crypto.js              PBKDF2 + AES-GCM
│   ├── auth.js                 cadastro / login
│   ├── credentials.js           CRUD + busca + guarda de sessão
│   ├── generator.js              gerador de senhas
│   ├── clipboard.js               limpeza automática da área de transferência
│   ├── import-export.js            importar/exportar Excel
│   ├── backup.js                    backup/restauração em .json
│   ├── autolock.js                   bloqueio automático por inatividade
│   └── settings.js                    troca de senha mestra
└── supabase/
    └── schema.sql            script para rodar no Supabase
```

---

## 4. Configurar o Supabase

1. Crie um projeto gratuito em [supabase.com](https://supabase.com).
2. Vá em **SQL Editor** → cole o conteúdo de `supabase/schema.sql` →
   **Run**. Isso cria as tabelas `vault_config` e `vault_items`, com
   RLS habilitado (cada usuário só enxerga as próprias linhas).
3. Vá em **Authentication → Providers** e confirme que **Email** está
   habilitado (é o único provider usado).
4. (Opcional, recomendado para testes) Em **Authentication → Settings**,
   desative "Confirm email" temporariamente para não depender de um
   servidor de e-mail configurado. Reative em produção.
5. Vá em **Project Settings → API** e copie:
   - **Project URL**
   - **anon public key**
6. Cole os dois valores em `js/config.js`:
   ```js
   window.APP_CONFIG = {
     SUPABASE_URL: "https://SEU-PROJETO.supabase.co",
     SUPABASE_ANON_KEY: "sua-chave-anon-aqui",
     ...
   };
   ```

A chave `anon` é pública por definição — pode ficar exposta no
front-end sem problema. **Nunca** use a `service_role key` aqui.

---

## 5. Rodar localmente

Como é tudo estático, não precisa de servidor Node nem build. Duas
opções simples:

**Opção A — VS Code + extensão Live Server**
Abra a pasta `vault-app` no VS Code, clique com o botão direito em
`index.html` → "Open with Live Server".

**Opção B — Python só para servir arquivos estáticos** (não roda
lógica nenhuma do app, só serve os arquivos — funciona mesmo sem
Python instalado, usando qualquer servidor estático equivalente):
```bash
cd vault-app
python -m http.server 5500
```
Depois abra `http://localhost:5500` no navegador.

> Abrir o `index.html` direto com duplo clique (`file://`) também
> funciona na maior parte dos navegadores modernos, mas alguns
> recursos (Clipboard API, `crypto.subtle`) podem exigir um contexto
> `http://localhost` ou `https://`. Recomendo sempre servir por um
> destes métodos.

---

## 6. Publicar no Netlify

1. Crie uma conta em [netlify.com](https://netlify.com).
2. **Add new site → Deploy manually** e arraste a pasta `vault-app`
   inteira — ou conecte um repositório Git com essa pasta.
3. Não há build command nem diretório de build — é um site 100%
   estático. Se o Netlify pedir, deixe "Build command" vazio e
   "Publish directory" como a raiz do projeto.
4. Pronto — o link gerado (`https://seu-site.netlify.app`) já é o
   cofre funcionando para qualquer pessoa que você compartilhar o
   acesso.

Como toda a lógica sensível roda no navegador de quem acessa, o
Netlify só precisa servir arquivos estáticos — ele nunca vê senha
nenhuma.

---

## 7. Checklist de segurança

- [x] Senha mestra nunca é transmitida nem armazenada — só um hash
      bcrypt de autenticação (Supabase Auth) e um ciphertext de
      verificação (`verifier`), nenhum dos dois reversível para a senha.
- [x] Chave de criptografia derivada com PBKDF2-SHA256, 250.000
      iterações, salt aleatório de 16 bytes por usuário.
- [x] Cada credencial cifrada individualmente com AES-256-GCM
      (autenticado — qualquer adulteração do ciphertext quebra a
      decifragem) e IV aleatório próprio.
- [x] Chave de criptografia gerada como `extractable: false` — não
      pode ser exportada em texto puro nem pelo próprio código.
- [x] Row Level Security no Postgres: cada usuário só lê/escreve as
      próprias linhas, reforçado no banco, não só no front-end.
- [x] Bloqueio automático apaga a chave da memória de verdade
      (não só esconde a tela) após inatividade.
- [x] Área de transferência limpa automaticamente após copiar senha.
- [x] Exportação para Excel exige confirmação explícita, avisando
      que o arquivo gerado não é criptografado.
- [x] Backup contém apenas dados já cifrados — pode ser guardado
      em qualquer lugar sem expor as credenciais.
- [x] Troca de senha mestra re-criptografa todas as credenciais e
      atualiza a senha de login do Supabase Auth junto.
- [ ] **Pendente de você:** ativar "Confirm email" em produção e
      revisar os limites de rate-limit de autenticação do Supabase
      para o seu caso de uso.

### Limitações conhecidas (leia antes de usar em produção)
- A troca de senha mestra **não é atômica**: se a conexão cair no
  meio da re-criptografia de muitas credenciais, alguns itens podem
  ficar cifrados com a chave antiga e outros com a nova. Evite trocar
  a senha mestra com conexão instável.
- Não há recuperação de senha mestra esquecida — é o preço do
  "zero-knowledge": nem o Supabase, nem quem programou isso, consegue
  recuperar uma senha mestra perdida. Recomendo guardar em um lugar
  seguro (papel, cofre físico, outro gerenciador) só como último recurso.
- O app não impede múltiplas abas abertas simultaneamente com chaves
  diferentes na memória — se você trocar a senha mestra em uma aba,
  as outras abas abertas continuam com a chave antiga até recarregar.

---

## 8. Próximos passos possíveis (fora do escopo atual)
- Versão desktop "de verdade" empacotando com Electron (ícone,
  atalho, sem precisar do navegador aberto).
- 2FA no login via Supabase Auth (TOTP).
- Campos customizados por credencial (hoje é um conjunto fixo:
  site, usuário, senha, URL, notas).