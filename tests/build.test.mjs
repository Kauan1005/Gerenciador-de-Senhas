// Testa scripts/build.mjs: o que vai para dist/ e a trava contra chave de serviço no site.
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { ROOT, done, ok } from "./lib.mjs";

console.log("\n== Build (dist/)");
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (role) => `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ iss: "supabase", role })}.assinatura`;
const run = (env) => spawnSync(process.execPath, [join(ROOT, "scripts", "build.mjs")], { cwd: ROOT, env: { PATH: process.env.PATH, ...env }, encoding: "utf8" });
const dist = join(ROOT, "dist");
rmSync(dist, { recursive: true, force: true });

const good = run({ SUPABASE_URL: "https://abcdefghij.supabase.co", SUPABASE_ANON_KEY: jwt("anon") });
ok(good.status === 0 && existsSync(join(dist, "vault.html")), "o build com a chave pública (anon) funciona");

const files = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? files(join(dir, e.name)).map((f) => e.name + "/" + f) : [e.name]));
const all = files(dist);
ok(["index.html", "vault.html", "projects.html", "js/config.js", "js/crypto.js", "js/projects.js", "vendor/supabase-js-2.119.0.umd.js", "vendor/xlsx-0.20.3.full.min.js", "_headers"].every((f) => all.includes(f)), "dist/ tem as páginas, os scripts, as bibliotecas locais e os cabeçalhos");
ok(!all.some((f) => /README|SECURITY|schema\.sql|config\.example|^tests\/|^scripts\/|^supabase\/|\.git/.test(f)), "dist/ NÃO tem README, SQL, scripts, testes nem arquivos de exemplo");
const headers = readFileSync(join(dist, "_headers"), "utf8");
ok(headers.includes("connect-src 'self' https://abcdefghij.supabase.co") && !headers.includes("__SUPABASE_HOST__"), "a CSP recebe o host do seu projeto Supabase");
const cfg = readFileSync(join(dist, "js", "config.js"), "utf8");
ok(cfg.includes("abcdefghij.supabase.co") && /"KDF_ITERATIONS": 600000/.test(cfg) && /"LEGACY_LOGIN": true/.test(cfg) && /"SESSION_STORE": "tab"/.test(cfg), "o config.js gerado traz os padrões seguros (600 mil iterações, sessão só na aba)");

const svc = run({ SUPABASE_URL: "https://abcdefghij.supabase.co", SUPABASE_ANON_KEY: jwt("service_role") });
ok(svc.status !== 0 && /service_role/.test(svc.stderr) && !existsSync(join(dist, "js", "config.js")), "chave com papel service_role é RECUSADA (e dist/ não é gerado)");
const sec = run({ SUPABASE_URL: "https://abcdefghij.supabase.co", SUPABASE_ANON_KEY: "sb_secret_abc123" });
ok(sec.status !== 0 && /SECRETA/.test(sec.stderr), "chave sb_secret_ é RECUSADA");
const http = run({ SUPABASE_URL: "http://abcdefghij.supabase.co", SUPABASE_ANON_KEY: jwt("anon") });
ok(http.status !== 0 && /https/.test(http.stderr), "URL do Supabase sem https é recusada");
const none = run({});
ok(none.status !== 0 || existsSync(join(ROOT, "js", "config.js")), "sem variáveis (e sem js/config.js) o build para com uma mensagem clara");

rmSync(dist, { recursive: true, force: true });
done("Build");
