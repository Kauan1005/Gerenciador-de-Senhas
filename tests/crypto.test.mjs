// Testes da criptografia (Node, sem navegador): AES-GCM com AAD, derivação separada de login e cifra, arquivos em blocos,
// integridade e as bibliotecas locais (SRI).
import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { ROOT, done, ok } from "./lib.mjs";

const C = createRequire(import.meta.url)("../js/crypto.js");
const IT = 100000; // mínimo aceito (rápido para teste)
console.log("\n== Criptografia");

// ---------------- derivação e AES-GCM
const salt = C.generateSaltBase64();
const key = await C.deriveKey("Senha-Mestra-De-Teste-1", salt, IT);
const key2 = await C.deriveKey("Senha-Mestra-De-Teste-1", salt, IT);
const wrong = await C.deriveKey("outra-senha-qualquer-12", salt, IT);
const v = await C.createVerifier(key);
ok(await C.checkVerifier(key2, v.verifier, v.verifier_iv), "a mesma senha e o mesmo sal derivam a mesma chave (verificador abre)");
ok(!(await C.checkVerifier(wrong, v.verifier, v.verifier_iv)), "senha errada não abre o verificador");
let threw = false;
try { await C.deriveKey("x", salt, 1000); } catch { threw = true; }
ok(threw, "iterações abaixo do piso (servidor malicioso) são recusadas");
ok(key.extractable === false, "a chave do cofre não é exportável");

const userA = "11111111-1111-4111-8111-111111111111";
const userB = "22222222-2222-4222-8222-222222222222";
const idA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const idB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const aad = C.aadFor(2, userA, "item", idA);
const enc = await C.encryptJSON(key, { title: "Gmail", password: "p@ss" }, aad);
ok((await C.decryptJSON(key, enc.ciphertext, enc.iv, aad)).title === "Gmail", "v2: cifra e decifra com o mesmo AAD");
for (const [name, a] of [["outro id de registro", C.aadFor(2, userA, "item", idB)], ["outro usuário", C.aadFor(2, userB, "item", idA)], ["outro tipo (projeto)", C.aadFor(2, userA, "project", idA)], ["sem AAD", undefined]]) {
  let bad = false;
  try { await C.decryptJSON(key, enc.ciphertext, enc.iv, a); } catch { bad = true; }
  ok(bad, `v2: o blob trocado de lugar não decifra (${name})`);
}
const legacy = await C.encryptJSON(key, { title: "Antigo" }); // versão 1: sem AAD
ok((await C.decryptJSON(key, legacy.ciphertext, legacy.iv, C.aadFor(1, userA, "item", idA))).title === "Antigo", "v1 (contas antigas) continua abrindo, sem AAD");
const e2 = await C.encryptJSON(key, { a: 1 }, aad);
ok(enc.iv !== e2.iv, "cada cifragem usa um IV novo");
const tampered = C.bufToBase64(Uint8Array.from(new Uint8Array(C.base64ToBuf(enc.ciphertext)), (b, i) => (i === 3 ? b ^ 1 : b)));
let t = false;
try { await C.decryptJSON(key, tampered, enc.iv, aad); } catch { t = true; }
ok(t, "um bit alterado no blob faz a decifragem falhar (autenticidade)");

// ---------------- segredo de login separado da chave do cofre
const s1 = await C.deriveAuthSecret("Senha-Mestra-De-Teste-1", "Fulano@Exemplo.com", IT);
const s2 = await C.deriveAuthSecret("Senha-Mestra-De-Teste-1", "  fulano@exemplo.com ", IT);
const s3 = await C.deriveAuthSecret("Senha-Mestra-De-Teste-1", "outro@exemplo.com", IT);
const s4 = await C.deriveAuthSecret("Senha-Mestra-De-Teste-2", "fulano@exemplo.com", IT);
ok(s1 === s2, "o segredo de login ignora maiúsculas e espaços do e-mail");
ok(s1 !== s3 && s1 !== s4, "muda com o e-mail e com a senha");
ok(!s1.includes("Senha-Mestra") && s1 !== "Senha-Mestra-De-Teste-1" && C.base64ToBuf(s1).byteLength === 32, "não contém a senha mestra e tem 256 bits");

// ---------------- senha mestra
ok(C.MIN_MASTER_LENGTH === 5 && C.masterPasswordProblem("abcd") !== null, "senha mestra com menos de 5 caracteres é recusada");
ok(C.masterPasswordProblem("abcde") === null && C.masterPasswordProblem("12345") === null, "com 5 caracteres a senha é aceita");
ok(C.masterPasswordProblem("aaaaaaaaaaaaaaaa") !== null, "um único caractere repetido é recusado");
ok(C.masterPasswordProblem("123456789012") !== null, "senha conhecida é recusada");
ok(C.masterPasswordProblem("Cavalo-Grampo-Bateria-9") === null, "uma boa frase-senha é aceita");

// ---------------- arquivos em blocos
const FEK = await C.generateFileKey();
const fk = await C.importFileKey(FEK);
const base = `cofre/v2|${userA}|file|p1/f1`;
const sizes = [0, 1, 1024, C.FILE_CHUNK_BYTES, C.FILE_CHUNK_BYTES + 1, 2 * C.FILE_CHUNK_BYTES + 12345];
for (const size of sizes) {
  const data = randomBytes(size);
  const { blob, sha256, size: sz } = await C.encryptFile(new Blob([data]), fk, base);
  const plain = Buffer.from(await (await C.decryptFile(blob, fk, base, "application/zip")).arrayBuffer());
  ok(plain.equals(data) && sz === size && sha256 === createHash("sha256").update(data).digest("hex"), `arquivo de ${size} bytes: ida e volta idêntica e SHA-256 correto`);
}

const sample = randomBytes(2 * C.FILE_CHUNK_BYTES + 777);
const { blob: encFile } = await C.encryptFile(new Blob([sample]), fk, base);
const raw = Buffer.from(await encFile.arrayBuffer());
const failsWith = async (buf, aadBase = base, k = fk) => {
  try { await C.decryptFile(new Blob([buf]), k, aadBase); return false; } catch { return true; }
};
ok(!raw.includes(sample.subarray(0, 64)), "o arquivo cifrado não contém o conteúdo original");
const flipped = Buffer.from(raw); flipped[flipped.length - 20] ^= 1;
ok(await failsWith(flipped), "um byte alterado no meio do arquivo é detectado");
ok(await failsWith(raw.subarray(0, raw.length - 40)), "arquivo truncado (último bloco cortado) é detectado");
const step = C.FILE_CHUNK_BYTES + 16;
const swapped = Buffer.concat([raw.subarray(0, 16), raw.subarray(16 + step, 16 + 2 * step), raw.subarray(16, 16 + step), raw.subarray(16 + 2 * step)]);
ok(await failsWith(swapped), "blocos trocados de ordem são detectados");
ok(await failsWith(Buffer.concat([raw, raw.subarray(16, 16 + step)])), "bloco extra acrescentado é detectado");
ok(await failsWith(raw, `cofre/v2|${userB}|file|p1/f1`), "arquivo de outro usuário não decifra com o AAD errado");
ok(await failsWith(raw, base, await C.importFileKey(await C.generateFileKey())), "chave errada não decifra");
ok(await failsWith(Buffer.from("isto não é um arquivo cifrado do cofre")), "arquivo que não é do cofre é recusado");

// ---------------- bibliotecas locais com SRI
const sri = (f) => "sha384-" + createHash("sha384").update(readFileSync(join(ROOT, f))).digest("base64");
const html = ["index.html", "vault.html", "projects.html"].map((f) => readFileSync(join(ROOT, f), "utf8")).join("\n");
ok(!/https?:\/\/(?!www\.w3\.org)[^"' ]+\.js/.test(html), "nenhuma página carrega JavaScript de fora do próprio site");
ok(html.includes(sri("vendor/supabase-js-2.119.0.umd.js")), "SRI do supabase-js confere com o arquivo local");
ok(html.includes(sri("vendor/xlsx-0.20.3.full.min.js")), "SRI do SheetJS confere com o arquivo local");
ok(/xlsx-0\.20\.3/.test(html) && !/xlsx@0\.18/.test(html), "SheetJS 0.20.3 (a 0.18.5 tinha falhas conhecidas) no lugar da antiga");
ok(!/\son[a-z]+="/i.test(html) && !/<script(?![^>]*\ssrc=)[^>]*>/i.test(html), "sem scripts nem manipuladores de evento inline (compatível com a CSP)");

done("Criptografia");
