// Capturas das páginas estáticas (recuperação e privacidade).
import { join } from "node:path";
import { ROOT, launch, startServer } from "./lib.mjs";
const server = await startServer();
const br = await launch();
try {
  const c = await br.newContext({ viewport: { width: 1280, height: 800 } });
  await c.route("**/vendor/supabase-js-*.js", (r) => r.abort());
  const p = await c.newPage();
  for (const name of ["recovery", "privacidade"]) {
    await p.goto(server.url + "/" + name + ".html");
    await p.screenshot({ path: join(ROOT, "tests", "shots", name + ".png") });
  }
} finally {
  await br.close();
  await server.close();
}
