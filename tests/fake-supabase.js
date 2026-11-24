/* Supabase SIMULADO para os testes (roda dentro do navegador de teste).
 * Imita o que o app usa: auth (e-mail/senha), tabelas com RLS por usuário, reset de senha e storage.
 * O "servidor" guarda tudo em localStorage (sobrevive a trocas de página) e REGISTRA toda senha que recebe
 * (db.passwordsSeen): é assim que os testes provam que a senha mestra não chega ao servidor.
 * Nunca fala com a rede e nunca toca no seu banco de verdade. */
(() => {
  const KEY = "__fakedb";
  const SESSION = "__fakesession";
  const fresh = () => ({
    users: [],
    tables: { vault_config: [], vault_items: [], vault_projects: [] },
    schema: { itemVersion: true, authVersion: true, projects: true, rpc: true },
    flags: {},
    passwordsSeen: []
  });
  const load = () => JSON.parse(localStorage.getItem(KEY) || "null") || fresh();
  const save = (d) => localStorage.setItem(KEY, JSON.stringify(d));
  const uid = () => {
    try { return JSON.parse(sessionStorage.getItem(SESSION) || "null")?.user?.id || null; } catch { return null; }
  };

  // Storage simulado que SOBREVIVE a recarregar a página (como o de verdade): grava em localStorage em base64.
  const toB64 = (buf) => { let s = ""; const u = new Uint8Array(buf); for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000)); return btoa(s); };
  const persist = async (k, blob) => localStorage.setItem("__fs:" + k, toB64(await blob.arrayBuffer()));
  class PersistMap extends Map {
    set(k, blob) { super.set(k, blob); persist(k, blob); return this; }
    delete(k) { localStorage.removeItem("__fs:" + k); return super.delete(k); }
  }
  if (!window.__fakeStorage) {
    window.__fakeStorage = new PersistMap();
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && k.startsWith("__fs:")) Map.prototype.set.call(window.__fakeStorage, k.slice(5), new Blob([Uint8Array.from(atob(localStorage.getItem(k)), (c) => c.charCodeAt(0))]));
    }
  }

  const COLS = (schema) => ({
    vault_config: ["user_id", "salt", "kdf_iterations", "wrapped_dek", "wrapped_dek_iv", "recovery_wrapped_dek", "recovery_wrapped_dek_iv", "created_at", ...(schema.authVersion ? ["auth_version"] : [])],
    vault_items: ["id", "user_id", "encrypted_data", "iv", "created_at", ...(schema.itemVersion ? ["version", "updated_at"] : [])],
    vault_projects: ["id", "user_id", "encrypted_data", "iv", "version", "created_at", "updated_at"]
  });

  const missingCol = (t, c) => ({ code: "42703", message: `column ${t}.${c} does not exist` });
  const missingTable = (t) => ({ code: "42P01", message: `relation "public.${t}" does not exist` });

  class Query {
    constructor(table) {
      this.table = table;
      this.op = "select";
      this.cols = "*";
      this.filters = [];
      this.ord = null;
      this.max = null;
      this.rows = null;
      this.patch = null;
      this.onConflict = "id";
      this.mode = "many";
    }
    select(cols) { if (this.op === "select") this.cols = cols || "*"; else this.returning = cols || "*"; return this; }
    insert(rows) { this.op = "insert"; this.rows = Array.isArray(rows) ? rows : [rows]; return this; }
    upsert(rows, opts) { this.op = "upsert"; this.rows = Array.isArray(rows) ? rows : [rows]; this.onConflict = (opts && opts.onConflict) || "id"; return this; }
    update(patch) { this.op = "update"; this.patch = patch; return this; }
    delete() { this.op = "delete"; return this; }
    eq(c, v) { this.filters.push([c, v]); return this; }
    order(c, o) { this.ord = [c, !(o && o.ascending === false)]; return this; }
    limit(n) { this.max = n; return this; }
    maybeSingle() { this.mode = "maybe"; return this; }
    single() { this.mode = "single"; return this; }
    then(res, rej) { return Promise.resolve().then(() => this.run()).then(res, rej); }

    run() {
      const db = load();
      const t = this.table;
      const allowed = COLS(db.schema)[t];
      if (!allowed) return { data: null, error: missingTable(t) };
      if (t === "vault_projects" && !db.schema.projects) return { data: null, error: missingTable(t) };
      const me = uid();
      const rows = db.tables[t];
      const own = (r) => me && r.user_id === me;
      const match = (r) => own(r) && this.filters.every(([c, v]) => r[c] === v);
      const pick = (r, cols) => {
        if (!cols || cols === "*") return { ...r };
        const out = {};
        for (const c of cols.split(",").map((s) => s.trim())) out[c] = r[c];
        return out;
      };
      const checkCols = (cols) => {
        if (!cols || cols === "*") return null;
        for (const c of cols.split(",").map((s) => s.trim())) if (!allowed.includes(c)) return missingCol(t, c);
        return null;
      };
      const finish = (list, cols) => {
        const data = list.map((r) => pick(r, cols));
        if (this.mode === "maybe") return { data: data[0] ?? null, error: null };
        if (this.mode === "single") return data.length ? { data: data[0], error: null } : { data: null, error: { message: "no rows", code: "PGRST116" } };
        return { data, error: null };
      };
      const defaults = (r) => {
        const now = new Date().toISOString();
        const out = { ...r };
        if (allowed.includes("id") && !out.id) out.id = crypto.randomUUID();
        if (!out.user_id) out.user_id = me;
        out.created_at ||= now;
        if (t === "vault_items" && db.schema.itemVersion) { out.version ??= 1; out.updated_at ||= now; }
        if (t === "vault_projects") { out.version ??= 2; out.updated_at ||= now; }
        if (t === "vault_config" && db.schema.authVersion) out.auth_version ??= 1;
        return out;
      };
      const validate = (r) => {
        if (!me) return { code: "42501", message: "permission denied" };
        for (const k of Object.keys(r)) if (!allowed.includes(k)) return missingCol(t, k);
        if (r.user_id && r.user_id !== me) return { code: "42501", message: "new row violates row-level security policy" };
        if ((r.encrypted_data || "").length > 262144) return { code: "23514", message: "size" };
        return null;
      };

      if (this.op === "select") {
        const bad = checkCols(this.cols) || this.filters.map(([c]) => (allowed.includes(c) ? null : missingCol(t, c))).find(Boolean);
        if (bad) return { data: null, error: bad };
        let list = rows.filter(match);
        if (this.ord) {
          const [c, asc] = this.ord;
          list = [...list].sort((a, b) => (a[c] > b[c] ? 1 : a[c] < b[c] ? -1 : 0) * (asc ? 1 : -1));
        }
        if (this.max != null) list = list.slice(0, this.max);
        return finish(list, this.cols);
      }

      if (this.op === "insert" || this.op === "upsert") {
        const made = [];
        for (const r of this.rows) {
          const err = validate(r);
          if (err) return { data: null, error: err };
          const row = defaults(r);
          const idx = rows.findIndex((x) => x[this.onConflict] === row[this.onConflict]);
          if (idx >= 0) {
            if (this.op === "insert" || !own(rows[idx])) return { data: null, error: { code: "23505", message: "duplicate key value" } };
            rows[idx] = { ...rows[idx], ...row, created_at: rows[idx].created_at };
          } else {
            rows.push(row);
          }
          made.push(row);
        }
        save(db);
        return finish(made, this.returning || "*");
      }

      if (this.op === "update") {
        for (const k of Object.keys(this.patch)) if (!allowed.includes(k)) return { data: null, error: missingCol(t, k) };
        if (db.flags.failUpdate === t) return { data: null, error: { message: "falha simulada" } };
        const hit = rows.filter(match);
        hit.forEach((r) => Object.assign(r, this.patch));
        save(db);
        return { data: hit, error: null };
      }

      if (this.op === "delete") {
        const keep = rows.filter((r) => !match(r));
        db.tables[t] = keep;
        save(db);
        return { data: null, error: null };
      }
      return { data: null, error: { message: "op?" } };
    }
  }

  function createClient(url, key, opts) {
    const store = (opts && opts.auth && opts.auth.storage) || sessionStorage;
    const mkSession = (user) => ({ access_token: "tok-" + user.id, user: { id: user.id, email: user.email } });
    return {
      auth: {
        async signUp({ email, password }) {
          const db = load();
          db.passwordsSeen.push(password);
          const e = String(email).trim().toLowerCase();
          if (db.users.some((u) => u.email === e)) { save(db); return { data: { user: null, session: null }, error: { message: "User already registered" } }; }
          const user = { id: crypto.randomUUID(), email: e, password };
          db.users.push(user);
          save(db);
          const session = db.flags.confirmEmail ? null : mkSession(user);
          if (session) sessionStorage.setItem(SESSION, JSON.stringify(session));
          return { data: { user: { id: user.id, email: e }, session }, error: null };
        },
        async signInWithPassword({ email, password }) {
          const db = load();
          db.passwordsSeen.push(password);
          save(db);
          const user = db.users.find((u) => u.email === String(email).trim().toLowerCase());
          if (!user || user.password !== password) return { data: { user: null, session: null }, error: { message: "Invalid login credentials" } };
          const session = mkSession(user);
          sessionStorage.setItem(SESSION, JSON.stringify(session));
          return { data: { user: session.user, session }, error: null };
        },
        async getSession() {
          const s = JSON.parse(sessionStorage.getItem(SESSION) || "null");
          return { data: { session: s }, error: null };
        },
        async resetPasswordForEmail(email, opts) {
          const db = load();
          (db.resets ||= []).push({ email: String(email).toLowerCase(), redirectTo: opts && opts.redirectTo });
          save(db);
          return { data: {}, error: null };
        },
        async signOut() { sessionStorage.removeItem(SESSION); return { error: null }; },
        async updateUser({ password }) {
          const db = load();
          const me = uid();
          if (!me) return { data: null, error: { message: "not authenticated" } };
          if (db.flags.failUpdateUser) return { data: null, error: { message: "falha simulada ao trocar a senha de login" } };
          db.passwordsSeen.push(password);
          db.users.find((u) => u.id === me).password = password;
          save(db);
          return { data: { user: { id: me } }, error: null };
        }
      },
      from: (t) => new Query(t),
      rpc: async () => ({ data: null, error: { code: "PGRST202", message: "function not found" } }),
      storage: {
        from: (bucket) => ({
          async upload(path, blob, o) {
            const me = uid();
            if (!me || !String(path).startsWith(me + "/")) return { data: null, error: { message: "new row violates row-level security policy" } };
            if (blob.size > 50 * 1024 * 1024) return { data: null, error: { message: "The object exceeded the maximum allowed size" } };
            if (o && o.contentType && o.contentType !== "application/octet-stream") return { data: null, error: { message: "mime type not supported" } };
            if (window.__fakeStorage.has(bucket + "/" + path)) return { data: null, error: { message: "The resource already exists" } };
            window.__fakeStorage.set(bucket + "/" + path, blob);
            await persist(bucket + "/" + path, blob);
            return { data: { path }, error: null };
          },
          async download(path) {
            const me = uid();
            const b = window.__fakeStorage.get(bucket + "/" + path);
            if (!me || !String(path).startsWith(me + "/") || !b) return { data: null, error: { message: "Object not found" } };
            return { data: b, error: null };
          },
          async remove(paths) {
            const me = uid();
            for (const p of paths) if (me && String(p).startsWith(me + "/")) window.__fakeStorage.delete(bucket + "/" + p);
            return { data: [], error: null };
          }
        })
      }
    };
  }

  window.supabase = { createClient };
})();
