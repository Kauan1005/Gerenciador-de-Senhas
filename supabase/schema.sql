-- ============================================================
-- COFRE: esquema do banco (Supabase / Postgres)
-- ============================================================
-- Como usar: Supabase > SQL Editor > colar este arquivo inteiro > Run.
--
-- É IDEMPOTENTE e NÃO APAGA DADOS: pode rodar sobre o banco que já tem
-- credenciais guardadas e pode rodar de novo quando quiser. Ele só
-- cria o que falta e REDEFINE as regras de acesso (RLS) para as
-- tabelas do cofre, removendo qualquer regra antiga mais frouxa.
--
-- O que ele garante:
--   vault_config   (1 linha por usuário: sal, iterações, chave do cofre (DEK) embrulhada pela senha mestra e pela chave de recuperação)
--   vault_items    (credenciais já cifradas no navegador)
--   vault_projects (projetos já cifrados no navegador)  <- NOVO
--   bucket privado "project-files" (arquivos cifrados dos projetos) <- NOVO
--   RLS: cada usuário só enxerga e altera as PRÓPRIAS linhas/arquivos.
--
-- Nada aqui guarda texto puro: o servidor só vê blobs cifrados.
-- ============================================================

-- ------------------------------------------------------------
-- 1) vault_config
-- ------------------------------------------------------------
create table if not exists public.vault_config (
  user_id        uuid primary key references auth.users (id) on delete cascade default auth.uid(),
  salt           text    not null,
  kdf_iterations integer not null,
  wrapped_dek             text not null,
  wrapped_dek_iv          text not null,
  recovery_wrapped_dek    text,
  recovery_wrapped_dek_iv text,
  auth_version   smallint not null default 1,
  created_at     timestamptz not null default now()
);

-- bancos criados antes: estas colunas já existem (formato com DEK + chave de recuperação); só garante as novas
alter table public.vault_config add column if not exists auth_version smallint not null default 1;
alter table public.vault_config add column if not exists created_at timestamptz not null default now();
alter table public.vault_config alter column user_id set default auth.uid();

do $$
begin
  -- piso de custo de derivação (vale para linhas novas/alteradas; linhas antigas não são rejeitadas)
  if not exists (select 1 from pg_constraint where conname = 'vault_config_kdf_min') then
    alter table public.vault_config add constraint vault_config_kdf_min check (kdf_iterations >= 100000) not valid;
  end if;
end $$;

-- ------------------------------------------------------------
-- 2) vault_items
-- ------------------------------------------------------------
create table if not exists public.vault_items (
  id             uuid primary key default gen_random_uuid(),
  user_id        uuid not null references auth.users (id) on delete cascade default auth.uid(),
  encrypted_data text not null,
  iv             text not null,
  version        smallint not null default 1,
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now()
);

-- version: 1 = formato antigo (sem AAD); 2 = formato novo (AAD liga o blob ao usuário e ao id)
alter table public.vault_items add column if not exists version smallint not null default 1;
alter table public.vault_items add column if not exists updated_at timestamptz not null default now();
alter table public.vault_items alter column user_id set default auth.uid();

create index if not exists vault_items_user_idx on public.vault_items (user_id);

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'vault_items_size') then
    alter table public.vault_items add constraint vault_items_size
      check (octet_length(encrypted_data) <= 262144 and octet_length(iv) <= 64) not valid;
  end if;
end $$;

-- ------------------------------------------------------------
-- 3) vault_projects (NOVO)
-- ------------------------------------------------------------
create table if not exists public.vault_projects (
  id             uuid primary key default gen_random_uuid(),
  user_id        uuid not null references auth.users (id) on delete cascade default auth.uid(),
  encrypted_data text not null,
  iv             text not null,
  version        smallint not null default 2,
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now(),
  constraint vault_projects_size check (octet_length(encrypted_data) <= 262144 and octet_length(iv) <= 64)
);

create index if not exists vault_projects_user_idx on public.vault_projects (user_id);

-- ------------------------------------------------------------
-- 4) updated_at automático
-- ------------------------------------------------------------
create or replace function public.cofre_touch_updated_at()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

drop trigger if exists vault_items_touch on public.vault_items;
create trigger vault_items_touch before update on public.vault_items
  for each row execute function public.cofre_touch_updated_at();

drop trigger if exists vault_projects_touch on public.vault_projects;
create trigger vault_projects_touch before update on public.vault_projects
  for each row execute function public.cofre_touch_updated_at();

-- ------------------------------------------------------------
-- 5) RLS: cada usuário só mexe nas próprias linhas
-- ------------------------------------------------------------
alter table public.vault_config   enable row level security;
alter table public.vault_items    enable row level security;
alter table public.vault_projects enable row level security;

-- remove QUALQUER regra antiga destas tabelas (regras permissivas somam-se; aqui valem só as de baixo)
do $$
declare r record;
begin
  for r in
    select policyname, tablename from pg_policies
    where schemaname = 'public' and tablename in ('vault_config', 'vault_items', 'vault_projects')
  loop
    execute format('drop policy if exists %I on public.%I', r.policyname, r.tablename);
  end loop;
end $$;

-- vault_config: ler, criar e alterar a própria. Sem DELETE (apagar a configuração deixaria o cofre ilegível).
create policy "cofre config: ler a propria" on public.vault_config
  for select to authenticated using ((select auth.uid()) = user_id);
create policy "cofre config: criar a propria" on public.vault_config
  for insert to authenticated with check ((select auth.uid()) = user_id);
create policy "cofre config: alterar a propria" on public.vault_config
  for update to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);

create policy "cofre itens: ler os proprios" on public.vault_items
  for select to authenticated using ((select auth.uid()) = user_id);
create policy "cofre itens: criar os proprios" on public.vault_items
  for insert to authenticated with check ((select auth.uid()) = user_id);
create policy "cofre itens: alterar os proprios" on public.vault_items
  for update to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "cofre itens: apagar os proprios" on public.vault_items
  for delete to authenticated using ((select auth.uid()) = user_id);

create policy "cofre projetos: ler os proprios" on public.vault_projects
  for select to authenticated using ((select auth.uid()) = user_id);
create policy "cofre projetos: criar os proprios" on public.vault_projects
  for insert to authenticated with check ((select auth.uid()) = user_id);
create policy "cofre projetos: alterar os proprios" on public.vault_projects
  for update to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "cofre projetos: apagar os proprios" on public.vault_projects
  for delete to authenticated using ((select auth.uid()) = user_id);

-- sem login (papel anon) não há acesso nenhum
revoke all on public.vault_config   from anon;
revoke all on public.vault_items    from anon;
revoke all on public.vault_projects from anon;
grant select, insert, update          on public.vault_config   to authenticated;
grant select, insert, update, delete  on public.vault_items    to authenticated;
grant select, insert, update, delete  on public.vault_projects to authenticated;

-- ------------------------------------------------------------
-- 6) limpeza: versão anterior deste arquivo criava rotate_vault(); a troca de senha agora só re-embrulha a DEK
-- ------------------------------------------------------------
drop function if exists public.rotate_vault(jsonb, jsonb, jsonb);

-- ------------------------------------------------------------
-- 7) Storage: bucket privado para os arquivos cifrados dos projetos
-- ------------------------------------------------------------
-- Os arquivos já chegam cifrados (application/octet-stream) e com nome aleatório:
--   <id do usuário>/<id do projeto>/<id do arquivo>.bin
-- Limite de 50 MB por arquivo (o teto do plano gratuito do Supabase).
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('project-files', 'project-files', false, 52428800, array['application/octet-stream'])
on conflict (id) do update
  set public = false,
      file_size_limit = excluded.file_size_limit,
      allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "cofre arquivos: ler os proprios"    on storage.objects;
drop policy if exists "cofre arquivos: enviar os proprios" on storage.objects;
drop policy if exists "cofre arquivos: apagar os proprios" on storage.objects;

create policy "cofre arquivos: ler os proprios" on storage.objects
  for select to authenticated
  using (bucket_id = 'project-files' and (storage.foldername(name))[1] = (select auth.uid())::text);
create policy "cofre arquivos: enviar os proprios" on storage.objects
  for insert to authenticated
  with check (bucket_id = 'project-files' and (storage.foldername(name))[1] = (select auth.uid())::text);
create policy "cofre arquivos: apagar os proprios" on storage.objects
  for delete to authenticated
  using (bucket_id = 'project-files' and (storage.foldername(name))[1] = (select auth.uid())::text);

-- ------------------------------------------------------------
-- Conferência (opcional): rode depois, separado, para ver o resultado
-- ------------------------------------------------------------
-- select tablename, rowsecurity from pg_tables where schemaname = 'public' and tablename like 'vault_%';
-- select tablename, policyname, cmd, roles from pg_policies where schemaname = 'public' and tablename like 'vault_%' order by 1, 3;
-- select id, public, file_size_limit from storage.buckets where id = 'project-files';
