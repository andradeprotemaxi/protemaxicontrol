-- =====================================================================
-- CENTRAL OPERACIONAL — banco de dados (Supabase)
-- Cole tudo no Supabase → SQL Editor → Run. Pode rodar de novo sem erro.
-- Quem não está logado só LÊ. Gravar exige usuário + PIN válidos e
-- a permissão certa (o admin pode tudo). PIN fica criptografado.
-- =====================================================================
create extension if not exists pgcrypto with schema extensions;

create table if not exists public.usuarios (
  id text primary key,
  nome text not null,
  login text unique not null,
  pin_hash text not null,
  papel text not null default 'operador',
  permissoes jsonb not null default '[]'::jsonb,
  foto text default '',
  ativo boolean not null default true,
  criado timestamptz default now()
);

create table if not exists public.registros (
  tipo text not null,
  id text not null,
  dados jsonb not null default '{}'::jsonb,
  atualizado timestamptz default now(),
  primary key (tipo, id)
);

alter table public.usuarios enable row level security;   -- ninguém lê direto (protege o PIN)
alter table public.registros enable row level security;

drop policy if exists "leitura publica" on public.registros;
create policy "leitura publica" on public.registros for select to anon, authenticated using (true);

-- ---------- funções internas ----------
create or replace function public._usuario_valido(p_login text, p_pin text)
returns public.usuarios language sql stable security definer set search_path = public, extensions as $$
  select * from public.usuarios
  where lower(login) = lower(p_login) and ativo and pin_hash = extensions.crypt(p_pin, pin_hash)
  limit 1
$$;

create or replace function public._pode(p_papel text, p_perm jsonb, p_tipo text)
returns boolean language sql immutable as $$
  select case
    when p_papel = 'admin' then true
    when p_tipo = 'sessao' then true
    when p_tipo in ('os','segware','importacao') then p_perm ? 'os'
    when p_tipo = 'cliente' then p_perm ? 'clientes'
    when p_tipo = 'arquivo' then p_perm ? 'arquivos'
    when p_tipo like 'coord\_%' then p_perm ? 'coordenador'
    when p_tipo like 'rel\_%' then p_perm ? 'coordenador'
    else false   -- tarefa, check, config: só admin
  end
$$;

revoke all on function public._usuario_valido(text, text) from public, anon, authenticated;

-- ---------- funções chamadas pelo app ----------
create or replace function public.rpc_usuarios()
returns json language sql stable security definer set search_path = public as $$
  select coalesce(json_agg(json_build_object('id',id,'nome',nome,'login',login,'papel',papel,
    'permissoes',permissoes,'foto',foto,'ativo',ativo) order by nome), '[]'::json)
  from public.usuarios
$$;

create or replace function public.rpc_login(p_login text, p_pin text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare u public.usuarios;
begin
  u := public._usuario_valido(p_login, p_pin);
  if u.id is null then return null; end if;
  return json_build_object('id',u.id,'nome',u.nome,'login',u.login,'papel',u.papel,
    'permissoes',u.permissoes,'foto',u.foto,'ativo',u.ativo);
end $$;

create or replace function public.rpc_salvar(p_login text, p_pin text, p_tipo text, p_id text, p_dados jsonb)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
declare u public.usuarios;
begin
  u := public._usuario_valido(p_login, p_pin);
  if u.id is null or not public._pode(u.papel, u.permissoes, p_tipo) then
    raise exception 'sem permissao';
  end if;
  insert into public.registros(tipo, id, dados, atualizado) values (p_tipo, p_id, p_dados, now())
  on conflict (tipo, id) do update set dados = excluded.dados, atualizado = now();
  return true;
end $$;

create or replace function public.rpc_salvar_lote(p_login text, p_pin text, p_itens jsonb)
returns integer language plpgsql security definer set search_path = public, extensions as $$
declare u public.usuarios; it jsonb; n integer := 0;
begin
  u := public._usuario_valido(p_login, p_pin);
  if u.id is null then raise exception 'sem permissao'; end if;
  for it in select * from jsonb_array_elements(p_itens) loop
    if not public._pode(u.papel, u.permissoes, it->>'tipo') then raise exception 'sem permissao'; end if;
    insert into public.registros(tipo, id, dados, atualizado) values (it->>'tipo', it->>'id', it->'dados', now())
    on conflict (tipo, id) do update set dados = excluded.dados, atualizado = now();
    n := n + 1;
  end loop;
  return n;
end $$;

create or replace function public.rpc_excluir(p_login text, p_pin text, p_tipo text, p_id text)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
declare u public.usuarios;
begin
  u := public._usuario_valido(p_login, p_pin);
  if u.id is null or not public._pode(u.papel, u.permissoes, p_tipo) or p_tipo = 'sessao' then
    raise exception 'sem permissao';
  end if;
  delete from public.registros where tipo = p_tipo and id = p_id;
  return true;
end $$;

create or replace function public.rpc_usuario_salvar(p_login text, p_pin text, p_user jsonb)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
declare u public.usuarios;
begin
  u := public._usuario_valido(p_login, p_pin);
  if u.id is null or u.papel <> 'admin' then raise exception 'sem permissao'; end if;
  insert into public.usuarios(id, nome, login, pin_hash, papel, permissoes, foto, ativo)
  values (p_user->>'id', p_user->>'nome', lower(p_user->>'login'),
          extensions.crypt(coalesce(nullif(p_user->>'pin',''), gen_random_uuid()::text), extensions.gen_salt('bf')),
          coalesce(p_user->>'papel','operador'), coalesce(p_user->'permissoes','[]'::jsonb),
          coalesce(p_user->>'foto',''), coalesce((p_user->>'ativo')::boolean, true))
  on conflict (id) do update set
    nome = excluded.nome, login = excluded.login, papel = excluded.papel,
    permissoes = excluded.permissoes, foto = excluded.foto, ativo = excluded.ativo,
    pin_hash = case when coalesce(p_user->>'pin','') <> '' then excluded.pin_hash else public.usuarios.pin_hash end;
  return true;
end $$;

create or replace function public.rpc_usuario_excluir(p_login text, p_pin text, p_id text)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
declare u public.usuarios;
begin
  u := public._usuario_valido(p_login, p_pin);
  if u.id is null or u.papel <> 'admin' or u.id = p_id then raise exception 'sem permissao'; end if;
  delete from public.usuarios where id = p_id;
  return true;
end $$;

grant execute on function public.rpc_usuarios(), public.rpc_login(text,text),
  public.rpc_salvar(text,text,text,text,jsonb), public.rpc_salvar_lote(text,text,jsonb),
  public.rpc_excluir(text,text,text,text), public.rpc_usuario_salvar(text,text,jsonb),
  public.rpc_usuario_excluir(text,text,text) to anon, authenticated;

-- ---------- administrador inicial (TROQUE O PIN depois de entrar) ----------
insert into public.usuarios(id, nome, login, pin_hash, papel)
values ('u_admin', 'Andrade', 'andrade', extensions.crypt('1234', extensions.gen_salt('bf')), 'admin')
on conflict (id) do nothing;

insert into public.registros(tipo, id, dados) values ('config', 'geral', '{"sla":3,"empresa":"Protemaxi"}')
on conflict do nothing;

-- ---------- tempo real (painel atualiza sozinho em todas as telas) ----------
do $$ begin
  alter publication supabase_realtime add table public.registros;
exception when duplicate_object then null; end $$;

-- ---------- arquivos (qualquer formato) ----------
insert into storage.buckets (id, name, public) values ('arquivos', 'arquivos', true)
on conflict (id) do nothing;
drop policy if exists "arquivos enviar" on storage.objects;
create policy "arquivos enviar" on storage.objects for insert to anon, authenticated with check (bucket_id = 'arquivos');
drop policy if exists "arquivos ler" on storage.objects;
create policy "arquivos ler" on storage.objects for select to anon, authenticated using (bucket_id = 'arquivos');
