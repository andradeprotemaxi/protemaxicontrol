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
    when p_tipo in ('chat','nota') then true   -- qualquer usuário logado (só mexe no que é seu)
    when p_tipo in ('os','segware','importacao') then p_perm ? 'os'
    when p_tipo = 'cliente' then p_perm ? 'clientes'
    when p_tipo = 'arquivo' then p_perm ? 'arquivos'
    when p_tipo like 'coord\_%' then p_perm ? 'coordenador'
    when p_tipo like 'rel\_%' then p_perm ? 'coordenador'
    else false   -- tarefa, check, config: só admin
  end
$$;

revoke all on function public._usuario_valido(text, text) from public, anon, authenticated;

-- chat e anotações: cada um só grava/apaga o que é seu (o id começa com o id do usuário). Admin pode tudo.
create or replace function public._dono_ok(p_uid text, p_papel text, p_tipo text, p_id text)
returns boolean language sql immutable as $$
  select p_papel = 'admin' or p_tipo not in ('chat','nota') or split_part(p_id, ':', 1) = p_uid
$$;

-- ---------- funções chamadas pelo app ----------
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
  if u.id is null or not public._pode(u.papel, u.permissoes, p_tipo) or not public._dono_ok(u.id, u.papel, p_tipo, p_id) then
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
    if not public._pode(u.papel, u.permissoes, it->>'tipo') or not public._dono_ok(u.id, u.papel, it->>'tipo', it->>'id') then raise exception 'sem permissao'; end if;
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
  if u.id is null or not public._pode(u.papel, u.permissoes, p_tipo) or p_tipo = 'sessao' or not public._dono_ok(u.id, u.papel, p_tipo, p_id) then
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

grant execute on function public.rpc_login(text,text),
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

-- =====================================================================
-- SEGURANÇA v2 (19/11/2026): dados só para quem está logado,
-- dashboard público só com números, pedidos de acesso com aprovação do admin
-- =====================================================================
alter table public.usuarios add column if not exists pendente boolean not null default false;
alter table public.usuarios add column if not exists obs text default '';
create table if not exists public.registros_excluidos (tipo text not null, id text not null, em timestamptz default now(), primary key (tipo, id));
alter table public.registros_excluidos enable row level security;
create index if not exists registros_atualizado_idx on public.registros(atualizado);

-- ninguém lê a tabela direto (nem com a chave pública): só pelas funções abaixo
drop policy if exists "leitura publica" on public.registros;
-- arquivos: o link de cada arquivo continua abrindo, mas ninguém lista a pasta
drop policy if exists "arquivos ler" on storage.objects;

-- lista de usuários só para quem está logado
drop function if exists public.rpc_usuarios();
create or replace function public.rpc_usuarios(p_login text, p_pin text)
returns json language plpgsql stable security definer set search_path = public, extensions as $$
declare u public.usuarios;
begin
  u := public._usuario_valido(p_login, p_pin);
  if u.id is null then raise exception 'sem permissao'; end if;
  return (select coalesce(json_agg(json_build_object('id',id,'nome',nome,'login',login,'papel',papel,
    'permissoes',permissoes,'foto',foto,'ativo',ativo,'pendente',pendente,'obs',obs) order by nome), '[]'::json)
    from public.usuarios where u.papel = 'admin' or not pendente);
end $$;

-- dados completos (ou só o que mudou desde p_desde) para quem está logado
create or replace function public.rpc_sync(p_login text, p_pin text, p_desde timestamptz)
returns json language plpgsql stable security definer set search_path = public, extensions as $$
declare u public.usuarios;
begin
  u := public._usuario_valido(p_login, p_pin);
  if u.id is null then raise exception 'sem permissao'; end if;
  return json_build_object(
    'agora', now() - interval '10 seconds',
    'regs', (select coalesce(json_agg(json_build_object('tipo',tipo,'id',id,'dados',dados)), '[]'::json)
             from public.registros where p_desde is null or atualizado > p_desde),
    'dels', (select coalesce(json_agg(json_build_object('tipo',tipo,'id',id)), '[]'::json)
             from public.registros_excluidos where p_desde is not null and em > p_desde));
end $$;

-- excluir: guarda o registro do que foi apagado para as outras telas saberem
create or replace function public.rpc_excluir(p_login text, p_pin text, p_tipo text, p_id text)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
declare u public.usuarios;
begin
  u := public._usuario_valido(p_login, p_pin);
  if u.id is null or not public._pode(u.papel, u.permissoes, p_tipo) or p_tipo = 'sessao' or not public._dono_ok(u.id, u.papel, p_tipo, p_id) then
    raise exception 'sem permissao';
  end if;
  delete from public.registros where tipo = p_tipo and id = p_id;
  insert into public.registros_excluidos(tipo, id, em) values (p_tipo, p_id, now())
  on conflict (tipo, id) do update set em = now();
  return true;
end $$;

-- admin salva usuário (aprovar pedido = salvar com pendente false)
create or replace function public.rpc_usuario_salvar(p_login text, p_pin text, p_user jsonb)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
declare u public.usuarios;
begin
  u := public._usuario_valido(p_login, p_pin);
  if u.id is null or u.papel <> 'admin' then raise exception 'sem permissao'; end if;
  insert into public.usuarios(id, nome, login, pin_hash, papel, permissoes, foto, ativo, pendente)
  values (p_user->>'id', p_user->>'nome', lower(p_user->>'login'),
          extensions.crypt(coalesce(nullif(p_user->>'pin',''), gen_random_uuid()::text), extensions.gen_salt('bf')),
          coalesce(p_user->>'papel','operador'), coalesce(p_user->'permissoes','[]'::jsonb),
          coalesce(p_user->>'foto',''), coalesce((p_user->>'ativo')::boolean, true), false)
  on conflict (id) do update set
    nome = excluded.nome, login = excluded.login, papel = excluded.papel,
    permissoes = excluded.permissoes, foto = excluded.foto, ativo = excluded.ativo,
    pendente = coalesce((p_user->>'pendente')::boolean, false),
    pin_hash = case when coalesce(p_user->>'pin','') <> '' then excluded.pin_hash else public.usuarios.pin_hash end;
  return true;
end $$;

-- pedido de acesso (tela de login): entra bloqueado até o admin autorizar
create or replace function public.rpc_solicitar(p_nome text, p_login text, p_pin text, p_obs text)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
begin
  p_nome := left(trim(coalesce(p_nome,'')), 80); p_login := lower(left(trim(coalesce(p_login,'')), 40));
  if length(p_nome) < 2 or p_login !~ '^[a-z0-9._-]{3,40}$' then raise exception 'dados invalidos'; end if;
  if coalesce(p_pin,'') !~ '^[0-9]{4,8}$' then raise exception 'pin invalido'; end if;
  if exists (select 1 from public.usuarios where lower(login) = p_login) then raise exception 'usuario ja existe'; end if;
  if (select count(*) from public.usuarios where pendente) >= 20 then raise exception 'muitos pedidos pendentes'; end if;
  insert into public.usuarios(id, nome, login, pin_hash, papel, permissoes, ativo, pendente, obs)
  values ('u_' || substr(md5(random()::text || clock_timestamp()::text), 1, 12), p_nome, p_login,
          extensions.crypt(p_pin, extensions.gen_salt('bf')), 'visitante', '[]'::jsonb, false, true, left(coalesce(p_obs,''), 200));
  return true;
end $$;

-- dashboard público: só números agregados, sem nomes de clientes
create or replace function public.rpc_publico()
returns json language sql stable security definer set search_path = public as $$
  with p as (select (now() at time zone 'America/Fortaleza')::date hoje,
                    coalesce(nullif((select (dados->>'sla')::int from public.registros where tipo='config' and id='geral'), 0), 3) sla),
  os as (
    select dados->>'status' st,
           case when dados->>'abertura' ~ '^\d{4}-\d{2}-\d{2}' then left(dados->>'abertura',10)::date end ab,
           case when dados->>'prazo' ~ '^\d{4}-\d{2}-\d{2}' then left(dados->>'prazo',10)::date end pr,
           case when dados->>'conclusao' ~ '^\d{4}-\d{2}-\d{2}' then left(dados->>'conclusao',10)::date end co
    from public.registros where tipo = 'os'),
  cl as (select id, dados->>'categoria' cat, nullif(dados->>'grupo','') grp from public.registros where tipo = 'cliente')
  select json_build_object(
    'hoje', p.hoje,
    'abertas', (select count(*) from os where st = 'aberta'),
    'execucao', (select count(*) from os where st = 'execucao'),
    'semana', (select count(*) from os where st = 'concluida' and co >= date_trunc('week', p.hoje)::date),
    'atrasadas', (select count(*) from os where st in ('aberta','execucao') and coalesce(pr, ab + p.sla) < p.hoje),
    'd_verde', (select count(*) from os where st in ('aberta','execucao') and ab is not null and p.hoje - ab <= 2),
    'd_amarelo', (select count(*) from os where st in ('aberta','execucao') and ab is not null and p.hoje - ab between 3 and 4),
    'd_vermelho', (select count(*) from os where st in ('aberta','execucao') and ab is not null and p.hoje - ab >= 5),
    'ouro', (select count(distinct coalesce(grp, id)) from cl where cat = 'ouro'),
    'prata', (select count(distinct coalesce(grp, id)) from cl where coalesce(cat,'') <> 'ouro'),
    'contas', (select count(*) from cl),
    'serie', (select json_agg(json_build_object('d', d::date,
                'abertas', (select count(*) from os where ab = d::date),
                'concluidas', (select count(*) from os where co = d::date)) order by d)
              from generate_series(p.hoje - 13, p.hoje, interval '1 day') d)
  ) from p
$$;

grant execute on function public.rpc_usuarios(text,text), public.rpc_sync(text,text,timestamptz),
  public.rpc_solicitar(text,text,text,text), public.rpc_publico(),
  public.rpc_excluir(text,text,text,text), public.rpc_usuario_salvar(text,text,jsonb) to anon, authenticated;

-- cada pessoa pode trocar a própria foto
create or replace function public.rpc_minha_foto(p_login text, p_pin text, p_foto text)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
declare u public.usuarios;
begin
  u := public._usuario_valido(p_login, p_pin);
  if u.id is null then raise exception 'sem permissao'; end if;
  if length(coalesce(p_foto,'')) > 400000 then raise exception 'foto grande demais'; end if;
  update public.usuarios set foto = coalesce(p_foto,'') where id = u.id;
  return true;
end $$;
grant execute on function public.rpc_minha_foto(text,text,text) to anon, authenticated;

-- =====================================================================
-- MÁQUINAS (19/11/2026): cada computador/celular precisa ser autorizado
-- pelo admin antes de entrar. O app envia o PIN como "PIN|id-da-máquina".
-- =====================================================================
create table if not exists public.dispositivos (
  id text not null, user_id text not null references public.usuarios(id) on delete cascade,
  nome text default '', status text not null default 'pendente',  -- pendente | autorizado | bloqueado
  criado timestamptz default now(), visto timestamptz default now(),
  primary key (id, user_id)
);
alter table public.dispositivos enable row level security;

create or replace function public._usuario_valido(p_login text, p_pin text)
returns public.usuarios language sql stable security definer set search_path = public, extensions as $$
  select u.* from public.usuarios u
  where lower(u.login) = lower(p_login) and u.ativo and not u.pendente
    and u.pin_hash = extensions.crypt(split_part(p_pin, '|', 1), u.pin_hash)
    and (u.papel = 'admin' or exists (select 1 from public.dispositivos d
         where d.id = split_part(p_pin, '|', 2) and d.user_id = u.id and d.status = 'autorizado'))
  limit 1
$$;
revoke all on function public._usuario_valido(text, text) from public, anon, authenticated;

drop function if exists public.rpc_login(text, text);
create or replace function public.rpc_login(p_login text, p_pin text, p_maquina text default '')
returns json language plpgsql security definer set search_path = public, extensions as $$
declare u public.usuarios; dev text := split_part(p_pin, '|', 2); st text;
begin
  select * into u from public.usuarios where lower(login) = lower(p_login) and ativo and not pendente
    and pin_hash = extensions.crypt(split_part(p_pin, '|', 1), pin_hash) limit 1;
  if u.id is null then return null; end if;
  if length(dev) < 8 then raise exception 'maquina invalida'; end if;
  insert into public.dispositivos(id, user_id, nome, status, visto)
  values (dev, u.id, left(coalesce(p_maquina,''), 120), case when u.papel = 'admin' then 'autorizado' else 'pendente' end, now())
  on conflict (id, user_id) do update set visto = now(), nome = case when excluded.nome <> '' then excluded.nome else public.dispositivos.nome end
  returning status into st;
  if st <> 'autorizado' then return json_build_object('maquina', st, 'nome', u.nome); end if;
  return json_build_object('id',u.id,'nome',u.nome,'login',u.login,'papel',u.papel,
    'permissoes',u.permissoes,'foto',u.foto,'ativo',u.ativo);
end $$;

create or replace function public.rpc_dispositivos(p_login text, p_pin text)
returns json language plpgsql stable security definer set search_path = public, extensions as $$
declare u public.usuarios;
begin
  u := public._usuario_valido(p_login, p_pin);
  if u.id is null or u.papel <> 'admin' then raise exception 'sem permissao'; end if;
  return (select coalesce(json_agg(json_build_object('id',d.id,'user',d.user_id,'pessoa',x.nome,'nome',d.nome,'status',d.status,'criado',d.criado,'visto',d.visto) order by d.visto desc), '[]'::json)
          from public.dispositivos d join public.usuarios x on x.id = d.user_id);
end $$;

create or replace function public.rpc_dispositivo_status(p_login text, p_pin text, p_id text, p_user text, p_status text)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
declare u public.usuarios;
begin
  u := public._usuario_valido(p_login, p_pin);
  if u.id is null or u.papel <> 'admin' then raise exception 'sem permissao'; end if;
  if p_status = 'excluir' then delete from public.dispositivos where id = p_id and user_id = p_user;
  elsif p_status in ('autorizado','bloqueado','pendente') then update public.dispositivos set status = p_status where id = p_id and user_id = p_user;
  else raise exception 'status invalido'; end if;
  return true;
end $$;

grant execute on function public.rpc_login(text,text,text), public.rpc_dispositivos(text,text),
  public.rpc_dispositivo_status(text,text,text,text,text) to anon, authenticated;

-- =====================================================================
-- MISSÕES (19/11/2026): quem tem a permissão "missoes" cria e marca como
-- realizado; o dashboard público mostra as missões pendentes (pop-up para todos)
-- =====================================================================
create or replace function public._pode(p_papel text, p_perm jsonb, p_tipo text)
returns boolean language sql immutable as $$
  select case
    when p_papel = 'admin' then true
    when p_tipo = 'sessao' then true
    when p_tipo in ('chat','nota') then true
    when p_tipo in ('os','segware','importacao') then p_perm ? 'os'
    when p_tipo = 'cliente' then p_perm ? 'clientes'
    when p_tipo = 'arquivo' then p_perm ? 'arquivos'
    when p_tipo = 'missao' then p_perm ? 'missoes'
    when p_tipo like 'coord\_%' then p_perm ? 'coordenador'
    when p_tipo like 'rel\_%' then p_perm ? 'coordenador'
    else false
  end
$$;

-- dashboard público: números agregados + missões pendentes
create or replace function public.rpc_publico()
returns json language sql stable security definer set search_path = public as $$
  with p as (select (now() at time zone 'America/Fortaleza')::date hoje,
                    coalesce(nullif((select (dados->>'sla')::int from public.registros where tipo='config' and id='geral'), 0), 3) sla),
  os as (
    select dados->>'status' st,
           case when dados->>'abertura' ~ '^\d{4}-\d{2}-\d{2}' then left(dados->>'abertura',10)::date end ab,
           case when dados->>'prazo' ~ '^\d{4}-\d{2}-\d{2}' then left(dados->>'prazo',10)::date end pr,
           case when dados->>'conclusao' ~ '^\d{4}-\d{2}-\d{2}' then left(dados->>'conclusao',10)::date end co
    from public.registros where tipo = 'os'),
  cl as (select id, dados->>'categoria' cat, nullif(dados->>'grupo','') grp from public.registros where tipo = 'cliente')
  select json_build_object(
    'hoje', p.hoje,
    'abertas', (select count(*) from os where st = 'aberta'),
    'execucao', (select count(*) from os where st = 'execucao'),
    'semana', (select count(*) from os where st = 'concluida' and co >= date_trunc('week', p.hoje)::date),
    'atrasadas', (select count(*) from os where st in ('aberta','execucao') and coalesce(pr, ab + p.sla) < p.hoje),
    'd_verde', (select count(*) from os where st in ('aberta','execucao') and ab is not null and p.hoje - ab <= 2),
    'd_amarelo', (select count(*) from os where st in ('aberta','execucao') and ab is not null and p.hoje - ab between 3 and 4),
    'd_vermelho', (select count(*) from os where st in ('aberta','execucao') and ab is not null and p.hoje - ab >= 5),
    'ouro', (select count(distinct coalesce(grp, id)) from cl where cat = 'ouro'),
    'prata', (select count(distinct coalesce(grp, id)) from cl where coalesce(cat,'') <> 'ouro'),
    'contas', (select count(*) from cl),
    'missoes', (select coalesce(jsonb_agg(r.dados || jsonb_build_object('id', r.id)), '[]'::jsonb) from public.registros r
                where r.tipo = 'missao' and coalesce(r.dados->>'feito','false') <> 'true' and coalesce(r.dados->>'ativo','true') <> 'false'),
    'serie', (select json_agg(json_build_object('d', d::date,
                'abertas', (select count(*) from os where ab = d::date),
                'concluidas', (select count(*) from os where co = d::date)) order by d)
              from generate_series(p.hoje - 13, p.hoje, interval '1 day') d)
  ) from p
$$;

grant execute on function public.rpc_publico() to anon, authenticated;

-- dashboard público (19/11): números + OS pendentes/recentes + clientes (nome e categoria) + missões
create or replace function public.rpc_publico()
returns json language sql stable security definer set search_path = public as $$
  with p as (select (now() at time zone 'America/Fortaleza')::date hoje,
                    coalesce(nullif((select (dados->>'sla')::int from public.registros where tipo='config' and id='geral'), 0), 3) sla),
  os as (
    select dados->>'status' st,
           case when dados->>'abertura' ~ '^\d{4}-\d{2}-\d{2}' then left(dados->>'abertura',10)::date end ab,
           case when dados->>'prazo' ~ '^\d{4}-\d{2}-\d{2}' then left(dados->>'prazo',10)::date end pr,
           case when dados->>'conclusao' ~ '^\d{4}-\d{2}-\d{2}' then left(dados->>'conclusao',10)::date end co
    from public.registros where tipo = 'os'),
  cl as (select id, dados->>'categoria' cat, nullif(dados->>'grupo','') grp from public.registros where tipo = 'cliente')
  select json_build_object(
    'hoje', p.hoje,
    'abertas', (select count(*) from os where st = 'aberta'),
    'execucao', (select count(*) from os where st = 'execucao'),
    'semana', (select count(*) from os where st = 'concluida' and co >= date_trunc('week', p.hoje)::date),
    'atrasadas', (select count(*) from os where st in ('aberta','execucao') and coalesce(pr, ab + p.sla) < p.hoje),
    'd_verde', (select count(*) from os where st in ('aberta','execucao') and ab is not null and p.hoje - ab <= 2),
    'd_amarelo', (select count(*) from os where st in ('aberta','execucao') and ab is not null and p.hoje - ab between 3 and 4),
    'd_vermelho', (select count(*) from os where st in ('aberta','execucao') and ab is not null and p.hoje - ab >= 5),
    'ouro', (select count(distinct coalesce(grp, id)) from cl where cat = 'ouro'),
    'prata', (select count(distinct coalesce(grp, id)) from cl where coalesce(cat,'') <> 'ouro'),
    'contas', (select count(*) from cl),
    'os', (select coalesce(jsonb_agg((r.dados - 'valor' - 'orcamento') || jsonb_build_object('id', r.id)), '[]'::jsonb) from public.registros r
           where r.tipo = 'os' and (coalesce(r.dados->>'status','') in ('aberta','execucao')
             or (r.dados->>'conclusao' ~ '^\d{4}-\d{2}-\d{2}' and left(r.dados->>'conclusao',10)::date >= p.hoje - 30))),
    'clientes', (select coalesce(jsonb_agg(jsonb_build_object('id', r.id, 'nome', r.dados->>'nome', 'categoria', r.dados->>'categoria', 'grupo', r.dados->>'grupo')), '[]'::jsonb)
           from public.registros r where r.tipo = 'cliente'),
    'config', (select dados from public.registros where tipo = 'config' and id = 'geral'),
    'missoes', (select coalesce(jsonb_agg(r.dados || jsonb_build_object('id', r.id)), '[]'::jsonb) from public.registros r
                where r.tipo = 'missao' and coalesce(r.dados->>'feito','false') <> 'true' and coalesce(r.dados->>'ativo','true') <> 'false'),
    'serie', (select json_agg(json_build_object('d', d::date,
                'abertas', (select count(*) from os where ab = d::date),
                'concluidas', (select count(*) from os where co = d::date)) order by d)
              from generate_series(p.hoje - 13, p.hoje, interval '1 day') d)
  ) from p
$$;

grant execute on function public.rpc_publico() to anon, authenticated;


-- dashboard público (19/11 v7): números + OS + clientes (nome, categoria, grupo e popup) + missões
create or replace function public.rpc_publico()
returns json language sql stable security definer set search_path = public as $$
  with p as (select (now() at time zone 'America/Fortaleza')::date hoje,
                    coalesce(nullif((select (dados->>'sla')::int from public.registros where tipo='config' and id='geral'), 0), 3) sla),
  os as (
    select dados->>'status' st,
           case when dados->>'abertura' ~ '^\d{4}-\d{2}-\d{2}' then left(dados->>'abertura',10)::date end ab,
           case when dados->>'prazo' ~ '^\d{4}-\d{2}-\d{2}' then left(dados->>'prazo',10)::date end pr,
           case when dados->>'conclusao' ~ '^\d{4}-\d{2}-\d{2}' then left(dados->>'conclusao',10)::date end co
    from public.registros where tipo = 'os'),
  cl as (select id, dados->>'categoria' cat, nullif(dados->>'grupo','') grp from public.registros where tipo = 'cliente')
  select json_build_object(
    'hoje', p.hoje,
    'abertas', (select count(*) from os where st = 'aberta'),
    'execucao', (select count(*) from os where st = 'execucao'),
    'semana', (select count(*) from os where st = 'concluida' and co >= date_trunc('week', p.hoje)::date),
    'atrasadas', (select count(*) from os where st in ('aberta','execucao') and coalesce(pr, ab + p.sla) < p.hoje),
    'd_verde', (select count(*) from os where st in ('aberta','execucao') and ab is not null and p.hoje - ab <= 2),
    'd_amarelo', (select count(*) from os where st in ('aberta','execucao') and ab is not null and p.hoje - ab between 3 and 4),
    'd_vermelho', (select count(*) from os where st in ('aberta','execucao') and ab is not null and p.hoje - ab >= 5),
    'ouro', (select count(distinct coalesce(grp, id)) from cl where cat = 'ouro'),
    'prata', (select count(distinct coalesce(grp, id)) from cl where coalesce(cat,'') <> 'ouro'),
    'contas', (select count(*) from cl),
    'os', (select coalesce(jsonb_agg((r.dados - 'valor' - 'orcamento') || jsonb_build_object('id', r.id)), '[]'::jsonb) from public.registros r
           where r.tipo = 'os' and (coalesce(r.dados->>'status','') in ('aberta','execucao')
             or (r.dados->>'conclusao' ~ '^\d{4}-\d{2}-\d{2}' and left(r.dados->>'conclusao',10)::date >= p.hoje - 30))),
    'clientes', (select coalesce(jsonb_agg(jsonb_build_object('id', r.id, 'nome', r.dados->>'nome', 'categoria', r.dados->>'categoria', 'grupo', r.dados->>'grupo', 'popup', r.dados->'popup', 'apelidos', r.dados->'apelidos')), '[]'::jsonb)
           from public.registros r where r.tipo = 'cliente'),
    'config', (select dados from public.registros where tipo = 'config' and id = 'geral'),
    'missoes', (select coalesce(jsonb_agg(r.dados || jsonb_build_object('id', r.id)), '[]'::jsonb) from public.registros r
                where r.tipo = 'missao' and coalesce(r.dados->>'feito','false') <> 'true' and coalesce(r.dados->>'ativo','true') <> 'false'),
    'serie', (select json_agg(json_build_object('d', d::date,
                'abertas', (select count(*) from os where ab = d::date),
                'concluidas', (select count(*) from os where co = d::date)) order by d)
              from generate_series(p.hoje - 13, p.hoje, interval '1 day') d)
  ) from p
$$;

grant execute on function public.rpc_publico() to anon, authenticated;
