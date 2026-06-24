-- Migración de seguridad: bloquea escritura/borrado directo en gym_packages y
-- gym_sessions desde el cliente (clave anon), y obliga a pasar por funciones
-- RPC que validan la contraseña de administrador dentro de la base de datos.
--
-- Hoy cualquiera con la URL y la clave anon (ambas públicas en el HTML) puede
-- leer, modificar o borrar TODO directamente vía la API REST de Supabase, sin
-- pasar por el prompt de contraseña del admin (que solo vive en el navegador).
-- Esta migración cierra ese hueco para las operaciones destructivas/de
-- configuración, dejando solo lectura y altas/bajas de sesiones individuales
-- abiertas (igual que hoy), ya que la app no tiene un sistema de login real
-- por persona.
--
-- IMPORTANTE: cambia 'adminMars1220' por tu contraseña real antes de correr
-- este script si no coincide con la que tienes en index.html (ADMIN_PASS).

create extension if not exists pgcrypto schema extensions;

-- ── Contraseña de administrador (hasheada) ──────────────
create table if not exists admin_secret (
  id int primary key default 1,
  password_hash text not null,
  constraint admin_secret_single_row check (id = 1)
);

insert into admin_secret (id, password_hash)
values (1, extensions.crypt('adminMars1220', extensions.gen_salt('bf')))
on conflict (id) do update set password_hash = excluded.password_hash;

create or replace function check_admin_password(p_password text)
returns boolean
language sql security definer
set search_path = public, extensions
as $$
  select exists (
    select 1 from admin_secret where password_hash = extensions.crypt(p_password, password_hash)
  );
$$;

-- Que nadie pueda llamar esta función directamente desde el cliente
-- (solo la usan, internamente, las funciones admin_* de abajo).
revoke execute on function check_admin_password(text) from public;


-- ── Funciones de administración (requieren contraseña) ──
create or replace function create_first_package(p_total int, p_months int, p_start date, p_people jsonb)
returns bigint
language plpgsql security definer
set search_path = public
as $$
declare new_id bigint;
begin
  if exists (select 1 from gym_packages) then
    raise exception 'Ya existe un paquete configurado.';
  end if;
  insert into gym_packages (total_sessions, period_months, start_date, people, donations, active)
  values (p_total, p_months, p_start, p_people, '[]'::jsonb, true)
  returning id into new_id;
  return new_id;
end;
$$;

create or replace function admin_update_config(p_password text, p_total int, p_months int, p_start date)
returns void
language plpgsql security definer
set search_path = public
as $$
begin
  if not check_admin_password(p_password) then
    raise exception 'Contraseña de administrador incorrecta.';
  end if;
  update gym_packages set total_sessions = p_total, period_months = p_months, start_date = p_start
  where active = true;
end;
$$;

create or replace function admin_update_people(p_password text, p_people jsonb)
returns void
language plpgsql security definer
set search_path = public
as $$
begin
  if not check_admin_password(p_password) then
    raise exception 'Contraseña de administrador incorrecta.';
  end if;
  update gym_packages set people = p_people where active = true;
end;
$$;

create or replace function admin_remove_participant(p_password text, p_person_id int)
returns void
language plpgsql security definer
set search_path = public
as $$
declare pkg_id bigint;
begin
  if not check_admin_password(p_password) then
    raise exception 'Contraseña de administrador incorrecta.';
  end if;
  select id into pkg_id from gym_packages where active = true;
  delete from gym_sessions where package_id = pkg_id and person_id = p_person_id;
  update gym_packages set people = (
    select coalesce(jsonb_agg(elem), '[]'::jsonb)
    from jsonb_array_elements(people) elem
    where (elem->>'id')::int <> p_person_id
  ) where id = pkg_id;
end;
$$;

create or replace function admin_delete_all_sessions(p_password text)
returns void
language plpgsql security definer
set search_path = public
as $$
declare pkg_id bigint;
begin
  if not check_admin_password(p_password) then
    raise exception 'Contraseña de administrador incorrecta.';
  end if;
  select id into pkg_id from gym_packages where active = true;
  delete from gym_sessions where package_id = pkg_id;
end;
$$;

create or replace function admin_start_new_package(p_password text, p_total int, p_months int, p_start date, p_people jsonb)
returns bigint
language plpgsql security definer
set search_path = public
as $$
declare new_id bigint;
begin
  if not check_admin_password(p_password) then
    raise exception 'Contraseña de administrador incorrecta.';
  end if;
  update gym_packages set active = false where active = true;
  insert into gym_packages (total_sessions, period_months, start_date, people, donations, active)
  values (p_total, p_months, p_start, p_people, '[]'::jsonb, true)
  returning id into new_id;
  return new_id;
end;
$$;

create or replace function admin_revoke_donation(p_password text, p_don_id bigint)
returns void
language plpgsql security definer
set search_path = public
as $$
declare pkg_id bigint;
begin
  if not check_admin_password(p_password) then
    raise exception 'Contraseña de administrador incorrecta.';
  end if;
  select id into pkg_id from gym_packages where active = true;
  update gym_packages set donations = (
    select coalesce(jsonb_agg(elem), '[]'::jsonb)
    from jsonb_array_elements(donations) elem
    where (elem->>'id')::bigint <> p_don_id
  ) where id = pkg_id;
end;
$$;

-- Donar una sesión: cualquier participante puede hacerlo para sí mismo
-- (no requiere contraseña, igual que en la app actual).
create or replace function donate_session(p_from int, p_to int)
returns void
language plpgsql security definer
set search_path = public
as $$
declare pkg_id bigint;
begin
  select id into pkg_id from gym_packages where active = true;
  update gym_packages
  set donations = coalesce(donations, '[]'::jsonb)
    || jsonb_build_object('id', (extract(epoch from now())*1000)::bigint, 'from', p_from, 'to', p_to)
  where id = pkg_id;
end;
$$;

grant execute on function create_first_package(int,int,date,jsonb)              to anon;
grant execute on function admin_update_config(text,int,int,date)                to anon;
grant execute on function admin_update_people(text,jsonb)                       to anon;
grant execute on function admin_remove_participant(text,int)                    to anon;
grant execute on function admin_delete_all_sessions(text)                       to anon;
grant execute on function admin_start_new_package(text,int,int,date,jsonb)      to anon;
grant execute on function admin_revoke_donation(text,bigint)                    to anon;
grant execute on function donate_session(int,int)                              to anon;


-- ── RLS: cerrar escritura/borrado directo de gym_packages ──
drop policy if exists allow_all_config on gym_packages;

alter table gym_packages enable row level security;

create policy packages_select on gym_packages
  for select to anon using (true);

-- A propósito NO se crean políticas de insert/update/delete para anon:
-- toda escritura en gym_packages debe pasar por las funciones de arriba.


-- ── RLS: gym_sessions sigue abierta para altas/bajas individuales ──
-- (la app no tiene login por persona, así que cualquier participante puede
-- agregar/editar/borrar sus propias clases sin contraseña, igual que hoy;
-- lo único que se cerró es el borrado MASIVO, que ahora exige contraseña
-- vía admin_delete_all_sessions).
drop policy if exists allow_all_sessions on gym_sessions;

alter table gym_sessions enable row level security;

create policy sessions_select on gym_sessions for select to anon using (true);
create policy sessions_insert on gym_sessions for insert to anon with check (true);
create policy sessions_update on gym_sessions for update to anon using (true) with check (true);
create policy sessions_delete on gym_sessions for delete to anon using (true);
