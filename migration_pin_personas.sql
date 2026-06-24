-- Migración: PIN individual por persona.
-- Cada participante puede tener un PIN propio; sin él, nadie (ni siquiera
-- otro participante) puede agregar, editar o borrar SUS clases. El admin
-- sigue pudiendo hacerlo todo con su contraseña, sin necesitar el PIN de
-- nadie. Si una persona no tiene PIN asignado, puede seguir operando sin que
-- se le pida (útil mientras el admin no ha terminado de configurar PINs).
--
-- Ejecutar DESPUÉS de migration_seguridad_rls.sql (usa check_admin_password
-- y la extensión pgcrypto que esa migración ya configura).

-- ── Tabla de PINs (hasheados), una fila por nombre de persona ──
create table if not exists person_pins (
  person_name text primary key,
  pin_hash text not null
);

alter table person_pins enable row level security;
-- A propósito no se crea ninguna policy: nadie puede leer/escribir esta
-- tabla directamente desde el cliente. Solo las funciones de abajo
-- (security definer) pueden tocarla.


-- ── Funciones de PIN ─────────────────────────────────────
create or replace function admin_set_person_pin(p_password text, p_person_name text, p_pin text)
returns void
language plpgsql security definer
set search_path = public, extensions
as $$
begin
  if not check_admin_password(p_password) then
    raise exception 'Contraseña de administrador incorrecta.';
  end if;
  insert into person_pins (person_name, pin_hash)
  values (lower(trim(p_person_name)), extensions.crypt(p_pin, extensions.gen_salt('bf')))
  on conflict (person_name) do update set pin_hash = excluded.pin_hash;
end;
$$;

create or replace function person_has_pin(p_person_name text)
returns boolean
language sql security definer
set search_path = public
as $$
  select exists (select 1 from person_pins where person_name = lower(trim(p_person_name)));
$$;

create or replace function check_person_pin(p_person_name text, p_pin text)
returns boolean
language sql security definer
set search_path = public, extensions
as $$
  select exists (
    select 1 from person_pins
    where person_name = lower(trim(p_person_name))
      and pin_hash = extensions.crypt(p_pin, pin_hash)
  );
$$;

revoke execute on function check_person_pin(text, text) from public;
grant execute on function admin_set_person_pin(text, text, text) to anon;
grant execute on function person_has_pin(text)                   to anon;


-- ── Funciones de sesiones: validan admin o el PIN del dueño ──
create or replace function add_session(
  p_package_id bigint, p_person_id int, p_date date, p_time time,
  p_actor_name text default null, p_actor_pin text default null, p_admin_password text default null
)
returns gym_sessions
language plpgsql security definer
set search_path = public
as $$
declare result gym_sessions; needs_pin boolean;
begin
  if p_admin_password is not null and check_admin_password(p_admin_password) then
    -- admin: autorizado
  else
    needs_pin := person_has_pin(coalesce(p_actor_name, ''));
    if needs_pin and not check_person_pin(p_actor_name, coalesce(p_actor_pin, '')) then
      raise exception 'PIN incorrecto.';
    end if;
  end if;
  insert into gym_sessions (person_id, date, time, package_id)
  values (p_person_id, p_date, p_time, p_package_id)
  returning * into result;
  return result;
end;
$$;

create or replace function update_session_time(
  p_session_id bigint, p_time time,
  p_actor_name text default null, p_actor_pin text default null, p_admin_password text default null
)
returns void
language plpgsql security definer
set search_path = public
as $$
declare needs_pin boolean;
begin
  if p_admin_password is not null and check_admin_password(p_admin_password) then
    -- admin: autorizado
  else
    needs_pin := person_has_pin(coalesce(p_actor_name, ''));
    if needs_pin and not check_person_pin(p_actor_name, coalesce(p_actor_pin, '')) then
      raise exception 'PIN incorrecto.';
    end if;
  end if;
  update gym_sessions set time = p_time where id = p_session_id;
end;
$$;

create or replace function delete_session(
  p_session_id bigint,
  p_actor_name text default null, p_actor_pin text default null, p_admin_password text default null
)
returns void
language plpgsql security definer
set search_path = public
as $$
declare needs_pin boolean;
begin
  if p_admin_password is not null and check_admin_password(p_admin_password) then
    -- admin: autorizado
  else
    needs_pin := person_has_pin(coalesce(p_actor_name, ''));
    if needs_pin and not check_person_pin(p_actor_name, coalesce(p_actor_pin, '')) then
      raise exception 'PIN incorrecto.';
    end if;
  end if;
  delete from gym_sessions where id = p_session_id;
end;
$$;

-- Reemplaza la función de donaciones de la migración anterior: ahora
-- también exige el PIN de quien dona (o la contraseña de admin).
create or replace function donate_session(
  p_from int, p_to int,
  p_actor_name text default null, p_actor_pin text default null, p_admin_password text default null
)
returns void
language plpgsql security definer
set search_path = public
as $$
declare pkg_id bigint; needs_pin boolean;
begin
  if p_admin_password is not null and check_admin_password(p_admin_password) then
    -- admin: autorizado
  else
    needs_pin := person_has_pin(coalesce(p_actor_name, ''));
    if needs_pin and not check_person_pin(p_actor_name, coalesce(p_actor_pin, '')) then
      raise exception 'PIN incorrecto.';
    end if;
  end if;
  select id into pkg_id from gym_packages where active = true;
  update gym_packages
  set donations = coalesce(donations, '[]'::jsonb)
    || jsonb_build_object('id', (extract(epoch from now())*1000)::bigint, 'from', p_from, 'to', p_to)
  where id = pkg_id;
end;
$$;

grant execute on function add_session(bigint,int,date,time,text,text,text)        to anon;
grant execute on function update_session_time(bigint,time,text,text,text)        to anon;
grant execute on function delete_session(bigint,text,text,text)                  to anon;
grant execute on function donate_session(int,int,text,text,text)                 to anon;


-- ── RLS: las sesiones ya no se escriben directo desde el cliente ──
-- (todo pasa por add_session / update_session_time / delete_session, que
-- validan PIN o contraseña de admin antes de tocar la tabla).
drop policy if exists sessions_insert on gym_sessions;
drop policy if exists sessions_update on gym_sessions;
drop policy if exists sessions_delete on gym_sessions;
-- sessions_select se mantiene (todos pueden ver el calendario).
