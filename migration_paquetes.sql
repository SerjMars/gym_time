-- Migración: soporte de múltiples paquetes (las clases de cada paquete ya no se mezclan)
-- Ejecutar una sola vez en el SQL Editor de Supabase.

-- 1. Renombrar la tabla de configuración a "paquetes"
alter table gym_config rename to gym_packages;

-- 2. Permitir múltiples filas: agregar bandera de activo y fecha de creación
alter table gym_packages add column if not exists active boolean not null default true;
alter table gym_packages add column if not exists created_at timestamptz not null default now();

-- 3. Asegurar que las inserciones nuevas no choquen con el id=1 ya usado
select setval(pg_get_serial_sequence('gym_packages','id'), (select max(id) from gym_packages));

-- 4. Vincular cada sesión a un paquete
alter table gym_sessions add column if not exists package_id bigint references gym_packages(id);
update gym_sessions set package_id = (select id from gym_packages limit 1) where package_id is null;
alter table gym_sessions alter column package_id set not null;
