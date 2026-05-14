-- ============================================================
-- TechFix Secure Secrets Lab — PostgreSQL Setup
-- Alumno : Jose Daniel Zumarraga
-- Materia: Desarrollo de Software Seguro
-- Docente: Rodrigo Ramírez
-- Fecha  : 2026-05-13
--
-- Requisito: extensión pgcrypto para bcrypt nativo
-- Ejecutar: psql -U postgres -f postgres_setup.sql
-- ============================================================

-- ------------------------------------------------------------
-- 0. Extensión para bcrypt dentro de PostgreSQL
-- ------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================
-- 1. TABLA roles
--    Estructura idéntica a la de tu base de datos (screenshot):
--      name        CHARACTER VARYING(50) PRIMARY KEY
--      description TEXT
-- ============================================================
CREATE TABLE IF NOT EXISTS roles (
    name        CHARACTER VARYING(50) PRIMARY KEY,
    description TEXT
);

-- Roles exactos del screenshot
INSERT INTO roles (name, description) VALUES
    ('admin',     'Administrador con acceso total'),
    ('user',      'Usuario regular con permisos limitados'),
    ('moderator', 'Moderador con permisos de supervisión'),
    ('guest',     'Usuario invitado con permisos mínimos')
ON CONFLICT (name) DO NOTHING;

-- ============================================================
-- 2. TABLA users
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id                    SERIAL PRIMARY KEY,
    username              VARCHAR(50)  NOT NULL UNIQUE,
    email                 VARCHAR(100) NOT NULL UNIQUE,
    password_hash         TEXT         NOT NULL,
    role                  VARCHAR(50)  NOT NULL DEFAULT 'user'
                              REFERENCES roles(name) ON UPDATE CASCADE ON DELETE RESTRICT,
    is_active             BOOLEAN      NOT NULL DEFAULT TRUE,
    failed_login_attempts INTEGER      NOT NULL DEFAULT 0,
    account_locked        BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_login            TIMESTAMPTZ,

    CONSTRAINT chk_username_length CHECK (LENGTH(username) >= 3 AND LENGTH(username) <= 50)
);

CREATE INDEX IF NOT EXISTS idx_users_username  ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_role      ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active);

-- ============================================================
-- 3. TABLA audit_logs
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id         SERIAL PRIMARY KEY,
    user_id    INTEGER     REFERENCES users(id) ON DELETE SET NULL,
    action     VARCHAR(50) NOT NULL,
    resource   VARCHAR(100),
    details    JSONB,
    ip_address INET,
    status     VARCHAR(20) CHECK (status IN ('success', 'failure')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_user_id   ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_created   ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_action    ON audit_logs(action);

-- ============================================================
-- 4. DATOS DE PRUEBA — bcrypt cost 12 generado con pgcrypto
--
--    Contraseñas (solo para este lab educativo):
--      admin      → Admin@TechFix2024!
--      alice      → UserPass@2024
--      bob        → UserPass@2024
--      moderator  → ModPass@2024
--      guest      → GuestPass@2024
--
--    crypt(plain, gen_salt('bf', 12)) es equivalente
--    a bcrypt.hash(password, 12) en Node.js.
-- ============================================================
INSERT INTO users (username, email, password_hash, role, created_at, last_login) VALUES

    ('admin',
     'admin@techfix.local',
     crypt('Admin@TechFix2024!', gen_salt('bf', 12)),
     'admin',
     NOW() - INTERVAL '30 days',
     NOW() - INTERVAL '1 day'),

    ('alice',
     'alice@techfix.local',
     crypt('UserPass@2024', gen_salt('bf', 12)),
     'user',
     NOW() - INTERVAL '20 days',
     NOW() - INTERVAL '2 days'),

    ('bob',
     'bob@techfix.local',
     crypt('UserPass@2024', gen_salt('bf', 12)),
     'user',
     NOW() - INTERVAL '15 days',
     NOW() - INTERVAL '5 days'),

    ('moderator',
     'moderator@techfix.local',
     crypt('ModPass@2024', gen_salt('bf', 12)),
     'moderator',
     NOW() - INTERVAL '25 days',
     NOW() - INTERVAL '3 days'),

    ('guest',
     'guest@techfix.local',
     crypt('GuestPass@2024', gen_salt('bf', 12)),
     'guest',
     NOW() - INTERVAL '10 days',
     NOW() - INTERVAL '7 days')

ON CONFLICT (username) DO NOTHING;

-- ============================================================
-- 5. DATOS DE AUDITORÍA de ejemplo
-- ============================================================
INSERT INTO audit_logs (user_id, action, resource, details, ip_address, status, created_at) VALUES
    (1, 'LOGIN',          'authentication', '{"method":"password"}',                        '192.168.1.10',  'success', NOW() - INTERVAL '1 day'),
    (2, 'LOGIN',          'authentication', '{"method":"password"}',                        '192.168.1.11',  'success', NOW() - INTERVAL '2 days'),
    (1, 'USER_CREATED',   'users',          '{"new_user":"guest"}',                         '192.168.1.10',  'success', NOW() - INTERVAL '10 days'),
    (5, 'LOGIN',          'authentication', '{"method":"password","attempts":3}',            '203.0.113.50',  'failure', NOW() - INTERVAL '3 days'),
    (1, 'ADMIN_STATS',    'admin',          '{"requested_by":"admin"}',                     '192.168.1.10',  'success', NOW() - INTERVAL '1 hour'),
    (1, 'PASSWORD_RESET', 'users',          '{"target_user_id":2}',                         '192.168.1.10',  'success', NOW() - INTERVAL '5 days');

-- ============================================================
-- 6. ROL DE APLICACIÓN — mínimo privilegio
--    La app Node.js se conecta como 'techfix_app', no como postgres
-- ============================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'techfix_app') THEN
        CREATE ROLE techfix_app LOGIN PASSWORD 'AppPass@TechFix2024!';
    END IF;
END
$$;

-- Solo los permisos estrictamente necesarios
GRANT USAGE  ON SCHEMA public TO techfix_app;
GRANT SELECT, INSERT, UPDATE ON users      TO techfix_app;
GRANT SELECT, INSERT          ON audit_logs TO techfix_app;
GRANT SELECT                  ON roles      TO techfix_app;
GRANT USAGE, SELECT ON SEQUENCE users_id_seq      TO techfix_app;
GRANT USAGE, SELECT ON SEQUENCE audit_logs_id_seq TO techfix_app;
-- Sin DELETE, sin DROP, sin acceso a system tables

-- ============================================================
-- 7. TRIGGER: updated_at automático en users
-- ============================================================
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.last_login = OLD.last_login; -- preservar
    RETURN NEW;
END;
$$;

-- Función para bloquear cuenta tras 5 intentos fallidos
CREATE OR REPLACE FUNCTION check_failed_logins()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.failed_login_attempts >= 5 THEN
        NEW.account_locked = TRUE;
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE TRIGGER trg_lock_account
BEFORE UPDATE OF failed_login_attempts ON users
FOR EACH ROW EXECUTE FUNCTION check_failed_logins();

-- ============================================================
-- 8. VERIFICACIÓN FINAL
-- ============================================================

-- Roles (debe coincidir con el screenshot)
SELECT name, description FROM roles ORDER BY name;

-- Usuarios con metadatos (SIN password_hash)
SELECT id, username, email, role, is_active, account_locked,
       to_char(created_at, 'YYYY-MM-DD') AS created,
       to_char(last_login,  'YYYY-MM-DD') AS last_login
FROM   users
ORDER  BY id;

-- Comprobar que el hash del admin funciona (debe retornar TRUE)
SELECT username,
       (password_hash = crypt('Admin@TechFix2024!', password_hash)) AS password_ok
FROM   users
WHERE  username = 'admin';

-- ============================================================
-- 9. VARIABLES .env PARA NODE.JS
--
--    Agregar en practica-de-laboratorio/.env:
--
--    DB_HOST=localhost
--    DB_PORT=5432
--    DB_NAME=<nombre_de_tu_base_de_datos>
--    DB_USER=techfix_app
--    DB_PASSWORD=AppPass@TechFix2024!
--
--    En config/database.js:
--
--    const { Pool } = require('pg');
--    const pool = new Pool({
--        host:     process.env.DB_HOST,
--        port:     Number(process.env.DB_PORT),
--        database: process.env.DB_NAME,
--        user:     process.env.DB_USER,
--        password: process.env.DB_PASSWORD,
--    });
--    module.exports = pool;
--
--    Login seguro (sin SQL injection, parámetro posicional):
--
--    const { rows } = await pool.query(
--        `SELECT * FROM users
--         WHERE username = $1 AND is_active = TRUE AND account_locked = FALSE`,
--        [username]
--    );
--    // Verificar contraseña en Node.js con bcrypt:
--    const valid = rows[0] && await bcrypt.compare(password, rows[0].password_hash);
-- ============================================================
