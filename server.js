/**
 * TechFix Secure Secrets Lab — Servidor Seguro
 * Alumno: Jose Daniel Zumarraga
 * Materia: Desarrollo de Software Seguro
 *
 * Vulnerabilidades corregidas:
 *   V1 — Exposición de Datos Sensibles → auth JWT + sin password_hash
 *   V2 — Manejo Deficiente de Errores  → sin stack trace al cliente
 *   V3 — Missing Authentication        → JWT + validación de rol admin
 *   V4 — Path Traversal                → path.basename + whitelist + JWT
 */

require('dotenv').config();

const express = require('express');
const fs      = require('node:fs');
const path    = require('node:path');
const bcrypt  = require('bcrypt');
const jwt     = require('jsonwebtoken');
const helmet  = require('helmet');
const pool    = require('./config/database');

const app = express();

app.use(helmet());
app.use(express.json());
app.use(express.static('public'));

const JWT_SECRET = process.env.JWT_SECRET;
const PORT       = process.env.PORT || 3000;

if (!JWT_SECRET) {
    console.error('FATAL: JWT_SECRET no definido en .env');
    process.exit(1);
}

// ── Sistema de logging ────────────────────────────────────────────────────────

const logsDir           = path.join(__dirname, 'logs');
const connectionLogFile = path.join(logsDir, 'connections.log');
const activityLogFile   = path.join(logsDir, 'activity.log');

if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
}

// Registra el path, nunca la query string (podría tener credenciales)
app.use((req, res, next) => {
    const entry = `[${new Date().toISOString()}] ${req.method} ${req.path} | IP: ${req.ip}\n`;
    fs.appendFileSync(connectionLogFile, entry);
    next();
});

function logActivity(action, details) {
    const entry = `[${new Date().toISOString()}] ACTION: ${action} | ${JSON.stringify(details)}\n`;
    fs.appendFileSync(activityLogFile, entry);
}

// ── Middlewares de autenticación ──────────────────────────────────────────────

function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Autenticación requerida' });
    }
    try {
        req.user = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
        next();
    } catch {
        res.status(403).json({ error: 'Token inválido o expirado' });
    }
}

function requireRole(role) {
    return (req, res, next) => {
        if (req.user?.role !== role) {
            return res.status(403).json({ error: 'Acceso denegado: privilegios insuficientes' });
        }
        next();
    };
}

// ── Login ─────────────────────────────────────────────────────────────────────

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password ||
        typeof username !== 'string' ||
        typeof password !== 'string' ||
        username.length > 100) {
        return res.status(400).json({ error: 'Datos de entrada inválidos' });
    }

    logActivity('LOGIN_ATTEMPT', { username });

    try {
        const { rows } = await pool.query(
            `SELECT id, username, password_hash, role, is_active, account_locked
             FROM users WHERE username = $1`,
            [username]
        );

        const user = rows[0];

        if (!user || user.account_locked || !user.is_active) {
            logActivity('LOGIN_FAILED', { username, reason: 'not_found_or_locked' });
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }

        const passwordValid = await bcrypt.compare(password, user.password_hash);

        if (!passwordValid) {
            await pool.query(
                'UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = $1',
                [user.id]
            );
            logActivity('LOGIN_FAILED', { username, reason: 'wrong_password' });
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }

        await pool.query(
            'UPDATE users SET failed_login_attempts = 0, last_login = NOW() WHERE id = $1',
            [user.id]
        );

        await pool.query(
            `INSERT INTO audit_logs (user_id, action, resource, details, ip_address, status)
             VALUES ($1, 'LOGIN', 'authentication', $2, $3, 'success')`,
            [user.id, JSON.stringify({ method: 'password' }), req.ip]
        );

        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        logActivity('LOGIN_SUCCESS', { username });
        res.json({ message: `Bienvenido ${user.username}`, token, role: user.role });

    } catch (err) {
        const errorId = `ERR-${Date.now()}`;
        console.error(`[${errorId}]`, err);
        res.status(500).json({ error: 'Error interno del servidor', errorId });
    }
});

// ── V1 CORREGIDA: GET /users — auth requerida, sin password_hash ──────────────

app.get('/users', authMiddleware, async (req, res) => {
    try {
        const { rows } = await pool.query(
            'SELECT id, username, email, role, is_active, created_at FROM users ORDER BY id'
        );
        logActivity('GET_ALL_USERS', { requestedBy: req.user.username, count: rows.length });
        res.json(rows);
    } catch (err) {
        const errorId = `ERR-${Date.now()}`;
        console.error(`[${errorId}]`, err);
        res.status(500).json({ error: 'Error interno del servidor', errorId });
    }
});

// ── V2 CORREGIDA: GET /error — sin stack trace al cliente ────────────────────

app.get('/error', (req, res) => {
    logActivity('ERROR_TEST', { requestedBy: req.ip });
    res.json({ message: 'Endpoint de prueba — sin información interna expuesta' });
});

// ── V3 CORREGIDA: GET /admin/stats — JWT + rol admin ─────────────────────────

app.get('/admin/stats', authMiddleware, requireRole('admin'), async (req, res) => {
    try {
        const total  = await pool.query('SELECT COUNT(*) AS total FROM users');
        const byRole = await pool.query(
            'SELECT role, COUNT(*) AS count FROM users GROUP BY role ORDER BY role'
        );
        const recent = await pool.query(
            `SELECT COUNT(*) AS count FROM audit_logs
             WHERE created_at > NOW() - INTERVAL '24 hours'`
        );

        logActivity('ADMIN_STATS_REQUEST', { requestedBy: req.user.username });
        res.json({
            totalUsers:    Number(total.rows[0].total),
            usersByRole:   byRole.rows,
            last24hEvents: Number(recent.rows[0].count),
            serverTime:    new Date(),
            uptime:        process.uptime()
        });
    } catch (err) {
        const errorId = `ERR-${Date.now()}`;
        console.error(`[${errorId}]`, err);
        res.status(500).json({ error: 'Error interno del servidor', errorId });
    }
});

// ── V4 CORREGIDA: GET /logs/:file — path.basename + whitelist + JWT ──────────

const allowedLogFiles = new Set(['connections.log', 'activity.log']);

app.get('/logs/:file', authMiddleware, requireRole('admin'), (req, res) => {
    const file     = path.basename(req.params.file);
    const filePath = path.resolve(logsDir, file);

    if (!allowedLogFiles.has(file) || !filePath.startsWith(path.resolve(logsDir))) {
        return res.status(403).json({ error: 'Acceso denegado: archivo no permitido' });
    }

    try {
        const content = fs.readFileSync(filePath, 'utf-8');
        res.type('text/plain').send(content);
    } catch {
        res.status(404).json({ error: 'Archivo no encontrado' });
    }
});

// ── Manejador global de errores (V2) ─────────────────────────────────────────

app.use((err, req, res, next) => {
    const errorId = `ERR-${Date.now()}`;
    console.error(`[${errorId}]`, err);
    logActivity('ERROR_OCCURRED', { errorId, message: err.message });
    res.status(500).json({ error: 'Error interno del servidor', errorId });
});

// ── Inicio ────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
    console.log(`\n${'='.repeat(50)}`);
    console.log(`TechFix Secure Lab`);
    console.log(`URL  : http://localhost:${PORT}`);
    console.log(`BD   : PostgreSQL → ${process.env.DB_NAME}`);
    console.log(`Modo : ${process.env.NODE_ENV || 'development'}`);
    console.log(`${'='.repeat(50)}\n`);
    logActivity('SERVER_START', { port: PORT, db: process.env.DB_NAME });
});
