require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
    host:     process.env.DB_HOST     || 'localhost',
    port:     Number(process.env.DB_PORT) || 5432,
    database: process.env.DB_NAME,
    user:     process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    // Límites de conexión para la app educativa
    max:              10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
});

// Verificar conectividad al arrancar
pool.on('connect', () => {
    console.log('[DB] Conexión establecida con PostgreSQL');
});

pool.on('error', (err) => {
    console.error('[DB] Error inesperado en el pool:', err.message);
});

module.exports = pool;
