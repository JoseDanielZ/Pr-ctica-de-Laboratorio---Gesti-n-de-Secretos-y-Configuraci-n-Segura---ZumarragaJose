# TechFix Secure Secrets Lab

**Carrera:** Ingeniería en Sistemas
**Materia:** Desarrollo de Software Seguro
**Práctica:** Gestión de Secretos y Configuración Segura
**Estudiante:** Jose Daniel Zumarraga
**Docente:** Rodrigo Ramírez

---

## Descripción

Laboratorio práctico de auditoría de seguridad web. La aplicación TechFix fue desarrollada con vulnerabilidades intencionales para identificarlas, documentarlas y corregirlas aplicando buenas prácticas de desarrollo seguro.

---

## Tecnologías

- Node.js + Express.js
- PostgreSQL (bcrypt con cost 12 via pgcrypto)
- JWT (jsonwebtoken)
- Helmet.js (cabeceras HTTP de seguridad)
- dotenv (gestión de secretos)

---

## Estructura del proyecto

```text
practica-de-laboratorio/
├── server.js                 ← servidor con vulnerabilidades corregidas
├── .env                      ← secretos (excluido del repo)
├── .env.example              ← plantilla de variables de entorno
├── .gitignore
├── package.json
├── postgres_setup.sql        ← esquema y datos de prueba
│
├── config/
│   └── database.js           ← pool de conexión PostgreSQL
│
├── public/
│   ├── index.html            ← interfaz de usuario
│   ├── app.js                ← lógica del cliente
│   └── styles.css
│
└── logs/
    ├── connections.log       ← generado en tiempo de ejecución
    └── activity.log          ← generado en tiempo de ejecución
```

---

## Inicio rápido

```bash
# 1. Instalar dependencias
npm install

# 2. Configurar variables de entorno
cp .env.example .env
# Editar .env con los valores reales

# 3. Ejecutar el script SQL en PostgreSQL
psql -U postgres -f postgres_setup.sql

# 4. Iniciar el servidor
node server.js
```

El servidor queda disponible en `http://localhost:3000`.

Credenciales de prueba:

| Usuario | Contraseña         | Rol   |
|---------|--------------------|-------|
| admin   | Admin@TechFix2024! | admin |
| alice   | UserPass@2024      | user  |
| bob     | UserPass@2024      | user  |

---

## Vulnerabilidades identificadas y corregidas

### V1 — Exposición de Datos Sensibles

**Clasificación:** OWASP A02:2021 — Cryptographic Failures
**Severidad:** Crítica
**Endpoint:** `GET /users`

**Problema:** El endpoint no requería autenticación y devolvía `password_hash` de todos los usuarios directamente al cliente.

**Corrección:** Autenticación JWT obligatoria mediante middleware. El `SELECT` excluye `password_hash` de la respuesta.

---

### V2 — Manejo Deficiente de Errores

**Clasificación:** OWASP A09:2021 — Security Logging and Monitoring Failures
**Severidad:** Media
**Endpoint:** `GET /error`

**Problema:** El servidor exponía el stack trace completo, rutas del sistema de archivos y nombres de módulos directamente al cliente en la respuesta JSON.

**Corrección:** Respuesta genérica al cliente con un `errorId` para trazabilidad interna. El detalle del error solo queda en los logs del servidor.

---

### V3 — Missing Authentication

**Clasificación:** OWASP A01:2021 — Broken Access Control
**Severidad:** Crítica
**Endpoint:** `GET /admin/stats`

**Problema:** El endpoint administrativo no implementaba autenticación ni validación de roles. Devolvía información privilegiada (host de BD, versión de Node.js) sin verificar la identidad del cliente.

**Corrección:** Middleware `authMiddleware` + `requireRole('admin')`. La respuesta solo incluye métricas estadísticas sin datos internos del sistema.

---

### V4 — Path Traversal

**Clasificación:** OWASP A01:2021 — Broken Access Control
**Severidad:** Crítica
**Endpoint:** `GET /logs/:file`

**Problema:** El parámetro `:file` se usaba sin validación, permitiendo secuencias `../` para navegar fuera del directorio `/logs` y leer archivos arbitrarios del sistema (`.env`, `server.js`, etc.).

**Corrección:** `path.basename()` elimina cualquier componente de directorio. Whitelist explícita de archivos permitidos. Requiere JWT con rol admin.
