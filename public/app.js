/**
 * ===============================
 * APLICACIÓN CLIENTE — VERSIÓN SEGURA
 * Correcciones aplicadas:
 *   V3 (XSS): innerHTML → textContent
 *   V4 (Credenciales en URL): GET → POST con body JSON
 *   V6 (Auth): envío de JWT en cabecera Authorization
 * ===============================
 */

let authToken = null;

function login() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;

    if (!username || !password) {
        setOutput("Por favor completa todos los campos");
        return;
    }

    // CORRECCIÓN — Credenciales en URL:
    // POST con body JSON en lugar de GET con query params
    fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    })
    .then(res => res.json())
    .then(data => {
        if (data.token) {
            authToken = data.token;
            // CORRECCIÓN V3 (XSS): textContent en lugar de innerHTML
            setOutput(data.message);

            document.getElementById('admin-section').style.display =
                data.role === 'admin' ? 'block' : 'none';
        } else {
            setOutput(data.error || 'Error de autenticación');
        }
    })
    .catch(() => {
        setOutput("Error de conexión con el servidor");
    });
}

function logout() {
    authToken = null;
    setOutput("Sesión cerrada");
    document.getElementById('admin-section').style.display = 'none';
}

// CORRECCIÓN V3 (XSS): helper centralizado que siempre usa textContent
function setOutput(text) {
    document.getElementById('login-output').textContent = text;
}

function getUsers() {
    if (!authToken) {
        setOutput("Debes iniciar sesión primero");
        return;
    }

    // CORRECCIÓN V6: JWT en cabecera Authorization
    fetch('/users', {
        headers: { 'Authorization': `Bearer ${authToken}` }
    })
    .then(res => res.json())
    .then(data => {
        // CORRECCIÓN V3 (XSS): textContent — sin renderizado de HTML
        setOutput(JSON.stringify(data, null, 2));
    })
    .catch(() => {
        setOutput("Error al obtener usuarios");
    });
}

function saveUser() {
    if (!authToken) {
        setOutput("Debes iniciar sesión primero");
        return;
    }

    const username = prompt("Nombre de usuario (mín. 3 caracteres):");
    const password = prompt("Contraseña (mín. 8 caracteres):");

    if (!username || !password) {
        setOutput("Operación cancelada");
        return;
    }

    fetch('/save', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${authToken}`
        },
        body: JSON.stringify({ username, password })
    })
    .then(res => res.json())
    .then(data => {
        // CORRECCIÓN V3 (XSS): textContent
        setOutput(data.message || data.error);
    })
    .catch(() => {
        setOutput("Error al guardar usuario");
    });
}
