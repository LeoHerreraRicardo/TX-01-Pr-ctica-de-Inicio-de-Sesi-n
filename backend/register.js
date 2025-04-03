// Importar dependencias
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const argon2 = require("argon2");
const crypto = require("crypto");
const bodyParser = require("body-parser");

// Configurar Express
const app = express();
app.use(cors()); // Permite comunicación con el frontend
app.use(bodyParser.json());

// Simular base de datos en memoria
const users = [];

// Función de hash personalizada
function customHash(input, rounds, salt) {
    let totalRounds = Math.pow(2, rounds);
    let hash = input;
    salt = salt || Math.floor(Math.random() * 0x7fffffff).toString(36);
    for (let i = 0; i < totalRounds; i++) {
        hash = crypto.createHash("md5").update(salt + hash).digest("hex");
    }
    return `$custom$${rounds}$${Buffer.from(salt).toString("base64")}$${Buffer.from(hash).toString("base64")}`;
}

// Validar contraseña
function validarPassword(password) {
    return (
        password.length >= 10 && 
        /[A-Z]/.test(password) && 
        /[a-z]/.test(password) && 
        /[0-9]/.test(password) && 
        /[^A-Za-z0-9\s]/.test(password) 
    );
}

// Ruta para registrar usuario
app.post("/register", async (req, res) => {
    const { username, password, confirmPassword } = req.body;

    if (!username || !password || !confirmPassword) {
        return res.status(400).json({ message: "Todos los campos son obligatorios" });
    }

    if (password !== confirmPassword) {
        return res.status(400).json({ message: "Las contraseñas no coinciden" });
    }

    if (!validarPassword(password)) {
        return res.status(400).json({ message: "La contraseña no cumple los requisitos" });
    }

    let salt = await bcrypt.genSalt(10);
    const hashedPassword = {
        bcrypt10: await bcrypt.hash(password, 10),
        bcryptSalt: await bcrypt.hash(password, salt),
        bcryptSalt22: await bcrypt.hash(password, "$2a$10$0123456789012345678901."),
        argon2: await argon2.hash(password),
        custom: customHash(password, 10),
    };

    users.push({ username, password: hashedPassword.bcrypt10 });
    res.status(201).json({ message: "Usuario registrado exitosamente" });
});

// Iniciar servidor
app.listen(3000, () => {
    console.log("Servidor corriendo en http://localhost:3000");
});
