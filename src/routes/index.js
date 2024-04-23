const express = require('express');
const bcrypt = require('bcrypt');
const { login, logout, products } = require('./controllers');

const loginRouter = express.Router();
const productsRouter = express.Router();
const logoutRouter = express.Router();

// Ruta de login
loginRouter.get('/', (req, res) => {
    if (req.session.user) {
        res.redirect('/products');
    } else {
        res.render('login.ejs', { csrfToken: req.csrfToken() });
    }
});
loginRouter.post('/', async (req, res) => {
    const { email, password } = req.body;
    // Validación y autenticación del usuario
    // ...
    // Verificación de la contraseña
    const passwordHash = 'hash_de_la_contraseña'; // Obtener desde la base de datos
    const passwordMatch = await bcrypt.compare(password, passwordHash);
    if (passwordMatch) {
        // Autenticación exitosa, crear sesión
        req.session.user = {
            email: email,
            role: 'admin' // O el rol correspondiente
        };
        res.redirect('/products');
    } else {
        // Autenticación fallida
        res.render('login.ejs', { error: 'Credenciales inválidas', csrfToken: req.csrfToken() });
    }
});

// Ruta de productos
productsRouter.get('/', (req, res) => {
    if (req.session.user) {
        res.render('products.ejs', { user: req.session.user });
    } else {
        res.redirect('/');
    }
});

// Ruta de logout
logoutRouter.get('/', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

module.exports = {
    loginRouter,
    productsRouter,
    logoutRouter
};
