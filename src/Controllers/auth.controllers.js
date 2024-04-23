const bcrypt = require('bcrypt');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const User = require('./user.model');

// Controlador de inicio de sesión con sesión
async function loginWithSession(req, res, next) {
    passport.authenticate('local', (err, user, info) => {
        if (err) return next(err);
        if (!user) return res.status(401).json({ message: info.message });
        req.logIn(user, (err) => {
            if (err) return next(err);
            return res.json(user);
        });
    })(req, res, next);
}

// Controlador de inicio de sesión con JWT
async function loginWithJWT(req, res, next) {
    passport.authenticate('local', { session: false }, async (err, user, info) => {
        if (err) return next(err);
        if (!user) return res.status(401).json({ message: info.message });
        const token = jwt.sign({ sub: user._id }, 'jwt-secret', { expiresIn: '1h' });
        return res.json({ user, token });
    })(req, res, next);
}

module.exports = {
    loginWithSession,
    loginWithJWT
};
