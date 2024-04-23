const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const bcrypt = require('bcrypt');
const User = require('./user.model');

// Estrategia de autenticación local
passport.use(new LocalStrategy({
    usernameField: 'email'
}, async (email, password, done) => {
    try {
        const user = await User.findOne({ email });
        if (!user) return done(null, false, { message: 'Correo electrónico no encontrado' });
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) return done(null, false, { message: 'Contraseña incorrecta' });
        return done(null, user);
    } catch (error) {
        return done(error);
    }
}));

// Estrategia de autenticación JWT
passport.use(new JwtStrategy({
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: 'jwt-secret'
}, async (jwt_payload, done) => {
    try {
        const user = await User.findById(jwt_payload.sub);
        if (!user) return done(null, false);
        return done(null, user);
    } catch (error) {
        return done(error, false);
    }
}));
