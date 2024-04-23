const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GitHubStrategy = require('passport-github').Strategy;

const app = express();

// Configuración de sesión
app.use(session({
    secret: 'secret-key',
    resave: false,
    saveUninitialized: true
}));

// Middleware para parsear los cuerpos de las solicitudes
app.use(bodyParser.urlencoded({ extended: true }));

// Inicializar Passport
app.use(passport.initialize());
app.use(passport.session());

// Configuración de Passport
passport.use(new LocalStrategy(async (email, password, done) => {
    try {
        const user = await getUserByEmail(email);
        if (!user) {
            return done(null, false, { message: 'Correo electrónico no encontrado' });
        }
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return done(null, false, { message: 'Contraseña incorrecta' });
        }
        return done(null, user);
    } catch (error) {
        return done(error);
    }
}));

passport.use(new GitHubStrategy({
    clientID: GITHUB_CLIENT_ID,
    clientSecret: GITHUB_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/github/callback"
  },
  function(accessToken, refreshToken, profile, cb) {
    return cb(null, profile);
  }
));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await getUserById(id);
        done(null, user);
    } catch (error) {
        done(error);
    }
});

// Rutas
app.get('/', (req, res) => {
    res.render('index.ejs');
});

app.post('/login', passport.authenticate('local', {
    successRedirect: '/products',
    failureRedirect: '/',
    failureFlash: true
}));

app.get('/auth/github', passport.authenticate('github'));

app.get('/auth/github/callback',
  passport.authenticate('github', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/products');
  });

app.get('/products', (req, res) => {
    if (req.isAuthenticated()) {
        res.render('products.ejs', { user: req.user });
    } else {
        res.redirect('/');
    }
});

app.get('/logout', (req, res) => {
    req.logout();
    res.redirect('/');
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor iniciado en http://localhost:${PORT}`);
});
