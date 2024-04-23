const bcrypt = require('bcrypt');
const User = require('./user.model'); // Importa el modelo de usuario

// Controlador de login
async function login(req, res) {
    const { email, password } = req.body;

    try {
        // Buscar el usuario por correo electrónico en la base de datos
        const user = await User.findOne({ email });

        if (!user) {
            // El usuario no existe
            return res.render('login.ejs', { error: 'Credenciales inválidas', csrfToken: req.csrfToken() });
        }

        // Comparar la contraseña proporcionada con la contraseña almacenada utilizando bcrypt
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (passwordMatch) {
            // Autenticación exitosa, crear sesión
            req.session.user = {
                id: user.id,
                email: user.email,
                role: user.role
            };
            return res.redirect('/products');
        } else {
            // Autenticación fallida
            return res.render('login.ejs', { error: 'Credenciales inválidas', csrfToken: req.csrfToken() });
        }
    } catch (error) {
        console.error('Error al intentar iniciar sesión:', error);
        return res.status(500).json({ error: 'Error interno del servidor' });
    }
}

module.exports = {
    login
};
