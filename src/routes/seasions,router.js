const express = require('express');
const passport = require('passport');
const User = require('./user.model');

const router = express.Router();

// Obtener usuario actual
router.get('/current', passport.authenticate('jwt', { session: false }), async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        res.json(user);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener el usuario actual' });
    }
});

module.exports = router;

