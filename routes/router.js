const express = require('express');

const indexRoutes = require('./home/index');
const authRoutes = require('./auth/auth');

// Router
const router = express.Router();

// Home Routes
router.use(indexRoutes);

// Auth Routes
router.use(authRoutes);

module.exports = router;