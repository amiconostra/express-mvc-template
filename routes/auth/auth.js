const express = require('express');
const path = require('path');
const rootdir = require('../../helpers/rootdir');
const inputValidator = require(path.join(rootdir, 'middlewares', 'input-validator'));

// Controllers
const authController = require(path.join(rootdir, 'controllers', 'auth', 'auth'));

const router = express.Router();

router.get('/auth/register', authController.getRegister);

router.post('/auth/register', inputValidator.validate('register'), authController.postRegister);

router.get('/auth/login', authController.getLogin);

router.post('/auth/login', inputValidator.validate('username'), authController.postLogin);

router.get('/auth/logout', authController.getLogout);

router.get('/auth/verification/verify-email/:userId/:token', authController.getVerifyEmail);

router.get('/auth/account/reset-password', authController.getResetPasswordEmail);

router.post('/auth/account/reset-password', inputValidator.validate('email'), authController.postResetPasswordEmail);

router.get('/auth/account/password/reset/:userId/:token', authController.resetUserPassword);

router.post('/auth/account/password/reset', inputValidator.validate('resetPassword'), authController.resetPassword);

module.exports = router;