const crypto = require('crypto');
const path = require('path');
const rootdir = require('../../helpers/rootdir');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const mailConfig = require(path.join(rootdir, 'config', 'mail'));
const { validationResult } = require('express-validator');
const mongoose = require('mongoose');
const tokenGenerator = require(path.join(rootdir, 'helpers', 'token-generator'));

// Mailer
const mailTransporter = nodemailer.createTransport(mailConfig.smtp);

// Models
const User = require(path.join(rootdir, 'models', 'user'));

exports.getRegister = (req, res, next) => {
    res.render('auth/register', {
        pageTitle: 'Register',
        success: req.flash('success')[0],
        error: req.flash('error')[0],
        input: {email: '', username: ''}
    });
};

exports.postRegister = (req, res, next) => {
    const serverUrl = req.protocol + '://' + req.get('host');
    const email = req.body.email;
    const username = req.body.username;
    const password = req.body.password;

    const errors = validationResult(req);
    if(!errors.isEmpty()) {
        return res.status(422).render('auth/register', {
            pageTitle: 'Register',
            error: errors.array()[0].msg,
            success: '',
            input: {email: email, username: username}
        });
    }

    crypto.randomBytes(32, async(err, buffer) => {
        if(err) {
            const error = new Error('Failed to Generate Token');
            error.statusCode = 500;
            return next(error);
        }

        const token = buffer.toString('hex');

        try {
            const user = await User.findOne({$or: [{email: email}, {username: username}]});
            if(user) {
                req.flash('error', 'Username or Email Already Exists!');
                return res.redirect('/auth/register');
            }

            const hashedPassword = await bcrypt.hash(password, 12);
            const newUser = new User({email: email, username: username.toLowerCase(), password: hashedPassword, verifyToken: token, verifyTokenExpiration: Date.now() + 600000});
            await newUser.save();

            req.flash('success', 'User successfully registered! Check your Email for Verification!');
            res.redirect('/auth/login');

            await mailTransporter.sendMail({
                to: email,
                from: mailConfig.general.noreply_mail,
                subject: 'Registration Successful!',
                html: `
                    <h1>You Successfully Signed Up!</h1>
                    <p>Email Verification</p>
                    <p>Verify Token: ${token}</p>
                    <p>Click <a href="${serverUrl}/auth/verification/verify-email/${newUser._id}/${token}">${serverUrl}/auth/verification/verify-email/${newUser._id}/${token}</a> To Verify Your Email</p>
                `
            });

        } catch(err) {
            const error = new Error(err);
            error.statusCode = 500;
            return next(error);
        }
    });
};

exports.getLogin = async(req, res, next) => {
    res.render('auth/login', {
        pageTitle: 'Login',
        success: req.flash('success')[0],
        error: req.flash('error')[0],
        input: {username: ''}
    });
};

exports.postLogin = async(req, res, next) => {
    const username = req.body.username;
    const password = req.body.password;

    const errors = validationResult(req);
    if(!errors.isEmpty()) {
        return res.status(422).render('auth/login', {
            pageTitle: 'Login',
            error: errors.array()[0].msg,
            success: '',
            input: {username: username}
        });
    }

    try { 
        const user = await User.findOne({username: username});
        if(!user) {
            req.flash('error', 'User not found');
            return res.redirect('/auth/login');
        }

        const matches = await bcrypt.compare(password, user.password);
        if(!matches) {
            req.flash('error', 'Invalid Password');
            return res.redirect('/auth/login');
        }

        req.session.user = user;
        req.session.isAuthenticated = true;

        return req.session.save(err => {
            res.redirect('/');
        });

    } catch(err) {
        const error = new Error(err);
        error.statusCode = 500;
        return next(error);
    }
};

exports.getLogout = (req, res, next) => {
    req.session.destroy(err => {
        res.redirect('/auth/login');
    });
};

exports.getVerifyEmail = async(req, res, next) => {
    const userId = req.params.userId;
    const token = req.params.token;

    if(!mongoose.Types.ObjectId.isValid(userId)) {
        req.flash('error', 'Invalid UserId');
        return res.redirect(`/auth/login`);
    }

    try {
        const user = await User.findById(userId);
        if(!user) {
            req.flash('error', 'User not Found');
            return res.redirect(`/auth/login`);
        }

        if(user.verifyToken !== token) {
            req.flash('error', 'Invalid Verify Token');
            return res.redirect(`/auth/login`);
        }

        if(Date.now() > user.verifyTokenExpiration) {
            req.flash('error', 'Verify Token Expired');
            return res.redirect(`/auth/login`);
        }

        user.verifiedEmail = true;
        user.verifyToken = undefined;
        user.verifyTokenExpiration = undefined;
        await user.save();
        req.flash('success', 'Email has been Verified');
        res.redirect('/auth/login');
    } catch(err) {
        const error = new Error(err);
        error.statusCode = 500;
        return next(error);
    }
};

exports.getResetPasswordEmail = async(req, res, next) => {
    res.render('auth/reset-password', {
        pageTitle: 'Reset Password',
        success: req.flash('success')[0],
        error: req.flash('error')[0],
        input: {email: ''}
    });
};

exports.postResetPasswordEmail = async(req, res, next) => {
    const serverUrl = req.protocol + '://' + req.get('host');
    const email = req.body.email;

    const errors = validationResult(req);
    if(!errors.isEmpty()) {
        return res.status(422).render('auth/reset-password', {
            pageTitle: 'Reset Password',
            error: errors.array()[0].msg,
            success: '',
            input: {email: ''}
        });
    }

    try {
        const token = await tokenGenerator(32);

        const user = await User.findOne({email: email});
        if(!user) {
            req.flash('error', 'No such User with this Email');
            return res.redirect('/auth/account/reset-password');
        }
        
        user.resetToken = token;
        user.resetTokenExpiration = Date.now() + 600000; //10 Minutes

        await user.save();
        req.flash('success', 'Password reset email sent!');
        res.redirect('/auth/login');

        await mailTransporter.sendMail({
            to: email,
            from: mailConfig.general.noreply_mail,
            subject: 'Reset Password',
            html: `
                <p>Requested Password Reset</p>
                <p>Click <a href="${serverUrl}/auth/account/password/reset/${user._id}/${token}">${serverUrl}/auth/account/password/reset/${user._id}/${token}</a> To Reset password</p>
            `
        });

    } catch(err) {
        const error = new Error(err);
        error.status = 500;
        return next(error);
    }
};

exports.resetUserPassword = async(req, res, next) => {
    const userId = req.params.userId;
    const token = req.params.token;

    if(!mongoose.Types.ObjectId.isValid(userId)) {
        req.flash('error', 'Invalid UserId');
        return res.redirect(`/auth/login`);
    }

    try {
        const user = await User.findById(userId);
        if(!user) {
            req.flash('error', 'User not Found');
            return res.redirect('/auth/login');
        }

        if(user.resetToken !== token) {
            req.flash('error', 'Invalid Reset Token');
            return res.redirect('/auth/login');
        }

        if(Date.now() > user.resetTokenExpiration) {
            req.flash('error', 'Reset Token Expired');
            return res.redirect('/auth/login');
        }

        res.render('auth/reset-user-password', {
            pageTitle: 'Reset Password',
            success: req.flash('success')[0],
            error: req.flash('error')[0],
            userId: user._id.toString(),
            resetToken: token
        });

    } catch(err) {
        const error = new Error(err);
        error.status = 500;
        return next(error);
    }
};

exports.resetPassword = async(req, res, next) => {
    const token = req.body.resetToken;
    const userId = req.body.userId;
    const password = req.body.password;
    const errors = validationResult(req);
    
    if(!errors.isEmpty()) {
        req.flash('error', errors.array()[0].msg);
        return res.redirect(`/auth/account/password/reset/${userId}/${token}`);
    }

    if(!mongoose.Types.ObjectId.isValid(userId)) {
        req.flash('error', 'Invalid UserId');
        return res.redirect(`/auth/login`);
    }

    try {
        const user = await User.findOne({_id: userId, resetToken: token, resetTokenExpiration: {$gt: Date.now()}});
        if(!user) {
            req.flash('error', 'Invalid Token');
            return res.redirect('/');
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        user.password = hashedPassword;
        user.resetToken = undefined;
        user.resetTokenExpiration = undefined;
        await user.save();
        req.flash('success', 'Password Successfully Reset');
        res.redirect('/auth/login');
    } catch(err) {
        const error = new Error(err);
        error.status = 500;
        return next(error);
    }
};