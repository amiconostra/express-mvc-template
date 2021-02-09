const express = require('express');
const mongoose = require('mongoose');
require('dotenv').config();
const expressLayouts = require('express-ejs-layouts');
const session = require('./config/session');
const flash = require('connect-flash');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const mongodbConfig = require('./config/mongodb');

// CSRF Settings
const csrfProtection = csrf();

// Express APP
const app = express();

// Express Settings
app.set('view engine', 'ejs');
app.set('views', 'views');
app.set('layout', 'layout');

// Express Middlewares
app.use(cookieParser());
app.use(expressLayouts);
app.use(express.static('public'));
app.use(express.urlencoded({extended: true}));
app.use(express.json());
app.use(session());
app.use(csrfProtection);
app.use(flash());

// Shared Across Views
app.use((req, res, next) => {
    res.locals.isAuthenticated = req.session.isAuthenticated;
    res.locals.csrfToken = req.csrfToken();
    next();
});

// Routes
app.use('/', require('./routes/router'));

// Internal Error Handler
// Development Error Handler
if (app.get('env') === 'development') {
    app.use((err, req, res, next) => {
        res.status(err.statusCode || 500);
        res.render('error/500', {
            pageTitle: '500',
            message: err.message,
            error: err
        });
    });
};

// Production Error Handler
app.use((err, req, res, next) => {
    res.status(err.statusCode || 500);
    res.render('error/500', {
        pageTitle: '500',
        message: err.message,
        error: {}
    });
});

mongoose.connect(mongodbConfig.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true, useFindAndModify: false })
    .then((result) => {
        app.listen(process.env.PORT || 3000, () => {
            console.log('Running on Port', process.env.PORT || 3000);
        });
    })
    .catch((err) => {
        console.log(err);
    });