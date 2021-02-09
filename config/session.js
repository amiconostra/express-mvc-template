const session = require('express-session');
const MongoDBStore = require('connect-mongodb-session')(session);
const mongodbConfig = require('./mongodb');

module.exports = (req, res, next) => {
    // Session DB
    const store = new MongoDBStore({
        uri: mongodbConfig.MONGODB_URI,
        collection: 'sessions'
    });

    return session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        store: store,
        // cookie: { secure: true }
    });
};