const express = require('express');
const path = require('path');
const rootdir = require('../../helpers/rootdir');

// Controllers
const indexController = require(path.join(rootdir, 'controllers', 'home', 'index'));

const router = express.Router();

router.get('/', indexController.getIndex);

module.exports = router;