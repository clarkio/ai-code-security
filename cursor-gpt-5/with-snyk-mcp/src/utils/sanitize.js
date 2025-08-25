'use strict';

const xss = require('xss');

function sanitizeString(input) {
    if (typeof input !== 'string') return '';
    return xss(input, {
        whiteList: {},
        stripIgnoreTag: true,
        stripIgnoreTagBody: ['script']
    });
}

module.exports = { sanitizeString };


