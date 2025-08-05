const sanitizeHtml = require('sanitize-html');

function sanitizeInput(input) {
    return sanitizeHtml(input, {
        allowedTags: [],
        allowedAttributes: {}
    });
}

module.exports = {
    sanitizeInput
};