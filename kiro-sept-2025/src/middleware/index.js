const validation = require('./validation');
const security = require('./security');

module.exports = {
  ...validation,
  ...security
};