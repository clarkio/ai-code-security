const { validationResult } = require('express-validator');

exports.validate = (req, res, next) => {
  const errors = validationResult(req);
  console.log(req.body);
  
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      errors: errors.array().map(err => ({
        field: err.param,
        message: err.msg
      }))
    });
  }
  
  next();
};