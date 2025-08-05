const { body, validationResult } = require('express-validator');

const noteValidationRules = () => {
    return [
        body('title')
            .notEmpty().withMessage('Title is required')
            .isLength({ max: 100 }).withMessage('Title must be less than 100 characters'),
        body('content')
            .notEmpty().withMessage('Content is required')
            .isLength({ max: 1000 }).withMessage('Content must be less than 1000 characters'),
    ];
};

const validate = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    next();
};

module.exports = {
    noteValidationRules,
    validate,
};