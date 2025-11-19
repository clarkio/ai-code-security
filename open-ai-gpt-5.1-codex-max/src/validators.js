const Joi = require('joi');

const username = Joi.string().alphanum().min(3).max(32).trim();
const password = Joi.string()
  .min(12)
  .max(128)
  .regex(/[A-Z]/)
  .regex(/[a-z]/)
  .regex(/[0-9]/)
  .regex(/[^A-Za-z0-9]/);

const title = Joi.string().min(1).max(150).trim();
const content = Joi.string().min(1).max(5000).trim();

module.exports = {
  registerSchema: Joi.object({
    username: username.required(),
    password: password.required(),
  }),
  loginSchema: Joi.object({
    username: username.required(),
    password: Joi.string().required(),
  }),
  noteSchema: Joi.object({
    title: title.required(),
    content: content.required(),
  }),
};
