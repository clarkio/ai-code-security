const express = require("express");
const Joi = require("joi");
const argon2 = require("argon2");
const { v4: uuidv4 } = require("uuid");

const registerSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  password: Joi.string().min(12).max(128).required(),
});

const loginSchema = Joi.object({
  username: Joi.string().required(),
  password: Joi.string().required(),
});

module.exports = (knex) => {
  const router = express.Router();

  router.post("/register", async (req, res, next) => {
    try {
      const { error, value } = registerSchema.validate(req.body);
      if (error) return res.status(400).json({ error: error.message });

      const { username, password } = value;
      const existing = await knex("users").where({ username }).first();
      if (existing)
        return res.status(409).json({ error: "Username already taken" });

      const hash = await argon2.hash(password);
      const user = { id: uuidv4(), username, password_hash: hash };

      await knex("users").insert(user);
      req.session.userId = user.id;
      res.status(201).json({ id: user.id, username: user.username });
    } catch (err) {
      next(err);
    }
  });

  router.post("/login", async (req, res, next) => {
    try {
      const { error, value } = loginSchema.validate(req.body);
      if (error) return res.status(400).json({ error: error.message });

      const { username, password } = value;
      const user = await knex("users").where({ username }).first();
      if (!user) return res.status(401).json({ error: "Invalid credentials" });

      const ok = await argon2.verify(user.password_hash, password);
      if (!ok) return res.status(401).json({ error: "Invalid credentials" });

      req.session.regenerate((err) => {
        if (err) return next(err);
        req.session.userId = user.id;
        res.json({ id: user.id, username: user.username });
      });
    } catch (err) {
      next(err);
    }
  });

  router.post("/logout", (req, res, next) => {
    req.session.destroy((err) => {
      if (err) return next(err);
      res.clearCookie("sid");
      res.json({ ok: true });
    });
  });

  router.get("/me", (req, res) => {
    if (!req.session.userId)
      return res.status(401).json({ error: "Not authenticated" });
    res.json({ id: req.session.userId });
  });

  return router;
};
