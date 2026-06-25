"use strict";

/**
 * Page routes — render EJS templates.
 * Templates auto-escape output (EJS `<%= %>`), preventing reflected/stored XSS.
 */

const express = require("express");

const router = express.Router();
const repo = require("../db/repository");
const { requireAuth } = require("../middleware/auth");

// Home → redirect based on auth state
router.get("/", (req, res) => {
  if (req.user) return res.redirect("/notes");
  return res.redirect("/login");
});

// Login page
router.get("/login", (req, res) => {
  if (req.user) return res.redirect("/notes");
  return res.render("login", { title: "Login" });
});

// Register page
router.get("/register", (req, res) => {
  if (req.user) return res.redirect("/notes");
  return res.render("register", { title: "Register" });
});

// Notes page (protected)
router.get("/notes", requireAuth, (req, res, next) => {
  try {
    const notes = repo.listNotes(req.user.id);
    return res.render("notes", { title: "My Notes", notes });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
