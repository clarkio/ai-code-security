const bcrypt = require("bcrypt");
const db = require("../config/database");
const { validationResult } = require("express-validator");

exports.getRegister = (req, res) => {
  res.render("register", { title: "Register", errors: [] });
};

exports.postRegister = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.render("register", {
      title: "Register",
      errors: errors.array(),
    });
  }

  const { username, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 12); // Salt rounds: 12

    db.run(
      "INSERT INTO users (username, password) VALUES (?, ?)",
      [username, hashedPassword],
      function (err) {
        if (err) {
          if (err.message.includes("UNIQUE constraint failed")) {
            return res.render("register", {
              title: "Register",
              errors: [{ msg: "Username already exists" }],
            });
          }
          console.error(err);
          return res.status(500).send("Server error");
        }
        res.redirect("/login");
      }
    );
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
};

exports.getLogin = (req, res) => {
  res.render("login", { title: "Login", errors: [] });
};

exports.postLogin = (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.render("login", { title: "Login", errors: errors.array() });
  }

  const { username, password } = req.body;

  db.get(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, user) => {
      if (err) {
        console.error(err);
        return res.status(500).send("Server error");
      }

      if (!user) {
        return res.render("login", {
          title: "Login",
          errors: [{ msg: "Invalid credentials" }],
        });
      }

      const match = await bcrypt.compare(password, user.password);

      if (!match) {
        return res.render("login", {
          title: "Login",
          errors: [{ msg: "Invalid credentials" }],
        });
      }

      // Regenerate session to prevent session fixation
      req.session.regenerate((err) => {
        if (err) {
          console.error(err);
          return res.status(500).send("Server error");
        }
        req.session.user = { id: user.id, username: user.username };
        res.redirect("/notes");
      });
    }
  );
};

exports.postLogout = (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error(err);
      return res.status(500).send("Server error");
    }
    res.redirect("/");
  });
};
