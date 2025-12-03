const db = require("../config/database");
const { validationResult } = require("express-validator");

exports.getNotes = (req, res) => {
  db.all(
    "SELECT * FROM notes WHERE user_id = ? ORDER BY created_at DESC",
    [req.session.user.id],
    (err, rows) => {
      if (err) {
        console.error(err);
        return res.status(500).send("Server error");
      }
      res.render("notes/index", { title: "My Notes", notes: rows });
    }
  );
};

exports.getCreateNote = (req, res) => {
  res.render("notes/create", { title: "Create Note", errors: [], note: {} });
};

exports.postCreateNote = (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.render("notes/create", {
      title: "Create Note",
      errors: errors.array(),
      note: req.body,
    });
  }

  const { title, content } = req.body;

  db.run(
    "INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)",
    [req.session.user.id, title, content],
    function (err) {
      if (err) {
        console.error(err);
        return res.status(500).send("Server error");
      }
      res.redirect("/notes");
    }
  );
};

exports.getEditNote = (req, res) => {
  const noteId = req.params.id;
  db.get(
    "SELECT * FROM notes WHERE id = ? AND user_id = ?",
    [noteId, req.session.user.id],
    (err, row) => {
      if (err) {
        console.error(err);
        return res.status(500).send("Server error");
      }
      if (!row) {
        return res.status(404).send("Note not found");
      }
      res.render("notes/edit", { title: "Edit Note", errors: [], note: row });
    }
  );
};

exports.postEditNote = (req, res) => {
  const errors = validationResult(req);
  const noteId = req.params.id;

  if (!errors.isEmpty()) {
    return res.render("notes/edit", {
      title: "Edit Note",
      errors: errors.array(),
      note: { ...req.body, id: noteId },
    });
  }

  const { title, content } = req.body;

  db.run(
    "UPDATE notes SET title = ?, content = ? WHERE id = ? AND user_id = ?",
    [title, content, noteId, req.session.user.id],
    function (err) {
      if (err) {
        console.error(err);
        return res.status(500).send("Server error");
      }
      res.redirect("/notes");
    }
  );
};

exports.postDeleteNote = (req, res) => {
  const noteId = req.params.id;
  db.run(
    "DELETE FROM notes WHERE id = ? AND user_id = ?",
    [noteId, req.session.user.id],
    function (err) {
      if (err) {
        console.error(err);
        return res.status(500).send("Server error");
      }
      res.redirect("/notes");
    }
  );
};
