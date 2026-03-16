const fs = require("node:fs");
const path = require("node:path");

function readState(databasePath) {
  if (!fs.existsSync(databasePath)) {
    return { nextId: 1, notes: [] };
  }

  const raw = fs.readFileSync(databasePath, "utf8");
  const parsed = JSON.parse(raw);

  if (
    !parsed ||
    !Array.isArray(parsed.notes) ||
    !Number.isInteger(parsed.nextId)
  ) {
    throw new Error("Invalid notes data file.");
  }

  return parsed;
}

function writeState(databasePath, state) {
  const directory = path.dirname(databasePath);
  fs.mkdirSync(directory, { recursive: true });

  const temporaryPath = `${databasePath}.tmp`;
  fs.writeFileSync(temporaryPath, JSON.stringify(state, null, 2), {
    encoding: "utf8",
    mode: 0o600,
  });
  fs.renameSync(temporaryPath, databasePath);
}

function createStore(config) {
  let state = readState(config.databasePath);

  function persist() {
    writeState(config.databasePath, state);
  }

  function normalizeNote(note) {
    return {
      id: note.id,
      title: note.title,
      content: note.content,
      created_at: note.created_at,
      updated_at: note.updated_at,
    };
  }

  return {
    listNotes() {
      return [...state.notes]
        .sort(
          (left, right) =>
            right.updated_at.localeCompare(left.updated_at) ||
            right.id - left.id,
        )
        .map(normalizeNote);
    },
    createNote(input) {
      const timestamp = new Date().toISOString();
      const note = {
        id: state.nextId,
        title: input.title,
        content: input.content,
        created_at: timestamp,
        updated_at: timestamp,
      };

      state = {
        nextId: state.nextId + 1,
        notes: [...state.notes, note],
      };
      persist();
      return normalizeNote(note);
    },
    getNoteById(id) {
      const note = state.notes.find((candidate) => candidate.id === id);
      return note ? normalizeNote(note) : null;
    },
    updateNote(input) {
      const timestamp = new Date().toISOString();
      let updatedNote = null;

      state = {
        nextId: state.nextId,
        notes: state.notes.map((note) => {
          if (note.id !== input.id) {
            return note;
          }

          updatedNote = {
            ...note,
            title: input.title,
            content: input.content,
            updated_at: timestamp,
          };
          return updatedNote;
        }),
      };

      persist();
      return updatedNote ? normalizeNote(updatedNote) : null;
    },
    deleteNote(id) {
      const initialLength = state.notes.length;
      state = {
        nextId: state.nextId,
        notes: state.notes.filter((note) => note.id !== id),
      };

      if (state.notes.length !== initialLength) {
        persist();
      }

      return initialLength !== state.notes.length;
    },
  };
}

module.exports = {
  createStore,
};
