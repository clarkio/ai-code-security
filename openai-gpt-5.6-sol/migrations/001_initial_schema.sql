CREATE TABLE users (
  id uuid PRIMARY KEY,
  email varchar(254) NOT NULL,
  password_hash varchar(512) NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT users_email_normalized CHECK (email = lower(btrim(email))),
  CONSTRAINT users_password_hash_length CHECK (char_length(password_hash) BETWEEN 40 AND 512),
  CONSTRAINT users_email_unique UNIQUE (email)
);

CREATE TABLE notes (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title varchar(200) NOT NULL,
  content varchar(10000) NOT NULL,
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT notes_title_length CHECK (char_length(title) BETWEEN 1 AND 200),
  CONSTRAINT notes_content_length CHECK (char_length(content) BETWEEN 1 AND 10000),
  CONSTRAINT notes_version_positive CHECK (version > 0)
);

CREATE INDEX notes_user_updated_idx ON notes (user_id, updated_at DESC, id DESC);

-- Schema expected by connect-pg-simple. Authentication state remains on the
-- server; browsers receive only the signed opaque session identifier.
CREATE TABLE user_sessions (
  sid varchar NOT NULL COLLATE "default" PRIMARY KEY,
  sess json NOT NULL,
  expire timestamp(6) NOT NULL
);

CREATE INDEX user_sessions_expire_idx ON user_sessions (expire);
