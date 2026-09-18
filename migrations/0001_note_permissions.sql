-- Apply to the existing Memos database before deploying the SSO version.
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  name TEXT NOT NULL,
  email TEXT,
  UNIQUE(issuer, subject)
);
ALTER TABLE notes ADD COLUMN owner_id TEXT REFERENCES users(id);
CREATE INDEX notes_owner ON notes(owner_id);
CREATE TABLE note_permissions (
  note_id INTEGER NOT NULL REFERENCES notes(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  can_edit INTEGER NOT NULL DEFAULT 0 CHECK(can_edit IN (0,1)),
  PRIMARY KEY(note_id, user_id)
);
CREATE INDEX permissions_user ON note_permissions(user_id, note_id);
CREATE TABLE note_hidden (
  note_id INTEGER NOT NULL REFERENCES notes(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  deleted_at INTEGER NOT NULL,
  PRIMARY KEY(note_id, user_id)
);
CREATE TABLE oidc_states (
  id TEXT PRIMARY KEY,
  verifier TEXT NOT NULL,
  nonce TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE auth_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  is_admin INTEGER NOT NULL CHECK(is_admin IN (0,1)),
  expires_at INTEGER NOT NULL
);
