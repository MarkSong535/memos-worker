CREATE TABLE public_shares (
  token TEXT PRIMARY KEY,
  note_id INTEGER NOT NULL REFERENCES notes(id) ON DELETE CASCADE,
  file_id TEXT,
  image_id TEXT,
  parent_token TEXT REFERENCES public_shares(token) ON DELETE CASCADE,
  expires_at INTEGER
);
CREATE INDEX public_shares_note ON public_shares(note_id);
