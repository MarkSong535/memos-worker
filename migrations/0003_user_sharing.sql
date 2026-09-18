-- Preserve the existing sharing default; administrators can disable it per user.
ALTER TABLE users ADD COLUMN can_share INTEGER NOT NULL DEFAULT 1 CHECK(can_share IN (0, 1));
ALTER TABLE public_shares ADD COLUMN created_by TEXT REFERENCES users(id);
-- Older links did not record their creator; attribute them to the note owner.
UPDATE public_shares SET created_by = (SELECT owner_id FROM notes WHERE notes.id = public_shares.note_id);
CREATE INDEX public_shares_creator ON public_shares(created_by);
