-- Old rows contain bearer tokens, so invalidate them rather than retain a
-- compatibility path that would accept raw database credentials.
DELETE FROM auth_sessions;
DELETE FROM oidc_states;
ALTER TABLE auth_sessions ADD COLUMN authenticated_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE oidc_states ADD COLUMN reauth_user_id TEXT;
ALTER TABLE oidc_states ADD COLUMN started_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE oidc_states ADD COLUMN return_to TEXT NOT NULL DEFAULT '/';
CREATE INDEX auth_sessions_user ON auth_sessions(user_id);
