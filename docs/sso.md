# Authentik SSO and note access

This version replaces the shared password login with OIDC. Deploy only after applying the migration and setting the client secret. Existing notes remain intact with no owner and are visible only to administrators until assigned or explicitly shared.

## Authentik

Application slug: `notes`. Confidential OAuth2/OIDC provider, strict redirect URI `https://n.markso.ng/api/auth/callback`, asymmetric RS256 signing key. Assign `openid`, `profile`, and `email` mappings and enable **Include claims in id_token**. Verify the profile mapping returns `groups` as an array of names. Bind groups `notes` and `notes_admin` to the application with policy engine mode **Any**.

The committed `wrangler.toml` contains the client ID, discovery URL, and application origin. Store `OIDC_CLIENT_SECRET` as a Cloudflare Worker secret, never as a plain-text variable or committed file.

## Deploy an existing installation

Use Node.js 22.13+ for the SQLite-backed tests. From the repository root:

```sh
npm ci
npm test
npx wrangler d1 export memos-db --remote --output /tmp/memos-before-sso.sql
npx wrangler d1 migrations apply memos-db --remote
npx wrangler secret put OIDC_CLIENT_SECRET
npx wrangler deploy
```

The export contains private notes: keep it secure and outside Git. `secret put` prompts for the value; omit that step if the correct secret is already configured. The migration adds columns/tables without deleting existing notes. It expects the existing Memos tables, not an empty database. Do not run the SQL manually more than once; Wrangler records applied migrations. Production migrations and deployment are not performed by the tests.

If Cloudflare Access also protects the hostname, its policy must allow the intended users to reach the application and callback. OIDC does not change that outer policy.

After deployment, sign in with a member of `notes_admin`, open **Manage note access**, assign owners for old notes, and verify with two distinct `notes` users. The user selector lists people after their first successful login.

## Permissions

- `notes`: create notes; view/edit owned notes; view or edit other notes only when granted by an admin.
- `notes_admin`: view/edit all notes, including unassigned notes; assign ownership and user grants; restore a user's hidden note; permanently delete notes.
- An edit grant also permits viewing. Owners always have view/edit access; transfer ownership to remove those implicit rights. A user in both groups is an administrator.
- Member deletion records `note_hidden(note_id, user_id, deleted_at)`. It hides the note only from that user, even if they own it or have a grant. It preserves the note and files for admins and other authorized readers.
- Admin deletion removes the note, its permission/hide records, tag links, attached storage objects and retained detached attachments. Standalone images referenced by another note are retained. Unreferenced standalone uploads are not garbage-collected automatically.
- List/search/tag/statistics/timeline/attachment queries enforce the same visibility rule. Direct requests are checked server-side. API responses and file responses are not cached.
- User preferences are stored separately per user. Legacy shared preferences are not imported.

## Existing features restricted by this change

Public sharing is read-only. Administrators can share any unflagged note; members can share only their own unflagged notes (an edit grant does not permit sharing). Any deletion flag blocks public access for the entire note. Deletion revokes all existing note/file links; restoring visibility does not reactivate those links. Attachments generated for a public note expire or revoke with their parent link. Links are stored in D1; legacy KV-only links must be recreated after migration. Telegram webhooks/media proxies and note merging are disabled until they can preserve ownership and access. Docs remain admin-only because the existing Docs tree has no user ownership model. External images/Imgur links remain external resources; the app cannot revoke access to copies or externally hosted files.

Clearing a note's content cannot silently delete it. Removing an attachment during editing detaches it from the note but retains its stored object until admin deletion. Use the note Delete action for per-user hiding.

## Authentication and validation

The login flow uses authorization code + PKCE, an HttpOnly state cookie, atomic single-use state, and signature/issuer/audience/expiry/nonce validation using `jose`. Identity is keyed by OIDC issuer + subject, not email. Users missing both groups are rejected. The legacy password login and old session cookies are not accepted.

Sessions last three hours after successful login, independently of the ID token’s remaining lifetime. The ID token must still be valid when establishing the session. Authentik group changes take effect on the next login, within that three-hour bound; app-managed note and sharing permissions are checked on each request. Existing sessions retain their original expiry until the next login. Logout ends this application's session; it does not end the Authentik browser session. A new sign-in can therefore reuse Authentik SSO.

`npm test` runs the real request handler against an in-memory SQLite database with the migration, plus signed-token and mocked-provider callback tests. `npx wrangler deploy --dry-run` checks bundling without deployment. A real browser login must still be verified against the configured Authentik provider and production secret.

## Admin-controlled user sharing

The admin page has an **Allow sharing** switch for each user. Sharing remains enabled by default, preserving the previous owner-sharing policy. Only admins can change it. Turning it off blocks new note/file shares and expiration updates, revokes links created by that user (including derived media), and takes effect on subsequent requests without requiring a new login. Re-enabling does not resurrect revoked links. Users can still revoke links on their own notes.

Admins retain sharing privileges regardless of this user setting. Admin-created links remain active when a member's sharing permission is removed. Ownership and deletion restrictions still apply: enabled members can share only their own unflagged notes; even admins cannot share flagged notes.

Apply migration `0003_user_sharing.sql` using the normal migrations command before deploying. Earlier D1 links lacked creator information, so the migration conservatively attributes those existing links to their note owner. Newly created links distinguish member-created from admin-created links.

## Note deletion controls

Each note has a trash icon before Edit. Administrators see red if any user has flagged the note and the normal theme icon color otherwise; members always see the normal theme icon color and are not sent the deletion-status field. The admin trash action offers **Flag as deleted** or **Permanently delete**. Flagging uses the existing per-user deletion record, retains the note for administrators, and revokes public shares. An admin's own flag does not hide the note from other authorized readers. Restore flags through the note's lock icon. The access page no longer lists all notes or offers a note-ID chooser.

## Session hardening

Apply `0004_session_hardening.sql` before deploying this version. It invalidates old sessions and pending login attempts once; users then sign in again. Database session IDs are now SHA-256 hashes of random cookie tokens. The browser still receives the random token in the Secure, HttpOnly, SameSite=Lax, host-only cookie. A copied database hash cannot be used as a login cookie. A stolen browser cookie can still be replayed, so this is not device-bound authentication.

Normal sessions retain their three-hour absolute lifetime. Successful login and reauthentication replace the current browser's old session token. **Sign out all devices** revokes every session for the current account. Admins also have a per-user session-revocation button beside the sharing controls. This ends Notes sessions, not the user's Authentik session or future login eligibility.

Admin permission changes, user session revocation, public-share creation/updates, and permanent note deletion require verified authentication within the previous ten minutes. Reading, editing, and flagging notes do not require this extra check. The app requests OIDC `prompt=login` and `max_age=0`, validates the signed `auth_time`, and requires the same issuer/subject as the original account. Authentik must honor fresh-login requests and return `auth_time`; missing/stale claims are rejected. Configure MFA in the Authentik flow if required; the app does not claim that this step necessarily invokes MFA. Actions are not automatically replayed after reauthentication: repeat the action after returning.

The UI uses anti-framing and restrictive base/object policies. Existing origin checks protect state-changing requests; API responses remain non-cacheable. No hardware identifier or browser fingerprint is treated as a credential.
