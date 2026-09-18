import { canShare } from './sharing.js';
const json = (body, status = 200) => Response.json(body, { status });
const quote = value => "'" + String(value).replaceAll("'", "''") + "'";

// Every note-reading query uses this source, including counts and attachments.
export function notesSource(env) {
  if (env.user?.isAdmin) return 'notes';
  if (!env.user?.id) return '(SELECT * FROM notes WHERE 0)';
  const id = quote(env.user.id);
  return `(SELECT * FROM notes WHERE (owner_id = ${id} OR EXISTS (SELECT 1 FROM note_permissions p WHERE p.note_id = notes.id AND p.user_id = ${id})) AND NOT EXISTS (SELECT 1 FROM note_hidden h WHERE h.note_id = notes.id AND h.user_id = ${id}))`;
}
export async function canEdit(note, env) {
  if (env.user.isAdmin || note.owner_id === env.user.id) return true;
  return !!await env.DB.prepare('SELECT 1 FROM note_permissions WHERE note_id = ? AND user_id = ? AND can_edit = 1').bind(note.id, env.user.id).first();
}
export async function decorate(notes, env) {
  return Promise.all(notes.map(async note => ({ ...note, can_edit: await canEdit(note, env), can_share: await canShare(note, env), is_admin: env.user.isAdmin, ...(env.user.isAdmin ? { is_deleted: !!await env.DB.prepare('SELECT 1 FROM note_hidden WHERE note_id = ? LIMIT 1').bind(note.id).first() } : {}) })));
}
export async function authorize(request, env, id) {
  const note = await env.DB.prepare(`SELECT * FROM ${notesSource(env)} WHERE id = ?`).bind(id).first();
  if (!note) return json({ error: 'Not found' }, 404);
  // Delete is a personal hide action for members, so even readers may use it.
  if (!['GET', 'HEAD', 'DELETE'].includes(request.method) && !await canEdit(note, env)) return json({ error: 'Read-only note' }, 403);
  return null;
}
export async function imageAllowed(imageId, env) {
  if (env.user.isAdmin) return true;
  const path = `/api/images/${imageId}`;
  const attached = await env.DB.prepare(`SELECT id FROM ${notesSource(env)} WHERE instr(content, ?) > 0 OR instr(COALESCE(pics, ''), ?) > 0 LIMIT 1`).bind(path, path).first();
  if (attached) return true;
  // An uploader may preview an unattached image, but cannot use ownership to
  // bypass a hidden note or permissions changed by an administrator.
  const anyNote = await env.DB.prepare("SELECT id FROM notes WHERE instr(content, ?) > 0 OR instr(COALESCE(pics, ''), ?) > 0 LIMIT 1").bind(path, path).first();
  if (anyNote) return false;
  const object = await env.NOTES_R2_BUCKET.head(`uploads/${imageId}`);
  return object?.customMetadata?.ownerId === env.user.id;
}
export async function adminRoute(request, env) {
  if (!env.user.isAdmin) return json({ error: 'Admin access required' }, 403);
  const path = new URL(request.url).pathname;
  if (path === '/api/admin/users' && request.method === 'GET') {
    return json((await env.DB.prepare('SELECT id, name, email, can_share FROM users ORDER BY name').all()).results);
  }
  const userMatch = path.match(/^\/api\/admin\/users\/([^/]+)\/sharing$/);
  if (userMatch) {
    if (request.method !== 'PUT') return json({ error: 'Method not allowed' }, 405);
    const body = await request.json().catch(() => null);
    if (!body || typeof body.can_share !== 'boolean') return json({ error: 'can_share must be a boolean' }, 400);
    const id = decodeURIComponent(userMatch[1]);
    if (!await env.DB.prepare('SELECT id FROM users WHERE id = ?').bind(id).first()) return json({ error: 'User not found' }, 404);
    await env.DB.batch([
      env.DB.prepare('UPDATE users SET can_share = ? WHERE id = ?').bind(Number(body.can_share), id),
      ...(!body.can_share ? [env.DB.prepare('DELETE FROM public_shares WHERE created_by = ?').bind(id)] : []),
    ]);
    return json({ success: true, can_share: body.can_share });
  }
  const match = path.match(/^\/api\/admin\/notes\/(\d+)\/permissions$/);
  if (!match) return json({ error: 'Not found' }, 404);
  const id = Number(match[1]);
  const note = await env.DB.prepare('SELECT id, owner_id FROM notes WHERE id = ?').bind(id).first();
  if (!note) return json({ error: 'Not found' }, 404);
  if (request.method === 'GET') {
    const grants = (await env.DB.prepare('SELECT user_id, can_edit FROM note_permissions WHERE note_id = ?').bind(id).all()).results;
    const hidden = (await env.DB.prepare('SELECT user_id, deleted_at FROM note_hidden WHERE note_id = ?').bind(id).all()).results;
    return json({ ...note, grants, hidden });
  }
  if (request.method !== 'PUT') return json({ error: 'Method not allowed' }, 405);
  const body = await request.json();
  if (!Array.isArray(body.grants) || body.grants.length > 500 || !Array.isArray(body.restore || [])) return json({ error: 'Invalid permissions' }, 400);
  const users = new Set((await env.DB.prepare('SELECT id FROM users').all()).results.map(u => u.id));
  if (body.owner_id !== null && !users.has(body.owner_id)) return json({ error: 'Unknown owner' }, 400);
  if (body.grants.some(g => !users.has(g.user_id) || typeof g.can_edit !== 'boolean') || (body.restore || []).some(id => !users.has(id))) return json({ error: 'Invalid user or permission' }, 400);
  if (new Set(body.grants.map(g => g.user_id)).size !== body.grants.length) return json({ error: 'Duplicate user' }, 400);
  await env.DB.batch([
    env.DB.prepare('UPDATE notes SET owner_id = ? WHERE id = ?').bind(body.owner_id, id),
    env.DB.prepare('DELETE FROM note_permissions WHERE note_id = ?').bind(id),
    ...body.grants.map(g => env.DB.prepare('INSERT INTO note_permissions (note_id, user_id, can_edit) VALUES (?, ?, ?)').bind(id, g.user_id, Number(g.can_edit))),
    ...(body.restore || []).map(uid => env.DB.prepare('DELETE FROM note_hidden WHERE note_id = ? AND user_id = ?').bind(id, uid)),
  ]);
  return json({ success: true });
}

export async function validateMediaReferences(content, env) {
  if (env.user.isAdmin) return true;
  for (const match of content.matchAll(/\/api\/(images|files)\/([a-zA-Z0-9-]+)(?:\/([a-zA-Z0-9-]+))?/g)) {
    if (match[1] === 'images') {
      if (!await imageAllowed(match[2], env)) return false;
    } else {
      if (!/^\d+$/.test(match[2])) return false;
      if (!await env.DB.prepare(`SELECT id FROM ${notesSource(env)} WHERE id = ?`).bind(Number(match[2])).first()) return false;
    }
  }
  return true;
}
