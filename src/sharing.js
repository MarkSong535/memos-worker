const json = (body, status = 200) => Response.json(body, { status });
export async function shareableNote(env, id) {
  return env.DB.prepare('SELECT * FROM notes WHERE id = ? AND NOT EXISTS (SELECT 1 FROM note_hidden WHERE note_id = notes.id)').bind(id).first();
}
export async function canShare(note, env) {
  return !!(note && (env.user.isAdmin || (env.user.canShare && note.owner_id === env.user.id)) && await shareableNote(env, note.id));
}
const filesOf = note => typeof note.files === 'string' ? JSON.parse(note.files || '[]') : (note.files || []);
async function insertShare(env, noteId, fileId, imageId, parent, expiry, creator = null) {
  const token = crypto.randomUUID();
  await env.DB.prepare('INSERT INTO public_shares (token, note_id, file_id, image_id, parent_token, expires_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(token, noteId, fileId, imageId, parent, expiry, creator).run();
  return token;
}
async function lookup(env, token) {
  const share = await env.DB.prepare('SELECT * FROM public_shares WHERE token = ? AND (expires_at IS NULL OR expires_at > ?)').bind(token, Date.now()).first();
  if (!share) return null;
  if (share.created_by && !await env.DB.prepare('SELECT id FROM users WHERE id = ? AND can_share = 1').bind(share.created_by).first()) return null;
  if (share.parent_token && !await env.DB.prepare('SELECT token FROM public_shares WHERE token = ? AND (expires_at IS NULL OR expires_at > ?)').bind(share.parent_token, Date.now()).first()) return null;
  const note = await shareableNote(env, share.note_id);
  return note ? { share, note } : null;
}
export async function manageShare(request, env, id, fileId = null) {
  const note = await env.DB.prepare('SELECT * FROM notes WHERE id = ?').bind(id).first();
  if (!note || (!env.user.isAdmin && note.owner_id !== env.user.id)) return json({ error: 'Only the owner or an administrator can share this note' }, 403);
  if (request.method === 'DELETE') {
    // Revocation remains possible even when a note is flagged.
    await env.DB.prepare('DELETE FROM public_shares WHERE note_id = ? AND file_id IS ? AND image_id IS NULL AND parent_token IS NULL').bind(id, fileId).run();
    return json({ success: true });
  }
  if (!env.user.isAdmin && !env.user.canShare) return json({ error: 'An administrator has disabled sharing for your account' }, 403);
  if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405);
  if (!await shareableNote(env, id)) return json({ error: 'Deleted notes cannot be shared. An administrator must restore them first.' }, 409);
  if (fileId && !filesOf(note).some(file => file.id === fileId)) return json({ error: 'File not found' }, 404);
  const body = await request.json().catch(() => ({}));
  const ttl = body.expirationTtl ?? (fileId ? 0 : 3600);
  if (!Number.isSafeInteger(ttl) || ttl > 31536000) return json({ error: 'Invalid expiration' }, 400);
  const expiry = ttl > 0 ? Date.now() + ttl * 1000 : null;
  if (body.publicId) {
    const existing = await env.DB.prepare('SELECT token FROM public_shares WHERE token = ? AND note_id = ? AND file_id IS ? AND parent_token IS NULL').bind(body.publicId, id, fileId).first();
    if (!existing) return json({ error: 'Invalid public ID for this note' }, 400);
    await env.DB.batch([
      env.DB.prepare('UPDATE public_shares SET expires_at = ? WHERE token = ?').bind(expiry, body.publicId),
      env.DB.prepare('UPDATE public_shares SET expires_at = ? WHERE parent_token = ?').bind(expiry, body.publicId),
    ]);
    return json({ success: true });
  }
  const creator = env.user.isAdmin ? null : env.user.id;
  const existing = await env.DB.prepare('SELECT token FROM public_shares WHERE note_id = ? AND file_id IS ? AND image_id IS NULL AND parent_token IS NULL AND created_by IS ? AND (expires_at IS NULL OR expires_at > ?) LIMIT 1').bind(id, fileId, creator, Date.now()).first();
  const token = existing?.token || await insertShare(env, id, fileId, null, null, expiry, creator);
  const origin = env.APP_ORIGIN;
  return fileId ? json({ url: `${origin}/api/public/file/${token}`, publicId: token }) : json({ displayUrl: `${origin}/share.html?id=${token}`, rawUrl: `${origin}/api/public/note/raw/${token}`, publicId: token });
}
export async function publicShare(request, env) {
  if (request.method !== 'GET') return json({ error: 'Public links are read-only' }, 405);
  const match = new URL(request.url).pathname.match(/^\/api\/public\/(note\/raw|note|file)\/([a-zA-Z0-9-]+)$/);
  if (!match) return json({ error: 'Not found' }, 404);
  const result = await lookup(env, match[2]);
  if (!result) return json({ error: 'Share not found or expired' }, 404);
  const { share, note } = result;
  if (match[1] === 'file') {
    if (!share.file_id && !share.image_id) return json({ error: 'Not a file share' }, 404);
    let key, type, name;
    if (share.image_id) {
      const path = `/api/images/${share.image_id}`;
      if (!note.content.includes(path)) return json({ error: 'Media removed' }, 404);
      key = `uploads/${share.image_id}`;
    } else {
      const file = filesOf(note).find(file => file.id === share.file_id);
      if (!file && !(share.parent_token && note.content.includes(`/api/files/${note.id}/${share.file_id}`))) return json({ error: 'File removed' }, 404);
      key = `${note.id}/${share.file_id}`; type = file?.type; name = file?.name;
    }
    const object = await env.NOTES_R2_BUCKET.get(key);
    if (!object) return json({ error: 'File not found' }, 404);
    const headers = new Headers(); object.writeHttpMetadata(headers);
    headers.set('Content-Type', type || headers.get('Content-Type') || 'application/octet-stream');
    headers.set('Content-Disposition', `inline; filename*=UTF-8''${encodeURIComponent(name || 'media')}`);
    headers.set('Content-Security-Policy', "sandbox; default-src 'none'; style-src 'unsafe-inline'");
    return new Response(object.body, { headers });
  }
  if (share.file_id || share.image_id || share.parent_token) return json({ error: 'Not a note share' }, 404);
  if (match[1] === 'note/raw') return new Response(note.content, { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
  async function media(fileId, imageId) {
    const existing = await env.DB.prepare('SELECT token FROM public_shares WHERE parent_token = ? AND file_id IS ? AND image_id IS ?').bind(share.token, fileId, imageId).first();
    const token = existing?.token || await insertShare(env, note.id, fileId, imageId, share.token, share.expires_at, share.created_by);
    return `/api/public/file/${token}`;
  }
  let content = note.content;
  for (const match of note.content.matchAll(/\/api\/(images|files)\/([a-zA-Z0-9-]+)(?:\/([a-zA-Z0-9-]+))?/g)) {
    // A shared note must not publish attachments belonging to a different note.
    if (match[1] === 'files' && Number(match[2]) !== note.id) continue;
    const url = await media(match[1] === 'files' ? match[3] : null, match[1] === 'images' ? match[2] : null);
    content = content.replaceAll(match[0], url);
  }
  const files = await Promise.all(filesOf(note).map(async file => ({ id: file.id, name: file.name, size: file.size, type: file.type, public_url: await media(file.id, null) })));
  return json({ content, files, updated_at: note.updated_at });
}
export async function listShares(env) {
  const rows = (await env.DB.prepare(`SELECT s.*, n.content, n.updated_at FROM public_shares s JOIN notes n ON n.id = s.note_id WHERE s.parent_token IS NULL AND (s.expires_at IS NULL OR s.expires_at > ?) AND NOT EXISTS (SELECT 1 FROM note_hidden WHERE note_id = n.id) ${env.user.isAdmin ? '' : 'AND n.owner_id = ?'}`).bind(Date.now(), ...(env.user.isAdmin ? [] : [env.user.id])).all()).results;
  const noteShares = [], fileShares = [];
  for (const row of rows) {
    if (!row.file_id) noteShares.push({ noteId: row.note_id, publicId: row.token, updatedAt: row.updated_at, snippet: row.content.slice(0, 120), displayUrl: `${env.APP_ORIGIN}/share.html?id=${row.token}`, rawUrl: `${env.APP_ORIGIN}/api/public/note/raw/${row.token}` });
    else {
      const note = await shareableNote(env, row.note_id), file = filesOf(note).find(f => f.id === row.file_id);
      if (file) fileShares.push({ noteId: row.note_id, fileId: row.file_id, updatedAt: row.updated_at, publicId: row.token, name: file.name, size: file.size, type: file.type, url: `${env.APP_ORIGIN}/api/public/file/${row.token}` });
    }
  }
  return json({ noteShares, fileShares, totalNoteShares: noteShares.length, totalFileShares: fileShares.length });
}
