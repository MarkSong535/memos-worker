const $ = id => document.getElementById(id);
let users = [], active;
async function api(path, options = {}) {
  const res = await fetch(path, options);
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}));
    throw Object.assign(new Error(res.status === 401 ? 'Session expired. Return to Notes and sign in again.' : detail.error || 'Request failed'), { code: detail.code });
  }
  return res.status === 204 ? null : res.json();
}
function report(error) {
  $('status').textContent = error.message;
  if (error.code === 'REAUTH_REQUIRED') {
    const link = document.createElement('a');
    link.href = `/api/auth/login?reauth=1&return_to=${encodeURIComponent(location.pathname + location.search)}`;
    link.textContent = ' Verify identity, then repeat your action.';
    $('status').append(link);
  }
}
function option(value, label) { const el = document.createElement('option'); el.value = value; el.textContent = label; return el; }
function renderUserSharing() {
  $('user-sharing').replaceChildren();
  for (const user of users) {
    const label = document.createElement('label'), toggle = document.createElement('input');
    toggle.type = 'checkbox'; toggle.checked = !!user.can_share;
    label.append(toggle, `Allow sharing: ${user.name}${user.email ? ` (${user.email})` : ''}`);
    toggle.onchange = async () => {
      const requested = toggle.checked;
      toggle.disabled = true;
      try {
        await api(`/api/admin/users/${encodeURIComponent(user.id)}/sharing`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ can_share: requested }) });
        user.can_share = Number(requested);
        $('status').textContent = requested ? `Sharing enabled for ${user.name}.` : `Sharing disabled for ${user.name}; their existing links were revoked.`;
      } catch (error) { toggle.checked = !!user.can_share; report(error); }
      finally { toggle.disabled = false; }
    };
    const revoke = document.createElement('button');
    revoke.textContent = 'Sign out all devices';
    revoke.onclick = async () => {
      if (!confirm(`End all Notes sessions for ${user.name}?`)) return;
      try { await api(`/api/admin/users/${encodeURIComponent(user.id)}/sessions`, { method: 'DELETE' }); $('status').textContent = `Sessions ended for ${user.name}.`; }
      catch (error) { report(error); }
    };
    label.append(revoke);
    $('user-sharing').append(label);
  }
}
async function openNote(id) {
  const note = await api(`/api/admin/notes/${id}/permissions`);
  active = id; $('title').textContent = `Note #${id}`;
  $('owner').replaceChildren(option('', 'Unassigned — administrators only unless granted below'));
  users.forEach(u => $('owner').append(option(u.id, u.name + (u.email ? ` (${u.email})` : ''))));
  $('owner').value = note.owner_id || '';
  $('grants').replaceChildren();
  for (const user of users) {
    const row = document.createElement('tr'); row.dataset.user = user.id;
    const name = document.createElement('td'); name.textContent = user.name;
    const access = document.createElement('td'), select = document.createElement('select');
    select.append(option('none', 'No additional access'), option('view', 'View'), option('edit', 'View and edit'));
    const grant = note.grants.find(g => g.user_id === user.id);
    select.value = grant ? (grant.can_edit ? 'edit' : 'view') : 'none'; access.append(select);
    const hiddenCell = document.createElement('td');
    const hidden = note.hidden.find(h => h.user_id === user.id);
    if (hidden) {
      const label = document.createElement('label'), restore = document.createElement('input'); restore.type = 'checkbox'; restore.className = 'restore';
      label.append(restore, `Restore (hidden ${new Date(hidden.deleted_at).toLocaleString()})`); hiddenCell.append(label);
    } else hiddenCell.textContent = 'No';
    row.append(name, access, hiddenCell); $('grants').append(row);
  }
  $('editor').hidden = false; $('status').textContent = '';
}
$('save').onclick = async () => {
  const grants = [], restore = [];
  for (const row of $('grants').children) {
    const value = row.querySelector('select').value;
    if (value !== 'none') grants.push({ user_id: row.dataset.user, can_edit: value === 'edit' });
    if (row.querySelector('.restore')?.checked) restore.push(row.dataset.user);
  }
  try {
    await api(`/api/admin/notes/${active}/permissions`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ owner_id: $('owner').value || null, grants, restore }) });
    await openNote(active); $('status').textContent = 'Permissions saved.';
  } catch (error) { report(error); }
};
$('flag').onclick = async () => {
  try {
    await api(`/api/notes/${active}?mode=flag`, { method: 'DELETE' });
    await openNote(active);
    $('status').textContent = 'Note flagged as deleted. Administrators retain access; public links are revoked.';
  } catch (error) { report(error); }
};
$('purge').onclick = async () => {
  if (!confirm(`Permanently delete note #${active}? This cannot be undone.`)) return;
  try { await api(`/api/notes/${active}`, { method: 'DELETE' }); location.href = '/'; } catch (error) { report(error); }
};
try {
  const me = await api('/api/me');
  if (!me.isAdmin) throw new Error('Administrator access required.');
  users = await api('/api/admin/users'); renderUserSharing();
  const id = new URLSearchParams(location.search).get('note');
  if (id && /^\d+$/.test(id)) await openNote(Number(id));
  else $('status').textContent = 'Open a note’s lock icon to manage its access.';
} catch (error) { report(error); }
