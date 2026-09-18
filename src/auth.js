import { createRemoteJWKSet, jwtVerify } from 'jose';
const cookieName = '__Host-notes_session';
const stateCookie = '__Host-notes_oidc';
const json = (body, status) => Response.json(body, { status });
const cookie = (name, value, maxAge) => `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
const readCookie = (req, name) => (req.headers.get('Cookie') || '').split(';').map(x => x.trim()).find(x => x.startsWith(name + '='))?.slice(name.length + 1);
const random = () => crypto.randomUUID() + crypto.randomUUID();
const redirect = (url, cookies) => new Response(null, { status: 302, headers: { Location: url, 'Set-Cookie': cookies } });

export async function authenticate(request, env) {
  const id = readCookie(request, cookieName);
  if (!id) return null;
  const session = await env.DB.prepare('SELECT u.id, u.name, u.email, u.can_share, s.is_admin FROM auth_sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ? AND s.expires_at > ?').bind(id, Date.now()).first();
  return session ? { id: session.id, name: session.name, email: session.email, isAdmin: !!session.is_admin, canShare: !!session.can_share } : null;
}
export function roleFromClaims(payload) {
  if (!Array.isArray(payload.groups) || !payload.groups.every(g => typeof g === 'string')) return null;
  if (payload.groups.includes('notes_admin')) return 'admin';
  return payload.groups.includes('notes') ? 'member' : null;
}
export async function validateIdentity(token, key, config, clientId, nonce) {
  const { payload } = await jwtVerify(token, key, { issuer: config.issuer, audience: clientId, algorithms: ['RS256', 'ES256'], requiredClaims: ['sub', 'exp', 'iat', 'nonce'] });
  if (payload.nonce !== nonce || (payload.azp && payload.azp !== clientId) || (Array.isArray(payload.aud) && payload.aud.length > 1 && payload.azp !== clientId)) throw new Error('Invalid identity binding');
  const role = roleFromClaims(payload);
  if (!role) throw Object.assign(new Error('Required group missing from verified ID token'), { code: 'SSO_GROUPS_MISSING' });
  return { payload, role };
}
async function discovery(env) {
  const url = env.OIDC_DISCOVERY_URL;
  if (!url || !env.OIDC_CLIENT_ID || !env.OIDC_CLIENT_SECRET || !env.APP_ORIGIN) throw Object.assign(new Error('SSO is not configured'), { code: 'SSO_CONFIGURATION_MISSING' });
  const response = await fetch(url);
  if (!response.ok) throw new Error('Discovery failed');
  const config = await response.json();
  const origin = new URL(url).origin;
  for (const field of ['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri']) {
    if (new URL(config[field]).origin !== origin || !config[field].startsWith('https://')) throw new Error('Invalid provider endpoint');
  }
  return config;
}
export async function authRoute(request, env) {
  const url = new URL(request.url);
  if (url.pathname === '/api/auth/logout' && request.method === 'POST') {
    if (request.headers.get('Origin') !== env.APP_ORIGIN) return json({ error: 'Invalid origin' }, 403);
    const id = readCookie(request, cookieName);
    if (id) await env.DB.prepare('DELETE FROM auth_sessions WHERE id = ?').bind(id).run();
    return new Response('{}', { headers: { 'Content-Type': 'application/json', 'Set-Cookie': cookie(cookieName, '', 0) } });
  }
  if (request.method !== 'GET' || !['/api/auth/login', '/api/auth/callback'].includes(url.pathname)) return json({ error: 'Not found' }, 404);
  let stage = 'discovery';
  try {
    const config = await discovery(env);
    const callback = `${env.APP_ORIGIN}/api/auth/callback`;
    if (url.pathname === '/api/auth/login') {
      const state = random(), verifier = random(), nonce = random();
      const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
      const challenge = btoa(String.fromCharCode(...new Uint8Array(digest))).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
      stage = 'login_state';
      await env.DB.batch([
        env.DB.prepare('DELETE FROM oidc_states WHERE expires_at < ?').bind(Date.now()),
        env.DB.prepare('DELETE FROM auth_sessions WHERE expires_at < ?').bind(Date.now()),
        env.DB.prepare('INSERT INTO oidc_states (id, verifier, nonce, expires_at) VALUES (?, ?, ?, ?)').bind(state, verifier, nonce, Date.now() + 600000),
      ]);
      const target = new URL(config.authorization_endpoint);
      target.search = new URLSearchParams({ client_id: env.OIDC_CLIENT_ID, redirect_uri: callback, response_type: 'code', scope: 'openid profile email', state, nonce, code_challenge: challenge, code_challenge_method: 'S256' });
      return redirect(target.toString(), cookie(stateCookie, state, 600));
    }
    const state = url.searchParams.get('state');
    if (!state || readCookie(request, stateCookie) !== state || !url.searchParams.get('code')) return json({ error: 'Invalid login response' }, 400);
    // DELETE RETURNING consumes the state atomically, preventing callback replay.
    stage = 'login_state';
    const login = await env.DB.prepare('DELETE FROM oidc_states WHERE id = ? AND expires_at > ? RETURNING verifier, nonce').bind(state, Date.now()).first();
    if (!login) return json({ error: 'Login expired; please try again' }, 400);
    stage = 'token_exchange';
    const response = await fetch(config.token_endpoint, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', code: url.searchParams.get('code'), client_id: env.OIDC_CLIENT_ID, client_secret: env.OIDC_CLIENT_SECRET, redirect_uri: callback, code_verifier: login.verifier }) });
    if (!response.ok) throw new Error('Token exchange failed');
    const tokens = await response.json();
    stage = 'token_validation';
    const { payload, role } = await validateIdentity(tokens.id_token, createRemoteJWKSet(new URL(config.jwks_uri)), config, env.OIDC_CLIENT_ID, login.nonce);
    stage = 'session_storage';
    const candidate = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO users (id, issuer, subject, name, email) VALUES (?, ?, ?, ?, ?) ON CONFLICT(issuer, subject) DO UPDATE SET name = excluded.name, email = excluded.email').bind(candidate, payload.iss, payload.sub, String(payload.name || payload.preferred_username || payload.sub), String(payload.email || '')).run();
    const user = await env.DB.prepare('SELECT id FROM users WHERE issuer = ? AND subject = ?').bind(payload.iss, payload.sub).first();
    const sid = random();
    // Group changes take effect on next login, with a maximum five-minute session.
    const lifetime = Math.max(0, Math.min(300, payload.exp - Math.floor(Date.now() / 1000)));
    if (!lifetime) throw new Error('Expired identity');
    await env.DB.prepare('INSERT INTO auth_sessions (id, user_id, is_admin, expires_at) VALUES (?, ?, ?, ?)').bind(sid, user.id, Number(role === 'admin'), Date.now() + lifetime * 1000).run();
    const result = redirect(env.APP_ORIGIN, cookie(cookieName, sid, lifetime));
    result.headers.append('Set-Cookie', cookie(stateCookie, '', 0));
    return result;
  } catch (error) {
    const missingSchema = /no such (table|column)|has no column named/i.test(error.message);
    const code = missingSchema ? 'SSO_DATABASE_MIGRATION_REQUIRED' : error.code === 'SSO_GROUPS_MISSING' ? error.code : error.code === 'SSO_CONFIGURATION_MISSING' ? error.code : `SSO_${stage.toUpperCase()}_FAILED`;
    const messages = {
      SSO_DATABASE_MIGRATION_REQUIRED: 'The server database is missing the SSO migration. An administrator must apply the database migrations.',
      SSO_CONFIGURATION_MISSING: 'The server is missing required OIDC configuration. Check the client ID, client secret, discovery URL, and app origin.',
      SSO_GROUPS_MISSING: 'The verified identity token does not contain notes or notes_admin in its groups claim. Check the Authentik profile scope mapping and Include claims in id_token setting.',
      SSO_DISCOVERY_FAILED: 'The server could not load or validate the Authentik discovery configuration.',
      SSO_LOGIN_STATE_FAILED: 'The server could not store or read the login state. Check the database connection and migrations.',
      SSO_TOKEN_EXCHANGE_FAILED: 'Authentik rejected the authorization-code exchange. Check the client secret and registered callback URL, then start a new login.',
      SSO_TOKEN_VALIDATION_FAILED: 'The identity token could not be verified. Check the provider signing key, issuer, audience, and token lifetime.',
      SSO_SESSION_STORAGE_FAILED: 'The server could not save the signed-in session. Check the database connection and migrations.',
    };
    console.error(JSON.stringify({ event: 'sso_failed', stage, code }));
    return json({ error: messages[code], code }, code === 'SSO_GROUPS_MISSING' ? 403 : missingSchema ? 503 : 502);
  }
}
