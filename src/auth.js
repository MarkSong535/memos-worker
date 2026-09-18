import { createRemoteJWKSet, jwtVerify } from 'jose';
const SESSION_DURATION_SECONDS = 3 * 60 * 60;
const FRESH_AUTH_SECONDS = 10 * 60;
const cookieName = '__Host-notes_session';
const stateCookie = '__Host-notes_oidc';
const json = (body, status) => Response.json(body, { status });
const cookie = (name, value, maxAge) => `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
const readCookie = (req, name) => (req.headers.get('Cookie') || '').split(';').map(x => x.trim()).find(x => x.startsWith(name + '='))?.slice(name.length + 1);
const random = () => crypto.randomUUID() + crypto.randomUUID();
const redirect = (url, cookies) => new Response(null, { status: 302, headers: { Location: url, 'Set-Cookie': cookies } });

export async function hashSessionToken(token) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
}
export function requireFreshAuthentication(user) {
  if (!user.authenticatedAt || Date.now() - user.authenticatedAt > FRESH_AUTH_SECONDS * 1000 || user.authenticatedAt > Date.now() + 60000) {
    return json({ error: 'Please verify your identity with Authentik before this sensitive action.', code: 'REAUTH_REQUIRED' }, 403);
  }
  return null;
}
export function freshAuthenticationTime(payload, login) {
  const now = Math.floor(Date.now() / 1000);
  const time = payload.auth_time;
  const valid = Number.isSafeInteger(time) && time > 0 && time <= now + 60;
  if (login.reauth_user_id && (!valid || time < Math.floor(login.started_at / 1000) - 60 || now - time > 300)) {
    throw Object.assign(new Error('Fresh authentication was not confirmed'), { code: 'SSO_REAUTH_FAILED' });
  }
  return valid ? time * 1000 : 0;
}
const safeReturnPath = path => path === '/' || /^\/admin\.html(?:\?note=\d+)?$/.test(path || '') ? path : '/';

export async function authenticate(request, env) {
  const id = readCookie(request, cookieName);
  if (!id || id.length < 32 || id.length > 256) return null;
  const session = await env.DB.prepare('SELECT u.id, u.name, u.email, u.can_share, s.is_admin, s.authenticated_at FROM auth_sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ? AND s.expires_at > ?').bind(await hashSessionToken(id), Date.now()).first();
  return session ? { id: session.id, name: session.name, email: session.email, isAdmin: !!session.is_admin, canShare: !!session.can_share, authenticatedAt: session.authenticated_at } : null;
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
  if (['/api/auth/logout', '/api/auth/logout-all'].includes(url.pathname) && request.method === 'POST') {
    if (request.headers.get('Origin') !== env.APP_ORIGIN) return json({ error: 'Invalid origin' }, 403);
    const id = readCookie(request, cookieName);
    if (url.pathname === '/api/auth/logout-all') {
      const user = await authenticate(request, env);
      if (!user) return json({ error: 'Unauthorized' }, 401);
      await env.DB.prepare('DELETE FROM auth_sessions WHERE user_id = ?').bind(user.id).run();
    } else if (id) await env.DB.prepare('DELETE FROM auth_sessions WHERE id = ?').bind(await hashSessionToken(id)).run();
    return new Response('{}', { headers: { 'Content-Type': 'application/json', 'Set-Cookie': cookie(cookieName, '', 0) } });
  }
  if (request.method !== 'GET' || !['/api/auth/login', '/api/auth/callback'].includes(url.pathname)) return json({ error: 'Not found' }, 404);
  let stage = 'discovery';
  try {
    const config = await discovery(env);
    const callback = `${env.APP_ORIGIN}/api/auth/callback`;
    if (url.pathname === '/api/auth/login') {
      const reauth = url.searchParams.get('reauth') === '1';
      const previousUser = reauth ? await authenticate(request, env) : null;
      if (reauth && !previousUser) return redirect('/api/auth/login', cookie(stateCookie, '', 0));
      const state = random(), verifier = random(), nonce = random();
      const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
      const challenge = btoa(String.fromCharCode(...new Uint8Array(digest))).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
      stage = 'login_state';
      await env.DB.batch([
        env.DB.prepare('DELETE FROM oidc_states WHERE expires_at < ?').bind(Date.now()),
        env.DB.prepare('DELETE FROM auth_sessions WHERE expires_at < ?').bind(Date.now()),
        env.DB.prepare('INSERT INTO oidc_states (id, verifier, nonce, expires_at, reauth_user_id, started_at, return_to) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(state, verifier, nonce, Date.now() + 600000, previousUser?.id || null, Date.now(), safeReturnPath(url.searchParams.get('return_to'))),
      ]);
      const target = new URL(config.authorization_endpoint);
      target.search = new URLSearchParams({ client_id: env.OIDC_CLIENT_ID, redirect_uri: callback, response_type: 'code', scope: 'openid profile email', state, nonce, code_challenge: challenge, code_challenge_method: 'S256' });
      if (reauth) { target.searchParams.set('prompt', 'login'); target.searchParams.set('max_age', '0'); }
      return redirect(target.toString(), cookie(stateCookie, state, 600));
    }
    const state = url.searchParams.get('state');
    if (!state || readCookie(request, stateCookie) !== state || !url.searchParams.get('code')) return json({ error: 'Invalid login response' }, 400);
    // DELETE RETURNING consumes the state atomically, preventing callback replay.
    stage = 'login_state';
    const login = await env.DB.prepare('DELETE FROM oidc_states WHERE id = ? AND expires_at > ? RETURNING verifier, nonce, reauth_user_id, started_at, return_to').bind(state, Date.now()).first();
    if (!login) return json({ error: 'Login expired; please try again' }, 400);
    stage = 'token_exchange';
    const response = await fetch(config.token_endpoint, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', code: url.searchParams.get('code'), client_id: env.OIDC_CLIENT_ID, client_secret: env.OIDC_CLIENT_SECRET, redirect_uri: callback, code_verifier: login.verifier }) });
    if (!response.ok) throw new Error('Token exchange failed');
    const tokens = await response.json();
    stage = 'token_validation';
    const { payload, role } = await validateIdentity(tokens.id_token, createRemoteJWKSet(new URL(config.jwks_uri)), config, env.OIDC_CLIENT_ID, login.nonce);
    const authenticatedAt = freshAuthenticationTime(payload, login);
    if (login.reauth_user_id) {
      const original = await env.DB.prepare('SELECT issuer, subject FROM users WHERE id = ?').bind(login.reauth_user_id).first();
      if (!original || original.issuer !== payload.iss || original.subject !== payload.sub) throw Object.assign(new Error('Reauthentication identity changed'), { code: 'SSO_REAUTH_FAILED' });
    }
    stage = 'session_storage';
    const candidate = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO users (id, issuer, subject, name, email) VALUES (?, ?, ?, ?, ?) ON CONFLICT(issuer, subject) DO UPDATE SET name = excluded.name, email = excluded.email').bind(candidate, payload.iss, payload.sub, String(payload.name || payload.preferred_username || payload.sub), String(payload.email || '')).run();
    const user = await env.DB.prepare('SELECT id FROM users WHERE issuer = ? AND subject = ?').bind(payload.iss, payload.sub).first();
    const sid = random();
    // The verified ID token establishes identity at login; the app session has
    // its own lifetime and does not expire when that short-lived token does.
    const lifetime = SESSION_DURATION_SECONDS;
    const previousToken = readCookie(request, cookieName);
    await env.DB.batch([
      ...(previousToken ? [env.DB.prepare('DELETE FROM auth_sessions WHERE id = ?').bind(await hashSessionToken(previousToken))] : []),
      env.DB.prepare('INSERT INTO auth_sessions (id, user_id, is_admin, expires_at, authenticated_at) VALUES (?, ?, ?, ?, ?)').bind(await hashSessionToken(sid), user.id, Number(role === 'admin'), Date.now() + lifetime * 1000, authenticatedAt),
    ]);
    const result = redirect(new URL(safeReturnPath(login.return_to), env.APP_ORIGIN).toString(), cookie(cookieName, sid, lifetime));
    result.headers.append('Set-Cookie', cookie(stateCookie, '', 0));
    return result;
  } catch (error) {
    const missingSchema = /no such (table|column)|has no column named/i.test(error.message);
    const code = missingSchema ? 'SSO_DATABASE_MIGRATION_REQUIRED' : ['SSO_GROUPS_MISSING', 'SSO_REAUTH_FAILED'].includes(error.code) ? error.code : error.code === 'SSO_CONFIGURATION_MISSING' ? error.code : `SSO_${stage.toUpperCase()}_FAILED`;
    const messages = {
      SSO_DATABASE_MIGRATION_REQUIRED: 'The server database is missing the SSO migration. An administrator must apply the database migrations.',
      SSO_CONFIGURATION_MISSING: 'The server is missing required OIDC configuration. Check the client ID, client secret, discovery URL, and app origin.',
      SSO_REAUTH_FAILED: 'Fresh authentication was not confirmed for the same account. Sign in again using the original account; the provider must return a fresh auth_time claim.',
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
