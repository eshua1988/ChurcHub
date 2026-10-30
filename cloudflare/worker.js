const headers = { "content-type": "application/json; charset=utf-8" };
const json = (body, init = {}) => new Response(JSON.stringify(body), { ...init, headers: { ...headers, ...(init.headers || {}) } });
const fail = (message, status = 400) => json({ error: message }, { status });
const id = () => crypto.randomUUID();

async function schema(db) {
  await db.exec(`
    CREATE TABLE IF NOT EXISTS hub_users (id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, name TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'member', department TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS hub_sessions (token TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS hub_rooms (id TEXT PRIMARY KEY, name TEXT NOT NULL, department TEXT, owner_id TEXT NOT NULL, access_mode TEXT NOT NULL DEFAULT 'members', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS hub_room_members (room_id TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'member', PRIMARY KEY (room_id, user_id));
    CREATE TABLE IF NOT EXISTS hub_room_messages (id TEXT PRIMARY KEY, room_id TEXT NOT NULL, author_id TEXT NOT NULL, body TEXT NOT NULL, message_type TEXT NOT NULL DEFAULT 'chat', attachment TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS hub_room_requests (id TEXT PRIMARY KEY, room_id TEXT NOT NULL, user_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(room_id, user_id));
  `);
}

function cookie(request, name) { return (request.headers.get('Cookie') || '').split(';').map(v => v.trim()).find(v => v.startsWith(`${name}=`))?.slice(name.length + 1); }
async function user(request, env) {
  const token = cookie(request, 'hub_session');
  if (!token) return null;
  return env.HUB_DB.prepare(`SELECT u.id,u.email,u.name,u.role,u.department FROM hub_sessions s JOIN hub_users u ON u.id=s.user_id WHERE s.token=? AND s.expires_at > datetime('now')`).bind(token).first();
}
async function password(value, salt = crypto.getRandomValues(new Uint8Array(16))) {
  const bytes = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, await crypto.subtle.importKey('raw', new TextEncoder().encode(value), 'PBKDF2', false, ['deriveBits']), 256);
  return `${Array.from(salt).map(v => v.toString(16).padStart(2, '0')).join('')}:${Array.from(new Uint8Array(bytes)).map(v => v.toString(16).padStart(2, '0')).join('')}`;
}
async function validPassword(value, stored) { const [salt] = stored.split(':'); return (await password(value, Uint8Array.from(salt.match(/../g).map(v => parseInt(v, 16))))) === stored; }
async function signedIn(request, env) { const current = await user(request, env); return current || null; }
async function roomAllowed(env, current, roomId) {
  const room = await env.HUB_DB.prepare('SELECT * FROM hub_rooms WHERE id=?').bind(roomId).first();
  if (!room) return null;
  if (current.role === 'admin' || room.owner_id === current.id || room.access_mode === 'all') return room;
  const member = await env.HUB_DB.prepare('SELECT 1 FROM hub_room_members WHERE room_id=? AND user_id=?').bind(roomId, current.id).first();
  return member ? room : null;
}
const readJson = request => request.json().catch(() => ({}));

export default { async fetch(request, env) {
  const url = new URL(request.url);
  if (request.method === 'OPTIONS') return new Response(null, { headers: { Allow: 'GET, POST, PATCH, DELETE, OPTIONS' } });
  if (!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(request);
  await schema(env.HUB_DB);

  if (url.pathname === '/api/health') return json({ ok: true, service: 'church-hub-api', storage: 'r2', database: 'd1' });
  if (url.pathname === '/api/auth/register' && request.method === 'POST') {
    const body = await readJson(request); const email = String(body.email || '').trim().toLowerCase(); const name = String(body.name || '').trim(); const pass = String(body.password || '');
    if (!/^\S+@\S+\.\S+$/.test(email) || !name || pass.length < 8) return fail('Укажите имя, корректный email и пароль не короче 8 символов.');
    const existing = await env.HUB_DB.prepare('SELECT * FROM hub_users WHERE email=?').bind(email).first();
    if (existing) {
      if (!await validPassword(pass, existing.password)) return json({ status: 'existing', message: 'Аккаунт с этим email уже существует. Нажмите «Войти» и используйте пароль от созданного аккаунта.' });
      const token = id(); await env.HUB_DB.prepare("INSERT INTO hub_sessions (token,user_id,expires_at) VALUES (?,?,datetime('now','+30 days'))").bind(token, existing.id).run();
      return json({ user: { id: existing.id, email: existing.email, name: existing.name, role: existing.role, department: existing.department } }, { headers: { 'Set-Cookie': `hub_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000` } });
    }
    const count = await env.HUB_DB.prepare('SELECT COUNT(*) AS count FROM hub_users').first(); const userId = id(); const role = count.count === 0 ? 'admin' : 'member';
    try { await env.HUB_DB.prepare('INSERT INTO hub_users (id,email,password,name,role) VALUES (?,?,?,?,?)').bind(userId, email, await password(pass), name, role).run(); } catch (error) { console.error('User registration failed', error); return fail('Не удалось создать аккаунт. Попробуйте ещё раз.', 500); }
    const token = id(); await env.HUB_DB.prepare("INSERT INTO hub_sessions (token,user_id,expires_at) VALUES (?,?,datetime('now','+30 days'))").bind(token, userId).run();
    return json({ user: { id: userId, email, name, role } }, { status: 201, headers: { 'Set-Cookie': `hub_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000` } });
  }
  if (url.pathname === '/api/auth/login' && request.method === 'POST') {
    const body = await readJson(request); const account = await env.HUB_DB.prepare('SELECT * FROM hub_users WHERE email=?').bind(String(body.email || '').trim().toLowerCase()).first();
    if (!account || !await validPassword(String(body.password || ''), account.password)) return json({ status: 'invalid_credentials', message: 'Неверный email или пароль.' });
    const token = id(); await env.HUB_DB.prepare("INSERT INTO hub_sessions (token,user_id,expires_at) VALUES (?,?,datetime('now','+30 days'))").bind(token, account.id).run();
    return json({ user: { id: account.id, email: account.email, name: account.name, role: account.role, department: account.department } }, { headers: { 'Set-Cookie': `hub_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000` } });
  }
  if (url.pathname === '/api/auth/logout' && request.method === 'POST') { const token = cookie(request, 'hub_session'); if (token) await env.HUB_DB.prepare('DELETE FROM hub_sessions WHERE token=?').bind(token).run(); return json({ ok: true }, { headers: { 'Set-Cookie': 'hub_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0' } }); }
  if (url.pathname === '/api/bootstrap') {
    const current = await signedIn(request, env);
    if (!current) return json({ user: null, people: [], rooms: [] });
    const people = await env.HUB_DB.prepare('SELECT id,name,email,role,department FROM hub_users ORDER BY name').all();
    const rooms = await env.HUB_DB.prepare('SELECT r.*, u.name AS owner_name FROM hub_rooms r JOIN hub_users u ON u.id=r.owner_id ORDER BY r.created_at').all();
    return json({ user: current, people: people.results, rooms: rooms.results });
  }
  const current = await signedIn(request, env); if (!current) return fail('Требуется вход.', 401);
  if (url.pathname === '/api/rooms' && request.method === 'POST') {
    const body = await readJson(request); const name = String(body.name || '').trim(); if (!name) return fail('Укажите название комнаты.'); const roomId = id();
    await env.HUB_DB.prepare('INSERT INTO hub_rooms (id,name,department,owner_id,access_mode) VALUES (?,?,?,?,?)').bind(roomId, name, String(body.department || name), current.id, body.access_mode === 'all' ? 'all' : 'members').run();
    await env.HUB_DB.prepare('INSERT INTO hub_room_members (room_id,user_id,role) VALUES (?,?,?)').bind(roomId, current.id, 'owner').run(); return json({ id: roomId }, { status: 201 });
  }
  const messageMatch = url.pathname.match(/^\/api\/rooms\/([^/]+)\/messages$/);
  if (messageMatch) { const room = await roomAllowed(env, current, messageMatch[1]); if (!room) return fail('Нет доступа к комнате.', 403); if (request.method === 'GET') { const messages = await env.HUB_DB.prepare('SELECT m.*,u.name AS author_name FROM hub_room_messages m JOIN hub_users u ON u.id=m.author_id WHERE m.room_id=? ORDER BY m.created_at DESC LIMIT 100').bind(room.id).all(); return json({ room, messages: messages.results.reverse() }); } if (request.method === 'POST') { const body = await readJson(request); if (!String(body.body || '').trim() && !body.attachment) return fail('Введите сообщение или прикрепите файл.'); await env.HUB_DB.prepare('INSERT INTO hub_room_messages (id,room_id,author_id,body,message_type,attachment) VALUES (?,?,?,?,?,?)').bind(id(), room.id, current.id, String(body.body || body.attachment?.name || ''), body.message_type || 'chat', body.attachment ? JSON.stringify(body.attachment) : null).run(); return json({ ok: true }, { status: 201 }); } }
  const uploadMatch = url.pathname.match(/^\/api\/rooms\/([^/]+)\/files$/);
  if (uploadMatch && request.method === 'POST') { const room = await roomAllowed(env, current, uploadMatch[1]); if (!room) return fail('Нет доступа к комнате.', 403); const name = (url.searchParams.get('name') || 'file').replace(/[^\w.-]+/g, '_').slice(-120); const key = `rooms/${room.id}/${id()}-${name}`; await env.HUB_FILES.put(key, request.body, { httpMetadata: { contentType: request.headers.get('content-type') || 'application/octet-stream' } }); return json({ key, name, type: request.headers.get('content-type') || 'application/octet-stream' }, { status: 201 }); }
  const fileMatch = url.pathname.match(/^\/api\/files\/(.+)$/);
  if (fileMatch && request.method === 'GET') { const key = decodeURIComponent(fileMatch[1]); const roomId = key.split('/')[1]; if (!await roomAllowed(env, current, roomId)) return fail('Нет доступа к файлу.', 403); const object = await env.HUB_FILES.get(key); if (!object) return fail('Файл не найден.', 404); return new Response(object.body, { headers: { 'content-type': object.httpMetadata?.contentType || 'application/octet-stream', 'content-disposition': `inline; filename="${key.split('/').pop()}"` } }); }
  return fail('Маршрут не найден.', 404);
} };
