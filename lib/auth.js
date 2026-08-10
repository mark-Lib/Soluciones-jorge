// Autenticación simple con hash de contraseña (scrypt, nativo de Node) y
// sesiones firmadas con HMAC en una cookie httpOnly. Sin dependencias externas.
const crypto = require('crypto');
const store = require('./store');

const SESSION_COOKIE = 'sj_admin_session';
const SESSION_TTL_MS = 1000 * 60 * 60 * 12; // 12 horas

function getSessionSecret() {
  // Se recomienda fijar SESSION_SECRET como variable de entorno en producción.
  // Si no existe, se genera una por proceso (las sesiones expiran al reiniciar).
  if (!global.__SJ_SESSION_SECRET__) {
    global.__SJ_SESSION_SECRET__ = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
  }
  return global.__SJ_SESSION_SECRET__;
}

function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

function verifyPassword(password, salt, expectedHash) {
  const { hash } = hashPassword(password, salt);
  const a = Buffer.from(hash, 'hex');
  const b = Buffer.from(expectedHash, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function sign(value) {
  const h = crypto.createHmac('sha256', getSessionSecret()).update(value).digest('hex');
  return `${value}.${h}`;
}

function unsign(signed) {
  if (!signed) return null;
  const idx = signed.lastIndexOf('.');
  if (idx === -1) return null;
  const value = signed.slice(0, idx);
  const sig = signed.slice(idx + 1);
  const expected = crypto.createHmac('sha256', getSessionSecret()).update(value).digest('hex');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  return value;
}

function createSessionCookie(username) {
  const payload = JSON.stringify({ u: username, exp: Date.now() + SESSION_TTL_MS });
  const encoded = Buffer.from(payload).toString('base64url');
  const signed = sign(encoded);
  return `${SESSION_COOKIE}=${signed}; HttpOnly; Path=/; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}; SameSite=Lax`;
}

function clearSessionCookie() {
  return `${SESSION_COOKIE}=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax`;
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  header.split(';').forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    const k = pair.slice(0, idx).trim();
    const v = pair.slice(idx + 1).trim();
    out[k] = decodeURIComponent(v);
  });
  return out;
}

function getSession(req) {
  const cookies = parseCookies(req.headers.cookie);
  const raw = cookies[SESSION_COOKIE];
  const encoded = unsign(raw);
  if (!encoded) return null;
  try {
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    if (!payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch (err) {
    return null;
  }
}

function isAuthenticated(req) {
  const session = getSession(req);
  if (!session) return false;
  const admin = store.getAdmin();
  return !!admin && admin.username === session.u;
}

module.exports = {
  hashPassword,
  verifyPassword,
  createSessionCookie,
  clearSessionCookie,
  getSession,
  isAuthenticated
};
