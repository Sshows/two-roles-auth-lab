import { neon } from '@neondatabase/serverless';
import { randomBytes, scryptSync, timingSafeEqual, createHmac } from 'node:crypto';

const sql = neon(process.env.DATABASE_URL);
const cookieName = 'lab_session';

function hashPassword(password, salt = randomBytes(16).toString('hex')) {
  return `${salt}:${scryptSync(password, salt, 64).toString('hex')}`;
}

function checkPassword(password, saved) {
  const [salt, expected] = saved.split(':');
  const actual = scryptSync(password, salt, 64);
  const expectedBuffer = Buffer.from(expected, 'hex');
  return actual.length === expectedBuffer.length && timingSafeEqual(actual, expectedBuffer);
}

function sign(data) {
  return createHmac('sha256', process.env.SESSION_SECRET).update(data).digest('hex');
}

function sessionCookie(account) {
  const data = Buffer.from(JSON.stringify({ id: account.id, exp: Date.now() + 86400000 })).toString('base64url');
  return `${cookieName}=${data}.${sign(data)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`;
}

function readSession(req) {
  const value = req.headers.cookie?.split('; ').find(part => part.startsWith(`${cookieName}=`))?.slice(cookieName.length + 1);
  if (!value) return null;
  const [data, signature] = value.split('.');
  if (!data || !signature || signature.length !== 64) return null;
  if (!timingSafeEqual(Buffer.from(signature), Buffer.from(sign(data)))) return null;
  try {
    const session = JSON.parse(Buffer.from(data, 'base64url').toString());
    return session.exp > Date.now() ? session : null;
  } catch { return null; }
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  const action = req.query.action;
  if (req.method === 'GET' && action === 'me') {
    const session = readSession(req);
    if (!session) return res.status(401).json({ error: 'Войдите в аккаунт' });
    const rows = await sql`SELECT email, role FROM accounts WHERE id = ${session.id}`;
    return rows[0] ? res.json(rows[0]) : res.status(401).json({ error: 'Сеанс недействителен' });
  }
  if (req.method !== 'POST') return res.status(405).json({ error: 'Метод не поддерживается' });
  if (req.headers.origin && new URL(req.headers.origin).host !== req.headers.host) {
    return res.status(403).json({ error: 'Недопустимый источник запроса' });
  }
  if (action === 'logout') {
    res.setHeader('Set-Cookie', `${cookieName}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`);
    return res.json({ ok: true });
  }
  const { email, password, role, inviteCode } = req.body || {};
  if (typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      typeof password !== 'string' || password.length < 8 || password.length > 128) {
    return res.status(400).json({ error: 'Проверьте почту и пароль (минимум 8 символов)' });
  }
  const normalizedEmail = email.trim().toLowerCase();
  if (action === 'register') {
    if (!['user', 'admin'].includes(role)) return res.status(400).json({ error: 'Выберите роль' });
    const expectedCode = role === 'admin' ? process.env.ADMIN_INVITE_CODE : process.env.USER_INVITE_CODE;
    if (!expectedCode || inviteCode !== expectedCode) return res.status(403).json({ error: 'Неверный код приглашения' });
    try {
      const rows = await sql`INSERT INTO accounts (email, password_hash, role)
        VALUES (${normalizedEmail}, ${hashPassword(password)}, ${role}) RETURNING id, email, role`;
      res.setHeader('Set-Cookie', sessionCookie(rows[0]));
      return res.status(201).json({ email: rows[0].email, role: rows[0].role });
    } catch (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'Этот адрес или роль уже зарегистрированы' });
      throw error;
    }
  }
  if (action === 'login') {
    const rows = await sql`SELECT id, email, password_hash, role FROM accounts WHERE email = ${normalizedEmail}`;
    if (!rows[0] || !checkPassword(password, rows[0].password_hash)) {
      return res.status(401).json({ error: 'Неверная почта или пароль' });
    }
    res.setHeader('Set-Cookie', sessionCookie(rows[0]));
    return res.json({ email: rows[0].email, role: rows[0].role });
  }
  return res.status(404).json({ error: 'Неизвестное действие' });
}

