import { neon } from '@neondatabase/serverless';
import nodemailer from 'nodemailer';
import { randomInt, randomBytes, scryptSync, createHmac, timingSafeEqual } from 'node:crypto';

const sql = neon(process.env.DATABASE_URL);
const cookieName = 'lab_session';
const mail = nodemailer.createTransport({
  host: 'smtp.gmail.com', port: 465, secure: true,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  connectionTimeout: 10000, socketTimeout: 15000
});
const sign = value => createHmac('sha256', process.env.SESSION_SECRET).update(value).digest('hex');

function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  return salt + ':' + scryptSync(password, salt, 64).toString('hex');
}
function checkPassword(password, saved) {
  if (!/^[a-f0-9]{32}:[a-f0-9]{128}$/.test(saved)) return false;
  const [salt, hash] = saved.split(':');
  return timingSafeEqual(scryptSync(password, salt, 64), Buffer.from(hash, 'hex'));
}
function finishLogin(res, account) {
  const data = Buffer.from(JSON.stringify({ id: account.id, exp: Date.now() + 86400000 })).toString('base64url');
  res.setHeader('Set-Cookie', `${cookieName}=${data}.${sign(data)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`);
  return res.json({ name: account.name, email: account.email, role: account.role });
}

function readSession(req) {
  const value = req.headers.cookie?.split(';').map(x => x.trim()).find(x => x.startsWith(cookieName + '='))?.slice(cookieName.length + 1);
  if (!value) return null;
  const [data, signature] = value.split('.');
  if (!data || !/^[a-f0-9]{64}$/.test(signature || '')) return null;
  if (!timingSafeEqual(Buffer.from(signature), Buffer.from(sign(data)))) return null;
  try {
    const session = JSON.parse(Buffer.from(data, 'base64url').toString());
    return session.exp > Date.now() ? session : null;
  } catch { return null; }
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const action = req.query.action;
    if (action === 'users' || action === 'promote' || action === 'demote') {
      if (req.method !== 'POST') return res.status(405).json({ error: 'Метод не поддерживается' });
      if (req.headers.origin && new URL(req.headers.origin).host !== req.headers.host) return res.status(403).json({ error: 'Недопустимый источник' });
      const session = readSession(req);
      if (!session) return res.status(401).json({ error: 'Войдите в аккаунт' });
      const actors = await sql`SELECT role FROM accounts WHERE id = ${session.id}`;
      if (actors[0]?.role !== 'admin') return res.status(403).json({ error: 'Доступ только для администратора' });
      if (action === 'users') {
        const users = await sql`SELECT id, name, email, role, created_at FROM accounts ORDER BY created_at DESC LIMIT 200`;
        return res.json({ users });
      }
      const id = req.body?.id;
      if (typeof id !== 'string' || !/^[a-f0-9-]{36}$/i.test(id)) return res.status(400).json({ error: 'Некорректный аккаунт' });
      if (action === 'demote') {
        if (id === session.id) return res.status(400).json({ error: 'Нельзя снять права с самого себя' });
        const owner = process.env.ADMIN_EMAIL?.trim().toLowerCase() || '';
        const users = await sql`UPDATE accounts SET role = 'user'
          WHERE id = ${id} AND email <> ${owner} RETURNING id, name, email, role`;
        if (!users[0]) return res.status(403).json({ error: 'Нельзя снять права владельца сайта или аккаунт не найден' });
        return res.json(users[0]);
      }
      const users = await sql`UPDATE accounts SET role = 'admin' WHERE id = ${id} AND password_hash <> 'email-code' RETURNING id, name, email, role`;
      if (!users[0]) return res.status(404).json({ error: 'Аккаунт не найден или регистрация с паролем не завершена' });
      return res.json(users[0]);
    }
    if (req.method === 'GET' && action === 'me') {
      const session = readSession(req);
      if (!session) return res.status(401).json({ error: 'Войдите в аккаунт' });
      const rows = await sql`SELECT name, email, role FROM accounts WHERE id = ${session.id}`;
      return rows[0] ? res.json(rows[0]) : res.status(401).json({ error: 'Сеанс завершён' });
    }
    if (req.method !== 'POST') return res.status(405).json({ error: 'Метод не поддерживается' });
    if (req.headers.origin && new URL(req.headers.origin).host !== req.headers.host) return res.status(403).json({ error: 'Недопустимый источник' });
    if (action === 'logout') {
      res.setHeader('Set-Cookie', `${cookieName}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`);
      return res.json({ ok: true });
    }
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Введите корректную почту' });
    const password = req.body?.password;
    if (action === 'login' || action === 'register') {
      if (typeof password !== 'string' || password.length < 8 || password.length > 128) return res.status(400).json({ error: 'Пароль должен содержать от 8 до 128 символов' });
    }
    if (action === 'login') {
      const bucket = sign('login:' + email + ':' + Math.floor(Date.now() / 900000));
      const limits = await sql`INSERT INTO mail_limits (bucket, total) VALUES (${bucket}, 1)
        ON CONFLICT (bucket) DO UPDATE SET total = mail_limits.total + 1 RETURNING total`;
      if (limits[0].total > 20) return res.status(429).json({ error: 'Слишком много попыток. Попробуйте через 15 минут.' });
      const rows = await sql`SELECT id, name, email, password_hash, role FROM accounts WHERE email = ${email}`;
      if (!rows[0] || !checkPassword(password, rows[0].password_hash)) return res.status(401).json({ error: 'Неверная почта или пароль. Если входили только по коду, сначала завершите регистрацию с паролем.' });
      if (req.body.role !== rows[0].role) return res.status(403).json({ error: 'Выбранный тип входа не соответствует роли аккаунта' });
      return finishLogin(res, rows[0]);
    }
    if (action === 'register') {
      const name = typeof req.body.name === 'string' ? req.body.name.trim() : '';
      if (name.length < 2 || name.length > 80) return res.status(400).json({ error: 'Введите имя от 2 до 80 символов' });
      const existing = await sql`SELECT id FROM accounts WHERE email = ${email} AND password_hash <> 'email-code'`;
      if (existing.length) return res.status(409).json({ error: 'Аккаунт уже зарегистрирован. Перейдите на вкладку «Вход».' });
      // Ограничение запросов хранится в базе, поэтому работает между запусками функции.
      const ip = String(req.headers['x-vercel-forwarded-for'] || req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown').split(',')[0];
      const bucket = sign(ip + ':' + Math.floor(Date.now() / 3600000));
      const limits = await sql`INSERT INTO mail_limits (bucket, total) VALUES (${bucket}, 1)
        ON CONFLICT (bucket) DO UPDATE SET total = mail_limits.total + 1 RETURNING total`;
      if (limits[0].total > 10) return res.status(429).json({ error: 'Слишком много запросов. Попробуйте через час.' });
      const code = String(randomInt(100000, 1000000));
      const hash = sign(email + ':' + code);
      const saved = await sql`INSERT INTO login_codes (email, code_hash, expires_at, sent_at, attempts, pending_name, pending_hash)
        VALUES (${email}, ${hash}, now() + interval '10 minutes', now(), 0, ${name}, ${hashPassword(password)})
        ON CONFLICT (email) DO UPDATE SET code_hash = EXCLUDED.code_hash, expires_at = EXCLUDED.expires_at, sent_at = now(), attempts = 0, pending_name = EXCLUDED.pending_name, pending_hash = EXCLUDED.pending_hash
        WHERE login_codes.sent_at < now() - interval '60 seconds' RETURNING email`;
      if (!saved.length) return res.status(429).json({ error: 'Повторно отправить код можно через минуту.' });
      try {
        await mail.sendMail({ from: `Лист <${process.env.SMTP_USER}>`, to: email,
          subject: 'Подтверждение регистрации в Лист', text: `Код регистрации: ${code}\n\nДействует 10 минут. Введите его на сайте для сохранения аккаунта.\nЕсли вы не регистрировались, проигнорируйте письмо.` });
      } catch {
        await sql`UPDATE login_codes SET expires_at = now(), sent_at = now() - interval '61 seconds' WHERE email = ${email} AND code_hash = ${hash}`;
        return res.status(503).json({ error: 'Не удалось отправить письмо. Попробуйте ещё раз позже.' });
      }
      return res.json({ ok: true });
    }
    if (action === 'verify') {
      const code = String(req.body?.code || '');
      if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: 'Введите 6 цифр из письма' });
      // Один атомарный запрос увеличивает число попыток и погашает правильный код.
      const hash = sign(email + ':' + code);
      const rows = await sql`UPDATE login_codes SET attempts = attempts + 1,
        expires_at = CASE WHEN code_hash = ${hash} THEN now() ELSE expires_at END
        WHERE email = ${email} AND expires_at > now() AND attempts < 5 AND pending_hash IS NOT NULL RETURNING code_hash, pending_name, pending_hash`;
      if (!rows[0] || rows[0].code_hash !== hash) return res.status(401).json({ error: 'Код неверный, истёк или уже использован. Запросите новый.' });
      const role = email === process.env.ADMIN_EMAIL?.trim().toLowerCase() ? 'admin' : 'user';
      const accounts = await sql`INSERT INTO accounts (email, name, password_hash, role) VALUES (${email}, ${rows[0].pending_name}, ${rows[0].pending_hash}, ${role})
        ON CONFLICT (email) DO UPDATE SET name = EXCLUDED.name, password_hash = EXCLUDED.password_hash, role = EXCLUDED.role
        WHERE accounts.password_hash = 'email-code' RETURNING id, name, email, role`;
      if (!accounts[0]) return res.status(409).json({ error: 'Аккаунт уже зарегистрирован. Войдите с паролем.' });
      return finishLogin(res, accounts[0]);
    }
    return res.status(404).json({ error: 'Неизвестное действие' });
  } catch {
    return res.status(500).json({ error: 'Ошибка сервера. Попробуйте позже.' });
  }
}

