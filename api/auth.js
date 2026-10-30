import { neon } from '@neondatabase/serverless';
import nodemailer from 'nodemailer';
import { randomInt, createHmac, timingSafeEqual } from 'node:crypto';

const sql = neon(process.env.DATABASE_URL);
const cookieName = 'lab_session';
const mail = nodemailer.createTransport({
  host: 'smtp.gmail.com', port: 465, secure: true,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  connectionTimeout: 10000, socketTimeout: 15000
});
const sign = value => createHmac('sha256', process.env.SESSION_SECRET).update(value).digest('hex');

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
    if (req.method === 'GET' && action === 'me') {
      const session = readSession(req);
      if (!session) return res.status(401).json({ error: 'Войдите в аккаунт' });
      const rows = await sql`SELECT email, role FROM accounts WHERE id = ${session.id}`;
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
    if (action === 'send') {
      // Ограничение запросов хранится в базе, поэтому работает между запусками функции.
      const ip = String(req.headers['x-vercel-forwarded-for'] || req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown').split(',')[0];
      const bucket = sign(ip + ':' + Math.floor(Date.now() / 3600000));
      const limits = await sql`INSERT INTO mail_limits (bucket, total) VALUES (${bucket}, 1)
        ON CONFLICT (bucket) DO UPDATE SET total = mail_limits.total + 1 RETURNING total`;
      if (limits[0].total > 10) return res.status(429).json({ error: 'Слишком много запросов. Попробуйте через час.' });
      const code = String(randomInt(100000, 1000000));
      const hash = sign(email + ':' + code);
      const saved = await sql`INSERT INTO login_codes (email, code_hash, expires_at, sent_at, attempts)
        VALUES (${email}, ${hash}, now() + interval '10 minutes', now(), 0)
        ON CONFLICT (email) DO UPDATE SET code_hash = EXCLUDED.code_hash, expires_at = EXCLUDED.expires_at, sent_at = now(), attempts = 0
        WHERE login_codes.sent_at < now() - interval '60 seconds' RETURNING email`;
      if (!saved.length) return res.status(429).json({ error: 'Повторно отправить код можно через минуту.' });
      try {
        await mail.sendMail({ from: `Лист <${process.env.SMTP_USER}>`, to: email,
          subject: 'Код входа в Лист', text: `Ваш код: ${code}\n\nОн действует 10 минут и подходит для одного входа.\nЕсли вы не запрашивали вход, проигнорируйте письмо.` });
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
        WHERE email = ${email} AND expires_at > now() AND attempts < 5 RETURNING code_hash`;
      if (!rows[0] || rows[0].code_hash !== hash) return res.status(401).json({ error: 'Код неверный, истёк или уже использован. Запросите новый.' });
      const role = email === process.env.ADMIN_EMAIL?.trim().toLowerCase() ? 'admin' : 'user';
      const accounts = await sql`INSERT INTO accounts (email, password_hash, role) VALUES (${email}, 'email-code', ${role})
        ON CONFLICT (email) DO UPDATE SET role = EXCLUDED.role RETURNING id, email, role`;
      const account = accounts[0];
      const data = Buffer.from(JSON.stringify({ id: account.id, exp: Date.now() + 86400000 })).toString('base64url');
      res.setHeader('Set-Cookie', `${cookieName}=${data}.${sign(data)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`);
      return res.json({ email: account.email, role: account.role });
    }
    return res.status(404).json({ error: 'Неизвестное действие' });
  } catch {
    return res.status(500).json({ error: 'Ошибка сервера. Попробуйте позже.' });
  }
}

