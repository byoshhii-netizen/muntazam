import express from 'express';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { initDatabase, pool, hashPassword, verifyPassword, closeDatabase } from './db.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const port = Number(process.env.PORT || 3000);
const sessionSecret = process.env.SESSION_SECRET || 'muntazam-development-secret';
const isProduction = process.env.NODE_ENV === 'production';

app.use(express.json({ limit: '100kb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  next();
});

function sign(value) {
  return crypto.createHmac('sha256', sessionSecret).update(value).digest('hex');
}
function makeSession() {
  const expiresAt = Date.now() + 8 * 60 * 60 * 1000;
  const value = String(expiresAt);
  return `${value}.${sign(value)}`;
}
function validSession(value) {
  if (!value) return false;
  const [expiresAt, signature] = value.split('.');
  const expected = expiresAt ? sign(expiresAt) : '';
  return Boolean(expiresAt && signature && signature.length === expected.length && Number(expiresAt) > Date.now() && crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected)));
}
function cookies(req) {
  return Object.fromEntries((req.headers.cookie || '').split(';').filter(Boolean).map((part) => { const [key, ...value] = part.trim().split('='); return [key, decodeURIComponent(value.join('='))]; }));
}
function requireAuth(req, res, next) {
  if (!validSession(cookies(req).muntazam_session)) return res.status(401).json({ error: 'Oturum gerekli.' });
  next();
}
function createPairingKey() {
  return `MNT-${crypto.randomBytes(18).toString('hex').toUpperCase()}`;
}
function serializeDevice(row) {
  return { id: row.id, name: row.name, model: row.model, status: row.status, install: row.install_status, lastSeen: row.last_seen, address: row.address, protected: row.protected, screen: row.screen_available, pairingKey: row.pairing_key };
}

app.get('/api/health', async (_req, res) => {
  try { await pool.query('SELECT 1'); res.json({ ok: true, database: 'connected' }); } catch { res.status(503).json({ ok: false, database: 'unavailable' }); }
});

app.post('/api/auth/login', async (req, res) => {
  const { password } = req.body || {};
  if (!password) return res.status(400).json({ error: 'Şifre gerekli.' });
  try {
    const { rows } = await pool.query("SELECT value FROM app_settings WHERE key = 'admin_password_hash'");
    if (!rows[0] || !verifyPassword(password, rows[0].value)) return res.status(401).json({ error: 'Şifre hatalı.' });
    res.setHeader('Set-Cookie', `muntazam_session=${encodeURIComponent(makeSession())}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800${isProduction ? '; Secure' : ''}`);
    await pool.query('INSERT INTO audit_logs (event, detail) VALUES ($1, $2)', ['Oturum açıldı', 'Yönetici paneli']);
    res.json({ ok: true });
  } catch (error) { res.status(500).json({ error: 'Giriş sırasında veritabanı hatası.', detail: error.message }); }
});

app.post('/api/auth/logout', (_req, res) => { res.setHeader('Set-Cookie', 'muntazam_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0'); res.json({ ok: true }); });

app.get('/api/devices', requireAuth, async (_req, res) => {
  const { rows } = await pool.query('SELECT * FROM devices ORDER BY created_at ASC');
  res.json(rows.map(serializeDevice));
});

app.post('/api/devices', requireAuth, async (req, res) => {
  const { name, protected: isProtected = true } = req.body || {};
  if (!name || name.length > 80) return res.status(400).json({ error: 'Geçerli bir cihaz adı gerekli.' });
  const pairingKey = createPairingKey();
  const { rows } = await pool.query(`INSERT INTO devices (name, protected, pairing_key) VALUES ($1, $2, $3) RETURNING *`, [name.trim(), Boolean(isProtected), pairingKey]);
  await pool.query('INSERT INTO audit_logs (event, detail) VALUES ($1, $2)', ['Cihaz oluşturuldu', name.trim()]);
  res.status(201).json(serializeDevice(rows[0]));
});

app.patch('/api/devices/:id', requireAuth, async (req, res) => {
  const allowed = ['name', 'protected', 'install_status', 'model'];
  const entries = Object.entries(req.body || {}).filter(([key, value]) => allowed.includes(key) && value !== undefined);
  if (!entries.length) return res.status(400).json({ error: 'Güncellenecek alan yok.' });
  const values = entries.map(([, value]) => value);
  const setSql = entries.map(([key], index) => `${key} = $${index + 1}`).join(', ');
  values.push(req.params.id);
  const { rows } = await pool.query(`UPDATE devices SET ${setSql} WHERE id = $${values.length} RETURNING *`, values);
  if (!rows[0]) return res.status(404).json({ error: 'Cihaz bulunamadı.' });
  await pool.query('INSERT INTO audit_logs (event, detail) VALUES ($1, $2)', ['Cihaz güncellendi', rows[0].name]);
  res.json(serializeDevice(rows[0]));
});

app.post('/api/devices/:id/commands', requireAuth, async (req, res) => {
  const commands = new Set(['lock', 'restart', 'safe-mode']);
  if (!commands.has(req.body?.command)) return res.status(400).json({ error: 'Geçersiz komut.' });
  const { rows } = await pool.query('SELECT name FROM devices WHERE id = $1', [req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'Cihaz bulunamadı.' });
  await pool.query('INSERT INTO audit_logs (event, detail) VALUES ($1, $2)', [`Komut: ${req.body.command}`, rows[0].name]);
  res.status(202).json({ ok: true, status: 'queued', userVisible: true });
});

app.get('/api/activity', requireAuth, async (_req, res) => { const { rows } = await pool.query('SELECT id, event, detail, severity, created_at FROM audit_logs ORDER BY created_at DESC LIMIT 100'); res.json(rows); });
app.get('/api/settings', requireAuth, (_req, res) => res.json({ sessionHours: 8, requiresPairing: true, visibleCommands: true }));
app.patch('/api/settings/password', requireAuth, async (req, res) => { const { password } = req.body || {}; if (!password || password.length < 6) return res.status(400).json({ error: 'Şifre en az 6 karakter olmalı.' }); await pool.query("UPDATE app_settings SET value = $1, updated_at = NOW() WHERE key = 'admin_password_hash'", [hashPassword(password)]); await pool.query('INSERT INTO audit_logs (event, detail) VALUES ($1, $2)', ['Yönetici şifresi değiştirildi', 'Ayarlar']); res.json({ ok: true }); });

const distPath = path.join(__dirname, 'dist');
app.use(express.static(distPath));
app.get('*', (_req, res) => res.sendFile(path.join(distPath, 'index.html')));

initDatabase().then(() => app.listen(port, '0.0.0.0', () => console.log(`Muntazam listening on ${port}`))).catch((error) => { console.error('Database initialization failed:', error); process.exit(1); });
process.on('SIGTERM', async () => { await closeDatabase(); process.exit(0); });
