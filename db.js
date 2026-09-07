import pg from 'pg';
import crypto from 'node:crypto';

const { Pool } = pg;

if (!process.env.DATABASE_URL) {
  console.warn('DATABASE_URL tanimli degil. Railway PostgreSQL degiskenini ekleyin.');
}

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000
});

export async function initDatabase() {
  if (!process.env.DATABASE_URL) return;
  await pool.query(`
    CREATE EXTENSION IF NOT EXISTS pgcrypto;
    CREATE TABLE IF NOT EXISTS app_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS devices (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT NOT NULL,
      model TEXT NOT NULL DEFAULT 'Yeni endpoint',
      status TEXT NOT NULL DEFAULT 'offline' CHECK (status IN ('online', 'offline')),
      install_status TEXT NOT NULL DEFAULT 'Kurulum bekliyor',
      last_seen TEXT NOT NULL DEFAULT 'Henüz görülmedi',
      address TEXT NOT NULL DEFAULT 'Bekleniyor',
      protected BOOLEAN NOT NULL DEFAULT TRUE,
      screen_available BOOLEAN NOT NULL DEFAULT FALSE,
      pairing_key TEXT UNIQUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
      id BIGSERIAL PRIMARY KEY,
      event TEXT NOT NULL,
      detail TEXT NOT NULL DEFAULT '',
      severity TEXT NOT NULL DEFAULT 'info',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query(`
    INSERT INTO app_settings (key, value)
    VALUES ('admin_password_hash', $1)
    ON CONFLICT (key) DO NOTHING
  `, [hashPassword('123123')]);
}

export function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derivedKey}`;
}

export function verifyPassword(password, storedHash) {
  const [salt, key] = String(storedHash).split(':');
  if (!salt || !key) return false;
  const derivedKey = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(key, 'hex'), Buffer.from(derivedKey, 'hex'));
}

export function closeDatabase() {
  return pool.end();
}
