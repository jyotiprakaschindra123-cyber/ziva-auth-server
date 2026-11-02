'use strict';

const crypto = require('node:crypto');
const { promisify } = require('node:util');

const scryptAsync = promisify(crypto.scrypt);

const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEYLEN = 64;

function uuid() {
  return crypto.randomUUID();
}

function randomToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function hashToken(token, pepper) {
  return crypto.createHash('sha256').update(`${token}${pepper}`, 'utf8').digest('hex');
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a || ''), 'utf8');
  const right = Buffer.from(String(b || ''), 'utf8');
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

async function hashPassword(secret) {
  const salt = crypto.randomBytes(16);
  const hash = await scryptAsync(String(secret), salt, SCRYPT_KEYLEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: 64 * 1024 * 1024,
  });
  return [
    'scrypt',
    SCRYPT_N,
    SCRYPT_R,
    SCRYPT_P,
    salt.toString('base64'),
    hash.toString('base64'),
  ].join('$');
}

async function verifyPassword(secret, stored) {
  if (!stored || typeof stored !== 'string') return false;
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const n = Number.parseInt(parts[1], 10);
  const r = Number.parseInt(parts[2], 10);
  const p = Number.parseInt(parts[3], 10);
  if (![n, r, p].every(Number.isFinite)) return false;
  const salt = Buffer.from(parts[4], 'base64');
  const expected = Buffer.from(parts[5], 'base64');
  const actual = await scryptAsync(String(secret), salt, expected.length, {
    N: n,
    r,
    p,
    maxmem: 64 * 1024 * 1024,
  });
  if (actual.length !== expected.length) return false;
  return crypto.timingSafeEqual(actual, expected);
}

function canonicalLogin({ installationId, username, nonce, timestamp, deviceKey }) {
  return [
    'ziva-device-proof-v1',
    'login',
    installationId,
    username,
    nonce,
    String(timestamp),
    deviceKey,
  ].join('\n');
}

function canonicalSession({ installationId, sessionId, nonce, timestamp, deviceKey }) {
  return [
    'ziva-device-proof-v1',
    'session',
    installationId,
    sessionId,
    nonce,
    String(timestamp),
    deviceKey,
  ].join('\n');
}

function verifySignature(deviceKeyBase64Url, canonical, signatureBase64Url) {
  try {
    const keyDer = Buffer.from(deviceKeyBase64Url, 'base64url');
    if (keyDer.length < 64 || keyDer.length > 8192) return false;
    const key = crypto.createPublicKey({ key: keyDer, format: 'der', type: 'spki' });
    const signature = Buffer.from(signatureBase64Url, 'base64url');
    if (signature.length < 64 || signature.length > 1024) return false;
    return crypto.verify(
      'sha256',
      Buffer.from(canonical, 'utf8'),
      { key, padding: crypto.constants.RSA_PKCS1_PADDING },
      signature,
    );
  } catch {
    return false;
  }
}

function validateUsername(value) {
  if (typeof value !== 'string') return 'Username is required.';
  const username = value.trim();
  if (username.length < 3) return 'Username must be at least 3 characters.';
  if (username.length > 64) return 'Username is too long.';
  if (/\s/.test(username)) return 'Username cannot contain spaces.';
  return '';
}

function validatePassword(value) {
  if (typeof value !== 'string') return 'Password is required.';
  if (value.length < 6) return 'Password must be at least 6 characters.';
  if (value.length > 72) return 'Password is too long.';
  return '';
}

function normalizeLock(value) {
  if (value === undefined || value === null || value === '' || value === -1) return '';
  if (typeof value === 'number') {
    if (!Number.isInteger(value) || value < 0 || value > 999) return null;
    return String(value).padStart(3, '0');
  }
  if (typeof value === 'string') {
    const text = value.trim();
    if (text === '') return '';
    return /^\d{3}$/.test(text) ? text : null;
  }
  return null;
}

function validateLock(value) {
  return normalizeLock(value) === null
    ? 'Lock must be empty or exactly 3 digits.'
    : '';
}

function isBase64Url(value, min = 16, max = 8192) {
  return typeof value === 'string'
    && value.length >= min
    && value.length <= max
    && /^[A-Za-z0-9_-]+$/.test(value);
}

module.exports = {
  uuid,
  randomToken,
  hashToken,
  safeEqual,
  hashPassword,
  verifyPassword,
  canonicalLogin,
  canonicalSession,
  verifySignature,
  validateUsername,
  validatePassword,
  validateLock,
  normalizeLock,
  isBase64Url,
};
