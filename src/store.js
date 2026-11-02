'use strict';

const { Pool } = require('pg');
const { SCHEMA_SQL } = require('./schema');
const config = require('./config');

function httpError(status, code, message) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  return error;
}

function rowToUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    username: row.username,
    passwordHash: row.password_hash,
    lockHash: row.lock_hash,
    disabled: row.disabled,
    createdAt: row.created_at,
  };
}

function rowToDevice(row) {
  if (!row) return null;
  return {
    id: row.id,
    userId: row.user_id,
    installationId: row.installation_id,
    publicKey: row.public_key,
    deviceInfo: row.device_info,
    osName: row.os_name,
    osVersion: row.os_version,
    hostname: row.hostname,
    revoked: row.revoked,
    createdAt: row.created_at,
    lastSeenAt: row.last_seen_at,
  };
}

function rowToSession(row) {
  if (!row) return null;
  return {
    id: row.id,
    userId: row.user_id,
    deviceId: row.device_id,
    tokenHash: row.token_hash,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    lastSeenAt: row.last_seen_at,
    revoked: row.revoked,
    ip: row.ip,
    userAgent: row.user_agent,
  };
}

class MemoryStore {
  constructor() {
    this.users = [];
    this.devices = [];
    this.sessions = [];
    this.nonces = new Map();
    this.attempts = [];
    this.audits = [];
  }

  async init() {}
  async close() {}

  async createUser({ id, username, passwordHash, lockHash, disabled = false }) {
    if (this.users.some((user) => user.username === username)) {
      throw httpError(409, 'username_taken', 'Username is already registered.');
    }
    const user = {
      id,
      username,
      passwordHash,
      lockHash: lockHash || null,
      disabled: Boolean(disabled),
      createdAt: new Date().toISOString(),
    };
    this.users.push(user);
    return user;
  }

  async findUserByUsername(username) {
    return this.users.find((user) => user.username === username) || null;
  }

  async findUserById(id) {
    return this.users.find((user) => user.id === id) || null;
  }

  async setUserDisabled(id, disabled) {
    const user = await this.findUserById(id);
    if (!user) return null;
    user.disabled = Boolean(disabled);
    return user;
  }

  async setUserPassword(id, passwordHash, lockHash) {
    const user = await this.findUserById(id);
    if (!user) return null;
    user.passwordHash = passwordHash;
    user.lockHash = lockHash || null;
    return user;
  }

  async listUsers() {
    return this.users.map((user) => ({
      ...user,
      deviceCount: this.devices.filter((device) => device.userId === user.id).length,
      sessionCount: this.sessions.filter(
        (session) => session.userId === user.id && !session.revoked,
      ).length,
    }));
  }

  async createDevice({
    id,
    userId,
    installationId,
    publicKey,
    deviceInfo,
    osName,
    osVersion,
    hostname,
  }) {
    const device = {
      id,
      userId,
      installationId,
      publicKey,
      deviceInfo: deviceInfo || null,
      osName: osName || null,
      osVersion: osVersion || null,
      hostname: hostname || null,
      revoked: false,
      createdAt: new Date().toISOString(),
      lastSeenAt: new Date().toISOString(),
    };
    this.devices.push(device);
    return device;
  }

  async findDeviceByInstallationId(installationId) {
    return this.devices.find((device) => device.installationId === installationId) || null;
  }

  async findDeviceById(id) {
    return this.devices.find((device) => device.id === id) || null;
  }

  async setDeviceRevoked(id, revoked) {
    const device = await this.findDeviceById(id);
    if (!device) return null;
    device.revoked = Boolean(revoked);
    return device;
  }

  async countDevicesForUser(userId) {
    return this.devices.filter((device) => device.userId === userId && !device.revoked).length;
  }

  async touchDevice(id) {
    const device = await this.findDeviceById(id);
    if (device) device.lastSeenAt = new Date().toISOString();
  }

  async listDevicesForUser(userId) {
    return this.devices
      .filter((device) => device.userId === userId)
      .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  }

  async createSession({
    id,
    userId,
    deviceId,
    tokenHash,
    expiresAt,
    ip,
    userAgent,
  }) {
    const session = {
      id,
      userId,
      deviceId,
      tokenHash,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(expiresAt).toISOString(),
      lastSeenAt: new Date().toISOString(),
      revoked: false,
      ip: ip || null,
      userAgent: userAgent || null,
    };
    this.sessions.push(session);
    return session;
  }

  async findSessionByTokenHash(tokenHash) {
    return this.sessions.find((session) => session.tokenHash === tokenHash) || null;
  }

  async findSessionById(id) {
    return this.sessions.find((session) => session.id === id) || null;
  }

  async updateSession(id, { expiresAt, lastSeenAt }) {
    const session = await this.findSessionById(id);
    if (!session) return null;
    if (expiresAt) session.expiresAt = new Date(expiresAt).toISOString();
    if (lastSeenAt) session.lastSeenAt = new Date(lastSeenAt).toISOString();
    return session;
  }

  async revokeSession(id) {
    const session = await this.findSessionById(id);
    if (!session) return null;
    session.revoked = true;
    return session;
  }

  async revokeSessionsForDevice(deviceId) {
    for (const session of this.sessions) {
      if (session.deviceId === deviceId) session.revoked = true;
    }
  }

  async revokeSessionsForUser(userId) {
    for (const session of this.sessions) {
      if (session.userId === userId) session.revoked = true;
    }
  }

  async listSessionsForUser(userId) {
    return this.sessions
      .filter((session) => session.userId === userId)
      .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  }

  async insertNonce({ installationId, nonce, createdAt }) {
    const key = `${installationId}:${nonce}`;
    if (this.nonces.has(key)) {
      throw httpError(409, 'nonce_replay', 'Request nonce has already been used.');
    }
    this.nonces.set(key, createdAt || new Date());
  }

  async cleanupNonces(before) {
    const cutoff = new Date(before).getTime();
    for (const [key, createdAt] of this.nonces) {
      if (new Date(createdAt).getTime() < cutoff) this.nonces.delete(key);
    }
  }

  async recordLoginAttempt({ username, ip, success }) {
    this.attempts.push({
      username: username || null,
      ip: ip || null,
      success: Boolean(success),
      createdAt: new Date(),
    });
  }

  async countRecentFailedAttempts(username, ip, since) {
    const cutoff = new Date(since).getTime();
    const recent = this.attempts.filter(
      (attempt) => !attempt.success && attempt.createdAt.getTime() >= cutoff,
    );
    const byUser = recent.filter((attempt) => attempt.username === username).length;
    const byIp = recent.filter((attempt) => attempt.ip === ip).length;
    return Math.max(byUser, byIp);
  }

  async clearFailedAttempts(username, ip) {
    this.attempts = this.attempts.filter(
      (attempt) => attempt.success || (attempt.username !== username && attempt.ip !== ip),
    );
  }

  async audit({ event, userId, deviceId, sessionId, ip, detail }) {
    this.audits.push({
      event,
      userId: userId || null,
      deviceId: deviceId || null,
      sessionId: sessionId || null,
      ip: ip || null,
      detail: detail || null,
      createdAt: new Date().toISOString(),
    });
  }

  async listAudit(limit = 100) {
    return this.audits
      .slice()
      .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)))
      .slice(0, limit);
  }
}

class PostgresStore {
  constructor(connectionString) {
    this.pool = new Pool({
      connectionString,
      max: 3,
      ssl: process.env.PGSSL === 'disable' ? false : { rejectUnauthorized: false },
    });
  }

  async init() {
    await this.pool.query(SCHEMA_SQL);
  }

  async close() {
    await this.pool.end();
  }

  async createUser({ id, username, passwordHash, lockHash, disabled = false }) {
    try {
      const result = await this.pool.query(
        `INSERT INTO users (id, username, password_hash, lock_hash, disabled)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING *`,
        [id, username, passwordHash, lockHash || null, Boolean(disabled)],
      );
      return rowToUser(result.rows[0]);
    } catch (error) {
      if (error.code === '23505') {
        throw httpError(409, 'username_taken', 'Username is already registered.');
      }
      throw error;
    }
  }

  async findUserByUsername(username) {
    const result = await this.pool.query('SELECT * FROM users WHERE username = $1', [username]);
    return rowToUser(result.rows[0]);
  }

  async findUserById(id) {
    const result = await this.pool.query('SELECT * FROM users WHERE id = $1', [id]);
    return rowToUser(result.rows[0]);
  }

  async setUserDisabled(id, disabled) {
    const result = await this.pool.query(
      'UPDATE users SET disabled = $2 WHERE id = $1 RETURNING *',
      [id, Boolean(disabled)],
    );
    return rowToUser(result.rows[0]);
  }

  async setUserPassword(id, passwordHash, lockHash) {
    const result = await this.pool.query(
      `UPDATE users
       SET password_hash = $2, lock_hash = $3
       WHERE id = $1
       RETURNING *`,
      [id, passwordHash, lockHash || null],
    );
    return rowToUser(result.rows[0]);
  }

  async listUsers() {
    const result = await this.pool.query(
      `SELECT u.*,
              (SELECT count(*)::int FROM devices d WHERE d.user_id = u.id) AS device_count,
              (SELECT count(*)::int FROM sessions s
                 WHERE s.user_id = u.id AND s.revoked = false) AS session_count
       FROM users u
       ORDER BY u.created_at DESC`,
    );
    return result.rows.map((row) => ({
      ...rowToUser(row),
      deviceCount: row.device_count,
      sessionCount: row.session_count,
    }));
  }

  async createDevice({
    id,
    userId,
    installationId,
    publicKey,
    deviceInfo,
    osName,
    osVersion,
    hostname,
  }) {
    const result = await this.pool.query(
      `INSERT INTO devices
         (id, user_id, installation_id, public_key, device_info, os_name, os_version, hostname, last_seen_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
       RETURNING *`,
      [
        id,
        userId,
        installationId,
        publicKey,
        deviceInfo || null,
        osName || null,
        osVersion || null,
        hostname || null,
      ],
    );
    return rowToDevice(result.rows[0]);
  }

  async findDeviceByInstallationId(installationId) {
    const result = await this.pool.query(
      'SELECT * FROM devices WHERE installation_id = $1',
      [installationId],
    );
    return rowToDevice(result.rows[0]);
  }

  async findDeviceById(id) {
    const result = await this.pool.query('SELECT * FROM devices WHERE id = $1', [id]);
    return rowToDevice(result.rows[0]);
  }

  async setDeviceRevoked(id, revoked) {
    const result = await this.pool.query(
      'UPDATE devices SET revoked = $2 WHERE id = $1 RETURNING *',
      [id, Boolean(revoked)],
    );
    return rowToDevice(result.rows[0]);
  }

  async countDevicesForUser(userId) {
    const result = await this.pool.query(
      'SELECT count(*)::int AS count FROM devices WHERE user_id = $1 AND revoked = false',
      [userId],
    );
    return result.rows[0].count;
  }

  async touchDevice(id) {
    await this.pool.query('UPDATE devices SET last_seen_at = now() WHERE id = $1', [id]);
  }

  async listDevicesForUser(userId) {
    const result = await this.pool.query(
      'SELECT * FROM devices WHERE user_id = $1 ORDER BY created_at DESC',
      [userId],
    );
    return result.rows.map(rowToDevice);
  }

  async createSession({
    id,
    userId,
    deviceId,
    tokenHash,
    expiresAt,
    ip,
    userAgent,
  }) {
    const result = await this.pool.query(
      `INSERT INTO sessions
         (id, user_id, device_id, token_hash, expires_at, ip, user_agent)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [id, userId, deviceId, tokenHash, expiresAt, ip || null, userAgent || null],
    );
    return rowToSession(result.rows[0]);
  }

  async findSessionByTokenHash(tokenHash) {
    const result = await this.pool.query(
      'SELECT * FROM sessions WHERE token_hash = $1',
      [tokenHash],
    );
    return rowToSession(result.rows[0]);
  }

  async findSessionById(id) {
    const result = await this.pool.query('SELECT * FROM sessions WHERE id = $1', [id]);
    return rowToSession(result.rows[0]);
  }

  async updateSession(id, { expiresAt, lastSeenAt }) {
    const result = await this.pool.query(
      `UPDATE sessions
       SET expires_at = COALESCE($2, expires_at),
           last_seen_at = COALESCE($3, last_seen_at)
       WHERE id = $1
       RETURNING *`,
      [id, expiresAt || null, lastSeenAt || null],
    );
    return rowToSession(result.rows[0]);
  }

  async revokeSession(id) {
    const result = await this.pool.query(
      'UPDATE sessions SET revoked = true WHERE id = $1 RETURNING *',
      [id],
    );
    return rowToSession(result.rows[0]);
  }

  async revokeSessionsForDevice(deviceId) {
    await this.pool.query('UPDATE sessions SET revoked = true WHERE device_id = $1', [deviceId]);
  }

  async revokeSessionsForUser(userId) {
    await this.pool.query('UPDATE sessions SET revoked = true WHERE user_id = $1', [userId]);
  }

  async listSessionsForUser(userId) {
    const result = await this.pool.query(
      'SELECT * FROM sessions WHERE user_id = $1 ORDER BY created_at DESC',
      [userId],
    );
    return result.rows.map(rowToSession);
  }

  async insertNonce({ installationId, nonce, createdAt }) {
    const result = await this.pool.query(
      `INSERT INTO login_nonces (installation_id, nonce, created_at)
       VALUES ($1, $2, $3)
       ON CONFLICT (installation_id, nonce) DO NOTHING
       RETURNING id`,
      [installationId, nonce, createdAt || new Date()],
    );
    if (result.rowCount === 0) {
      throw httpError(409, 'nonce_replay', 'Request nonce has already been used.');
    }
  }

  async cleanupNonces(before) {
    await this.pool.query('DELETE FROM login_nonces WHERE created_at < $1', [before]);
  }

  async recordLoginAttempt({ username, ip, success }) {
    await this.pool.query(
      'INSERT INTO login_attempts (username, ip, success) VALUES ($1, $2, $3)',
      [username || null, ip || null, Boolean(success)],
    );
  }

  async countRecentFailedAttempts(username, ip, since) {
    const result = await this.pool.query(
      `SELECT
         (SELECT count(*)::int FROM login_attempts
           WHERE success = false AND created_at >= $1 AND username = $2) AS user_count,
         (SELECT count(*)::int FROM login_attempts
           WHERE success = false AND created_at >= $1 AND ip = $3) AS ip_count`,
      [since, username, ip],
    );
    return Math.max(result.rows[0].user_count, result.rows[0].ip_count);
  }

  async clearFailedAttempts(username, ip) {
    await this.pool.query(
      'DELETE FROM login_attempts WHERE success = false AND (username = $1 OR ip = $2)',
      [username, ip],
    );
  }

  async audit({ event, userId, deviceId, sessionId, ip, detail }) {
    await this.pool.query(
      `INSERT INTO audit_log (event, user_id, device_id, session_id, ip, detail)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        event,
        userId || null,
        deviceId || null,
        sessionId || null,
        ip || null,
        detail ? JSON.stringify(detail) : null,
      ],
    );
  }

  async listAudit(limit = 100) {
    const result = await this.pool.query(
      `SELECT * FROM audit_log ORDER BY created_at DESC LIMIT $1`,
      [Math.min(Math.max(Number(limit) || 100, 1), 500)],
    );
    return result.rows.map((row) => ({
      id: row.id,
      event: row.event,
      userId: row.user_id,
      deviceId: row.device_id,
      sessionId: row.session_id,
      ip: row.ip,
      detail: row.detail,
      createdAt: row.created_at,
    }));
  }
}

function createStore(connectionString = config.databaseUrl) {
  return connectionString ? new PostgresStore(connectionString) : new MemoryStore();
}

module.exports = {
  MemoryStore,
  PostgresStore,
  createStore,
  httpError,
};
