'use strict';

const express = require('express');
const configDefaults = require('./config');
const { createStore, httpError } = require('./store');
const {
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
} = require('./crypto');

function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

function fail(status, code, message) {
  throw httpError(status, code, message);
}

function clientIp(req) {
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '')
    .toString()
    .split(',')[0]
    .trim();
}

function headerValue(req, name) {
  const value = req.get(name);
  return typeof value === 'string' ? value.trim() : '';
}

function parseBody(req) {
  if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
    fail(400, 'invalid_request', 'A JSON object body is required.');
  }
  return req.body;
}

function parseTimestamp(value) {
  const timestamp = typeof value === 'string' ? Number.parseInt(value, 10) : value;
  if (!Number.isFinite(timestamp) || timestamp <= 0) {
    fail(400, 'invalid_timestamp', 'A valid request_timestamp is required.');
  }
  return Math.floor(timestamp);
}

function parseNonce(value) {
  if (!isBase64Url(value, 16, 128)) {
    fail(400, 'invalid_nonce', 'A valid request_nonce is required.');
  }
  return value;
}

function validateLoginBody(body) {
  const usernameError = validateUsername(body.username);
  if (usernameError) fail(400, 'invalid_username', usernameError);
  const passwordError = validatePassword(body.password);
  if (passwordError) fail(400, 'invalid_password', passwordError);
  const lockError = validateLock(body.lock);
  if (lockError) fail(400, 'invalid_lock', lockError);
  const lock = normalizeLock(body.lock);

  return {
    username: body.username.trim(),
    password: body.password,
    lock,
    nonce: parseNonce(body.request_nonce),
    timestamp: parseTimestamp(body.request_timestamp),
    deviceInfo: body.device_info && typeof body.device_info === 'object'
      ? body.device_info
      : null,
    osName: typeof body.os_name === 'string' ? body.os_name.slice(0, 128) : null,
    osVersion: typeof body.os_version === 'string' ? body.os_version.slice(0, 128) : null,
    hostname: typeof body.hostname === 'string' ? body.hostname.slice(0, 255) : null,
  };
}

function validateSessionBody(body, scope) {
  if (typeof body.session_id !== 'string' || !body.session_id) {
    fail(400, 'invalid_session', `${scope} requires a session_id.`);
  }
  return {
    sessionId: body.session_id,
    nonce: parseNonce(body.request_nonce),
    timestamp: parseTimestamp(body.request_timestamp),
  };
}

function proofHeaders(req) {
  const installationId = headerValue(req, 'x-ziva-installation-id');
  const deviceKey = headerValue(req, 'x-ziva-device-key');
  const signature = headerValue(req, 'x-ziva-device-signature');
  const proofVersion = headerValue(req, 'x-ziva-proof-version');
  const protocolVersion = headerValue(req, 'x-ziva-protocol-version');

  if (!installationId || !deviceKey || !signature) {
    fail(400, 'missing_device_proof', 'Device proof headers are required.');
  }
  if (proofVersion && proofVersion !== 'ziva-device-proof-v1') {
    fail(400, 'unsupported_proof', 'Unsupported device proof version.');
  }
  if (protocolVersion && protocolVersion !== '2') {
    fail(400, 'unsupported_protocol', 'Unsupported protocol version.');
  }
  if (!isBase64Url(deviceKey, 64, 8192)) {
    fail(400, 'invalid_device_key', 'The device public key is not valid base64url.');
  }
  if (!isBase64Url(signature, 64, 1024)) {
    fail(400, 'invalid_signature', 'The device signature is not valid base64url.');
  }
  return { installationId, deviceKey, signature };
}

async function verifyProof(store, req, body, scope, expectedDeviceKey, config) {
  const { installationId, deviceKey, signature } = proofHeaders(req);
  if (expectedDeviceKey && !safeEqual(deviceKey, expectedDeviceKey)) {
    fail(403, 'device_key_mismatch', 'The device key does not match this installation.');
  }

  const timestampMs = body.timestamp * 1000;
  const skewMs = config.clockSkewSeconds * 1000;
  if (Math.abs(Date.now() - timestampMs) > skewMs) {
    fail(401, 'stale_proof', 'The device proof timestamp is outside the allowed window.');
  }

  const canonical = scope === 'login'
    ? canonicalLogin({
      installationId,
      username: body.username,
      nonce: body.nonce,
      timestamp: body.timestamp,
      deviceKey,
    })
    : canonicalSession({
      installationId,
      sessionId: body.sessionId,
      nonce: body.nonce,
      timestamp: body.timestamp,
      deviceKey,
    });

  if (!verifySignature(deviceKey, canonical, signature)) {
    fail(401, 'invalid_proof', 'The device proof signature is invalid.');
  }

  await store.cleanupNonces(new Date(Date.now() - 10 * 60 * 1000));
  await store.insertNonce({
    installationId,
    nonce: body.nonce,
    createdAt: new Date(),
  });

  return { installationId, deviceKey };
}

function sessionExpiry(config) {
  return new Date(Date.now() + config.sessionTtlMs);
}

function remainingMs(expiresAt) {
  return Math.max(0, new Date(expiresAt).getTime() - Date.now());
}

function timingFields(expiresAt) {
  const now = new Date();
  return {
    server_time: now.toISOString(),
    server_time_utc: now.toISOString(),
    expires_at: new Date(expiresAt).toISOString(),
    remaining_ms: remainingMs(expiresAt),
  };
}

function loginResponse(session, user, device, token, config) {
  return {
    access_token: token,
    access_token_base64: Buffer.from(token, 'utf8').toString('base64'),
    device_id: device.id,
    session_id: session.id,
    user_id: user.id,
    username: user.username,
    ...timingFields(session.expiresAt),
    heartbeat_interval_seconds: config.heartbeatSeconds,
    status: 'active',
    protocol_version: 2,
    client_version: '2.2.1',
    installation_id: device.installationId,
    awaiting_initial_confirmation: false,
    initial_authorization_retry_used: false,
  };
}

function heartbeatResponse(session, user, device, config) {
  return {
    session_id: session.id,
    device_id: device.id,
    user_id: user.id,
    username: user.username,
    ...timingFields(session.expiresAt),
    heartbeat_interval_seconds: config.heartbeatSeconds,
    status: 'active',
    protocol_version: 2,
    client_version: '2.2.1',
    installation_id: device.installationId,
  };
}

function tokenFromRequest(req, body) {
  const authorization = headerValue(req, 'authorization');
  if (authorization.toLowerCase().startsWith('bearer ')) {
    return authorization.slice(7).trim();
  }
  if (body && typeof body.access_token === 'string') return body.access_token;
  return '';
}

async function loadLiveSession(store, req, body, config) {
  const token = tokenFromRequest(req, body);
  if (!token) fail(401, 'missing_token', 'A session token is required.');
  const session = await store.findSessionByTokenHash(hashToken(token, config.tokenPepper));
  if (!session) fail(401, 'invalid_session', 'The session token is not valid.');
  if (session.revoked) fail(403, 'revoked', 'The session has been revoked.');
  if (new Date(session.expiresAt).getTime() <= Date.now()) {
    fail(401, 'expired', 'The session has expired.');
  }
  const user = await store.findUserById(session.userId);
  if (!user || user.disabled) fail(403, 'user_disabled', 'The account is disabled.');
  const device = await store.findDeviceById(session.deviceId);
  if (!device || device.revoked) fail(403, 'device_revoked', 'The device has been revoked.');
  return { token, session, user, device };
}

function createApp(options = {}) {
  const config = { ...configDefaults, ...(options.config || {}) };
  const store = options.store || createStore(config.databaseUrl);
  const app = express();

  app.set('trust proxy', true);
  app.use(express.json({ limit: '32kb' }));

  let initPromise = null;
  app.use(asyncHandler(async (req, res, next) => {
    if (!initPromise) initPromise = store.init();
    await initPromise;
    next();
  }));

  app.get('/', (req, res) => {
    res.json({
      service: 'Ziva Browse authentication',
      protocol_version: 2,
      status: 'ok',
    });
  });

  app.get('/api/health', (req, res) => {
    res.json({
      ok: true,
      service: 'ziva-auth',
      protocol_version: 2,
      storage: config.databaseUrl ? 'postgres' : 'memory',
      admin_enabled: Boolean(config.adminToken),
      production: Boolean(config.isProduction),
    });
  });

  // ---------------------------------------------------------------------
  // Login
  // ---------------------------------------------------------------------
  app.post('/api/authenticate', asyncHandler(async (req, res) => {
    const body = parseBody(req);
    const input = validateLoginBody(body);
    const ip = clientIp(req);
    const usernameKey = input.username.toLowerCase();
    let failureRecorded = false;

    try {
      const failures = await store.countRecentFailedAttempts(
        usernameKey,
        ip,
        new Date(Date.now() - config.loginWindowMs),
      );
      if (failures >= config.maxLoginFailures) {
        failureRecorded = true;
        fail(
          429,
          'too_many_attempts',
          'Too many sign-in attempts. Please wait a moment and try again.',
        );
      }

      const proof = await verifyProof(store, req, input, 'login', null, config);

      const user = await store.findUserByUsername(usernameKey);
      if (!user || user.disabled) {
        failureRecorded = true;
        fail(
          401,
          'invalid_credentials',
          'Authentication failed: Invalid username, password, or account access.',
        );
      }

      const passwordOk = await verifyPassword(input.password, user.passwordHash);
      if (!passwordOk) {
        failureRecorded = true;
        fail(
          401,
          'invalid_credentials',
          'Authentication failed: Invalid username, password, or account access.',
        );
      }

      if (user.lockHash) {
        const lockOk = input.lock && await verifyPassword(input.lock, user.lockHash);
        if (!lockOk) {
          failureRecorded = true;
          fail(
            401,
            'invalid_credentials',
            'Authentication failed: Invalid username, password, or account access.',
          );
        }
      } else if (input.lock) {
        failureRecorded = true;
        fail(
          401,
          'invalid_credentials',
          'Authentication failed: Invalid username, password, or account access.',
        );
      }

      let device = await store.findDeviceByInstallationId(proof.installationId);
      if (device) {
        if (device.userId !== user.id) {
          failureRecorded = true;
          fail(403, 'device_in_use', 'This device is already bound to another account.');
        }
        if (device.revoked) {
          failureRecorded = true;
          fail(403, 'device_revoked', 'This device has been revoked.');
        }
        if (!safeEqual(device.publicKey, proof.deviceKey)) {
          failureRecorded = true;
          fail(403, 'device_key_mismatch', 'The device key does not match this installation.');
        }
        await store.touchDevice(device.id);
      } else {
        const deviceCount = await store.countDevicesForUser(user.id);
        if (deviceCount >= config.maxDevices) {
          failureRecorded = true;
          fail(403, 'device_limit', 'This account has reached its device limit.');
        }
        device = await store.createDevice({
          id: uuid(),
          userId: user.id,
          installationId: proof.installationId,
          publicKey: proof.deviceKey,
          deviceInfo: input.deviceInfo,
          osName: input.osName,
          osVersion: input.osVersion,
          hostname: input.hostname,
        });
      }

      const token = randomToken();
      const session = await store.createSession({
        id: uuid(),
        userId: user.id,
        deviceId: device.id,
        tokenHash: hashToken(token, config.tokenPepper),
        expiresAt: sessionExpiry(config),
        ip,
        userAgent: headerValue(req, 'user-agent'),
      });

      await store.recordLoginAttempt({ username: usernameKey, ip, success: true });
      await store.clearFailedAttempts(usernameKey, ip);
      await store.audit({
        event: 'login',
        userId: user.id,
        deviceId: device.id,
        sessionId: session.id,
        ip,
        detail: { username: user.username },
      });

      res.json(loginResponse(session, user, device, token, config));
    } catch (error) {
      if (!failureRecorded) {
        await store.recordLoginAttempt({ username: usernameKey, ip, success: false });
      }
      throw error;
    }
  }));

  // ---------------------------------------------------------------------
  // Heartbeat
  // ---------------------------------------------------------------------
  app.post('/api/auth/session/heartbeat', asyncHandler(async (req, res) => {
    const body = parseBody(req);
    const input = validateSessionBody(body, 'heartbeat');
    const live = await loadLiveSession(store, req, body, config);

    if (live.session.id !== input.sessionId) {
      fail(401, 'invalid_session', 'The session ID does not match the token.');
    }

    await verifyProof(
      store,
      req,
      input,
      'session',
      live.device.publicKey,
      config,
    );

    const expiresAt = sessionExpiry(config);
    const session = await store.updateSession(live.session.id, {
      expiresAt,
      lastSeenAt: new Date(),
    });
    await store.touchDevice(live.device.id);
    await store.audit({
      event: 'heartbeat',
      userId: live.user.id,
      deviceId: live.device.id,
      sessionId: live.session.id,
      ip: clientIp(req),
    });

    res.json(heartbeatResponse(session, live.user, live.device, config));
  }));

  // ---------------------------------------------------------------------
  // Logout
  // ---------------------------------------------------------------------
  app.post('/api/auth/session/logout', asyncHandler(async (req, res) => {
    const body = parseBody(req);
    const input = validateSessionBody(body, 'logout');
    const live = await loadLiveSession(store, req, body, config);

    if (live.session.id !== input.sessionId) {
      fail(401, 'invalid_session', 'The session ID does not match the token.');
    }

    await verifyProof(
      store,
      req,
      input,
      'session',
      live.device.publicKey,
      config,
    );

    await store.revokeSession(live.session.id);
    await store.audit({
      event: 'logout',
      userId: live.user.id,
      deviceId: live.device.id,
      sessionId: live.session.id,
      ip: clientIp(req),
    });

    res.json({ status: 'logged_out', session_id: live.session.id });
  }));

  // ---------------------------------------------------------------------
  // Admin
  // ---------------------------------------------------------------------
  function requireAdmin(req, res, next) {
    if (!config.adminToken) {
      return res.status(503).json({
        error: 'admin_disabled',
        message: 'Admin API is disabled. Set ADMIN_TOKEN on the server.',
      });
    }
    const authorization = headerValue(req, 'authorization');
    const token = authorization.toLowerCase().startsWith('bearer ')
      ? authorization.slice(7).trim()
      : '';
    if (!token || !safeEqual(token, config.adminToken)) {
      return res.status(401).json({
        error: 'unauthorized',
        message: 'A valid admin token is required.',
      });
    }
    return next();
  }

  app.post('/api/admin/users', requireAdmin, asyncHandler(async (req, res) => {
    const body = parseBody(req);
    const usernameError = validateUsername(body.username);
    if (usernameError) fail(400, 'invalid_username', usernameError);
    const passwordError = validatePassword(body.password);
    if (passwordError) fail(400, 'invalid_password', passwordError);
    const lockError = validateLock(body.lock);
    if (lockError) fail(400, 'invalid_lock', lockError);

    const username = body.username.trim().toLowerCase();
    const user = await store.createUser({
      id: uuid(),
      username,
      passwordHash: await hashPassword(body.password),
      lockHash: body.lock ? await hashPassword(body.lock) : null,
      disabled: false,
    });
    await store.audit({
      event: 'admin_create_user',
      userId: user.id,
      ip: clientIp(req),
      detail: { username: user.username },
    });
    res.status(201).json({
      user: {
        id: user.id,
        username: user.username,
        disabled: user.disabled,
        createdAt: user.createdAt,
      },
    });
  }));

  app.get('/api/admin/users', requireAdmin, asyncHandler(async (req, res) => {
    const users = await store.listUsers();
    res.json({
      users: users.map((user) => ({
        id: user.id,
        username: user.username,
        disabled: user.disabled,
        createdAt: user.createdAt,
        deviceCount: user.deviceCount,
        sessionCount: user.sessionCount,
      })),
    });
  }));

  app.post('/api/admin/users/:username/disable', requireAdmin, asyncHandler(async (req, res) => {
    const username = String(req.params.username || '').toLowerCase();
    const user = await store.findUserByUsername(username);
    if (!user) fail(404, 'user_not_found', 'User not found.');
    const disabled = req.body && req.body.disabled !== undefined
      ? Boolean(req.body.disabled)
      : true;
    const updated = await store.setUserDisabled(user.id, disabled);
    if (disabled) await store.revokeSessionsForUser(user.id);
    await store.audit({
      event: disabled ? 'admin_disable_user' : 'admin_enable_user',
      userId: user.id,
      ip: clientIp(req),
    });
    res.json({ user: { id: updated.id, username: updated.username, disabled: updated.disabled } });
  }));

  app.post('/api/admin/users/:username/password', requireAdmin, asyncHandler(async (req, res) => {
    const username = String(req.params.username || '').toLowerCase();
    const user = await store.findUserByUsername(username);
    if (!user) fail(404, 'user_not_found', 'User not found.');
    const body = parseBody(req);
    const passwordError = validatePassword(body.password);
    if (passwordError) fail(400, 'invalid_password', passwordError);
    const lockError = validateLock(body.lock);
    if (lockError) fail(400, 'invalid_lock', lockError);

    await store.setUserPassword(
      user.id,
      await hashPassword(body.password),
      body.lock ? await hashPassword(body.lock) : null,
    );
    await store.revokeSessionsForUser(user.id);
    await store.audit({
      event: 'admin_reset_password',
      userId: user.id,
      ip: clientIp(req),
    });
    res.json({ status: 'updated', username: user.username });
  }));

  app.post('/api/admin/devices/:deviceId/revoke', requireAdmin, asyncHandler(async (req, res) => {
    const device = await store.findDeviceById(req.params.deviceId);
    if (!device) fail(404, 'device_not_found', 'Device not found.');
    await store.setDeviceRevoked(device.id, true);
    await store.revokeSessionsForDevice(device.id);
    await store.audit({
      event: 'admin_revoke_device',
      userId: device.userId,
      deviceId: device.id,
      ip: clientIp(req),
    });
    res.json({ status: 'revoked', device_id: device.id });
  }));

  app.post('/api/admin/sessions/:sessionId/revoke', requireAdmin, asyncHandler(async (req, res) => {
    const session = await store.findSessionById(req.params.sessionId);
    if (!session) fail(404, 'session_not_found', 'Session not found.');
    await store.revokeSession(session.id);
    await store.audit({
      event: 'admin_revoke_session',
      userId: session.userId,
      deviceId: session.deviceId,
      sessionId: session.id,
      ip: clientIp(req),
    });
    res.json({ status: 'revoked', session_id: session.id });
  }));

  app.get('/api/admin/sessions', requireAdmin, asyncHandler(async (req, res) => {
    const username = typeof req.query.username === 'string'
      ? req.query.username.trim().toLowerCase()
      : '';
    if (!username) fail(400, 'username_required', 'A username query parameter is required.');
    const user = await store.findUserByUsername(username);
    if (!user) fail(404, 'user_not_found', 'User not found.');
    const sessions = await store.listSessionsForUser(user.id);
    res.json({
      username: user.username,
      sessions: sessions.map((session) => ({
        id: session.id,
        deviceId: session.deviceId,
        createdAt: session.createdAt,
        expiresAt: session.expiresAt,
        lastSeenAt: session.lastSeenAt,
        revoked: session.revoked,
        ip: session.ip,
      })),
    });
  }));

  app.get('/api/admin/audit', requireAdmin, asyncHandler(async (req, res) => {
    const limit = Number.parseInt(req.query.limit, 10) || 100;
    const entries = await store.listAudit(limit);
    res.json({ entries });
  }));

  app.use((req, res) => {
    res.status(404).json({ error: 'not_found', message: 'Endpoint not found.' });
  });

  app.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    if (error.type === 'entity.parse.failed') {
      return res.status(400).json({
        error: 'invalid_json',
        message: 'The request body is not valid JSON.',
      });
    }
    if (error.status) {
      return res.status(error.status).json({
        error: error.code || 'error',
        message: error.message,
      });
    }
    console.error('[ziva-auth] unhandled error', error);
    return res.status(500).json({
      error: 'server_error',
      message: 'The authentication service encountered an internal error.',
    });
  });

  app.locals.store = store;
  app.locals.config = config;
  return app;
}

module.exports = { createApp };
