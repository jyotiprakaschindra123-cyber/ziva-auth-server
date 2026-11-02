'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const { createApp } = require('../src/app');
const { MemoryStore } = require('../src/store');
const { canonicalLogin, canonicalSession } = require('../src/crypto');

const config = {
  adminToken: 'test-admin',
  tokenPepper: 'test-pepper',
  sessionTtlMs: 60 * 60 * 1000,
  heartbeatSeconds: 60,
  maxDevices: 5,
  maxLoginFailures: 100,
  loginWindowMs: 5 * 60 * 1000,
  clockSkewSeconds: 300,
  databaseUrl: '',
  isProduction: false,
};

const store = new MemoryStore();
const app = createApp({ store, config });

let server;
let base;

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'der' },
  privateKeyEncoding: { type: 'pkcs8', format: 'der' },
});
const privateKeyObject = crypto.createPrivateKey({
  key: privateKey,
  format: 'der',
  type: 'pkcs8',
});
const deviceKey = Buffer.from(publicKey).toString('base64url');
const installationId = crypto.randomUUID();

const bobKeys = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'der' },
  privateKeyEncoding: { type: 'pkcs8', format: 'der' },
});
const bobPrivateKey = crypto.createPrivateKey({
  key: bobKeys.privateKey,
  format: 'der',
  type: 'pkcs8',
});
const bobDeviceKey = Buffer.from(bobKeys.publicKey).toString('base64url');
const bobInstallationId = crypto.randomUUID();

let sessionToken = '';
let sessionId = '';

function sign(canonical, keyObject = privateKeyObject) {
  return crypto.sign('sha256', Buffer.from(canonical, 'utf8'), {
    key: keyObject,
    padding: crypto.constants.RSA_PKCS1_PADDING,
  }).toString('base64url');
}

function proofHeaders(signature, key = deviceKey, installation = installationId) {
  return {
    'content-type': 'application/json',
    'x-ziva-protocol-version': '2',
    'x-ziva-client-version': '2.2.1',
    'x-ziva-proof-version': 'ziva-device-proof-v1',
    'x-ziva-device-key': key,
    'x-ziva-device-signature': signature,
    'x-ziva-installation-id': installation,
  };
}

function loginRequest(overrides = {}, identity = {}) {
  const installation = identity.installationId || installationId;
  const key = identity.deviceKey || deviceKey;
  const keyObject = identity.privateKeyObject || privateKeyObject;
  const body = {
    username: 'alice',
    password: 'secret123',
    lock: 123,
    device_info: {
      installation_id: installation,
      public_key: key,
      app_version: '2.2.1',
      os: 'Windows',
    },
    os_name: 'Windows',
    os_version: '10.0.19045',
    hostname: 'test-host',
    request_nonce: crypto.randomBytes(16).toString('hex'),
    request_timestamp: Math.floor(Date.now() / 1000),
    ...overrides,
  };
  const canonical = canonicalLogin({
    installationId: installation,
    username: body.username,
    nonce: body.request_nonce,
    timestamp: body.request_timestamp,
    deviceKey: key,
  });
  return {
    body,
    headers: proofHeaders(sign(canonical, keyObject), key, installation),
  };
}

function sessionRequest(session = sessionId, nonce = crypto.randomBytes(16).toString('hex')) {
  const body = {
    session_id: session,
    request_nonce: nonce,
    request_timestamp: Math.floor(Date.now() / 1000),
  };
  const canonical = canonicalSession({
    installationId,
    sessionId: session,
    nonce: body.request_nonce,
    timestamp: body.request_timestamp,
    deviceKey,
  });
  return {
    body,
    headers: {
      ...proofHeaders(sign(canonical)),
      authorization: `Bearer ${sessionToken}`,
    },
  };
}

async function api(path, { method = 'GET', body, headers = {} } = {}) {
  const response = await fetch(`${base}${path}`, {
    method,
    headers: body ? { 'content-type': 'application/json', ...headers } : headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  let parsed = text;
  try {
    parsed = JSON.parse(text);
  } catch {
    // keep text
  }
  return { status: response.status, body: parsed };
}

before(async () => {
  await new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', () => {
      base = `http://127.0.0.1:${server.address().port}`;
      resolve();
    });
  });
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
});

test('health reports memory storage', async () => {
  const result = await api('/api/health');
  assert.equal(result.status, 200);
  assert.equal(result.body.ok, true);
  assert.equal(result.body.storage, 'memory');
});

test('admin creates a user', async () => {
  const result = await api('/api/admin/users', {
    method: 'POST',
    headers: { authorization: 'Bearer test-admin' },
    body: { username: 'alice', password: 'secret123', lock: '123' },
  });
  assert.equal(result.status, 201);
  assert.equal(result.body.user.username, 'alice');
});

test('login succeeds and returns a session', async () => {
  const { body, headers } = loginRequest();
  const result = await api('/api/authenticate', { method: 'POST', body, headers });
  assert.equal(result.status, 200, JSON.stringify(result.body));
  assert.equal(result.body.status, 'active');
  assert.equal(result.body.username, 'alice');
  assert.ok(result.body.access_token);
  assert.ok(result.body.session_id);
  assert.ok(result.body.device_id);
  assert.equal(result.body.installation_id, installationId);
  sessionToken = result.body.access_token;
  sessionId = result.body.session_id;
});

test('replayed login nonce is rejected', async () => {
  const { body, headers } = loginRequest();
  const first = await api('/api/authenticate', { method: 'POST', body, headers });
  assert.equal(first.status, 200, JSON.stringify(first.body));
  const second = await api('/api/authenticate', { method: 'POST', body, headers });
  assert.equal(second.status, 409);
  assert.equal(second.body.error, 'nonce_replay');
});

test('wrong password is rejected', async () => {
  const { body, headers } = loginRequest({ password: 'wrong-password' });
  const result = await api('/api/authenticate', { method: 'POST', body, headers });
  assert.equal(result.status, 401);
  assert.equal(result.body.error, 'invalid_credentials');
});

test('device key mismatch is rejected', async () => {
  const other = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  const otherKey = Buffer.from(other.publicKey).toString('base64url');
  const body = {
    username: 'alice',
    password: 'secret123',
    lock: '123',
    request_nonce: crypto.randomBytes(16).toString('hex'),
    request_timestamp: Math.floor(Date.now() / 1000),
  };
  const canonical = canonicalLogin({
    installationId,
    username: body.username,
    nonce: body.request_nonce,
    timestamp: body.request_timestamp,
    deviceKey: otherKey,
  });
  const signature = crypto.sign('sha256', Buffer.from(canonical, 'utf8'), {
    key: crypto.createPrivateKey({ key: other.privateKey, format: 'der', type: 'pkcs8' }),
    padding: crypto.constants.RSA_PKCS1_PADDING,
  }).toString('base64url');
  const result = await api('/api/authenticate', {
    method: 'POST',
    body,
    headers: proofHeaders(signature, otherKey),
  });
  assert.equal(result.status, 403);
  assert.equal(result.body.error, 'device_key_mismatch');
});

test('heartbeat extends a valid session', async () => {
  const { body, headers } = sessionRequest();
  const result = await api('/api/auth/session/heartbeat', { method: 'POST', body, headers });
  assert.equal(result.status, 200, JSON.stringify(result.body));
  assert.equal(result.body.status, 'active');
  assert.equal(result.body.session_id, sessionId);
  assert.ok(result.body.remaining_ms > 0);
});

test('admin can revoke a session', async () => {
  const result = await api(`/api/admin/sessions/${sessionId}/revoke`, {
    method: 'POST',
    headers: { authorization: 'Bearer test-admin' },
  });
  assert.equal(result.status, 200);
  assert.equal(result.body.status, 'revoked');
});

test('revoked session heartbeat is rejected', async () => {
  const { body, headers } = sessionRequest();
  const result = await api('/api/auth/session/heartbeat', { method: 'POST', body, headers });
  assert.equal(result.status, 403);
  assert.equal(result.body.error, 'revoked');
});

test('logout revokes a fresh session', async () => {
  const login = loginRequest();
  const loggedIn = await api('/api/authenticate', {
    method: 'POST',
    body: login.body,
    headers: login.headers,
  });
  assert.equal(loggedIn.status, 200, JSON.stringify(loggedIn.body));
  sessionToken = loggedIn.body.access_token;
  sessionId = loggedIn.body.session_id;

  const logout = sessionRequest();
  const result = await api('/api/auth/session/logout', {
    method: 'POST',
    body: logout.body,
    headers: logout.headers,
  });
  assert.equal(result.status, 200);
  assert.equal(result.body.status, 'logged_out');

  const heartbeat = sessionRequest();
  const afterLogout = await api('/api/auth/session/heartbeat', {
    method: 'POST',
    body: heartbeat.body,
    headers: heartbeat.headers,
  });
  assert.equal(afterLogout.status, 403);
});

test('admin lists users and audit entries', async () => {
  const users = await api('/api/admin/users', {
    headers: { authorization: 'Bearer test-admin' },
  });
  assert.equal(users.status, 200);
  assert.ok(users.body.users.some((user) => user.username === 'alice'));

  const audit = await api('/api/admin/audit', {
    headers: { authorization: 'Bearer test-admin' },
  });
  assert.equal(audit.status, 200);
  assert.ok(audit.body.entries.length > 0);
});

test('admin API requires the token', async () => {
  const result = await api('/api/admin/users');
  assert.equal(result.status, 401);
  assert.equal(result.body.error, 'unauthorized');
});

test('empty lock sentinel -1 works for an account without a lock', async () => {
  const created = await api('/api/admin/users', {
    method: 'POST',
    headers: { authorization: 'Bearer test-admin' },
    body: { username: 'bob', password: 'secret456' },
  });
  assert.equal(created.status, 201, JSON.stringify(created.body));

  const login = loginRequest(
    { username: 'bob', password: 'secret456', lock: -1 },
    {
      installationId: bobInstallationId,
      deviceKey: bobDeviceKey,
      privateKeyObject: bobPrivateKey,
    },
  );
  const result = await api('/api/authenticate', {
    method: 'POST',
    body: login.body,
    headers: login.headers,
  });
  assert.equal(result.status, 200, JSON.stringify(result.body));
  assert.equal(result.body.username, 'bob');
});
