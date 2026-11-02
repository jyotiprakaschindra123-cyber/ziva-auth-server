'use strict';

function intEnv(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const value = Number.parseInt(raw, 10);
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

module.exports = {
  databaseUrl: process.env.DATABASE_URL || '',
  adminToken: process.env.ADMIN_TOKEN || '',
  tokenPepper: process.env.ZIVA_TOKEN_PEPPER || 'dev-only-change-me',
  sessionTtlMs: intEnv('ZIVA_SESSION_TTL_SECONDS', 8 * 60 * 60) * 1000,
  heartbeatSeconds: intEnv('ZIVA_HEARTBEAT_SECONDS', 60),
  maxDevices: intEnv('ZIVA_MAX_DEVICES', 10),
  maxLoginFailures: intEnv('ZIVA_MAX_LOGIN_FAILURES', 8),
  loginWindowMs: intEnv('ZIVA_LOGIN_WINDOW_SECONDS', 5 * 60) * 1000,
  clockSkewSeconds: intEnv('ZIVA_CLOCK_SKEW_SECONDS', 5 * 60),
  nodeEnv: process.env.NODE_ENV || 'development',
  isProduction: process.env.NODE_ENV === 'production',
};
