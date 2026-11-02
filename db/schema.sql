-- Ziva Browse authentication schema (PostgreSQL 13+).
-- The server also runs this automatically on first request; this file is for
-- manual provisioning and review.

CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY,
  username text NOT NULL UNIQUE,
  password_hash text NOT NULL,
  lock_hash text,
  disabled boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS devices (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  installation_id text NOT NULL UNIQUE,
  public_key text NOT NULL,
  device_info jsonb,
  os_name text,
  os_version text,
  hostname text,
  revoked boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz
);

CREATE TABLE IF NOT EXISTS sessions (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  revoked boolean NOT NULL DEFAULT false,
  ip text,
  user_agent text
);

CREATE TABLE IF NOT EXISTS login_nonces (
  id bigserial PRIMARY KEY,
  installation_id text NOT NULL,
  nonce text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (installation_id, nonce)
);

CREATE TABLE IF NOT EXISTS login_attempts (
  id bigserial PRIMARY KEY,
  username text,
  ip text,
  success boolean NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_log (
  id bigserial PRIMARY KEY,
  event text NOT NULL,
  user_id uuid,
  device_id uuid,
  session_id uuid,
  ip text,
  detail jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_device_id ON sessions(device_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_login_attempts_created ON login_attempts(created_at);
CREATE INDEX IF NOT EXISTS idx_login_nonces_created ON login_nonces(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at);
