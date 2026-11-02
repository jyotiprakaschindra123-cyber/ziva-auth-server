'use strict';

/*
 * Create a user against the configured Postgres database.
 *
 *   DATABASE_URL=postgres://... node scripts/create-user.js alice secret123 123
 *
 * With the in-memory development store this process is separate from the
 * server, so use POST /api/admin/users instead.
 */

const { createStore } = require('../src/store');
const { hashPassword, validateUsername, validatePassword, validateLock, uuid } = require('../src/crypto');

async function main() {
  const [rawUsername, password, lock = ''] = process.argv.slice(2);
  if (!rawUsername || !password) {
    console.error('Usage: node scripts/create-user.js <username> <password> [3-digit-lock]');
    process.exit(2);
  }

  const username = rawUsername.trim().toLowerCase();
  const usernameError = validateUsername(username);
  const passwordError = validatePassword(password);
  const lockError = validateLock(lock);
  if (usernameError || passwordError || lockError) {
    console.error(usernameError || passwordError || lockError);
    process.exit(2);
  }

  const store = createStore(process.env.DATABASE_URL || '');
  if (!process.env.DATABASE_URL) {
    console.error('DATABASE_URL is required for this CLI. Use POST /api/admin/users for the memory store.');
    process.exit(2);
  }

  await store.init();
  try {
    const user = await store.createUser({
      id: uuid(),
      username,
      passwordHash: await hashPassword(password),
      lockHash: lock ? await hashPassword(lock) : null,
      disabled: false,
    });
    console.log(`created ${user.username} (${user.id})`);
  } finally {
    await store.close();
  }
}

main().catch((error) => {
  console.error(error.message || error);
  process.exit(1);
});
