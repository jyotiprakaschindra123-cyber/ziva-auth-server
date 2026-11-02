'use strict';

const { createApp } = require('./app');

const app = createApp();
const port = Number.parseInt(process.env.PORT || '3000', 10);

const server = app.listen(port, '0.0.0.0', () => {
  const storage = process.env.DATABASE_URL ? 'postgres' : 'memory';
  console.log(`[ziva-auth] listening on http://127.0.0.1:${port} (${storage})`);
  if (!process.env.DATABASE_URL) {
    console.log('[ziva-auth] no DATABASE_URL: using in-memory storage; users disappear on restart');
  }
  if (!process.env.ADMIN_TOKEN) {
    console.log('[ziva-auth] no ADMIN_TOKEN: admin endpoints are disabled');
  }
});

function shutdown(signal) {
  console.log(`[ziva-auth] ${signal}; shutting down`);
  server.close(() => {
    const store = app.locals.store;
    if (store && typeof store.close === 'function') {
      store.close().finally(() => process.exit(0));
    } else {
      process.exit(0);
    }
  });
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
