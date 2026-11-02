'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { normalizeLock, validateLock } = require('../src/crypto');

test('empty lock forms normalize to the empty string', () => {
  assert.equal(normalizeLock(undefined), '');
  assert.equal(normalizeLock(null), '');
  assert.equal(normalizeLock(''), '');
  assert.equal(normalizeLock('   '), '');
  assert.equal(normalizeLock(-1), '');
});

test('numeric locks are padded to three digits', () => {
  assert.equal(normalizeLock(0), '000');
  assert.equal(normalizeLock(7), '007');
  assert.equal(normalizeLock(12), '012');
  assert.equal(normalizeLock(123), '123');
});

test('three-digit string locks are preserved', () => {
  assert.equal(normalizeLock('012'), '012');
  assert.equal(normalizeLock(' 123 '), '123');
});

test('invalid locks are rejected', () => {
  for (const value of ['12', '1234', '-1', 1000, 1.5, true, {}, []]) {
    assert.equal(normalizeLock(value), null, `expected ${JSON.stringify(value)} to be invalid`);
    assert.equal(validateLock(value), 'Lock must be empty or exactly 3 digits.');
  }
});
