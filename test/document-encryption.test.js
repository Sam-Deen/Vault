import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDecipheriv, randomBytes } from 'node:crypto';
import { DocumentEncryption } from '../src/document-encryption.js';

const masterKey = randomBytes(32).toString('hex');
const encryption = new DocumentEncryption(masterKey);
const context = { id: 1, organizationId: 1, version: 1 };
const wrapped = encrypted => ({ wrappedKey: encrypted.wrappedKey, iv: encrypted.keyIv, authTag: encrypted.keyAuthTag });

function unwrap(encrypted, version) {
  const decipher = createDecipheriv('aes-256-gcm', Buffer.from(masterKey, 'hex'), Buffer.from(encrypted.keyIv, 'base64'), { authTagLength: 16 });
  decipher.setAAD(Buffer.from(JSON.stringify(['vault', 1, 1, version, 'key'])));
  decipher.setAuthTag(Buffer.from(encrypted.keyAuthTag, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(encrypted.wrappedKey, 'base64')), decipher.final()]);
}

test('AES-GCM envelopes round trip Unicode and empty document contents', () => {
  for (const content of ['', 'Private notes', 'Notities: \u00e9\u00e8\u00ea \ud83d\udd12\n\u6587\u4ef6']) {
    const encrypted = encryption.encrypt(content, context);
    assert.equal(encryption.decrypt({ ...context, ...encrypted }, wrapped(encrypted)), content);
    assert.equal(Buffer.from(encrypted.iv, 'base64').length, 12);
    assert.equal(Buffer.from(encrypted.authTag, 'base64').length, 16);
    assert.equal(Buffer.from(encrypted.wrappedKey, 'base64').length, 32);
    assert.notEqual(encrypted.iv, encrypted.keyIv);
    assert.equal(JSON.stringify(encryption), '{}');
  }
});

test('each encryption and version receives an independent data key and fresh content and wrapping IVs', () => {
  const first = encryption.encrypt('Same text', context);
  const again = encryption.encrypt('Same text', context);
  const next = encryption.encrypt('Same text', { ...context, version: 2 });
  const keys = [unwrap(first, 1), unwrap(again, 1), unwrap(next, 2)];
  try {
    assert.notDeepEqual(keys[0], keys[1]);
    assert.notDeepEqual(keys[0], keys[2]);
    assert.notDeepEqual(keys[1], keys[2]);
    for (const field of ['content', 'iv', 'keyIv']) assert.equal(new Set([first[field], again[field], next[field]]).size, 3);
  } finally {
    for (const key of keys) key.fill(0);
  }
});

test('tampered ciphertext, IVs, tags, and wrapped keys fail authentication', () => {
  const encrypted = encryption.encrypt('Private notes', context);
  for (const field of ['content', 'iv', 'authTag', 'wrappedKey', 'keyIv', 'keyAuthTag']) {
    const bytes = Buffer.from(encrypted[field], 'base64');
    bytes[0] ^= 1;
    const damaged = { ...encrypted, [field]: bytes.toString('base64') };
    assert.throws(() => encryption.decrypt({ ...context, ...damaged }, wrapped(damaged)), /authentication failed/);
  }
  for (const value of ['', '!', encrypted.authTag + '!']) {
    assert.throws(() => encryption.decrypt({ ...context, ...encrypted, authTag: value }, wrapped(encrypted)), /authentication failed/);
  }
});

test('wrong master keys and swapped document, tenant, or version contexts cannot decrypt', () => {
  const encrypted = encryption.encrypt('Private notes', context);
  assert.throws(() => new DocumentEncryption(randomBytes(32).toString('hex')).decrypt({ ...context, ...encrypted }, wrapped(encrypted)), /authentication failed/);
  for (const changed of [{ id: 2 }, { organizationId: 2 }, { version: 2 }, { version: 0 }]) {
    assert.throws(() => encryption.decrypt({ ...context, ...encrypted, ...changed }, wrapped(encrypted)), /authentication failed/);
  }
  assert.throws(() => encryption.decrypt({ ...context, ...encrypted }, undefined), /authentication failed/);
});

test('master keys have an exact 32-byte hexadecimal encoding with no default key', () => {
  for (const value of ['', null, ' ', '0'.repeat(63), '0'.repeat(65), 'z'.repeat(64), Buffer.alloc(32)]) {
    assert.throws(() => new DocumentEncryption(value), /DOCUMENT_MASTER_KEY/);
  }
});
