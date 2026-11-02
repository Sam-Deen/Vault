import { argon2Sync, randomBytes, timingSafeEqual } from 'node:crypto';

const options = { memory: 19456, passes: 2, parallelism: 1, tagLength: 32 };
const prefix = '$argon2id$v=19$m=19456,t=2,p=1$';

export function hashPassword(password) {
  const salt = randomBytes(16);
  const hash = argon2Sync('argon2id', { ...options, message: password, nonce: salt });
  return `${prefix}${salt.toString('base64').replace(/=+$/, '')}$${hash.toString('base64').replace(/=+$/, '')}`;
}

export function verifyPassword(password, stored) {
  if (!stored.startsWith(prefix)) return false;
  const [salt, hash] = stored.slice(prefix.length).split('$');
  const nonce = Buffer.from(salt, 'base64');
  const expected = Buffer.from(hash, 'base64');
  if (nonce.length !== 16 || expected.length !== options.tagLength) return false;
  const actual = argon2Sync('argon2id', { ...options, message: password, nonce });
  return timingSafeEqual(actual, expected);
}
