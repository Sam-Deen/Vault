import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

export class DocumentEncryption {
  #masterKey;

  constructor(masterKey = process.env.DOCUMENT_MASTER_KEY) {
    if (typeof masterKey !== 'string' || !/^[0-9a-f]{64}$/i.test(masterKey)) {
      throw new Error('DOCUMENT_MASTER_KEY must contain exactly 64 hexadecimal characters (32 bytes)');
    }
    this.#masterKey = Buffer.from(masterKey, 'hex');
  }

  encrypt(content, context) {
    if (typeof content !== 'string') throw new TypeError('Document content must be a string');
    const key = randomBytes(32);
    try {
      const document = seal(Buffer.from(content, 'utf8'), key, aad(context, 'content'));
      const wrapped = seal(key, this.#masterKey, aad(context, 'key'));
      return {
        content: document.ciphertext, iv: document.iv, authTag: document.authTag,
        wrappedKey: wrapped.ciphertext, keyIv: wrapped.iv, keyAuthTag: wrapped.authTag,
      };
    } finally {
      key.fill(0);
    }
  }

  decrypt(document, wrapped) {
    let key;
    try {
      if (!wrapped) throw new Error('Missing document key');
      key = unseal(wrapped.wrappedKey, wrapped.iv, wrapped.authTag, this.#masterKey, aad(document, 'key'));
      if (key.length !== 32) throw new Error('Invalid document key');
      return unseal(document.content, document.iv, document.authTag, key, aad(document, 'content')).toString('utf8');
    } catch {
      throw new Error('Document authentication failed');
    } finally {
      key?.fill(0);
    }
  }
}

function aad({ id, organizationId, version }, purpose) {
  if (![id, organizationId, version].every(value => Number.isSafeInteger(value) && value > 0)) {
    throw new Error('Invalid document encryption context');
  }
  return Buffer.from(JSON.stringify(['vault', id, organizationId, version, purpose]));
}

function seal(plaintext, key, context) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  cipher.setAAD(context);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    ciphertext: ciphertext.toString('base64'),
    iv: iv.toString('base64'),
    authTag: cipher.getAuthTag().toString('base64'),
  };
}

function unseal(content, iv, tag, key, context) {
  const decipher = createDecipheriv('aes-256-gcm', key, decode(iv, 12), { authTagLength: 16 });
  decipher.setAAD(context);
  decipher.setAuthTag(decode(tag, 16));
  return Buffer.concat([decipher.update(decode(content)), decipher.final()]);
}

function decode(value, length) {
  if (typeof value !== 'string') throw new Error('Invalid encrypted document');
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value || (length !== undefined && bytes.length !== length)) {
    throw new Error('Invalid encrypted document');
  }
  return bytes;
}
