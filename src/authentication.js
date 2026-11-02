import { randomBytes } from 'node:crypto';
import { HttpError } from './http-error.js';
import { verifyPassword } from './passwords.js';

export function createAuthentication(repository) {
  const sessions = new Map();
  const lifetime = 12 * 60 * 60 * 1000;
  function issue(userId, state) {
    const token = randomBytes(32).toString('base64url');
    sessions.set(token, { userId, state, expiresAt: Date.now() + lifetime });
    return token;
  }
  function session(req) {
    const match = /^Bearer ([A-Za-z0-9_-]+)$/.exec(req.get('authorization') ?? '');
    const token = match?.[1];
    const entry = token && sessions.get(token);
    if (!entry || entry.expiresAt <= Date.now()) {
      if (token) sessions.delete(token);
      throw new HttpError(401, 'Authentication required');
    }
    return { token, entry, user: repository.findUser(entry.userId) };
  }
  return {
    login(username, password) {
      const user = typeof username === 'string' && repository.findUserByUsername(username);
      if (!user || typeof password !== 'string' || !verifyPassword(password, user.passwordHash)) {
        throw new HttpError(401, 'Invalid credentials');
      }
      return { token: issue(user.id, 'pending'), state: 'pending', enrollmentRequired: !user.totpSecret };
    },
    pending(req, res, next) {
      try {
        const current = session(req);
        if (current.entry.state !== 'pending') throw new HttpError(403, 'Pending authentication required');
        req.auth = current;
        next();
      } catch (error) { next(error); }
    },
    protected(req, res, next) {
      try {
        const current = session(req);
        if (current.entry.state !== 'authenticated') throw new HttpError(403, 'TOTP verification required');
        req.user = current.user;
        next();
      } catch (error) { next(error); }
    },
    complete(req) {
      sessions.delete(req.auth.token);
      return { token: issue(req.auth.user.id, 'authenticated'), state: 'authenticated' };
    },
  };
}
