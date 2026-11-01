import { HttpError } from './http-error.js';
import { verifyPassword } from './passwords.js';

export function authenticate(repository) {
  return (req, res, next) => {
    const match = /^Basic\s+(\S+)$/i.exec(req.get('authorization') ?? '');
    if (match) {
      const credentials = Buffer.from(match[1], 'base64').toString('utf8');
      const colon = credentials.indexOf(':');
      if (colon >= 0) {
        const user = repository.findUserByUsername(credentials.slice(0, colon));
        if (user && verifyPassword(credentials.slice(colon + 1), user.passwordHash)) {
          req.user = user;
          return next();
        }
      }
    }
    res.set('WWW-Authenticate', 'Basic realm="Vault"');
    next(new HttpError(401, 'Authentication required'));
  };
}
