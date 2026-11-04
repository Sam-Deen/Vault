import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { parseEnv } from 'node:util';

const contents = existsSync('.env') ? readFileSync('.env', 'utf8') : '';
const configured = process.env.DOCUMENT_MASTER_KEY || parseEnv(contents).DOCUMENT_MASTER_KEY;
if (configured) {
  if (!/^[0-9a-f]{64}$/i.test(configured)) throw new Error('Existing DOCUMENT_MASTER_KEY is invalid; it was not replaced');
  console.log('DOCUMENT_MASTER_KEY is already configured; kept the existing key.');
} else {
  const line = `DOCUMENT_MASTER_KEY=${randomBytes(32).toString('hex')}`;
  const placeholder = /^(?:export\s+)?DOCUMENT_MASTER_KEY\s*=.*$/m;
  const updated = placeholder.test(contents) ? contents.replace(placeholder, line) : `${contents}${contents.endsWith('\n') || !contents ? '' : '\n'}${line}\n`;
  writeFileSync('.env', updated, { mode: 0o600 });
  console.log('Generated DOCUMENT_MASTER_KEY in the ignored .env file; keep it to reopen encrypted documents.');
}
