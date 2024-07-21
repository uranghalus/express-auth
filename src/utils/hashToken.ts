import * as crypto from 'crypto';

function hashToken(token: any) {
  return crypto.createHash('sha256').update(token).digest('hex');
}
export { hashToken };
