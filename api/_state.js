/**
 * api/_state.js -- shared HMAC state check, mirrored from the bot-side
 * utils/verification.py (_sign_state / verify_state). Keep both in sync:
 * same secret env var, same base64url encoding, same field names.
 */
const crypto = require('crypto');

const STATE_SECRET = process.env.VERIFY_STATE_SECRET;

function b64urlEncode(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(str) {
  const padded = str + '='.repeat((4 - (str.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function verifyState(state) {
  try {
    const dotIndex = state.indexOf('.');
    if (dotIndex === -1) return null;

    const b64 = state.slice(0, dotIndex);
    const sigB64 = state.slice(dotIndex + 1);

    const expectedSig = crypto.createHmac('sha256', STATE_SECRET).update(b64).digest();
    const expectedSigB64 = b64urlEncode(expectedSig);

    const sigBuf = Buffer.from(sigB64);
    const expectedBuf = Buffer.from(expectedSigB64);
    if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) {
      return null;
    }

    const payload = JSON.parse(b64urlDecode(b64).toString('utf8'));
    if (Date.now() > payload.expiresAt) return null;

    return payload;
  } catch (err) {
    return null;
  }
}

module.exports = { verifyState };
