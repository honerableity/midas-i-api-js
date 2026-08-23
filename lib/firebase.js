// Firestore bootstrap for Vercel serverless functions.
//
// Reuses the SAME Firebase project as the Discord bot (utils/firebase.py),
// so writes made by Discord commands (/product whitelist add,
// /verify linkgroup) are immediately visible here, and vice versa.
//
// Vercel env var required (Project Settings -> Environment Variables):
//   FIREBASE_SERVICE_ACCOUNT
//
// Paste the ENTIRE contents of serviceAccountKey.json as the value of that
// one env var (the same file the bot's utils/firebase.py loads from disk).
// Don't upload the raw file to Vercel -- env vars keep it out of the
// deployed bundle/git history.
//
// Fallback: if FIREBASE_SERVICE_ACCOUNT isn't set, falls back to three
// separate vars (FIREBASE_PROJECT_ID / FIREBASE_CLIENT_EMAIL /
// FIREBASE_PRIVATE_KEY) for anyone who already set those up.

const admin = require('firebase-admin');

function loadServiceAccount() {
  // Preferred: FIREBASE_SERVICE_ACCOUNT_B64 -- the ENTIRE serviceAccountKey.json,
  // base64-encoded into one line. This sidesteps dashboard editors that mangle
  // whitespace/newlines inside long JSON/PEM values (a common cause of
  // "DECODER routines::unsupported" errors from a corrupted private key).
  const b64 = process.env.FIREBASE_SERVICE_ACCOUNT_B64;
  if (b64) {
    let parsed;
    try {
      const jsonStr = Buffer.from(b64.trim(), 'base64').toString('utf8');
      parsed = JSON.parse(jsonStr);
    } catch (err) {
      throw new Error(
        `FIREBASE_SERVICE_ACCOUNT_B64 could not be decoded/parsed. Re-generate it with: base64 -w0 serviceAccountKey.json. Error: ${err.message}`
      );
    }
    return {
      projectId: parsed.project_id,
      clientEmail: parsed.client_email,
      privateKey: parsed.private_key,
    };
  }

  const raw = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (raw) {
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      throw new Error(
        `FIREBASE_SERVICE_ACCOUNT is not valid JSON -- paste the full contents of serviceAccountKey.json as-is. Parse error: ${err.message}`
      );
    }
    // Vercel's dashboard stores multi-line env values fine, but if this
    // was pasted through something that flattened newlines, the PEM key's
    // "\n" sequences can arrive as literal backslash-n. Normalize either way.
    return {
      projectId: parsed.project_id,
      clientEmail: parsed.client_email,
      privateKey: (parsed.private_key || '').replace(/\\n/g, '\n'),
    };
  }

  // Legacy fallback: three separate env vars.
  const projectId = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  const privateKey = (process.env.FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n');
  if (projectId && clientEmail && privateKey) {
    return { projectId, clientEmail, privateKey };
  }

  return null;
}

function getDb() {
  if (!admin.apps.length) {
    const creds = loadServiceAccount();
    if (!creds || !creds.projectId || !creds.clientEmail || !creds.privateKey) {
      throw new Error(
        'Missing Firebase credentials. Set FIREBASE_SERVICE_ACCOUNT to the full contents of serviceAccountKey.json.'
      );
    }

    admin.initializeApp({
      credential: admin.credential.cert(creds),
    });
  }
  return admin.firestore();
}

module.exports = { getDb, admin };
