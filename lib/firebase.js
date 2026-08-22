// Firestore bootstrap for Vercel serverless functions.
//
// Reuses the SAME Firebase project as the Discord bot (utils/firebase.py),
// so writes made by Discord commands (/product whitelist add,
// /verify linkgroup) are immediately visible here, and vice versa.
//
// Vercel env vars required (Project Settings -> Environment Variables):
//   FIREBASE_PROJECT_ID
//   FIREBASE_CLIENT_EMAIL
//   FIREBASE_PRIVATE_KEY   <- paste with literal \n escaped, see note below
//
// These three come from the same serviceAccountKey.json the bot uses
// (project_id, client_email, private_key fields). Don't upload the raw
// JSON file to Vercel; env vars keep the key out of the deployed bundle.
//
// Private key gotcha: Vercel's dashboard stores the value as a single-line
// string, so newlines in the PEM key arrive as literal "\n" chars instead
// of real line breaks. We swap them back below -- if you forget this,
// firebase-admin throws "Failed to parse private key" at cold start.

const admin = require('firebase-admin');

function getDb() {
  if (!admin.apps.length) {
    const projectId = process.env.FIREBASE_PROJECT_ID;
    const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
    const privateKey = (process.env.FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n');

    if (!projectId || !clientEmail || !privateKey) {
      throw new Error(
        'Missing FIREBASE_PROJECT_ID / FIREBASE_CLIENT_EMAIL / FIREBASE_PRIVATE_KEY env vars.'
      );
    }

    admin.initializeApp({
      credential: admin.credential.cert({ projectId, clientEmail, privateKey }),
    });
  }
  return admin.firestore();
}

module.exports = { getDb, admin };
