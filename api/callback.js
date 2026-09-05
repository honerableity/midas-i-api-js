/**
 * api/callback.js -- GET /api/callback
 *
 * Discord (not Roblox anymore) redirects here after the user approves
 * or denies the OAuth consent screen for /verify. Exchanges the code,
 * confirms via /users/@me that the token really belongs to the
 * discordId encoded in `state` (defense against someone pasting a
 * stolen link and authorizing with a different Discord account), then
 * flips the Firestore session to "oauth_done".
 *
 * Role assignment and the rules-agreement step both happen back in
 * Discord (commands/verify.py) -- this route never touches the bot
 * token/gateway, it only ever writes the session doc.
 *
 * DIAGNOSTIC LOGGING: temporary console.error() calls added at each
 * failure branch so Vercel logs show exactly which check failed. Safe
 * to strip once things are stable -- none of them log secrets, codes,
 * or full state/tokens.
 */
const { getDb } = require('../lib/firebase');
const { verifyState } = require('./_state');

const DISCORD_TOKEN_URL = 'https://discord.com/api/oauth2/token';
const DISCORD_USER_URL = 'https://discord.com/api/users/@me';

const DISCORD_CLIENT_ID = process.env.DISCORD_OAUTH_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_OAUTH_CLIENT_SECRET;
const DISCORD_REDIRECT_URI = process.env.DISCORD_OAUTH_REDIRECT_URI;

function errorPage(title, message) {
  return `<!doctype html><html><body style="font-family:sans-serif;text-align:center;padding:4rem">
<h2>${title}</h2><p>${message}</p><p>You can close this tab and go back to Discord.</p></body></html>`;
}

function successPage() {
  return `<!doctype html><html><body style="font-family:sans-serif;text-align:center;padding:4rem">
<h2>You're authorized!</h2>
<p>Go back to Discord and click <b>Continue</b> to accept the rules and get your role.</p></body></html>`;
}

module.exports = async (req, res) => {
  const { error, state, code } = req.query;

  let db;
  try {
    db = getDb();
  } catch (err) {
    console.error('[callback] getDb() failed -- check FIREBASE_SERVICE_ACCOUNT_B64 / FIREBASE_SERVICE_ACCOUNT env vars:', err.message);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(500).send(errorPage('Server error', 'Something went wrong on our end. Please try again shortly.'));
  }

  if (error) {
    console.error(`[callback] user declined OAuth consent: error=${error}`);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(200).send(errorPage(
      'Verification cancelled',
      'You declined the authorization request. Run /verify start again if you change your mind.',
    ));
  }

  if (!state || !code) {
    console.error(`[callback] missing state or code — state=${!!state} code=${!!code}`);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(400).send(errorPage('Bad request', 'Missing code or state.'));
  }

  const payload = verifyState(state);
  if (!payload) {
    console.error('[callback] verifyState() returned null -- signature mismatch, malformed state, or already-expired payload. Check that VERIFY_STATE_SECRET matches exactly between the bot and Vercel envs.');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(400).send(errorPage(
      'Link expired or invalid',
      'This verification link is no longer valid. Run /verify start again in Discord.',
    ));
  }

  const { discordId } = payload;
  console.error(`[callback] verifyState() OK for discordId=${discordId}, expiresAt=${payload.expiresAt}, now=${Date.now()}`);

  const sessionRef = db.collection('verifications').doc(discordId);
  const sessionSnap = await sessionRef.get();

  if (!sessionSnap.exists) {
    console.error(`[callback] no verifications/${discordId} doc in Firestore -- session was never created, already cleared, or discordId mismatch`);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(400).send(errorPage(
      'Link expired or invalid',
      'This verification link is no longer valid. Run /verify start again in Discord.',
    ));
  }

  if (sessionSnap.data().state !== state) {
    console.error(`[callback] state mismatch for discordId=${discordId} -- Firestore doc has a different/newer state than this URL. Likely caused by /verify start being re-run after this link was issued.`);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(400).send(errorPage(
      'Link expired or invalid',
      'This verification link is no longer valid. Run /verify start again in Discord.',
    ));
  }

  let tokenJson;
  try {
    const tokenRes = await fetch(DISCORD_TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: DISCORD_REDIRECT_URI,
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
      }),
    });
    if (!tokenRes.ok) throw new Error(`token exchange failed: ${tokenRes.status}`);
    tokenJson = await tokenRes.json();
  } catch (err) {
    console.error('[callback] Discord token exchange error:', err);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(502).send(errorPage('Discord error', 'Could not exchange the authorization code. Try /verify start again.'));
  }

  let discordUser;
  try {
    const userRes = await fetch(DISCORD_USER_URL, {
      headers: { Authorization: `Bearer ${tokenJson.access_token}` },
    });
    if (!userRes.ok) throw new Error(`user fetch failed: ${userRes.status}`);
    discordUser = await userRes.json();
  } catch (err) {
    console.error('[callback] Discord /users/@me error:', err);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(502).send(errorPage('Discord error', 'Could not confirm your account. Try /verify start again.'));
  }

  // The whole point of doing this OAuth roundtrip is to prove the person
  // clicking through really controls the Discord account tied to this
  // session -- if the id from /users/@me doesn't match discordId from
  // the signed state, someone forwarded/reused a link that wasn't theirs.
  if (String(discordUser.id) !== String(discordId)) {
    console.error(`[callback] account mismatch -- session was for discordId=${discordId} but OAuth token belongs to discordUser.id=${discordUser.id}`);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(403).send(errorPage(
      'Account mismatch',
      "The Discord account you authorized with doesn't match the one that started this verification. "
      + 'Run /verify start again from the account you want verified.',
    ));
  }

  await sessionRef.set({ status: 'oauth_done' }, { merge: true });
  console.error(`[callback] success -- discordId=${discordId} marked oauth_done`);

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res.status(200).send(successPage());
};
