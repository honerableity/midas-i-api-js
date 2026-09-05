/**
 * api/callback.js -- GET /api/callback
 *
 * Roblox redirects here after the user approves (or denies) the OAuth
 * consent screen for /verify. Lives next to your existing
 * /api/validate.js on the same Vercel deployment, so the redirect_uri
 * registered in the Roblox Creator Dashboard just points at this route
 * and no separate hosting/domain/TLS setup is needed.
 *
 * This file only talks to Roblox + Firestore. It never touches the
 * Discord bot token or gateway -- role assignment happens back on the
 * bot process when the user clicks "I've authorized" in Discord (see
 * commands/verify.py::_finish_verification), because that's the side
 * that actually holds a live discord.Client/guild cache.
 *
 * NOTE: swap the `db` import below for however /api/validate.js already
 * gets its initialized Firestore instance -- this assumes a shared
 * lib/firebase.js exporting `db`, same as the rest of api/.
 */
const { db } = require('../lib/firebase');
const { verifyState } = require('./_state');

const ROBLOX_TOKEN_URL = 'https://apis.roblox.com/oauth/v1/token';
const ROBLOX_USERINFO_URL = 'https://apis.roblox.com/oauth/v1/userinfo';

const ROBLOX_CLIENT_ID = process.env.ROBLOX_OAUTH_CLIENT_ID;
const ROBLOX_CLIENT_SECRET = process.env.ROBLOX_OAUTH_CLIENT_SECRET;
const ROBLOX_REDIRECT_URI = process.env.ROBLOX_OAUTH_REDIRECT_URI;

function errorPage(title, message) {
  return `<!doctype html><html><body style="font-family:sans-serif;text-align:center;padding:4rem">
<h2>${title}</h2><p>${message}</p><p>You can close this tab and go back to Discord.</p></body></html>`;
}

function successPage(username) {
  return `<!doctype html><html><body style="font-family:sans-serif;text-align:center;padding:4rem">
<h2>You're verified as ${username}!</h2>
<p>Go back to Discord and click <b>I've authorized</b> to get your role.</p></body></html>`;
}

module.exports = async (req, res) => {
  const { error, state, code } = req.query;

  if (error) {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(200).send(errorPage(
      'Verification cancelled',
      'You declined the Roblox authorization request. Run /verify start again if you change your mind.',
    ));
  }

  if (!state || !code) {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(400).send(errorPage('Bad request', 'Missing code or state.'));
  }

  const payload = verifyState(state);
  if (!payload) {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(400).send(errorPage(
      'Link expired or invalid',
      'This verification link is no longer valid. Run /verify start again in Discord.',
    ));
  }

  const { discordId } = payload;

  const sessionRef = db.collection('verifications').doc(discordId);
  const sessionSnap = await sessionRef.get();
  if (!sessionSnap.exists || sessionSnap.data().state !== state) {
    // Stale/replayed state -- the doc was cleared or superseded by a
    // newer /verify start since this link was issued.
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(400).send(errorPage(
      'Link expired or invalid',
      'This verification link is no longer valid. Run /verify start again in Discord.',
    ));
  }

  let tokenJson;
  try {
    const tokenRes = await fetch(ROBLOX_TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: ROBLOX_REDIRECT_URI,
        client_id: ROBLOX_CLIENT_ID,
        client_secret: ROBLOX_CLIENT_SECRET,
      }),
    });
    if (!tokenRes.ok) throw new Error(`token exchange failed: ${tokenRes.status}`);
    tokenJson = await tokenRes.json();
  } catch (err) {
    console.error('Roblox token exchange error:', err);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(502).send(errorPage('Roblox error', 'Could not exchange the authorization code. Try /verify start again.'));
  }

  let userinfo;
  try {
    const userinfoRes = await fetch(ROBLOX_USERINFO_URL, {
      headers: { Authorization: `Bearer ${tokenJson.access_token}` },
    });
    if (!userinfoRes.ok) throw new Error(`userinfo fetch failed: ${userinfoRes.status}`);
    userinfo = await userinfoRes.json();
  } catch (err) {
    console.error('Roblox userinfo error:', err);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(502).send(errorPage('Roblox error', 'Could not fetch your Roblox profile. Try /verify start again.'));
  }

  const robloxId = userinfo.sub;
  const robloxUsername = userinfo.preferred_username || userinfo.nickname;

  await sessionRef.set({
    status: 'authorized',
    robloxId,
    robloxUsername,
  }, { merge: true });

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res.status(200).send(successPage(robloxUsername));
}; 
