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
 * Discord (commands/verify.py + utils/verify_listener.py) -- this
 * route never touches the bot token/gateway, it only ever writes
 * Firestore docs.
 *
 * ALT-ACCOUNT FLAGGING (added):
 * On every successful OAuth callback, this route records the caller's
 * IP + a coarse User-Agent fingerprint into
 * verificationFingerprints/{discordId}, checks the IP against
 * proxycheck.io, and cross-references it against every OTHER
 * discordId in that collection whose account is currently verified.
 * A match doesn't block or kick anyone automatically -- it posts an
 * embed to the mod-log channel for a human to review and act on via
 * buttons (handled bot-side, see commands/altcheck.py).
 *
 * IMPORTANT CAVEAT (tell the user, don't just silently build this):
 * IP address is a weak signal on its own -- campus wifi, mobile carrier
 * CGNAT, and shared home networks routinely put unrelated people behind
 * the same public IP. That's exactly why this only flags for manual
 * review instead of auto-kicking.
 *
 * DIAGNOSTIC LOGGING: console.error() calls remain at each failure
 * branch so Vercel logs show exactly which check failed. Safe to trim
 * later -- none of them log secrets, codes, or full state/tokens.
 */
const { getDb, admin } = require('../lib/firebase');
const { verifyState } = require('./_state');

const DISCORD_TOKEN_URL = 'https://discord.com/api/oauth2/token';
const DISCORD_USER_URL = 'https://discord.com/api/users/@me';
const PROXYCHECK_URL = 'https://proxycheck.io/v2';

const DISCORD_CLIENT_ID = process.env.DISCORD_OAUTH_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_OAUTH_CLIENT_SECRET;
const DISCORD_REDIRECT_URI = process.env.DISCORD_OAUTH_REDIRECT_URI;
const PROXYCHECK_API_KEY = process.env.PROXYCHECK_API_KEY;

function errorPage(title, message) {
  return `<!doctype html><html><body style="font-family:sans-serif;text-align:center;padding:4rem">
<h2>${title}</h2><p>${message}</p><p>You can close this tab and go back to Discord.</p></body></html>`;
}

function successPage() {
  return `<!doctype html><html><body style="font-family:sans-serif;text-align:center;padding:4rem">
<h2>You're authorized!</h2>
<p>Go back to Discord -- I'll DM you the server rules in just a moment.</p></body></html>`;
}

/**
 * Best-effort extraction of the caller's real IP. Vercel sits behind a
 * proxy, so req.socket's address is Vercel's edge, not the visitor --
 * x-forwarded-for is what actually carries it. When multiple proxies
 * are involved the header can contain a comma-separated chain; the
 * FIRST entry is the original client.
 */
function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) {
    return String(xff).split(',')[0].trim();
  }
  return req.socket && req.socket.remoteAddress ? req.socket.remoteAddress : null;
}

/**
 * Coarse, dependency-free fingerprint from headers alone (no client-side
 * JS run on this page, so this is intentionally weak -- it's a
 * secondary signal to corroborate an IP match, not a standalone
 * identifier). Hashing keeps the stored value short and avoids storing
 * a raw User-Agent string per user.
 */
function computeFingerprint(req) {
  const crypto = require('crypto');
  const ua = req.headers['user-agent'] || '';
  const lang = req.headers['accept-language'] || '';
  const raw = `${ua}|${lang}`;
  return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16);
}

/**
 * Queries proxycheck.io for the given IP. Returns { isProxy, proxyType }
 * or null if the check couldn't be completed (missing API key, network
 * error, rate limit, etc) -- callers must treat null as "unknown", not
 * "not a proxy".
 */
async function checkProxy(ip) {
  if (!PROXYCHECK_API_KEY || !ip) return null;

  try {
    const url = `${PROXYCHECK_URL}/${encodeURIComponent(ip)}?key=${PROXYCHECK_API_KEY}&vpn=1&asn=1`;
    const res = await fetch(url);
    if (!res.ok) {
      console.error(`[callback] proxycheck.io returned ${res.status}`);
      return null;
    }
    const data = await res.json();
    const entry = data[ip];
    if (!entry) return null;

    return {
      isProxy: entry.proxy === 'yes',
      proxyType: entry.type || null,
    };
  } catch (err) {
    console.error('[callback] proxycheck.io request failed:', err.message);
    return null;
  }
}

/**
 * Records this verification attempt's IP/fingerprint, then looks for any
 * OTHER discordId with a matching IP or fingerprint that is currently in
 * verifiedUsers. Never throws -- alt-detection is a best-effort side
 * channel and must never break the actual verification flow if Firestore
 * hiccups here.
 */
async function recordAndCheckAltAccount(db, discordId, guildId, ip, fingerprint, proxyInfo) {
  try {
    const fpRef = db.collection('verificationFingerprints').doc(discordId);
    await fpRef.set({
      ip,
      fingerprint,
      guildId,
      isProxy: proxyInfo ? proxyInfo.isProxy : null,
      proxyType: proxyInfo ? proxyInfo.proxyType : null,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    }, { merge: true });

    if (!ip && !fingerprint) return null;

    const matches = new Map(); // discordId -> { matchedOn: Set }

    if (ip) {
      const ipSnap = await db.collection('verificationFingerprints').where('ip', '==', ip).get();
      ipSnap.forEach((doc) => {
        if (doc.id === discordId) return;
        if (!matches.has(doc.id)) matches.set(doc.id, new Set());
        matches.get(doc.id).add('ip');
      });
    }

    if (fingerprint) {
      const fpSnap = await db.collection('verificationFingerprints').where('fingerprint', '==', fingerprint).get();
      fpSnap.forEach((doc) => {
        if (doc.id === discordId) return;
        if (!matches.has(doc.id)) matches.set(doc.id, new Set());
        matches.get(doc.id).add('fingerprint');
      });
    }

    if (matches.size === 0) return null;

    // Only care about matches against accounts that are CURRENTLY verified
    // -- someone who already got kicked/unverified for this isn't a
    // useful "main account" to flag against again.
    const candidateIds = Array.from(matches.keys());
    const verifiedChecks = await Promise.all(
      candidateIds.map((id) => db.collection('verifiedUsers').doc(id).get()),
    );

    const confirmedMatches = [];
    verifiedChecks.forEach((snap, i) => {
      if (snap.exists) {
        confirmedMatches.push({
          discordId: candidateIds[i],
          matchedOn: Array.from(matches.get(candidateIds[i])),
        });
      }
    });

    if (confirmedMatches.length === 0) return null;

    return { newDiscordId: discordId, guildId, ip, isProxy: proxyInfo ? proxyInfo.isProxy : null, matches: confirmedMatches };
  } catch (err) {
    console.error('[callback] recordAndCheckAltAccount failed (non-fatal):', err.message);
    return null;
  }
}

/**
 * Writes a pending review doc that the bot picks up and posts as an
 * embed with action buttons in the mod-log channel. Done this way
 * (Firestore write here, bot renders the message) for the same reason
 * the oauth_done flow works this way -- this Vercel function has no
 * access to the bot's gateway connection or token.
 */
async function flagPossibleAlt(db, altInfo) {
  try {
    await db.collection('altFlags').add({
      newDiscordId: altInfo.newDiscordId,
      guildId: altInfo.guildId,
      ipPartial: altInfo.ip ? altInfo.ip.replace(/\.\d+$/, '.xxx') : null, // last IPv4 octet masked at rest
      isProxy: altInfo.isProxy,
      matchedAccounts: altInfo.matches,
      status: 'pending',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
  } catch (err) {
    console.error('[callback] flagPossibleAlt failed (non-fatal):', err.message);
  }
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

  const { discordId, guildId } = payload;
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

  // --- Alt-account flagging (non-blocking best-effort) ---------------
  // Everything below runs AFTER the session is already marked oauth_done,
  // and none of it can fail the verification itself: recordAndCheckAltAccount
  // and flagPossibleAlt both swallow their own errors and log instead of
  // throwing, and the success page is returned regardless of the outcome.
  const ip = getClientIp(req);
  const fingerprint = computeFingerprint(req);
  const proxyInfo = await checkProxy(ip);

  if (proxyInfo && proxyInfo.isProxy) {
    console.error(`[callback] proxycheck flagged ${discordId}'s IP as proxy/VPN (type=${proxyInfo.proxyType})`);
  }

  const altInfo = await recordAndCheckAltAccount(db, discordId, guildId, ip, fingerprint, proxyInfo);
  if (altInfo) {
    console.error(`[callback] possible alt account detected for ${discordId}: matches=${JSON.stringify(altInfo.matches)}`);
    await flagPossibleAlt(db, altInfo);
  }
  // ---------------------------------------------------------------------

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res.status(200).send(successPage());
};
