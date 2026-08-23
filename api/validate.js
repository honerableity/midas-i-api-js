// GET /api/validate?productId=...&placeId=...&robloxUserId=...&key=API_KEY
//
// Called from Roblox (Studio plugin or live game via HttpService) to check
// whether a Roblox user is allowed to use a given product in a given place.
//
// Access is granted if EITHER:
//   (a) this discordId is a plain owner of the product (products.owners,
//       granted via /product give or a completed ticket order) -- this
//       grants use in ANY place, no place-scoping at all, OR
//   (b) the place's universe is owned by a Roblox group, this product has
//       been whitelisted to that group (/product groupwhitelist), this user
//       has linked that same group to their account via "/verify linkgroup",
//       AND is still (live-checked, not cached) a member of that group.
//
// If a linked group was used for the grant, losing membership removes
// access on the very next call -- there is no cached/stale "still has
// access" window.
//
// Response shape is intentionally flat/simple since this is parsed by
// Luau's HttpService:JSONDecode, not a JS client.

const { getDb } = require('../lib/firebase');
const { getPlaceGroupOwnerId, isUserInGroup } = require('../lib/roblox');

function deny(res, status, reason) {
  return res.status(status).json({ allowed: false, reason });
}

module.exports = async (req, res) => {
  if (req.method !== 'GET') {
    return deny(res, 405, 'method_not_allowed');
  }

  // Shared-secret check so randoms can't hammer this endpoint / enumerate
  // product ownership. Set API_VALIDATE_KEY in Vercel env vars and bake the
  // same value into the Studio plugin / game script that calls this.
  const expectedKey = process.env.API_VALIDATE_KEY;
  if (expectedKey && req.query.key !== expectedKey) {
    return deny(res, 401, 'bad_api_key');
  }

  const { productId, placeId, robloxUserId } = req.query;
  if (!productId || !placeId || !robloxUserId) {
    return deny(res, 400, 'missing_params');
  }

  const db = getDb();

  // 1. Product must exist.
  const productSnap = await db.collection('products').doc(String(productId)).get();
  if (!productSnap.exists) {
    return deny(res, 404, 'product_not_found');
  }
  const product = productSnap.data();

  // 2. Resolve robloxUserId -> discordId. Only verified users can own/use
  //    products -- this mirrors the bot's existing verification gate.
  //
  // robloxId in Firestore may be stored as either a number (the bot saves
  // it straight from the Roblox API's JSON int) or a string, depending on
  // when the doc was written. Try both so this doesn't silently miss users
  // whose doc happens to use the other type.
  let verifiedQuery = await db
    .collection('verifiedUsers')
    .where('robloxId', '==', String(robloxUserId))
    .limit(1)
    .get();

  if (verifiedQuery.empty) {
    const asNumber = Number(robloxUserId);
    if (!Number.isNaN(asNumber)) {
      verifiedQuery = await db
        .collection('verifiedUsers')
        .where('robloxId', '==', asNumber)
        .limit(1)
        .get();
    }
  }

  if (verifiedQuery.empty) {
    return deny(res, 403, 'user_not_verified');
  }
  const discordId = verifiedQuery.docs[0].id;
  const verifiedUser = verifiedQuery.docs[0].data();

  // 3a. Plain ownership -- no place-scoping, valid everywhere.
  const owners = (product.owners || []).map(String);
  if (owners.includes(discordId)) {
    return res.status(200).json({
      allowed: true,
      via: 'ownership',
    });
  }

  // 3b. Linked-group grant: this product must be whitelisted to the group
  //     itself (productGroupWhitelists), and the requesting place's
  //     universe must be owned by that group, and the user must currently
  //     be a member of it.
  const linkedGroupIds = (verifiedUser.linkedGroupIds || []).map(String);
  if (linkedGroupIds.length > 0) {
    const groupOwnerId = await getPlaceGroupOwnerId(placeId);
    if (groupOwnerId && linkedGroupIds.includes(groupOwnerId)) {
      const groupGrantId = `${productId}_${groupOwnerId}`;
      const groupGrantSnap = await db
        .collection('productGroupWhitelists')
        .doc(groupGrantId)
        .get();

      if (groupGrantSnap.exists) {
        const stillMember = await isUserInGroup(robloxUserId, groupOwnerId);
        if (stillMember) {
          return res.status(200).json({
            allowed: true,
            via: 'linked_group',
            groupId: groupOwnerId,
          });
        }
        return deny(res, 403, 'group_membership_lost');
      }
    }
  }

  return deny(res, 403, 'not_whitelisted');
};
