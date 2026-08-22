// Live Roblox API lookups. No caching on purpose -- group access must be
// re-checked on every /api/validate call, so a dev who leaves a group loses
// access to that group's places immediately, not after some TTL expires.

/**
 * Resolves a Roblox placeId -> the universe's group owner id, or null if
 * the universe is owned by a solo user (not a group) or doesn't exist.
 */
async function getPlaceGroupOwnerId(placeId) {
  const placeRes = await fetch(
    `https://apis.roblox.com/universes/v1/places/${placeId}/universe`
  );
  if (!placeRes.ok) return null;
  const { universeId } = await placeRes.json();
  if (!universeId) return null;

  const gameRes = await fetch(
    `https://games.roblox.com/v1/games?universeIds=${universeId}`
  );
  if (!gameRes.ok) return null;
  const gameData = await gameRes.json();
  const game = (gameData.data || [])[0];
  if (!game || !game.creator) return null;

  // creator.type is "Group" or "User"
  if (game.creator.type !== 'Group') return null;
  return String(game.creator.id);
}

/**
 * True if robloxUserId is CURRENTLY a member of groupId. Hits the live
 * Roblox groups API every time -- see file header for why.
 */
async function isUserInGroup(robloxUserId, groupId) {
  const res = await fetch(
    `https://groups.roblox.com/v1/users/${robloxUserId}/groups/roles`
  );
  if (!res.ok) return false;
  const data = await res.json();
  const groups = data.data || [];
  return groups.some((g) => String(g.group.id) === String(groupId));
}

module.exports = { getPlaceGroupOwnerId, isUserInGroup };
