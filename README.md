# MIDAS Product Validation API (Vercel)

Serverless API that lets Roblox Studio / a live Roblox game ask: **"is this
Roblox user allowed to use this product in this place?"** It shares the same
Firestore project as the `midas-i-py` Discord bot.

## Why this exists

The bot's original product system (`utils/products.py`) only tracks
ownership: `products/{id}.owners = [discordId, ...]`. That's flat -- a
developer who owns a product could use it in *any* place, which isn't what
you want for shop products meant to be scoped per-project.

This adds a second layer on top of ownership: **place-scoped whitelisting**.

## Access model

A verified developer can use `productId` in `placeId` if **either**:

1. **Explicit whitelist** -- an admin ran
   `/product whitelist add @dev <productId> <placeId>` in Discord. Stored at
   `productWhitelists/{productId}_{discordId}.placeIds = [placeId, ...]`.

2. **Linked group** -- the product was whitelisted to a *group* via
   `/product groupwhitelist add <productId> <groupId>`
   (`productGroupWhitelists/{productId}_{groupId}`), the developer ran
   `/verify linkgroup <groupId>` to link that group to their account
   (`verifiedUsers/{discordId}.linkedGroupIds`), the place's universe is
   owned by that same group, **and** the developer is *currently* still a
   member of the group.

   Membership is checked live against the Roblox groups API on every single
   `/api/validate` call -- nothing is cached. Leave the group and access to
   its places is gone on the very next check, no delay.

If a developer got a product from somewhere else (not whitelisted to them
or their linked group for that place), `/api/validate` returns
`allowed: false`, even though they might technically "own" the product in
the bot's ownership sense.

## New Discord commands (added to midas-i-py)

- `/product whitelist add|remove @user <product_uuid> <place_id>` (admin)
- `/product groupwhitelist add|remove <product_uuid> <group_id>` (admin)
- `/verify linkgroup <group_id>` (any verified user -- fails if they aren't
  currently a member of that group)
- `/verify unlinkgroup <group_id>`

## Endpoint

```
GET /api/validate?productId=X&placeId=Y&robloxUserId=Z&key=API_VALIDATE_KEY
```

Response:
```json
{ "allowed": true, "via": "explicit_whitelist" }
{ "allowed": true, "via": "linked_group", "groupId": "123456" }
{ "allowed": false, "reason": "not_whitelisted_for_place" }
```

Reason codes: `bad_api_key`, `missing_params`, `product_not_found`,
`user_not_verified`, `group_membership_lost`, `not_whitelisted_for_place`.

## Deploy

1. `npm install` (just `firebase-admin`).
2. `vercel` (or connect the repo in the Vercel dashboard).
3. Set env vars from `.env.example` in Vercel Project Settings -- pull the
   three Firebase values from the **same** `serviceAccountKey.json` the bot
   uses, and pick your own `API_VALIDATE_KEY`.
4. Bake the same `API_VALIDATE_KEY` into whatever calls this from Roblox
   (see `luau-example/ProductValidator.luau`).

## Calling it from Roblox

See `luau-example/ProductValidator.luau`. In Studio, a plugin needs HTTP
requests enabled (Game Settings > Security, or plugin-side HttpService is
usually allowed by default depending on your plugin security model); in a
live game, `HttpService.HttpEnabled` must be on.

## Firestore collections touched

- `products` (read only -- existence check)
- `verifiedUsers` (read -- robloxId -> discordId, linkedGroupIds)
- `productWhitelists` (read -- explicit per-place grants)
- `productGroupWhitelists` (read -- group-level product grants)

None of these are written by this API -- all writes happen from the Discord
bot's slash commands, keeping a single source of truth.
