# Task 8 report

Implemented role-aware embedded usage scopes in the Keeper web dashboard.

- `user` sessions use only Overview and Analysis, with a shared opaque API-key selection.
- Embedded administrators receive dependent user/key selectors only on Analysis; selecting All users leaves the key selection empty and disabled.
- Scope requests abort on selection changes, surface stale/error states, and persist only opaque catalog IDs.
- Overview, Activity, Realtime, Analysis, and Latency requests carry the selected opaque scope.
- Embedded unauthenticated sessions show “Open Usage from Open WebUI” instead of login controls.

Validation completed:

- `npm test`
- `npm run lint`
- `npm run typecheck`

## Review fix round 1

- Admin “All users” now clears `keyCatalogId` immediately in rendered and persisted scope state, so no `key_catalog_id` is appended to scoped requests after a restored session or a selector reset.
- A user restored directly on `/key-ranking` is rendered as Overview before route-normalization effects run. The ranking page therefore cannot mount or start ranking API work for that role.
- Added regressions for restored All-user scope persistence/query sanitization and direct user-ranking route guarding.
