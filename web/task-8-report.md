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
