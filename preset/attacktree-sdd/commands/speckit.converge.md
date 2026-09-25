---
description: "AttackTree companion: inventory CR-### and defer evidence judgment to AttackTree converge"
strategy: append
---

## AttackTree: Control Requirements in Convergence

When `spec.md` contains `CR-###` requirements or `FEATURE_DIR/attack-tree.yaml` exists:

- Include every `CR-###` in the intent inventory alongside `FR-###` and `SC-###`.
- Do not judge whether a `CR-###` is satisfied from task checkboxes, control statuses, or code comments. If `FEATURE_DIR/security/attacktree-convergence-report.json` exists and is newer than the last change to `tasks.md`, take each requirement's verdict from it (`verified` means met; anything else is unmet). Otherwise, recommend running `__SPECKIT_COMMAND_ATTACKTREE_CONVERGE__` first and treat unverified `CR-###` as unmet.
- When AttackTree has already appended a `## Phase N: Control Convergence` section to `tasks.md` for the same gaps, do not duplicate those tasks; reference them instead.
- Trace any convergence task you append for a `CR-###` with the `[CR-###]` tag so AttackTree can find it.
