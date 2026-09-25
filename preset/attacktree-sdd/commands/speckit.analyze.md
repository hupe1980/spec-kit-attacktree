---
description: "AttackTree companion: inventory CR-### in the coverage analysis"
strategy: append
---

## AttackTree: Control Requirements Coverage

When `spec.md` contains `CR-###` requirements (the AttackTree-managed `### Control Requirements` block) or `FEATURE_DIR/attack-tree.yaml` exists:

- Add every `CR-###` to the requirements inventory with the same stable-key treatment as `FR-###` and `SC-###`.
- In Coverage Gaps, report each `CR-###` with zero tasks (a task counts when it carries the `[CR-###]` tag or is listed under `requirements[].tasks` in `attack-tree.yaml`). Severity: HIGH (the same as check A8 in `__SPECKIT_COMMAND_ATTACKTREE_CHECK__`).
- In Ambiguity Detection, flag `CR-###` statements without a measurable object or without a Given/When/Then acceptance scenario.
- Include `CR-###` rows in the Coverage Summary Table.
- For structural gaps inside the attack tree itself (dangling references, uncontrolled paths, expired decisions), do not re-derive them here; recommend `__SPECKIT_COMMAND_ATTACKTREE_CHECK__`, which computes them deterministically.
