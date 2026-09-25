---
description: "AttackTree companion: tag tasks with [CR-###] for every control requirement"
strategy: append
---

## AttackTree: Control Requirements

If `spec.md` contains a `### Control Requirements` section (between `<!-- attacktree:begin -->` and `<!-- attacktree:end -->`) or `FEATURE_DIR/attack-tree.yaml` exists, treat every `CR-###` there as a requirement that needs buildable work:

- Generate at least one task per `CR-###` that implements the control at the touchpoints named in `attack-tree.yaml` (`controls[].touchpoints`), and one test task that implements its Given/When/Then acceptance scenario (the control's `validation` steps say what the test must exercise).
- Tag those tasks with `[CR-###]` immediately after the story tag (a task serving several requirements uses one tag with a comma list, `[CR-001, CR-003]`); only bracket tags count, a prose mention such as "CR-001 through CR-005" links nothing, e.g. `- [ ] T031 [P] [US1] [CR-002] Filter retrieval by document visibility in src/retrieval/retriever.py`.
- Order security tasks by the attack tree's roadmap when `FEATURE_DIR/security/attacktree-simulation.md` exists: controls on uncovered choke points and single points of failure first, then quick wins.
- Place control tasks in the phase of the user story they protect; put cross-cutting ones (sessions, rate limiting, egress, logging) in the Foundational phase.
- Do not invent `CR-###` ids; use only those present in the spec or tree. If a control requirement cannot be mapped to any story, add it to the Foundational phase and say so in the completion report.
