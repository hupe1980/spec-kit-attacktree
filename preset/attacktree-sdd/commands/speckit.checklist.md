---
description: "AttackTree companion: offer a security-controls checklist built from CR acceptance criteria and control validation steps"
strategy: append
---

## AttackTree: Security Controls Checklist Type

If the user asks for a `security` or `controls` checklist (or the feature has `CR-###` requirements and no checklist type was specified, offer it):

- Source items from `FEATURE_DIR/attack-tree.yaml`: one item per `CR-###` acceptance scenario ("Is the Given/When/Then scenario for CR-002 covered by a test? [Completeness, Spec §CR-002]"), one item per control validation step ("Has 'publish a document containing an instruction to open a ticket' been executed as a micro attack simulation and its bypass rate recorded? [Traceability, attack-tree.yaml#control.untrusted-context-delimiting]"), one item per uncovered choke point or single point of failure from `FEATURE_DIR/security/attacktree-simulation.md` ("Does goal.exfiltrate-documents have a second, independent control on its most likely path? [Risk, attack-tree.yaml#goal.exfiltrate-documents]"), and one item per open goal without a decision at blocking residual risk.
- Keep the checklist's purpose: it validates that the control requirements are complete, unambiguous, and traceable; it does not execute tests or simulations.
- Name the file `checklists/security.md`.
