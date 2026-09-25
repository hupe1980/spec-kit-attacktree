## AttackTree Check Report

Feature: `001-agent-assistant` · Tree: `attack-tree.yaml` · Enforcement: `warn`

| ID | Check | Severity | Location | Summary | Recommendation |
|---|---|---|---|---|---|
| F1 | A14 | MEDIUM | `attack-tree.yaml#node.rrd-admin-export` | Node 'node.rrd-admin-export' needs clarification: [NEEDS CLARIFICATION: can administrators or content authors export the knowledge base directly, bypassing the assistant's visibility rules?] | Resolve the question in the spec (clarify command), then re-run the model command |
| F2 | A9 | LOW | `attack-tree.yaml#requirements` | 14 requirements have no verification entry yet (implementation not started): CR-001, CR-002, CR-003, CR-004, CR-005, CR-006, CR-007, CR-008, CR-009, CR-010, CR-011, CR-012, CR-013, CR-014 | Expected before implementation; run the converge command afterwards |

**Metrics**

- goals: 6
- attack vectors: 23
- controls: 14
- requirements: 14
- requirements with tasks: 0
- requirements verified: 0
- decisions: 0
- goals by residual risk: critical 4, high 2
- controls by status: proposed 14
- findings: medium 1, low 1

**Next actions**

- Resolve HIGH findings before implementation; MEDIUM may proceed with a note.
