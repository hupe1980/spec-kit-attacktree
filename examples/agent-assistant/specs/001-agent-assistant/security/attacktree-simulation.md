## AttackTree Simulation — 001-agent-assistant

Scenario: `current` · Active controls: 0

### Goals

| Goal | Impact | Likelihood | Risk | Strongest actor | Paths | Uncontrolled | Choke points | Most likely path |
|---|---|---|---|---|---|---|---|---|
| `goal.abuse-ticket-credential` | high | 80.0 (very-high) | **critical** | actor.operator | 3 | 3 | — | `node.atc-read-config` |
| `goal.deny-service` | medium | 85.0 (very-high) | **high** | actor.employee | 2 | 2 | — | `node.ds-flood` |
| `goal.forge-ticket` | high | 55.0 (high) | **high** | actor.outsider | 5 | 5 | — | `node.ft-phish` |
| `goal.impersonate-employee` | high | 75.0 (very-high) | **critical** | actor.employee | 3 | 3 | — | `node.ie-reporter-from-text` |
| `goal.poison-answers` | high | 80.0 (very-high) | **critical** | actor.operator | 3 | 3 | — | `node.pa-store-tamper` |
| `goal.read-restricted-documents` | critical | 59.5 (high) | **critical** | actor.employee | 5 | 5 | `node.rrd-egress`, `node.rrd-reach` | `node.rrd-answer-quotes` + `node.rrd-ask-directly` |

**Blocking** (risk in critical without an unexpired decision): `goal.abuse-ticket-credential`, `goal.impersonate-employee`, `goal.poison-answers`, `goal.read-restricted-documents`

Evaluated without these open questions (needs-clarification nodes): `node.rrd-admin-export` (goal.read-restricted-documents)

### Paths — `goal.abuse-ticket-credential`

| # | Leaves | Likelihood | Cost | Feasible for | Controls on path |
|---|---|---|---|---|---|
| P1 | `node.atc-read-config` | 80.0 | 0 | actor.operator | — none — |
| P2 | `node.atc-call-beyond-scope` + `node.atc-inject-document` | 32.5 | 100 | actor.outsider | — none — |
| P3 | `node.atc-call-beyond-scope` + `node.atc-inject-question` | 30.0 | 0 | actor.employee | — none — |

Achilles heels: `node.atc-read-config` (1/3 paths), `node.atc-call-beyond-scope` (2/3 paths), `node.atc-inject-document` (1/3 paths), `node.atc-inject-question` (1/3 paths)

### Paths — `goal.deny-service`

| # | Leaves | Likelihood | Cost | Feasible for | Controls on path |
|---|---|---|---|---|---|
| P1 | `node.ds-flood` | 85.0 | 0 | actor.employee | — none — |
| P2 | `node.ds-oversized` | 80.0 | 0 | actor.employee | — none — |

Achilles heels: `node.ds-flood` (1/2 paths), `node.ds-oversized` (1/2 paths)

### Paths — `goal.forge-ticket`

| # | Leaves | Likelihood | Cost | Feasible for | Controls on path |
|---|---|---|---|---|---|
| P1 | `node.ft-phish` | 55.0 | 500 | actor.outsider | — none — |
| P2 | `node.ft-replay` | 35.0 | 0 | actor.outsider | — none — |
| P3 | `node.ft-blind-confirmation` + `node.ft-inject-document` | 32.5 | 100 | actor.outsider | — none — |
| P4 | `node.ft-inject-document` + `node.ft-no-confirmation` | 29.2 | 100 | actor.outsider | — none — |
| P5 | `node.ft-inject-question` + `node.ft-no-confirmation` | 27.0 | 0 | actor.employee | — none — |

Achilles heels: `node.ft-inject-document` (2/5 paths), `node.ft-no-confirmation` (2/5 paths), `node.ft-phish` (1/5 paths), `node.ft-replay` (1/5 paths), `node.ft-blind-confirmation` (1/5 paths)

### Paths — `goal.impersonate-employee`

| # | Leaves | Likelihood | Cost | Feasible for | Controls on path |
|---|---|---|---|---|---|
| P1 | `node.ie-reporter-from-text` | 75.0 | 0 | actor.content-author, actor.employee | — none — |
| P2 | `node.ie-session-replay` | 40.0 | 0 | actor.outsider | — none — |
| P3 | `node.ie-in-transit` | 20.0 | 20000 | actor.outsider | — none — |

Achilles heels: `node.ie-reporter-from-text` (1/3 paths), `node.ie-session-replay` (1/3 paths), `node.ie-in-transit` (1/3 paths)

### Paths — `goal.poison-answers`

| # | Leaves | Likelihood | Cost | Feasible for | Controls on path |
|---|---|---|---|---|---|
| P1 | `node.pa-store-tamper` | 80.0 | 0 | actor.operator | — none — |
| P2 | `node.pa-inject-document` | 65.0 | 100 | actor.content-author | — none — |
| P3 | `node.pa-unauthorized-publish` | 60.0 | 0 | actor.employee | — none — |

Achilles heels: `node.pa-store-tamper` (1/3 paths), `node.pa-inject-document` (1/3 paths), `node.pa-unauthorized-publish` (1/3 paths)

### Paths — `goal.read-restricted-documents`

| # | Leaves | Likelihood | Cost | Feasible for | Controls on path |
|---|---|---|---|---|---|
| P1 | `node.rrd-answer-quotes` + `node.rrd-ask-directly` | 59.5 | 0 | actor.employee | — none — |
| P2 | `node.rrd-answer-quotes` + `node.rrd-inject-question` | 51.0 | 0 | actor.employee | — none — |
| P3 | `node.rrd-ask-directly` + `node.rrd-ticket-copies` | 31.5 | 0 | actor.employee | — none — |
| P4 | `node.rrd-inject-document` + `node.rrd-ticket-copies` | 29.2 | 100 | actor.outsider | — none — |
| P5 | `node.rrd-inject-question` + `node.rrd-ticket-copies` | 27.0 | 0 | actor.employee | — none — |

Achilles heels: `node.rrd-answer-quotes` (2/5 paths), `node.rrd-ask-directly` (2/5 paths), `node.rrd-ticket-copies` (3/5 paths), `node.rrd-inject-question` (2/5 paths), `node.rrd-inject-document` (1/5 paths)

### Uncovered choke points

Every feasible path to the goal crosses this node and no control is attached to it in this scenario:

- `goal.read-restricted-documents` → `node.rrd-egress`
- `goal.read-restricted-documents` → `node.rrd-reach`

### What-if: inactive controls

Risk reduction lowers a goal's best path; depth reduction cuts alternative paths the attacker would take once the best one is closed.

| Rank | Control | Status | Cost | Risk reduction | Depth reduction | Efficiency | Class | Goals |
|---|---|---|---|---|---|---|---|---|
| 1 | `control.visibility-filtered-retrieval` | proposed | medium | 4.76 | 15.86 | 1.5867 | quick win | `goal.read-restricted-documents` |
| 2 | `control.reporter-from-session` | proposed | low | 1.4 | 3.0 | 1.4 | quick win | `goal.impersonate-employee` |
| 3 | `control.rate-and-size-limits` | proposed | low | 1.36 | 2.64 | 1.36 | quick win | `goal.deny-service` |
| 4 | `control.validate-sso-per-request` | proposed | low | 0.9 | 4.16 | 0.9 | fill-in | `goal.forge-ticket` |
| 5 | `control.ticket-audit-record` | proposed | low | 0.55 | 1.788 | 0.55 | fill-in | `goal.forge-ticket` |
| 6 | `control.secrets-manager` | proposed | medium | 1.6 | 1.6 | 0.5333 | quick win | `goal.abuse-ticket-credential` |
| 7 | `control.least-privilege-kb-storage` | proposed | medium | 0.6 | 2.56 | 0.2 | fill-in | `goal.poison-answers` |
| 8 | `control.ticket-confirmation` | proposed | low | 0.0 | 7.416 | 0.0 | defence in depth | `goal.forge-ticket`, `goal.read-restricted-documents` |
| 9 | `control.untrusted-context-delimiting` | proposed | medium | 0.0 | 7.315 | 0.0 | defence in depth | `goal.abuse-ticket-credential`, `goal.forge-ticket`, `goal.read-restricted-documents` |
| 10 | `control.confirmation-shows-exact-fields` | proposed | low | 0.0 | 4.16 | 0.0 | defence in depth | `goal.forge-ticket`, `goal.read-restricted-documents` |
| 11 | `control.ticket-tool-least-privilege` | proposed | medium | 0.0 | 2.5 | 0.0 | defence in depth | `goal.abuse-ticket-credential` |
| 12 | `control.author-only-publish` | proposed | low | 0.0 | 1.92 | 0.0 | defence in depth | `goal.poison-answers` |
| 13 | `control.tls-everywhere` | proposed | low | 0.0 | 0.8 | 0.0 | defence in depth | `goal.impersonate-employee` |
| 14 | `control.corpus-validation` | proposed | medium | 0.0 | 0.65 | 0.0 | defence in depth | `goal.poison-answers` |

### Roadmap (greedy, most risk reduction per cost first)

| Step | Control | Risk reduction | Residual risk per goal |
|---|---|---|---|
| 1 | `control.visibility-filtered-retrieval` | 4.76 | goal.abuse-ticket-credential 80.0 (critical), goal.deny-service 85.0 (high), goal.forge-ticket 55.0 (high), goal.impersonate-employee 75.0 (critical), goal.poison-answers 80.0 (critical), goal.read-restricted-documents 0.0 (high) |
| 2 | `control.reporter-from-session` | 1.4 | goal.abuse-ticket-credential 80.0 (critical), goal.deny-service 85.0 (high), goal.forge-ticket 55.0 (high), goal.impersonate-employee 40.0 (high), goal.poison-answers 80.0 (critical), goal.read-restricted-documents 0.0 (high) |
| 3 | `control.validate-sso-per-request` | 1.7 | goal.abuse-ticket-credential 80.0 (critical), goal.deny-service 85.0 (high), goal.forge-ticket 32.5 (medium), goal.impersonate-employee 20.0 (medium), goal.poison-answers 80.0 (critical), goal.read-restricted-documents 0.0 (high) |
| 4 | `control.rate-and-size-limits` | 1.36 | goal.abuse-ticket-credential 80.0 (critical), goal.deny-service 17.0 (medium), goal.forge-ticket 32.5 (medium), goal.impersonate-employee 20.0 (medium), goal.poison-answers 80.0 (critical), goal.read-restricted-documents 0.0 (high) |
| 5 | `control.secrets-manager` | 1.6 | goal.abuse-ticket-credential 40.0 (high), goal.deny-service 17.0 (medium), goal.forge-ticket 32.5 (medium), goal.impersonate-employee 20.0 (medium), goal.poison-answers 80.0 (critical), goal.read-restricted-documents 0.0 (high) |
| 6 | `control.ticket-audit-record` | 0.325 | goal.abuse-ticket-credential 40.0 (high), goal.deny-service 17.0 (medium), goal.forge-ticket 24.4 (medium), goal.impersonate-employee 20.0 (medium), goal.poison-answers 80.0 (critical), goal.read-restricted-documents 0.0 (high) |
| 7 | `control.least-privilege-kb-storage` | 0.6 | goal.abuse-ticket-credential 40.0 (high), goal.deny-service 17.0 (medium), goal.forge-ticket 24.4 (medium), goal.impersonate-employee 20.0 (medium), goal.poison-answers 65.0 (high), goal.read-restricted-documents 0.0 (high) |

### Monte Carlo (2000 iterations, seed 42, ±15.0 points)

| Goal | Mean | P50 | P90 | P(≥ high) | Drivers |
|---|---|---|---|---|---|
| `goal.abuse-ticket-credential` | 80.0 | 79.9 | 88.6 | 1.0 | `node.atc-read-config` (1.0), `node.ft-blind-confirmation` (0.06) |
| `goal.deny-service` | 86.5 | 86.5 | 93.3 | 1.0 | `node.ds-flood` (0.85), `node.ds-oversized` (0.35) |
| `goal.forge-ticket` | 55.0 | 54.9 | 63.6 | 1.0 | `node.ft-phish` (1.0) |
| `goal.impersonate-employee` | 74.9 | 75.1 | 83.3 | 1.0 | `node.ie-reporter-from-text` (1.0) |
| `goal.poison-answers` | 80.0 | 79.9 | 88.0 | 1.0 | `node.pa-store-tamper` (0.99), `node.ft-blind-confirmation` (0.05), `node.pa-inject-document` (0.05) |
| `goal.read-restricted-documents` | 59.8 | 59.5 | 68.3 | 1.0 | `node.rrd-ask-directly` (0.71), `node.rrd-answer-quotes` (0.64), `node.rrd-inject-question` (0.07), `node.ie-reporter-from-text` (0.06) |
