# Configuration reference

AttackTree reads one configuration object per repository. Every key is optional; the engine falls back to a documented default for each. `config-template.yml` at the repository root is the annotated copy to start from.

## Where the file lives

```bash
cp .specify/extensions/attacktree/attacktree-config.template.yml \
   .specify/extensions/attacktree/attacktree-config.yml
```

`specify extension add attacktree` installs the template into `.specify/extensions/attacktree/`. Commit `attacktree-config.yml`; keep machine-specific values in `attacktree-config.local.yml`, which Spec Kit gitignores.

## Precedence

`load_config()` merges four layers, each overriding the one above it:

| # | Layer | Source |
|---|---|---|
| 1 | Extension defaults | `config.defaults` in `extension.yml` |
| 2 | Project config | `.specify/extensions/attacktree/attacktree-config.yml` |
| 3 | Local overrides | `.specify/extensions/attacktree/attacktree-config.local.yml` |
| 4 | Environment | `SPECKIT_ATTACKTREE_*` |

Merging is recursive: a mapping in a later layer is merged key by key into the earlier one. A scalar or a list is replaced outright: setting `profiles: [agentic]` discards the default `[default]` instead of appending to it. The `default` profile's scales still apply in that case; only its proposal libraries are lost.

## Environment variables

Exactly three are recognised:

| Variable | Effect |
|---|---|
| `SPECKIT_ATTACKTREE_ENFORCEMENT` | Replaces `enforcement`. |
| `SPECKIT_ATTACKTREE_PROFILES` | Replaces `profiles`; comma-separated, whitespace trimmed. |
| `SPECKIT_ATTACKTREE_SCENARIO` | Replaces `risk.scenario`. |

Other nested keys cannot be set from the environment; use the local override file.

## Keys

### `profiles`

```yaml
profiles: [default, agentic]
```

Profiles supply the scales and the proposal libraries. Default `[default]`. Each name resolves to `profiles/<name>.yaml`. The `default` profile's scales are always the base; the first active profile that declares `scales` overlays them, and every profile adds archetypes, vector and control proposals, and zones. A feature's own `attack-tree.yaml` wins over this setting: the engine reads `attacktree.profiles` from the tree first.

| Profile | Supplies |
|---|---|
| `default` | scales, Schneider's actor archetypes, 20 CAPEC-mapped vector proposals, 16 ASVS 4.0.3-mapped control proposals |
| `agentic` | five attack-surface zones, agentic archetypes, 15 vectors mapped to OWASP ASI/LLM 2026, ATLAS, MAESTRO, 16 control proposals split into deterministic and probabilistic |

### `enforcement`

```yaml
enforcement: warn   # warn | strict
```

Controls the exit code of the check command and the advice the agent gives. Default `warn`.

| Worst finding | `warn` | `strict` |
|---|---|---|
| critical | 2 | 2 |
| high | 1 | 1 |
| medium | 0 | 1 |
| low or none | 0 | 0 |

Under `strict` the check and simulate commands also state that implementation must not proceed while a CRITICAL finding or a blocking goal is open.

### `risk`

```yaml
risk:
  block_on: [critical]
  scenario: current
  max_paths: 200
```

| Key | Default | Effect |
|---|---|---|
| `block_on` | `[critical]` | Residual risk levels that make a goal "blocking": simulate exits `1`, converge does not converge, unless an unexpired decision targets the goal. |
| `scenario` | `current` | Which control statuses count as active in simulate, render, and check metrics: `none` (no control, the baseline), `current` (implemented, verified), `verified`, `planned` (planned, implemented, verified), `all` (everything not rejected). Converge always uses `verified`; check A6 always uses `all`. |
| `max_paths` | `200` | Cap on enumerated paths per node, kept per actor so every actor's most likely paths survive. Larger trees are flagged `truncated` (check A16) and choke points are computed on the sample. |

### `simulation`

```yaml
simulation:
  iterations: 2000
  seed: 42
  likelihood_spread: 15
```

| Key | Default | Effect |
|---|---|---|
| `iterations` | `2000` | Monte Carlo iterations; `0` disables the section. |
| `seed` | `42` | Random seed; identical inputs give identical results. |
| `likelihood_spread` | `15` | Points added and subtracted around each leaf likelihood when no `likelihood_range` is set; probabilistic controls are sampled ±15 % around their effect. |

`simulate --iterations N --seed N` override both for one run.

### `risk_acceptance`

```yaml
risk_acceptance:
  require_owner: true
  max_duration_days: 180
```

Governs check A10 over `decisions[]`. A decision must carry `owner`, `rationale`, and `expires`; anything missing is a **high** finding. `require_owner: false` drops `owner` from that set. `max_duration_days` caps how far ahead `expires` may sit; exceeding it is a **medium** finding. An expiry in the past, or one that is not `YYYY-MM-DD`, is **high**.

### `model`

```yaml
model:
  baseline: .specify/memory/attack-tree.yaml
  otm: ""
  write_requirements_to_spec: true
  render_markdown: true
  diagram: mermaid
```

| Key | Default | Effect |
|---|---|---|
| `baseline` | `.specify/memory/attack-tree.yaml` | Project-level tree inherited by each new feature tree for shared actors, assets, controls, and decisions. Read at `init` only, silently skipped when absent. |
| `otm` | `""` (off) | Path, relative to the feature directory or the repository, of an Open Threat Model file that `seed` reads, A13 links against, and A11 hashes. Empty disables OTM interop. |
| `write_requirements_to_spec` | `true` | Publishes the `CR-###` block into `spec.md` between the `attacktree` markers. `render --no-spec` overrides it for one run. |
| `render_markdown` | `true` | Writes `attack-tree.md`. `render --no-markdown` overrides it for one run. |
| `diagram` | `mermaid` | `mermaid` embeds one flowchart per goal in `attack-tree.md`; `none` omits them. |

### `verification`

```yaml
verification:
  test_command: ""
  scanners: []
  evidence_markers: ["CR-"]
  test_dirs: [tests, test, spec, __tests__]
```

| Key | Default | Consumed by | Effect |
|---|---|---|---|
| `test_dirs` | `[tests, test, spec, __tests__]` | engine | Directories walked when collecting evidence. |
| `evidence_markers` | `["CR-"]` | engine | Substrings searched in those files to tie a test to a requirement (`CR-001`, `CR_001`, `CR001` all match). |
| `test_command` | `""` | agent | The command converge runs, once, when it is invoked with `--run-tests`. Without the flag nothing is executed even if a command is configured. |
| `scanners` | `[]` | agent | Scanner or micro-simulation outputs converge may cite as evidence, recorded with `method: scan` or `simulation`. Never as a verdict on its own. |

The engine never executes `test_command` or `scanners`; `converge-scan` echoes them under `config.verification`, and the converge command prompt decides what to run. Running anything is opt-in: without `--run-tests`, converge reads artifacts and runs nothing.
