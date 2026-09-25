# Threat model of AttackTree itself

AttackTree runs inside a coding agent with read/write access to a repository. This is its own threat model, in the shape it asks of others: goals, paths, controls, status.

## Who attacks, what they want

Actors: the developer (privileged, trusted), other contributors to the repository (insider), authors of content the spec, plan, threat model, or code quotes (external, untrusted), package registries (external, semi-trusted).

| Goal | Impact | Paths | Controls | Status |
|---|---|---|---|---|
| **G1** Make the agent record controls as verified, or goals as mitigated, that are not | data high, compliance high | (a) instruction-like text in `spec.md`, `plan.md`, an OTM file, code, tests, or fetched pages steers the agent (indirect prompt injection); (b) `$ARGUMENTS` carries instructions; (c) a hand-edited `attack-tree.yaml` sets `status: verified` | every command treats artifact content as data and quotes suspicious text under "Unverified"; arguments only select scope and never reach a shell; `verified` needs an evidence pointer the engine checks; control and goal status are computed by `converge-apply`, never asserted; check A12 flags a `verified` claim without a passing verification entry | (a) mitigated by prompt discipline, residual risk remains because LLM adherence is probabilistic; (b), (c) mitigated |
| **G2** Overwrite human-authored content in `spec.md` or `tasks.md` | business medium | the CR block insertion or the appended convergence phase touches text outside its scope | writes are confined to the `<!-- attacktree:begin/end -->` markers, first insertion goes before `## Success Criteria`; `tasks.md` is append-only and byte-for-byte unchanged when converged; both covered by tests | mitigated |
| **G3** Run arbitrary commands through the extension | business high | `verification.test_command` or `scanners` in the config execute; the `uv run --with pyyaml --with jsonschema` fallback pulls packages from PyPI at first use | empty by default; only the configured command runs, once, from the repo root; the config is versioned and reviewable; the wrapper uses `uv` only when no local Python with PyYAML exists; teams can pre-install PyYAML | accepted: the config is developer-owned, same trust as any project script; version pins for the fallback are on the roadmap |
| **G4** Make the simulation lie | business medium | a tree whose ratings or control effects were chosen to pass; a `bypass_rate` recorded without a real measurement | the numbers are only as good as the ratings, and the commands say so; the check command's S5 pass questions implausible ratings; `bypass_rate` is written only by `converge-apply` from a verdict that carries an evidence pointer; history is append-only and reviewable in diffs | partially mitigated: the engine does not open the evidence |
| **G5** Read files outside the repository | data medium | `attacktree.extends` or `--otm` points outside the repository | the engine only reads YAML at those paths; rejection of paths outside the repo root is on the roadmap | open, low |
| **G6** Leak secrets or instruction blocks into rendered artifacts | data medium | the model command copies a secret or a system prompt into `attack-tree.yaml` or `attack-tree.md` | commands forbid verbatim reproduction; the renderer only emits tree fields | mitigated by prompt discipline |
| **G7** Run AttackTree without the developer noticing | business low | a project makes a hook mandatory | all hooks ship `optional: true`; changing that is an explicit, versioned edit of `.specify/extensions.yml` | mitigated |

## Did we do a good job

Tests cover G1(c) (A12, `verified` without evidence rejected, status roll-up), G2 (marker confinement, append-only tasks), and G4's write path (bypass rates only through verdicts). G1(a) and G6 rely on prompt discipline and should be exercised with adversarial fixtures (a spec containing injected instructions) as part of the v0.2 test suite. G3 and G5 are tracked for v0.2.
