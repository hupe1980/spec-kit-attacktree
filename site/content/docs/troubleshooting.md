+++
title = "Troubleshooting"
description = "Fixes for common AttackTree problems: missing Python runtime, feature detection, YAML parse errors, rejected merges, infeasible or unknown goals, truncation, and drift."
weight = 24
[extra]
group = "Guides"
+++

| Symptom | Cause and fix |
|---|---|
| `attacktree: no Python runtime with PyYAML found` | Install PyYAML (`pip install pyyaml`) or [uv](https://docs.astral.sh/uv/). The wrappers try `python3`, then `python`, then `uv run --with pyyaml --with jsonschema`. |
| `attacktree: no feature directory found` | Pass `--feature-dir specs/<feature>` before the subcommand, or set `SPECIFY_FEATURE`. The engine tries the flag, then `SPECIFY_FEATURE`, then the git branch name, then the newest `specs/*/spec.md`. |
| `YAML parse error … quote any scalar` | A value containing `: `, `#`, or starting with `[` is unquoted, typically a `[NEEDS CLARIFICATION: …]` name. Quote it and re-run `merge`. |
| `merge rejected, N validation error(s)` | The incoming tree references an id that does not exist, has a parent cycle, or puts an `attack` block on a node with children. The errors name the entity; fix the file rather than bypassing validation. |
| `cannot simulate, N validation error(s)` | Same cause; the simulation refuses to run on a broken tree. Run `attacktree.sh validate attack-tree.yaml`. |
| A goal has no feasible path although it has leaves | No modelled actor can perform the steps: skill, resources, and `requires` tags rule them out, or an AND needs steps that no single actor can do. The rendered outline shows each leaf's actors and requirements. |
| A goal's risk is `unknown` | Every path to it runs through a `needs-clarification` node. Answer the question with `/speckit-clarify` and re-run the model command. |
| `truncated` in the simulation, or check A16 | A subtree has more paths than `risk.max_paths`. Raise the limit, or split the goal into smaller goals. The best paths per actor are always kept. |
| Commands do not appear in the agent | Run `specify extension list`. If the extension is listed, restart the agent so it reloads its commands or skills. |
| A11 drift right after editing `spec.md` | Expected: re-run the model command so the hashes match. Rendering the `CR-###` block, or another extension's managed block, never counts as drift. |
| Converge reports `never hashed` | The tree predates source hashing. Run the model command once. |
| A control keeps falling back from `verified` to `implemented` | Check A12: a control counts as verified only while all its requirements have a passing verification. Run converge with evidence for the missing requirement. |
