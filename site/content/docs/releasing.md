+++
title = "Releasing"
description = "Maintainer checklist for releasing AttackTree: version bumps, the release workflow, install verification, and submission to the Spec Kit community catalog."
weight = 42
[extra]
group = "Project"
+++

For maintainers. The checklist follows Spec Kit's [publishing guide](https://github.com/github/spec-kit/blob/main/extensions/EXTENSION-PUBLISHING-GUIDE.md) and its Extension Submission issue template.

## Before tagging

| Guide requirement | Where it is satisfied |
|---|---|
| `extension.yml` with valid id, semver, short description, public repository URL, 2–5 lowercase tags | `extension.yml`; enforced by `tests/test_manifest.py` |
| `README.md` with overview, installation, configuration, usage, troubleshooting, contributing | `README.md`, with details on this site |
| `LICENSE` (permissive) and `CHANGELOG.md` | both at the root |
| Command files exist for every declared command and reference siblings only through `__SPECKIT_COMMAND_*__` tokens | `commands/`; enforced by tests |
| Config template with documented options and defaults | `config-template.yml`, `config.defaults` in the manifest; the tests check the two agree |
| No hardcoded secrets, validated inputs, trusted dependencies | PyYAML only; jsonschema optional; `$ARGUMENTS` never reaches a shell |
| Version bumped on every content change | Release workflow refuses a tag whose version differs from the manifest |

## Release

The site deploys itself from `main` through the Pages workflow; a release needs no extra step for it.

1. Bump `extension.version` in `extension.yml`, update `CHANGELOG.md`, and update `version` and `download_url` in `catalog.json` (the test suite checks they agree).
2. Tag and push:

   ```bash
   git tag v0.1.0 && git push origin v0.1.0
   ```

3. The Release workflow runs the tests, builds `attacktree-v0.1.0.zip`, smoke-installs it with the Spec Kit CLI, and publishes a GitHub Release whose notes include the archive's SHA-256.
4. Verify the two install paths the guide expects:

   ```bash
   specify extension add attacktree --from https://github.com/hupe1980/spec-kit-attacktree/archive/refs/tags/v0.1.0.zip
   specify extension add --dev /path/to/spec-kit-attacktree
   ```

## Submit to the community catalog

File an issue with the [Extension Submission](https://github.com/github/spec-kit/issues/new?template=extension_submission.yml) template. Do not open a pull request against `catalog.community.json`. Field values:

| Field | Value |
|---|---|
| Extension ID | `attacktree` |
| Extension Name | AttackTree — Attack Tree Modeling & Control Simulation |
| Version | from `extension.yml` |
| Description | Attack trees with attacker profiles, AND/OR path simulation, control roadmaps, and control-to-test traceability |
| Author | hupe1980 |
| Repository URL | https://github.com/hupe1980/spec-kit-attacktree |
| Download URL | https://github.com/hupe1980/spec-kit-attacktree/archive/refs/tags/vX.Y.Z.zip |
| License | MIT |
| Documentation URL | https://hupe1980.github.io/spec-kit-attacktree/ |
| Changelog URL | https://github.com/hupe1980/spec-kit-attacktree/blob/main/CHANGELOG.md |
| Required Spec Kit Version | `>=1.0.0` |
| Required Tools | Python 3 with PyYAML, or uv |
| Number of Commands | 4 |
| Number of Hooks | 7 |
| Tags | security, attack-trees, threat-modeling, risk-simulation, traceability |
| Key Features | `attack-tree.yaml` with actors, goals, AND/OR paths, controls; Schneier propagation with attacker profiles; choke points, single points of failure, what-if roadmap, seeded Monte Carlo; `CR-###` requirements published into `spec.md`; deterministic checks A1–A16 with SARIF; evidence-based convergence with measured bypass rates; seeds from and links to Open Threat Model files |
| Testing checklist | installs from the download URL (release workflow smoke test); commands executed on real projects; docs complete; no known vulnerabilities (see the [security page](@/docs/security.md)) |

The community catalog is discovery-only. Users either copy the entry into a catalog they trust or use the `--from` URL. The ready-made entry in `catalog.json` at the repository root is what a maintainer would paste.

## Self-hosted catalog

`catalog.json` is also a complete installable catalog. Teams can register it and install by name:

```bash
specify extension catalog add https://raw.githubusercontent.com/hupe1980/spec-kit-attacktree/main/catalog.json --name attacktree --install-allowed
specify extension add attacktree
```

Spec Kit ≥ 1.0.7 requires tag-pinned download URLs in catalogs, which is why `download_url` names a release tag rather than `main`.
