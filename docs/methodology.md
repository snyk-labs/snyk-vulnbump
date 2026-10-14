# Methodology

This page describes how VulnBump builds tasks, runs each harness, and verifies and scores the result. The paper ([`paper/vulnbump.pdf`](../paper/vulnbump.pdf)) has the full rationale. Code paths are relative to `benchmarking/scripts/`.

## Tasks

Each case in `cases/cases.yaml` gives:

- the repository URL and pinned commit;
- the container image;
- the install, build and test commands;
- a timeout (`timeout_s`, 6 h).

`clone_repos.py --cases ../cases/cases.yaml --out ../data/repos` clones every repository at its commit. Each clone holds only that commit: depth 1, no remote, no other refs or tags. So the agent can't read the upstream fix from later history. The harness refuses to copy a repository with commits beyond `HEAD`.

### Fixable vulnerabilities and upgrades

- **Fixable.** A vulnerability is *fixable* when the baseline `snyk test --all-projects` offers an upgrade or pin for it. Vulnerabilities with no fix path are reported but never counted against an agent.
- **Upgrade.** Each *upgrade* (task) is one package upgrade in one manifest, together with the vulnerabilities it fixes. This is a Snyk fix group (`harness/fix_plan.py`).
- **Vulnerability instance.** An instance is keyed by `(manifest, vulnerability id)`, so the same vulnerability in two manifests counts twice.
- **Shared instances.** One instance can sit under several upgrades, when it arrives through several dependency paths.
  - Each upgrade is scored on its own path.
  - The totals count each instance once: it is fixed only if every upgrade covering it cleared its path.
- **Moved instances.** If the vulnerability now arrives through a direct dependency that didn't carry it in the baseline (a relocated Maven coordinate, a newly declared package), it is not fixed. The report counts it as *moved*.

### One attempt per upgrade

Every upgrade starts from a fresh copy of the repository, so one upgrade's failure can't affect another. Each attempt is scored on its own.

## Harnesses

| Harness | `--harness` | What it gets and does |
|---|---|---|
| package manager bump | `package-manager-bump` | No model. It sets the named package to Snyk's recommended version with the ecosystem's own mechanism and refreshes the lockfile (`harness/pm_bump.py`). |
| package manager bump, `>=` Python pins | `package-manager-bump-min` | As above, but Python pins are `>=ver`, so the resolver picks the newest release (pip and Poetry cases only). |
| Claude Code unaided | `claude-code-unaided` | Claude Code, prompted with the test command and the upgrade's findings, but without the target version (`Upgrade X to fix these vulnerabilities:`) and without Snyk. |
| Claude Code + Snyk scan | `claude-code-snyk-scan` | Claude Code, prompted with the test command and the upgrade's `Upgrade X to Y to fix` block from the baseline Snyk scan. It may re-run `snyk test`. |
| Evo Remediation Agent | `evo-remediation-agent` | `snyk fix --agentic --sca --auto-approve --prepare-env --issue-ids <ids>`, once per upgrade, with the IDs of the vulnerabilities that upgrade fixes. |

### package manager bump

The package manager bump is the non-agentic baseline: it applies Snyk's recommended upgrade and nothing else.

- **Mechanism by ecosystem.**
  - npm, Yarn and Poetry use `npm install --package-lock-only`, `yarn add` and `poetry add --lock`.
  - In `requirements.txt` (following `-r` includes), the specifier becomes `==ver`, or a transitive pin is appended.
  - In Maven, the `<version>`, its property or the `<parent>` is bumped, and a managed dependency gets an explicit `<version>`.
  - In Gradle, the version string, catalog entry or variable is bumped, and a transitive-only package gets a `constraints {}` entry.
- **Missing declaration.** When the bump finds no declaration, the attempt fails with `bump-not-applied`.
- **Snyk-advice-solvable split.** Its PASS set defines the *Snyk-advice-solvable* split. It is a lower bound on what mechanical upgrading can solve.
- **Managed pins.** Under a Maven parent or BOM, or Spring's dependency-management plugin, the pin moves the named package but not the transitives the BOM manages. The split is broken down by declaration (`pm_bump_managed` on each attempt).

### Turn limits

`--max-turns 0`, the default, gives:

- the Evo Remediation Agent its own default budget;
- Claude Code 110 turns per upgrade (`claude_turn_budget` in `harness/agents.py`).

Each attempt records `turns_used` and `turn_capped`. A capped failure shows as `TURN_CAP`.

### Test edits

Agents may adapt tests to breaking changes (renames, API migrations, imports) but must not edit tests to make them pass. The prompts say so.

## Sandbox

Every attempt works on its own copy of the repository, so attempts are isolated, and several repositories can run at once (`--parallel-repos`).

The agent runs in a restricted container, the same for every harness:

- a non-root uid;
- a read-only root filesystem with `HOME=/tmp`, where only the repository, `/out` and `/tmp` are writable;
- 24 GB of memory.

Every harness runs in the same image: the ecosystem image with Claude Code added (`harness/claude_image.py`). The agent phase also mounts static `jq` and `yq` binaries from `data/tools/`.

The verifier then runs in a **separate container**, as root, with a fresh `/out`. It runs install, `snyk test`, build and tests (`harness/entrypoint.sh`). So nothing the agent leaves outside the repository (PATH shims, `~/.m2`, files in `/out`) can shape its verdict. `agent.diff` is taken between the two containers, so it holds the agent's changes only.

### Leakage controls

- **No history.** Repositories are single-commit clones.
- **No GitHub.**
  - Claude Code gets `WebFetch` deny rules for the GitHub hosts and has no `gh`.
  - The agent container maps GitHub, and the mirrors that serve repository files at any ref, to `0.0.0.0`. The mirrors are jsDelivr, raw.githack and Sourcegraph (`GITHUB_HOSTS` in `harness/docker.py`).
  - A few cases whose setup fetches from GitHub are exempt from the host block (`AGENT_NEEDS_GITHUB`).
  - The rest of the web stays open: advisories, changelogs and migration guides.
- **No Snyk for Claude Code unaided.**
  - It gets no Snyk CLI or token.
  - `snyk.io`, `security.snyk.io`, `api.snyk.io` and `app.snyk.io` are blocked (`SNYK_HOSTS`).
  - Links to `security.snyk.io` are removed from its prompt.
- **Residual risks.**
  - The block is `/etc/hosts` only, with no egress filtering.
  - `curl --resolve`, DNS-over-HTTPS, a hard-coded IP or an unlisted mirror get past it.
  - WebSearch snippets can still show GitHub pages.
  - The model may have memorised later versions of popular repositories.

## Validation

- **Baseline.** Before scoring any fix, every run re-checks the untouched repository: install, `snyk test`, build and tests.
  - This gives the vulnerabilities to fix, the fix plan, and the passing tests that later attempts must keep.
  - A repository whose baseline fails is marked invalid and left out of every rate.
- **Pre-flight.** `validate_baselines.py` runs the same baseline checks across all cases without any agent. Results go to `data/baseline-validation/<run_id>.json`.

## Evaluation

### Verdict

- **PASS**: every gate passed.
- **FAIL**: at least one gate failed. The report lists the reasons in gate order.
- **TIME_OUT**: the attempt hit its wall-clock budget and the container was killed.
- **HARNESS_ERROR**: the agent never produced a result (auth or startup failure). It is left out of every rate and shown as a separate count.

### Gates

| # | Gate | Evidence | Failure reason |
|---|---|---|---|
| 1 | Dependency resolution | The install command exits 0 after the fix | `deps-unresolved` |
| 2 | Rescan | The post-fix scan covers every target manifest, and the targeted vulnerabilities are gone | `verification-scan-failed` / `vuln-not-cleared` |
| 3 | Build | The build or load check exits 0; `n/a` where the case has none | `build-broken` |
| 4 | Tests | Baseline-passing tests still pass (JUnit XML), else the passing count is at least the baseline's | `tests-regressed` / `tests-not-measured` |

The verifier always runs every gate, so the report shows every gate that failed. The code is `harness/verdict.py` (`judge`).

- **Gate 2.**
  - Both scans run with `--ignore-policy`, so a `.snyk` ignore written by the agent can't hide a vulnerability. Edits to `.snyk` are flagged (`snyk_policy_modified`).
  - If the post-fix Maven scan can't build a tree because the fix outgrew the pinned `./mvnw`, it is retried once without the wrapper (`scan_without_wrapper`). The stale wrapper still fails gate 1.
- **Gate 3.**
  - Compiled ecosystems run a real compile. JS and Python cases get a build or load check where the repository supports one.
  - Gradle repositories have no install step, so gate 3 covers their dependency resolution.
- **Gate 4.**
  - Where the runner writes JUnit XML, every baseline-passing test must still pass, and none may be skipped or missing.
  - Other runners fall back to the passing count.
  - Edits to test files are flagged (`tests_modified`).

Two more checks can fail an attempt:

- **`boot-broken`**: only for cases with a `boot_cmd`.
- **`unexpected-collateral`**: a direct dependency bumped outside the fix's lane.
  - It fails an attempt only with `--strict-collateral`, which the paper doesn't use.
  - Collateral bumps are recorded either way (`harness/collateral.py`).

### Failure categories

`harness/failure_class.py` reads each failed attempt's logs:

1. It picks the log of the first failed gate.
2. It drops lines that also appear in the baseline log.
3. It matches the remaining lines against rules, in this order:

| Category | Typical signal |
|---|---|
| `timeout` | attempt killed at its budget, or a step exceeded its timeout |
| `dependency-conflict` | `Could not resolve dependencies`, `ERESOLVE`, `ResolutionImpossible` |
| `toolchain-version` | `class file has wrong version`, `EBADENGINE`, `Requires-Python` |
| `module-format` | `ERR_REQUIRE_ESM`, `Cannot use import statement outside a module` |
| `binary-incompatibility` | `NoSuchMethodError`, `NoClassDefFoundError`, `ClassNotFoundException` |
| `removed-api` | `cannot find symbol`, `package X does not exist`, `cannot import name` |
| `api-signature-change` | `incompatible types`, `cannot be applied to`, `unexpected keyword argument` |
| `test-assertion` | `AssertionError`, `AssertionFailedError`, `Expected:` |
| `other` | no rule matched |

The attempt also records the first matching error line, and the *culprit*: the changed dependency that the new error lines mention most often.

## Metrics

- **Which attempts count.** Rates are over valid repositories only, and exclude harness errors. The unit is an upgrade.
- **Macro rate.** Pooled rates weight repositories by their number of upgrades. So the report also gives a macro rate: the mean of per-repository rates.
- **Confidence interval.** The report's 95% interval is a percentile bootstrap that resamples repositories, each with all its upgrades (1,000 resamples, fixed seed). The paper's analysis scripts use 10,000 resamples.

| Metric | Definition |
|---|---|
| Vulnerability fix rate | Fixable baseline instances gone after the fix, out of all fixable instances |
| Deps / build / tests pass rate | Attempts that pass gate 1 / 3 / 4 |
| Pass rate | Attempts with a PASS verdict |
| Remaining vulnerabilities | Baseline instances still present after the fix, by severity |
| New vulnerabilities | Instances in the post-fix scan that weren't in the baseline, by severity (not penalised) |
| Tokens and cost | Agent tokens. Cost: tokens × `--price-in`/`--price-out` for the Evo Remediation Agent; Claude Code's own reported cost |
| Latency | Wall-clock time of the agent run alone |

The PDF report also breaks fix rate and pass rate down by:

- ecosystem;
- severity;
- fix difficulty: the smallest jump to a fixed release (patch / minor / major);
- direct versus transitive.

## Known gap

npm and Yarn cases install with a fallback, e.g. `npm install --legacy-peer-deps` after `npm ci`. Where the repository has a lockfile, the fallback runs, but gate 1 uses the strict command's exit code. Repositories without a `package-lock.json` can never pass `npm ci`, so for them the fallback is the install (`npm ci || npm install --legacy-peer-deps`), and an out-of-sync manifest can still pass gate 1.
