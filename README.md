# VulnBump

**A benchmark for vulnerability-driven dependency upgrades in real, runnable repositories.**

- Paper: [VulnBump: A Benchmark for Fixing Vulnerable Dependencies in Real Projects While Keeping the Build and Tests Green](https://arxiv.org/abs/2610.17374) (arXiv:2610.17374; [PDF in this repository](paper/vulnbump.pdf))
- Benchmark website with interactive results: [vulnbump.com](https://www.vulnbump.com/)

## What is VulnBump?

Each VulnBump task pairs a repository at a pinned, vulnerable commit with **one upgrade recommended by a Snyk scan**. The upgrade names a package, its target version and the vulnerabilities it fixes.

An agent gets a fresh copy of the repository and tries to apply the upgrade. Then an independent verifier re-checks the agent's working tree in a **fresh container**, with four gates:

1. **Dependencies resolve.** The repository installs with its strict install command.
2. **The rescan is clean.** A new Snyk scan shows the targeted vulnerabilities fixed.
3. **The repository builds.**
4. **Tests still pass.** Every test that passed before the upgrade still passes.

An upgrade is a **PASS** only if all four gates pass. The verdict uses only evidence the verifier collects itself. The agent's own report is recorded but never trusted.

See [docs/methodology.md](docs/methodology.md) for the task definition, sandbox, leakage controls, gates, failure categories and metrics.

## Dataset

The dataset has **43 repositories** across six package managers:

| Maven | Gradle | npm | Yarn | pip | Poetry |
|---|---|---|---|---|---|
| 18 | 3 | 11 | 3 | 3 | 5 |

They yield **307 upgrade tasks** covering **2,066 fixable vulnerability instances**. The repositories were selected to match Snyk Open Source production vulnerability distributions.

The cases are in [`benchmarking/cases/cases.yaml`](benchmarking/cases/cases.yaml). Each case gives the repository URL and pinned commit, the container image, the install, build and test commands, and a timeout.

Tasks are derived from a Snyk scan at run time, which needs the Snyk CLI and a token.

### Advisory drift

The repositories are pinned, but the vulnerability database is not. A later run on the same commits will usually find more than the paper's 2,066 instances (scanned 4–5 October 2026), and may recommend different target versions.

For example, a vulnerability published between the paper's agent runs and its package manager bump run changed the target of two upgrades in `tokuhirom/java-handbook`. So compare runs scanned on different days only on tasks with the same recommended upgrade, each against its own baseline.

## Harnesses

The paper evaluates four harnesses on the same 307 upgrades:

| Harness | What it gets and does | `--harness` and published report |
|---|---|---|
| **package manager bump**, the non-agentic baseline | Applies Snyk's recommended version with the repository's own package manager, and nothing else. | [`package-manager-bump`](benchmarking/reports/package-manager-bump/) ([`package-manager-bump-min`](benchmarking/reports/package-manager-bump-min/): Python `>=` pins) |
| **Claude Code unaided** | Claude Code with no Snyk access and no target version. | [`claude-code-unaided`](benchmarking/reports/claude-code-unaided/) |
| **Claude Code + Snyk scan** | Claude Code given the upgrade's block of the Snyk scan, which names the target version. It may re-run `snyk test`. | [`claude-code-snyk-scan`](benchmarking/reports/claude-code-snyk-scan/) |
| **Evo Remediation Agent** | Snyk's agentic remediation engine, run as `snyk fix --agentic --sca --auto-approve --prepare-env --issue-ids <ids>`. | [`evo-remediation-agent`](benchmarking/reports/evo-remediation-agent/) |

Run setup:

- **Model.** All three agents use Claude Sonnet 5.5 (`claude-sonnet-5-5`), with a limit of 110 agent turns per upgrade.
- **Claude Code version.** 2.1.289.
- **Attempts.** One attempt per upgrade, each from a fresh copy of the repository.
- **Test edits.** Agents may adapt tests to breaking changes (renames, API migrations, imports) but must not edit tests to make them pass.

## Results

| Metric | package manager bump | Claude Code unaided | Claude Code + Snyk scan | Evo Remediation Agent |
|---|---|---|---|---|
| PASS | 46.9% (144/307) | 59.6% (183) | 77.5% (238) | 90.2% (277) |
| Vulnerability instances fixed | 56.5% | 72.7% | 83.1% | 95.9% |
| Macro PASS (per repository) | 51.3% | 68.0% | 80.1% | 93.1% |

The package manager bump's 144 PASSes are a lower bound on what mechanical upgrading can solve.

Explore the results interactively at [vulnbump.com](https://www.vulnbump.com/).

The paper discusses the design's limits:

- Snyk built the benchmark, and Snyk Open Source is the judge.
- Each upgrade was run once.
- New vulnerabilities introduced by an upgrade are not penalised.

## Repository layout

```
benchmarking/
  cases/cases.yaml        the 43 cases
  scripts/                the uv project
    cli/                  command-line entry points: benchmark, merge_reports, rescore, pdf_report
    harness/              sandbox, agents, verifier and scoring
    tests/
    prepare_data.py       clone the repositories; fetch jq, yq and Gradle distributions
  reports/<harness>/      published reports: benchmark.json, benchmark.pdf, benchmark.txt
  analysis/               scripts that regenerate the paper's numbers and figures (see its README)
docs/                     methodology, run instructions, reproducing the paper
paper/                    the paper (PDF) and its LaTeX source and figures
```

`benchmarking/build/` and `benchmarking/data/` are local and gitignored. They hold:

- Snyk CLI binaries;
- repository clones;
- `jq`, `yq` and Gradle distributions;
- scan artefacts.

`prepare_data.py` fills them.

## Requirements

- Linux with Docker.
- [uv](https://docs.astral.sh/uv/) (Python ≥ 3.11).
- A `SNYK_TOKEN`. Tasks are derived from a Snyk scan. The harness downloads the preview Snyk CLI itself, because the Evo Remediation Agent (`snyk fix --agentic`) is a preview feature.
- An `ANTHROPIC_API_KEY` for the agent harnesses. The package manager bump needs none.
- A Maven read-through cache (one `docker run`): a full run otherwise hits Maven Central's rate limits.
- Resources: memory is the binding limit, at up to 24 GB per container. A full single-upgrade run of one agent takes 6–13 h on a 32-core, 62 GB host, plus about 1 GB of artefacts per run and about 22 GB of Docker images.

## Running

See [docs/running.md](docs/running.md) for setup, model access, the paper's configuration and costs. In short, from `benchmarking/scripts/`:

```bash
uv sync && uv run pytest -q tests          # the tests need no Docker, token or model
uv run python prepare_data.py              # clone the 43 repositories; fetch jq, yq, Gradle distributions
# start the Maven cache (docs/running.md), export SNYK_TOKEN, ANTHROPIC_API_KEY and MAVEN_MIRROR_URL, then:
uv run python -m cli.benchmark --harness evo-remediation-agent --model claude-sonnet-5-5
```

- `--case <name>` (repeatable) limits the run to some repositories.
- `uv run python -m cli.merge_reports --by-agent` merges reports from separate runs.

Outputs:

- `benchmarking/reports/<run_id>/benchmark.{json,txt,pdf}`: the report. The JSON is rewritten after every repository, so a run that dies part-way still leaves partial results.
- `benchmarking/data/scans/<run_id>/<case>/`: the baseline and post-fix scans, the install, build and test logs, the prompt, the agent log and `agent.diff`.

## Reproducing the paper's numbers and figures

See [docs/reproducing-paper.md](docs/reproducing-paper.md).

## Citation

```bibtex
@misc{pasiunaite2026vulnbump,
  title         = {{VulnBump}: A Benchmark for Fixing Vulnerable Dependencies in Real Projects While Keeping the Build and Tests Green},
  author        = {Pasiunaite, Gabija and McMorrow, Ryan and Clark, Brian and Tal, Liran and Tu, Luke},
  year          = {2026},
  eprint        = {2610.17374},
  archivePrefix = {arXiv},
  url           = {https://arxiv.org/abs/2610.17374}
}
```

## Licence

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). The benchmark repositories are third-party repositories under their own licences. They are cloned at run time, not distributed here.

## Issues

Report bugs and questions through GitHub issues on this repository.
