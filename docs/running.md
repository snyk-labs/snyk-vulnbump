# Running VulnBump

Commands run from `benchmarking/scripts/` unless stated otherwise.

| Harness (paper) | `--harness` |
|---|---|
| Evo Remediation Agent | `evo-remediation-agent` |
| Claude Code + Snyk scan | `claude-code-snyk-scan` |
| Claude Code unaided | `claude-code-unaided` |
| package manager bump (the non-agentic baseline) | `package-manager-bump` |
| package manager bump with `>=` Python pins | `package-manager-bump-min` |

## Requirements

- Linux (x86-64) with Docker.
- [uv](https://docs.astral.sh/uv/).
- A Snyk account and `SNYK_TOKEN`. Every run scans each repository before and after the fix.
- An `ANTHROPIC_API_KEY` for the agent harnesses (see [Model access](#model-access)). The package manager bump needs none.
- About 22 GB of Docker images, about 1 GB of artefacts per run, and up to 24 GB of memory per container.

## One-time setup

1. **Install the environment, and check the tests pass:**

   ```bash
   uv sync
   uv run pytest -q tests
   ```

2. **Fill `benchmarking/data/`:**

   ```bash
   uv run python prepare_data.py
   ```

   This fills three gitignored folders, skipping anything already present:
   - `data/repos/`: every case cloned at its pinned commit, at depth 1 with no remote, so agents can't read the upstream fix. `clone_repos.py --check` verifies that no clone leaks history.
   - `data/tools/`: static `jq` and `yq` binaries, checksum-verified. The agent container mounts them, because no fixture image ships them.
   - `data/gradle-dists/`: the Gradle wrapper distribution of each Gradle case. The agent container blocks GitHub, where the wrapper's download redirects, so the agent phase copies it from here.

3. **Start the Maven read-through cache.** A full run otherwise hits Maven Central's rate limits (HTTP 429), because every attempt resolves its dependencies three times.

   ```bash
   docker run -d --name vulnbump-maven-cache --restart unless-stopped -p 172.17.0.1:8093:80 \
       -v $PWD/harness/maven-mirror/nginx.conf:/etc/nginx/conf.d/default.conf:ro \
       -v $PWD/../data/maven-cache:/cache nginx:stable
   export MAVEN_MIRROR_URL=http://host.docker.internal:8093/maven2
   ```

   - `172.17.0.1` is Docker's default bridge address; use your host's if it differs.
   - The benchmark refuses to start if the mirror serves a compressed or altered canary POM (`harness/maven_mirror.py`), and Maven fails on any checksum mismatch.
   - After editing `nginx.conf`, run `docker restart vulnbump-maven-cache`. `nginx -s reload` keeps reading the old file through the bind mount.

4. **Behind a TLS-intercepting proxy only:** export `EXTRA_CA_CERT` with your proxy's root CA. On macOS, `harness/setup-certs.sh` extracts it. Without the CA, installs inside the containers fail.

## Snyk CLI

The CLI mode decides which Snyk CLI the harness mounts into the containers:

| Mode | CLI | Images |
|---|---|---|
| `--preview` (default) | The latest preview-channel CLI from downloads.snyk.io, downloaded to `build/snyk-preview` and refreshed when a newer one is published | the cases' own images (`maven:3.9-eclipse-temurin-17`, `node:20-bookworm`, …) |
| `--local` | Any CLI build you place at `build/snyk-local` | the cases' own images |
| `--release` | The GA CLI baked into the `snyk/snyk` images | `snyk/snyk:*` |

- **Evo Remediation Agent** (`snyk fix --agentic --experimental …`) is a preview feature. It needs `--preview` or a `--local` build; the GA CLI doesn't have it.
- **Pinning.** Each run pins the binary by sha256 under `data/snyk-builds/` and records the version in the report.
- **The paper's build.** The paper's runs used a pre-release CLI build (sha256 `683df459…`, `0.1.0-preview.aaf12cb8…`). Preview 1.1309.0 passed the same Evo Remediation Agent attempt on `wmaarts-pitest-mutation-testing-elements-plugin`. Later previews may behave differently.

## Model access

The agents call the model with your Anthropic API key:

```bash
export ANTHROPIC_API_KEY=...
```

- **Claude Code** reads `ANTHROPIC_API_KEY` itself.
- **Evo Remediation Agent** uses the Anthropic provider with the same key.
- **`--model`** sets one model for every agent. The paper used Claude Sonnet 5.5 (`--model claude-sonnet-5-5`).
- **The paper's runs** reached the same model through Vertex AI; the public harness uses the Anthropic API.
- **The package manager bump** calls no model and needs no key.

## Runs (the paper's configuration)

```bash
COMMON="--parallel-repos 5 --model claude-sonnet-5-5 --price-in 2 --price-out 10"

uv run python -m cli.benchmark $COMMON --harness evo-remediation-agent
uv run python -m cli.benchmark $COMMON --harness claude-code-snyk-scan
uv run python -m cli.benchmark $COMMON --harness claude-code-unaided
uv run python -m cli.benchmark $COMMON --harness package-manager-bump     --concurrency 4
uv run python -m cli.benchmark $COMMON --harness package-manager-bump-min --concurrency 4 $PY_CASES
```

`PY_CASES` is the pip and Poetry cases:

```bash
PY_CASES="--case hisatri-lrcapi --case airbnb-knowledge-repo --case encode-django-rest-framework \
  --case ddedalus-poetry-auto-export --case ewjoachim-poetry-to-pre-commit \
  --case predict-idlab-plotly-resampler --case qdrant-qdrant-client \
  --case wemake-services-wemake-python-styleguide"
```

### Run settings

- **Selecting cases.** `--case <name>` (repeatable) limits the run to some repositories.
- **Detaching.** A full run takes hours. Detach it so it survives the shell:

  ```bash
  setsid nohup uv run python -m cli.benchmark $COMMON --harness evo-remediation-agent \
      > ../data/evo.log 2>&1 < /dev/null &
  ```

- **Turn limits.** Leave out `--max-turns`.
  - The Evo Remediation Agent keeps its own default budget.
  - Claude Code gets 110 turns per upgrade.
  - Each attempt also has a wall-clock budget of `timeout_s` (6 h).
- **Cost flags.** `--price-in`/`--price-out` (USD per million tokens) only price the Evo Remediation Agent; Claude Code reports its own cost.
- **Merging.** Separate runs measure separate baselines. Merge their reports with `uv run python -m cli.merge_reports --by-agent -o merged.json a.json b.json`, which warns when the baselines differ. To share one baseline, run the harnesses together: `--harness evo-remediation-agent,claude-code-snyk-scan,claude-code-unaided`.
- **Repeats.** `--repeats 3` or more gives a publishable number, since every agent is stochastic.
- **LangSmith tracing.** With an Evo Remediation Agent development build, export `LANGSMITH_API_KEY` (and optionally `LANGSMITH_PROJECT`) to trace its attempts.

## Outputs

- `benchmarking/reports/<run_id>/benchmark.{json,txt,pdf}`: the report. The JSON is rewritten after every repository, so a run that dies part-way still leaves partial results (`"complete": false`).
- `benchmarking/data/scans/<run_id>/<case>/before/`: the baseline scan, plus its install, build and test logs.
- `benchmarking/data/scans/<run_id>/<case>/after/<agent>[-<upgrade>]/`, per attempt:
  - the post-fix scan and logs;
  - the prompt;
  - the agent log;
  - `agent.diff`: every change to the repository.

## Smoke check (no model or Snyk API calls)

This start-up check exits with code 2 and "no cases selected". Before stopping, it validates:

- the CLI binary and its pinned copy;
- `snyk --version`;
- the Maven mirror canary;
- the cases file and the repos directory.

```bash
SNYK_TOKEN=${SNYK_TOKEN:-dummy} ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-dummy} \
  uv run python -m cli.benchmark --case __none__
```

## Time, resources and cost

These are past single-upgrade runs of the 43 cases (about 305 attempts each), at `--parallel-repos` 4–5 on a 32-core, 62 GB host with no swap:

| Harness | Wall clock | LLM cost |
|---|---|---|
| Evo Remediation Agent | 5.7–7.8 h | $270–$430 (budget up to ~$700) |
| Claude Code + Snyk scan | ~13 h | ~$560 (an earlier Claude Code version's self-reported cost, which overstates by about 1.5×) |
| Claude Code unaided | ~6–8 h (est.) | ~$100–$125 (est.) |
| package manager bump | not recorded | none (no model) |

- **Where the time goes.** The agent phase takes 2–4 min per attempt; the rest of the wall clock is the harness's own install, scan, build and tests.
- **Memory** is the binding limit. Each container is capped at 24 GB (`DEFAULT_MEMORY` in `harness/docker.py`). Lower `--parallel-repos` if the host runs short.
- **Disk.**
  - About 1 GB of artefacts per run, under `data/scans/<run_id>/`.
  - About 22 GB of Docker images.
  - The sandboxes, under `/tmp`.
