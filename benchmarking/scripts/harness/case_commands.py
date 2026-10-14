"""How each case's install, build and test commands and images are derived.

benchmarking/cases/cases.yaml was generated with generate_case() from the
dataset selection (one row per repository: repo_url, commit_sha, display,
ecosystem, manifest_file, ...), and the tests check the checked-in cases
against these rules. To add a case, write its entry in cases.yaml by hand or
with generate_case().
"""

from __future__ import annotations

import re


# Machine-readable test reports land here so the harness can read per-test
# results back from the host (harness.test_results.collect_test_results).
# /out rather than /app keeps them out of agent.diff.
JUNIT_DIR = "/out/junit"

# Gate 1 must judge the strict, lockfile-faithful install. The fallback still
# runs so later steps have dependencies, but it no longer turns a failed
# install green.
_NPM_INSTALL = "npm ci; rc=$?; [ $rc -eq 0 ] || npm install --legacy-peer-deps; exit $rc"
_YARN_INSTALL = "yarn install --frozen-lockfile; rc=$?; [ $rc -eq 0 ] || yarn install; exit $rc"
# Repos with no package-lock.json: `npm ci` can never succeed, so the fallback
# is the install, baseline included.
_NPM_INSTALL_NO_LOCKFILE = "npm ci || npm install --legacy-peer-deps"

POETRY_VERSION = "2.5.1"


def _jest_json(cmd: str) -> str:
    """Append Jest's JSON results file; the default reporter still prints to the log."""
    return f"mkdir -p {JUNIT_DIR} && {cmd} --json --outputFile={JUNIT_DIR}/jest.json"


ECOSYSTEM_COMMANDS: dict[str, dict[str, str]] = {
    "gradle": {
        "install_cmd": "",
        "build_cmd": "./gradlew compileJava --no-daemon -q",
        # cleanTest forces a rerun, so reports are never stale or UP-TO-DATE;
        # --continue measures every module past the first failing one.
        "test_cmd": "./gradlew cleanTest test --continue --no-daemon",
        "test_framework": "gradle",
    },
    "maven": {
        # -ntp, not -q: -q hides the warnings harness.benchmark looks for
        # (corrupt or invalid POMs from the mirror).
        "install_cmd": "mvn -B -ntp dependency:resolve",
        "build_cmd": "mvn -B -ntp -DskipTests compile",
        # Keep going past failing modules; the gate reads per-test results, not the exit code.
        "test_cmd": "mvn -B -fae -Dmaven.test.failure.ignore=true test",
        "test_framework": "maven",
    },
    "npm": {
        "install_cmd": _NPM_INSTALL,
        "build_cmd": "",
        "test_cmd": "npm test",
    },
    "pip": {
        "install_cmd": (
            "pip install -q -r requirements.txt"
            " && if [ -f setup.py ] || [ -f pyproject.toml ]; then pip install -q -e '.[all,dev,test]'; fi"
            " && pip install -q pytest"
        ),
        "build_cmd": "",
        "test_cmd": f"pytest -q --junitxml={JUNIT_DIR}/pytest.xml",
        "test_framework": "pytest",
    },
    "poetry": {
        "install_cmd": f"pip install -q poetry=={POETRY_VERSION} && poetry install --no-interaction",
        "build_cmd": "",
        "test_cmd": f"poetry run pytest -q --junitxml={JUNIT_DIR}/pytest.xml",
        "test_framework": "pytest",
    },
    "yarn": {
        "install_cmd": _YARN_INSTALL,
        "build_cmd": "",
        "test_cmd": "yarn test",
    },
}

# Maven repos that ship ./mvnw. Their commands run through the wrapper, as
# snyk's scan does, so install/build/test use the Maven the project pins.
# -ntp is dropped: wrappers pinned below Maven 3.6.1 reject it.
MAVEN_WRAPPER_CASES = {
    "assertj-assertj-guava",
    "camunda-community-hub-camunda-platform-7-mockito",
    "citerus-dddsample-core",
    "informatici-openhospital-core",
    "jericks-geoserver-shell",
}


def _mvnw(cmd: str) -> str:
    if not cmd.startswith("mvn "):
        return cmd
    return "./mvnw " + " ".join(a for a in cmd.removeprefix("mvn ").split(" ") if a != "-ntp")


# Per-case overrides for repos that need special handling. Build/load checks
# for npm, yarn and Python are per repo: a type check or build where the repo
# has one, an import of the package otherwise.
CASE_OVERRIDES: dict[str, dict[str, str]] = {
    # --- npm ---
    "tryghost-ghost": {"install_cmd": _NPM_INSTALL_NO_LOCKFILE},
    "restify-node-restify": {
        "install_cmd": _NPM_INSTALL_NO_LOCKFILE,
        # `npm test` is `make prepush`, which stops at the first failing nodeunit
        # file before mocha runs; nodeunit's summary also has no count parser.
        # Run both suites unconditionally and read JUnit XML instead.
        "test_cmd": (
            f"mkdir -p {JUNIT_DIR}; ./node_modules/.bin/nodeunit --reporter junit"
            f" --output {JUNIT_DIR}/nodeunit test/*.test.js;"
            " ./node_modules/.bin/mocha --full-trace --no-exit --reporter xunit"
            f" --reporter-option output={JUNIT_DIR}/mocha.xml test/plugins/*.test.js"
        ),
    },
    "goparrot-geocoder": {
        "install_cmd": _NPM_INSTALL_NO_LOCKFILE,
        "build_cmd": "npm run typecheck",
    },
    "hantsy-nestjs-rest-sample": {
        "build_cmd": "npm run build",
        "test_cmd": _jest_json("npm test --"),
    },
    "ixartz-serverless-boilerplate-express-typescript": {
        "build_cmd": "npm run check-types",
        "test_cmd": _jest_json("npm test --"),
    },
    "kutia-software-company-express-typescript-starter": {
        "build_cmd": "npx tsc --noEmit",
        "test_cmd": _jest_json("npm test --"),
    },
    "santiq-bulletproof-nodejs": {
        # Its @types/mongoose clashes with mongoose's own types.
        "build_cmd": "npx tsc --noEmit --skipLibCheck",
        "test_cmd": _jest_json("npm test --"),
    },
    # The next three run mocha directly without the package script's --bail, which
    # stops at the first failure and leaves the rest of the suite unmeasured.
    "vpulim-node-soap": {
        "build_cmd": "npx tsc --noEmit -p .",
        "test_cmd": "npx mocha --timeout 15000 --exit test/*-test.js test/security/*.js",
    },
    "expressjs-generator": {"test_cmd": "npx mocha --reporter spec --check-leaks test/"},
    # Also drops the prettier check from `npm test`: it is not a test, and a
    # formatting nit would stop every test from running.
    "socketio-socket-io": {
        "test_cmd": "npm run compile && npx mocha --require test/support/hooks.js test/index.js test/webtransport.mjs",
    },
    # --- yarn ---
    "atlassian-react-beautiful-dnd": {
        # Webpack 4 (inside a rollup plugin) needs the legacy OpenSSL provider on node 20.
        "build_cmd": "NODE_OPTIONS=--openssl-legacy-provider yarn build:dist",
        "test_cmd": _jest_json("yarn test"),
    },
    "canva-public-js2nix": {"test_cmd": _jest_json("yarn test")},
    "hagopj13-node-express-boilerplate": {"test_cmd": _jest_json("yarn test")},
    # --- pip ---
    "hisatri-lrcapi": {
        # No setup.py/pyproject.toml: requirements only.
        "build_cmd": "python -c 'import app'",
    },
    "airbnb-knowledge-repo": {
        # Test dependencies are in extras, not base requirements.
        "install_cmd": "pip install -q -r requirements.txt && pip install -q -e '.[all]' && pip install -q pytest",
        "build_cmd": "python -c 'import knowledge_repo'",
    },
    "encode-django-rest-framework": {
        "build_cmd": (
            "python -c \"import django; from django.conf import settings; "
            "settings.configure(INSTALLED_APPS=['django.contrib.contenttypes', 'django.contrib.auth', 'rest_framework']); "
            "django.setup(); import rest_framework.views, rest_framework.serializers, rest_framework.routers\""
        ),
    },
    # --- poetry ---
    "ddedalus-poetry-auto-export": {"build_cmd": "poetry run python -c 'import poetry_auto_export'"},
    "ewjoachim-poetry-to-pre-commit": {"build_cmd": "poetry run python -c 'import poetry_to_pre_commit'"},
    "predict-idlab-plotly-resampler": {"build_cmd": "poetry run python -c 'import plotly_resampler'"},
    "qdrant-qdrant-client": {"build_cmd": "poetry run python -c 'import qdrant_client'"},
    "wemake-services-wemake-python-styleguide": {
        "build_cmd": "poetry run python -c 'import wemake_python_styleguide.checker'",
    },
}

RELEASE_IMAGES: dict[str, str] = {
    "gradle": "snyk/snyk:maven-3-jdk-17",
    "maven": "snyk/snyk:maven-3-jdk-17",
    "npm": "snyk/snyk:node-20",
    "pip": "snyk/snyk:python-3.11",
    "poetry": "snyk/snyk:python-3.11",
    "yarn": "snyk/snyk:node-20",
}


def slugify(display: str) -> str:
    name = display.split("::")[0]
    slug = name.lower().replace("/", "-")
    if "::" in display:
        submod = display.split("::")[1]
        slug += "-" + submod.lower()
    slug = re.sub(r"[^a-z0-9-]", "-", slug)
    slug = re.sub(r"-+", "-", slug).strip("-")
    return slug


def extract_subdirectory(display: str, manifest_file: str) -> str:
    if "::" in display:
        return display.split("::")[1]
    parts = manifest_file.rsplit("/", 1)
    if len(parts) > 1:
        return parts[0]
    return ""


def generate_case(row: dict[str, str]) -> dict:
    eco = row["ecosystem"]
    commands = ECOSYSTEM_COMMANDS.get(eco, {})

    name = slugify(row["display"])
    subdirectory = extract_subdirectory(row["display"], row["manifest_file"])

    test_framework = commands.get("test_framework", "")
    if not test_framework and row.get("test_framework_detected"):
        test_framework = row["test_framework_detected"]

    overrides = CASE_OVERRIDES.get(name, {})
    build_cmd = overrides.get("build_cmd", commands.get("build_cmd", ""))
    test_cmd = overrides.get("test_cmd", commands.get("test_cmd", ""))
    install_cmd = overrides.get("install_cmd", commands.get("install_cmd", ""))

    # Gradle submodules: the wrapper lives in the repo root (/app), but the
    # entrypoint cds into SUBDIR for scanning. Use absolute path so gradlew
    # is still found.
    if eco == "gradle" and subdirectory:
        build_cmd = build_cmd.replace("./gradlew", "/app/gradlew")
        test_cmd = test_cmd.replace("./gradlew", "/app/gradlew")
    if eco == "maven" and name in MAVEN_WRAPPER_CASES:
        install_cmd, build_cmd, test_cmd = map(_mvnw, (install_cmd, build_cmd, test_cmd))

    inputs: dict = {
        "name": name,
        "repo_url": row["repo_url"],
        "commit_sha": row["commit_sha"],
        "images": {
            "release": RELEASE_IMAGES.get(eco, ""),
            "local": row.get("image_used", ""),
        },
        "test_cmd": test_cmd,
        "install_cmd": install_cmd,
        "timeout_s": 21600,
    }
    if build_cmd:
        inputs["build_cmd"] = build_cmd
    if test_framework:
        inputs["test_framework"] = test_framework
    if subdirectory:
        inputs["subdirectory"] = subdirectory
    if "memory" in overrides:
        inputs["memory"] = overrides["memory"]

    return {
        "name": name,
        "inputs": inputs,
        "metadata": {
            "ecosystem": eco,
            "source": row.get("source", ""),
            "display": row["display"],
        },
    }
