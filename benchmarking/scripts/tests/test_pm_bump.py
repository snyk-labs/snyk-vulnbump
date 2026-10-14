import json
from pathlib import Path

from harness import benchmark
from harness.agents import (
    AGENT_FOR, HARNESS_PM_BUMP, HARNESS_PM_BUMP_MIN, MODE_SINGLE_UPGRADE,
)
from harness.fix_plan import FixGroup, FixPlan
from harness.pm_bump import bump, ecosystem_of
from harness.scenario import HarnessConfig, Scenario


def _group(manifest, frm, to, strategy="upgrade", index=0):
    return FixGroup(index=index, strategy=strategy, from_dep=frm, to_dep=to,
                    vuln_ids=("SNYK-1",), manifest=manifest)


def _write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def test_ecosystem_from_manifest():
    assert ecosystem_of("package-lock.json") == "npm"
    assert ecosystem_of("yarn.lock") == "yarn"
    assert ecosystem_of("pyproject.toml") == "poetry"
    assert ecosystem_of("requirements.txt") == "pip"
    assert ecosystem_of("pom.xml") == "maven"
    assert ecosystem_of("sub/build.gradle.kts") == "gradle"


# --- npm / yarn ------------------------------------------------------------

def test_npm_relocks_declared_dependency_keeping_exactness(tmp_path):
    _write(tmp_path, "package.json", json.dumps({"dependencies": {"ws": "8.11.0"}}))
    r = bump(tmp_path, _group("package-lock.json", "ws@8.11.0", "ws@8.21.0"))
    assert r.applied
    assert "npm install --package-lock-only --no-audit --no-fund --save-exact ws@8.21.0" in r.relock_cmd
    assert "--legacy-peer-deps" in r.relock_cmd


def test_npm_transitive_is_not_applied(tmp_path):
    _write(tmp_path, "package.json", json.dumps({"dependencies": {"express": "^4.0.0"}}))
    r = bump(tmp_path, _group("package-lock.json", "qs@6.0.0", "qs@6.5.0"))
    assert not r.applied and r.reason == "not-a-direct-dependency"


def test_yarn_keeps_dev_section(tmp_path):
    _write(tmp_path, "web/package.json", json.dumps({"devDependencies": {"rimraf": "^3.0.2"}}))
    r = bump(tmp_path, _group("web/yarn.lock", "rimraf@3.0.2", "rimraf@6.1.1"))
    assert r.relock_cmd == "cd web && yarn add --dev rimraf@6.1.1"


# --- Python ----------------------------------------------------------------

def test_pip_rewrites_declared_line(tmp_path):
    req = _write(tmp_path, "requirements.txt", "Flask==2.1.2 ; python_version>'3'\nrequests\n")
    assert bump(tmp_path, _group("requirements.txt", "flask@2.1.2", "flask@3.1.3")).applied
    assert req.read_text().splitlines()[0] == "Flask==3.1.3 ; python_version>'3'"


def test_pip_range_becomes_exact(tmp_path):
    req = _write(tmp_path, "requirements.txt", "Flask~=3.0.0\n")
    bump(tmp_path, _group("requirements.txt", "flask@3.0.3", "flask@3.1.3"))
    assert req.read_text() == "Flask==3.1.3\n"


def test_pip_transitive_is_pinned(tmp_path):
    req = _write(tmp_path, "requirements.txt", "requests==2.25.0")
    r = bump(tmp_path, _group("requirements.txt", "urllib3@1.26.0", "urllib3@2.8.0", "pin"))
    assert r.applied and r.relock_cmd == ""
    assert req.read_text().splitlines()[1].startswith("urllib3==2.8.0")


PYPROJECT = """[tool.poetry.dependencies]
python = "^3.9"
httpx = "^0.27"

[tool.poetry.group.dev.dependencies]
pytest = "^7.0"
"""


def test_poetry_transitive_pin_and_declared_group(tmp_path):
    _write(tmp_path, "pyproject.toml", PYPROJECT)
    pin = bump(tmp_path, _group("pyproject.toml", "anyio@4.8.0", "anyio@4.14.2", "pin"))
    assert pin.relock_cmd == "poetry add --lock --no-interaction anyio==4.14.2"
    dev = bump(tmp_path, _group("pyproject.toml", "pytest@7.0.0", "pytest@8.3.0", "pin"))
    assert dev.relock_cmd == "poetry add --lock --no-interaction --group dev pytest==8.3.0"


# --- Maven -----------------------------------------------------------------

POM = """<project>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.7.0</version>
  </parent>
  <properties>
    <jackson.version>2.15.0</jackson.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.h2database</groupId>
      <artifactId>h2</artifactId>
      <version>2.1.214</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>${jackson.version}</version>
    </dependency>
    <dependency>
      <groupId>org.postgresql</groupId>
      <artifactId>postgresql</artifactId>
    </dependency>
  </dependencies>
</project>
"""


def test_maven_literal_property_parent_and_managed(tmp_path):
    pom = _write(tmp_path, "pom.xml", POM)
    for frm, to in (
        ("com.h2database:h2@2.1.214", "com.h2database:h2@2.2.220"),
        ("com.fasterxml.jackson.core:jackson-databind@2.15.0",
         "com.fasterxml.jackson.core:jackson-databind@2.18.11"),
        ("org.springframework.boot:spring-boot-starter-parent@2.7.0",
         "org.springframework.boot:spring-boot-starter-parent@3.5.0"),
        ("org.postgresql:postgresql@42.3.7", "org.postgresql:postgresql@42.7.12"),
    ):
        r = bump(tmp_path, _group("pom.xml", frm, to))
        # Only the versionless postgresql takes its version from the parent.
        assert r.applied and r.managed == frm.startswith("org.postgresql")
    text = pom.read_text()
    assert "<version>2.2.220</version>" in text
    assert "<jackson.version>2.18.11</jackson.version>" in text
    assert "${jackson.version}" in text
    assert "<version>3.5.0</version>" in text
    assert "<artifactId>postgresql</artifactId>\n      <version>42.7.12</version>" in text


def test_maven_undeclared_is_not_applied(tmp_path):
    _write(tmp_path, "pom.xml", POM)
    r = bump(tmp_path, _group("pom.xml", "org.yaml:snakeyaml@1.30", "org.yaml:snakeyaml@2.0"))
    assert not r.applied and r.reason == "not-declared"


# --- Gradle ----------------------------------------------------------------

def test_gradle_literal_scoped_to_manifest_and_root(tmp_path):
    root_build = _write(tmp_path, "build.gradle.kts",
                        'dependencies { testImplementation("ch.qos.logback:logback-classic:1.3.14") }\n')
    other = _write(tmp_path, "tests/app/build.gradle",
                   "implementation 'ch.qos.logback:logback-classic:1.3.14'\n")
    _write(tmp_path, "core/build.gradle", "dependencies {}\n")
    r = bump(tmp_path, _group("core/build.gradle", "ch.qos.logback:logback-classic@1.3.14",
                              "ch.qos.logback:logback-classic@1.6.3"))
    assert r.applied and not r.managed
    assert "logback-classic:1.6.3" in root_build.read_text()
    assert "1.3.14" in other.read_text()


def test_gradle_version_catalog_ref(tmp_path):
    toml = _write(tmp_path, "gradle/libs.versions.toml",
                  '[versions]\nokhttp = "4.9.0"\n\n[libraries]\n'
                  'okhttp = { module = "com.squareup.okhttp3:okhttp", version.ref = "okhttp" }\n')
    _write(tmp_path, "build.gradle.kts", "dependencies { implementation(libs.okhttp) }\n")
    assert bump(tmp_path, _group("build.gradle.kts", "com.squareup.okhttp3:okhttp@4.9.0",
                                 "com.squareup.okhttp3:okhttp@4.12.0")).applied
    assert 'okhttp = "4.12.0"' in toml.read_text()


def test_gradle_interpolated_property(tmp_path):
    props = _write(tmp_path, "gradle.properties", "guavaVersion=31.0-jre\n")
    _write(tmp_path, "build.gradle", 'implementation "com.google.guava:guava:$guavaVersion"\n')
    assert bump(tmp_path, _group("build.gradle", "com.google.guava:guava@31.0-jre",
                                 "com.google.guava:guava@32.0.0-jre")).applied
    assert props.read_text() == "guavaVersion=32.0.0-jre\n"


def test_gradle_versionless_and_transitive(tmp_path):
    build = _write(tmp_path, "app/build.gradle.kts",
                   'dependencies {\n    implementation("org.springframework.boot:spring-boot-starter-web")\n}\n')
    r = bump(tmp_path, _group("app/build.gradle.kts",
                              "org.springframework.boot:spring-boot-starter-web@3.5.16",
                              "org.springframework.boot:spring-boot-starter-web@4.0.0"))
    assert r.managed
    assert '"org.springframework.boot:spring-boot-starter-web:4.0.0"' in build.read_text()
    r = bump(tmp_path, _group("app/build.gradle.kts", "ch.qos.logback:logback-core@1.5.34",
                              "ch.qos.logback:logback-core@1.5.36"))
    assert r.applied and not r.managed
    assert 'constraints {\n        implementation("ch.qos.logback:logback-core:1.5.36")' in build.read_text()


def _bump_cmd(tmp_path, monkeypatch, group, plan):
    monkeypatch.setattr(benchmark, "ensure_claude_image", lambda *a, **kw: "img")
    work, out = tmp_path / "work", tmp_path / "out"
    out.mkdir()
    _write(work, "package.json", json.dumps({"dependencies": {"ws": "^8.0.0"}}))
    cmd, _, mount_snyk = benchmark._agent_command_and_image(
        AGENT_FOR[(HARNESS_PM_BUMP, MODE_SINGLE_UPGRADE)],
        Scenario(name="demo", images={}, test_cmd="npm test", image="node:20"),
        HarnessConfig(), group, out, None, plan, "", work=work,
    )
    return cmd, mount_snyk, json.loads((out / "pm-bump.json").read_text())


def test_pm_bump_agent_relocks_without_snyk_or_llm(tmp_path, monkeypatch):
    g = _group("package-lock.json", "ws@8.11.0", "ws@8.21.0")
    cmd, mount_snyk, record = _bump_cmd(tmp_path, monkeypatch, g, FixPlan(groups=(g,)))
    assert mount_snyk is False
    assert cmd.startswith("npm install") and "claude" not in cmd and "snyk" not in cmd
    assert record["applied"]


def test_pm_bump_agent_not_applied_exits_nonzero(tmp_path, monkeypatch):
    g = _group("package-lock.json", "qs@6.0.0", "qs@6.5.0")
    cmd, _, record = _bump_cmd(tmp_path, monkeypatch, g, FixPlan(groups=(g,)))
    assert cmd.endswith("exit 3") and not record["applied"]


def test_pip_follows_includes(tmp_path):
    _write(tmp_path, "requirements.txt", "-r requirements/packaging.txt\n")
    inc = _write(tmp_path, "requirements/packaging.txt", "wheel>=0.36.2,<0.40.0\n")
    r = bump(tmp_path, _group("requirements.txt", "wheel@0.38.4", "wheel@0.46.2", "pin"))
    assert r.applied
    assert inc.read_text() == "wheel==0.46.2\n"
    assert (tmp_path / "requirements.txt").read_text() == "-r requirements/packaging.txt\n"


def test_min_policy_pins_python_with_lower_bound(tmp_path):
    req = _write(tmp_path, "requirements.txt", "Flask~=3.0.0\n")
    bump(tmp_path, _group("requirements.txt", "flask@3.0.3", "flask@3.1.3"), exact=False)
    bump(tmp_path, _group("requirements.txt", "urllib3@1.26.0", "urllib3@2.8.0", "pin"), exact=False)
    assert req.read_text().splitlines() == ["Flask>=3.1.3", "urllib3>=2.8.0  # transitive pin (package manager bump)"]
    _write(tmp_path, "pyproject.toml", PYPROJECT)
    r = bump(tmp_path, _group("pyproject.toml", "anyio@4.8.0", "anyio@4.14.2", "pin"), exact=False)
    assert r.relock_cmd == "poetry add --lock --no-interaction 'anyio>=4.14.2'"


def test_min_policy_leaves_other_ecosystems_exact(tmp_path):
    pom = _write(tmp_path, "pom.xml", POM)
    bump(tmp_path, _group("pom.xml", "com.h2database:h2@2.1.214", "com.h2database:h2@2.2.220"), exact=False)
    assert "<version>2.2.220</version>" in pom.read_text()


def test_pm_bump_min_agent_uses_lower_bound(tmp_path, monkeypatch):
    monkeypatch.setattr(benchmark, "ensure_claude_image", lambda *a, **kw: "img")
    work, out = tmp_path / "work", tmp_path / "out"
    out.mkdir()
    req = _write(work, "requirements.txt", "flask==2.1.2\n")
    g = _group("requirements.txt", "flask@2.1.2", "flask@3.1.3")
    _, _, mount_snyk = benchmark._agent_command_and_image(
        AGENT_FOR[(HARNESS_PM_BUMP_MIN, MODE_SINGLE_UPGRADE)],
        Scenario(name="demo", images={}, test_cmd="pytest", image="python:3.11"),
        HarnessConfig(), g, out, None, FixPlan(groups=(g,)), "", work=work,
    )
    assert mount_snyk is False and req.read_text() == "flask>=3.1.3\n"


GHOST = json.loads((Path(__file__).parent / "fixtures" / "ghost_before_trimmed.json").read_text())


def _bump_attempt(tmp_path, monkeypatch, agent_exit, declared=True):
    import subprocess

    from harness import docker
    from harness.outcome import BaselineResult

    plan = FixPlan.from_scan(GHOST)
    group = plan.groups[0]
    repos = tmp_path / "repos"
    deps = {group.from_package: group.from_version} if declared else {}
    _write(repos, "demo/package.json", json.dumps({"dependencies": deps}))

    def fake_docker_run(scenario, cfg, work, out, *, phase, **kw):
        if phase == docker.PHASE_AGENT:
            (out / "agent.exit").write_text(f"{agent_exit}\n")
        return subprocess.CompletedProcess([], 0, "", ""), False

    monkeypatch.setattr(benchmark, "docker_run", fake_docker_run)
    monkeypatch.setattr(benchmark, "ensure_claude_image", lambda *a, **kw: "img")
    attempt, _, _ = benchmark.run_attempt(
        Scenario(name="demo", images={}, test_cmd="npm test", image="node:20"),
        HarnessConfig(), repos,
        agent=AGENT_FOR[(HARNESS_PM_BUMP, MODE_SINGLE_UPGRADE)], group=group, plan=plan,
        baseline=BaselineResult(tests_passed_count=1, tests_exit=0), cli_before=GHOST,
    )
    return attempt


def test_failed_relock_fails_the_deps_gate_and_is_not_a_claim(tmp_path, monkeypatch):
    attempt = _bump_attempt(tmp_path, monkeypatch, agent_exit=1)
    assert attempt.deps_ok is False and "deps-unresolved" in attempt.reasons
    assert attempt.agent_claimed == [] and not attempt.claimed_not_fixed
    assert not attempt.harness_error


def test_successful_relock_claims_the_group(tmp_path, monkeypatch):
    attempt = _bump_attempt(tmp_path, monkeypatch, agent_exit=0)
    assert "deps-unresolved" not in attempt.reasons
    assert attempt.agent_claimed == list(attempt.requested_ids)
    assert attempt.pm_bump_managed is False


def test_unapplied_bump_reason_comes_first(tmp_path, monkeypatch):
    attempt = _bump_attempt(tmp_path, monkeypatch, agent_exit=3, declared=False)
    assert attempt.reasons[0] == "bump-not-applied" and "deps-unresolved" not in attempt.reasons


def test_gradle_transitive_under_spring_dependency_management(tmp_path):
    _write(tmp_path, "build.gradle.kts",
           'plugins {\n    id("io.spring.dependency-management") version "1.1.7"\n}\n')
    build = _write(tmp_path, "samples/app/build.gradle.kts", "dependencies {}\n")
    r = bump(tmp_path, _group("samples/app/build.gradle.kts", "ch.qos.logback:logback-core@1.5.34",
                              "ch.qos.logback:logback-core@1.5.36"))
    assert r.applied and r.managed and "managed" in r.edits[0]
    text = build.read_text()
    assert 'dependencyManagement {\n    dependencies {\n        dependency("ch.qos.logback:logback-core:1.5.36")' in text
    assert "constraints" not in text
