"""The package manager bump: bump to Snyk's recommended version, mechanically.

No LLM, no reasoning, no code or test edits. For one fix group it rewrites the
declaration of the package being upgraded to the plan's target version and
returns the command that refreshes the lockfile inside the container. Its PASS
set is the benchmark's Snyk-advice-solvable split: the tasks that Snyk's
recommended upgrade, applied literally to the named package, gets through
every gate. That is a lower bound on triviality: in a managed build (a Maven
parent or BOM, Spring's dependency-management plugin) pinning the named
package leaves the transitives the BOM manages where they were.

Manifest edits happen here, on the host, so they are unit-testable; the
re-lock runs in the fixture image with its own toolchain. When the package's
declaration cannot be found the bump is not applied, which is a result (the
task is not advice-solvable), not a harness error.

Per ecosystem:
  npm / yarn  `npm install <pkg>@<ver>` / `yarn add <pkg>@<ver>` for a declared
              dependency, keeping its section and exact/range style.
  poetry      `poetry add --lock <pkg>==ver`: replaces a declared dependency's
              constraint, or pins a transitive one as a direct dependency.
  pip         requirements.txt (and the files it -r includes): the declared
              line's specifier becomes `==ver`; a transitive package gets an
              appended `pkg==ver` pin.
  Python constraints are exact by default, like every other ecosystem's lock.
  With exact=False (the package-manager-bump-min harness) they are `>=ver` instead, and the
  resolver picks the newest release it can: a second mechanical policy, so the
  split can be reported under both.
  maven       the dependency's <version>, the property it references, or the
              <parent> version; a managed dependency gets an explicit <version>.
  gradle      `g:a:ver` literals, version catalogs, map notation, or the
              variable a coordinate interpolates; a transitive package gets a
              `constraints {}` entry, or a `dependencyManagement` entry under
              Spring's dependency-management plugin, which overrides constraints.
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from .fix_plan import FixGroup, split_package_spec

_SKIP_DIRS = {"node_modules", ".git", "target", "build", ".gradle", ".venv", "dist"}


@dataclass
class BumpResult:
    applied: bool
    edits: list[str] = field(default_factory=list)
    relock_cmd: str = ""
    reason: str = ""
    # The bump pinned a declaration whose version a BOM, parent or Spring's
    # dependency-management plugin manages; the BOM still manages its transitives.
    managed: bool = False


def ecosystem_of(manifest: str) -> str:
    name = Path(manifest).name
    if name in ("package.json", "package-lock.json", "npm-shrinkwrap.json"):
        return "npm"
    if name == "yarn.lock":
        return "yarn"
    if name in ("pyproject.toml", "poetry.lock"):
        return "poetry"
    if name.endswith(".txt"):
        return "pip"
    if name == "pom.xml":
        return "maven"
    if name.endswith((".gradle", ".gradle.kts")):
        return "gradle"
    return ""


_PYTHON = ("pip", "poetry")


def bump(root: Path, group: FixGroup, exact: bool = True) -> BumpResult:
    """Apply one group's bump under `root` (the scan root, i.e. /app or its subdirectory).

    exact=False pins Python packages with `>=` rather than `==`; other ecosystems are unaffected."""
    eco = ecosystem_of(group.manifest)
    handler = _HANDLERS.get(eco)
    if handler is None:
        return BumpResult(False, reason=f"unsupported-manifest:{group.manifest}")
    package, old = group.from_package, group.from_version
    new = split_package_spec(group.to_dep)[1]
    if not package or not new or new == old:
        return BumpResult(False, reason="no-target-version")
    kwargs = {"op": "==" if exact else ">="} if eco in _PYTHON else {}
    return handler(root, Path(group.manifest).parent, package, old, new, group.strategy, **kwargs)


def _in_dir(rel_dir: Path, cmd: str) -> str:
    return cmd if str(rel_dir) in ("", ".") else f"cd {shlex.quote(str(rel_dir))} && {cmd}"


# ---------------------------------------------------------------------------
# npm / yarn
# ---------------------------------------------------------------------------

_NPM_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


def _declared_spec(pkg_json: Path, package: str) -> tuple[str, str] | None:
    try:
        data = json.loads(pkg_json.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None
    for section in _NPM_SECTIONS:
        spec = (data.get(section) or {}).get(package)
        if spec is not None:
            return section, spec
    return None


def _is_exact(spec: str) -> bool:
    return bool(re.fullmatch(r"=?v?\d+\.\d+\.\d+\S*", spec.strip()))


def _bump_npm(root, rel_dir, package, old, new, strategy) -> BumpResult:
    declared = _declared_spec(root / rel_dir / "package.json", package)
    if declared is None:
        return BumpResult(False, reason="not-a-direct-dependency")
    _, spec = declared
    target = shlex.quote(f"{package}@{new}")
    exact = " --save-exact" if _is_exact(spec) else ""
    # Lockfile only: verify installs. Reifying here would fetch every tarball
    # (git deps included) through the agent sandbox, which blocks GitHub.
    base = f"npm install --package-lock-only --no-audit --no-fund{exact} {target}"
    cmd = f"{base} || {base} --legacy-peer-deps"
    return BumpResult(True, [f"{rel_dir / 'package.json'}: {package} {spec} -> {new}"],
                      _in_dir(rel_dir, cmd))


_YARN_FLAGS = {"devDependencies": " --dev", "peerDependencies": " --peer",
               "optionalDependencies": " --optional", "dependencies": ""}


def _bump_yarn(root, rel_dir, package, old, new, strategy) -> BumpResult:
    declared = _declared_spec(root / rel_dir / "package.json", package)
    if declared is None:
        return BumpResult(False, reason="not-a-direct-dependency")
    section, spec = declared
    style = " --exact" if _is_exact(spec) else " --tilde" if spec.startswith("~") else ""
    workspace = " -W" if (root / rel_dir / "package.json").exists() and _is_workspace_root(
        root / rel_dir / "package.json") else ""
    cmd = f"yarn add{_YARN_FLAGS[section]}{style}{workspace} {shlex.quote(f'{package}@{new}')}"
    return BumpResult(True, [f"{rel_dir / 'package.json'}: {package} {spec} -> {new}"],
                      _in_dir(rel_dir, cmd))


def _is_workspace_root(pkg_json: Path) -> bool:
    try:
        return "workspaces" in json.loads(pkg_json.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return False


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------

def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


_POETRY_SECTION = re.compile(
    r"^\[tool\.poetry\.(?:group\.([\w.-]+)\.)?(dev-)?dependencies\]\s*$")


def _poetry_group(pyproject: Path, package: str) -> str | None:
    """The Poetry group declaring `package` ("main" for the main section), or None."""
    try:
        lines = pyproject.read_text().splitlines()
    except FileNotFoundError:
        return None
    group = None
    want = _norm(package)
    for line in lines:
        if line.startswith("["):
            m = _POETRY_SECTION.match(line.strip())
            group = (m.group(1) or ("dev" if m.group(2) else "main")) if m else None
            continue
        if group is None:
            continue
        key = line.split("=", 1)[0].strip().strip('"\'')
        if "=" in line and _norm(key) == want:
            return group
    return None


def _bump_poetry(root, rel_dir, package, old, new, strategy, op="==") -> BumpResult:
    group = _poetry_group(root / rel_dir / "pyproject.toml", package)
    constraint = f"{op}{new}"
    if group is None:
        flag, what = "", "transitive pin"
    else:
        what = f"group {group}"
        flag = "" if group == "main" else f" --group {shlex.quote(group)}"
    cmd = f"poetry add --lock --no-interaction{flag} {shlex.quote(f'{package}{constraint}')}"
    return BumpResult(True, [f"{rel_dir / 'pyproject.toml'}: {package}{constraint} ({what})"],
                      _in_dir(rel_dir, cmd))


_REQ_LINE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?P<extras>\[[^\]]*\])?\s*(?P<spec>[<>=!~][^;#]*)?(?P<rest>.*)$")


_REQ_INCLUDE = re.compile(r"^\s*(?:-r|--requirement)[\s=]+(\S+)")


def _req_files(req: Path, seen: set[Path] | None = None) -> list[Path]:
    """`req` and every file it pulls in with -r, depth first."""
    seen = seen if seen is not None else set()
    if req in seen or not req.is_file():
        return []
    seen.add(req)
    out = [req]
    for line in req.read_text().splitlines():
        m = _REQ_INCLUDE.match(line)
        if m:
            out += _req_files((req.parent / m.group(1)).resolve(), seen)
    return out


def _bump_pip(root, rel_dir, package, old, new, strategy, op="==") -> BumpResult:
    # The file the scan reported, and the files it includes: a package
    # declared in an included file is bumped there, not pinned on top.
    req = root / rel_dir / "requirements.txt"
    if not req.is_file():
        return BumpResult(False, reason="manifest-missing")
    want = _norm(package)
    for f in _req_files(req.resolve()):
        lines = f.read_text().splitlines(keepends=True)
        for i, line in enumerate(lines):
            m = _REQ_LINE.match(line.rstrip("\n"))
            if not m or _norm(m["name"]) != want:
                continue
            rest = m["rest"].strip()
            newline = f"{m['name']}{m['extras'] or ''}{op}{new}{(' ' + rest) if rest else ''}\n"
            lines[i] = newline
            f.write_text("".join(lines))
            rel = f.relative_to(root.resolve())
            return BumpResult(True, [f"{rel}: {line.strip()} -> {newline.strip()}"])
    text = req.read_text()
    sep = "" if not text or text.endswith("\n") else "\n"
    pin = f"{package}{op}{new}  # transitive pin (package manager bump)\n"
    req.write_text(text + sep + pin)
    return BumpResult(True, [f"{req.relative_to(root)}: + {pin.strip()}"])


# ---------------------------------------------------------------------------
# Maven
# ---------------------------------------------------------------------------

_DEP_BLOCK = re.compile(r"<(dependency|parent|plugin)>(.*?)</\1>", re.S)


def _tag(block: str, name: str) -> re.Match | None:
    return re.search(rf"<{name}>\s*([^<]*?)\s*</{name}>", block)


def _files(root: Path, pattern: str) -> list[Path]:
    return sorted(p for p in root.rglob(pattern)
                  if not (_SKIP_DIRS & set(p.relative_to(root).parts[:-1])))


def _bump_maven(root, rel_dir, package, old, new, strategy) -> BumpResult:
    group_id, _, artifact_id = package.partition(":")
    poms = _files(root, "pom.xml")
    manifest = root / rel_dir / "pom.xml"
    # Declarations of g:a across every pom: (pom, block match, version value).
    decls = []
    for pom in poms:
        text = pom.read_text()
        for m in _DEP_BLOCK.finditer(text):
            block = m.group(2)
            g, a = _tag(block, "groupId"), _tag(block, "artifactId")
            if g and a and g.group(1) == group_id and a.group(1) == artifact_id:
                v = _tag(block, "version")
                decls.append((pom, m, v.group(1) if v else None))
    if not decls:
        return BumpResult(False, reason="not-declared")

    def rank(d):
        pom, _, v = d
        return (v is None, v != old and not (v or "").startswith("${"), pom != manifest)

    pom, m, version = sorted(decls, key=rank)[0]
    rel = pom.relative_to(root)
    if version is None:
        # Managed by a parent or BOM: pin it explicitly on the declaration.
        text = pom.read_text()
        block = m.group(0)
        a = _tag(block, "artifactId")
        new_block = block[:a.end()] + f"\n      <version>{new}</version>" + block[a.end():]
        pom.write_text(text[:m.start()] + new_block + text[m.end():])
        return BumpResult(True, [f"{rel}: {package} + <version>{new}</version>"], managed=True)
    prop = re.fullmatch(r"\$\{([^}]+)\}", version)
    if prop:
        name = prop.group(1)
        for p in [pom, *[x for x in poms if x != pom]]:
            text = p.read_text()
            pm = re.search(rf"<{re.escape(name)}>\s*([^<]*?)\s*</{re.escape(name)}>", text)
            if pm and not pm.group(1).startswith("${"):
                p.write_text(text[:pm.start(1)] + new + text[pm.end(1):])
                return BumpResult(True, [f"{p.relative_to(root)}: <{name}> {pm.group(1)} -> {new}"])
        return BumpResult(False, reason=f"property-not-in-repo:{name}")
    text = pom.read_text()
    block = m.group(0)
    v = _tag(block, "version")
    new_block = block[:v.start(1)] + new + block[v.end(1):]
    pom.write_text(text[:m.start()] + new_block + text[m.end():])
    return BumpResult(True, [f"{rel}: {package} {version} -> {new}"])


# ---------------------------------------------------------------------------
# Gradle
# ---------------------------------------------------------------------------

def _gradle_files(root: Path, rel_dir: Path) -> list[Path]:
    """The manifest's own build files plus what every subproject shares (root
    build, gradle/, buildSrc/, gradle.properties). Other subprojects are left alone."""
    out: list[Path] = []
    for d in dict.fromkeys([root / rel_dir, root]):
        out += [d / n for n in ("build.gradle", "build.gradle.kts", "gradle.properties")
                if (d / n).is_file()]
    for shared in ("gradle", "buildSrc"):
        if (root / shared).is_dir():
            base = root / shared
            out += [p for pat in ("*.gradle", "*.gradle.kts", "*.versions.toml", "*.kt")
                    for p in _files(base, pat)]
    return list(dict.fromkeys(out))


def _bump_gradle(root, rel_dir, package, old, new, strategy) -> BumpResult:
    group_id, _, artifact_id = package.partition(":")
    g, a, o = re.escape(group_id), re.escape(artifact_id), re.escape(old)
    files = _gradle_files(root, rel_dir)
    edits: list[str] = []
    managed = False
    variables: set[str] = set()
    catalog_refs: set[str] = set()

    patterns = (
        # "g:a:old" (also with a classifier) in build files and catalogs.
        re.compile(rf"(['\"]{g}:{a}:){o}((?::[^'\"]*)?['\"])"),
        # group: 'g', name: 'a', version: 'old'  /  group = "g", name = "a", version = "old"
        re.compile(rf"(group\s*[:=]\s*['\"]{g}['\"]\s*,\s*name\s*[:=]\s*['\"]{a}['\"]\s*,\s*"
                   rf"version\s*[:=]\s*['\"]){o}(['\"])"),
        # Catalog: module = "g:a", version = "old"
        re.compile(rf"(module\s*=\s*['\"]{g}:{a}['\"]\s*,\s*version\s*=\s*['\"]){o}(['\"])"),
    )
    for f in files:
        text = f.read_text()
        new_text = text
        for p in patterns:
            new_text = p.sub(rf"\g<1>{new}\g<2>", new_text)
        if new_text != text:
            f.write_text(new_text)
            edits.append(f"{f.relative_to(root)}: {package} {old} -> {new}")
        # Interpolated: "g:a:$var" / "g:a:${var}" / "g:a:" + var
        for m in re.finditer(rf"['\"]{g}:{a}:(?:\$\{{?([\w.]+)\}}?|['\"]\s*\+\s*([\w.]+))", text):
            variables.add((m.group(1) or m.group(2)).split(".")[-1])
        # Catalog: module = "g:a", version.ref = "key"  /  group/name + version.ref
        for m in re.finditer(rf"(?:module\s*=\s*['\"]{g}:{a}['\"]|group\s*=\s*['\"]{g}['\"]\s*,\s*"
                             rf"name\s*=\s*['\"]{a}['\"])\s*,\s*version\.ref\s*=\s*['\"]([\w.-]+)['\"]",
                             text):
            catalog_refs.add(m.group(1))
    if not edits:
        for name in variables | catalog_refs:
            n = re.escape(name)
            # name = 'old', val name = "old", set("name", "old"), name=old (properties), ext.name = 'old'
            var_pat = re.compile(
                rf"((?:^|[\s.])(?:val\s+|def\s+)?{n}\s*[=:]\s*['\"]?){o}(['\"]?\s*$)"
                rf"|(set\(\s*['\"]{n}['\"]\s*,\s*['\"]){o}(['\"])", re.M)
            for f in files:
                text = f.read_text()
                new_text = var_pat.sub(
                    lambda m: (m.group(1) or m.group(3)) + new + (m.group(2) or m.group(4)), text)
                if new_text != text:
                    f.write_text(new_text)
                    edits.append(f"{f.relative_to(root)}: {name} {old} -> {new}")
    if not edits:
        # Declared at another version (aligned or overridden elsewhere), or
        # versionless (managed by a BOM or plugin): pin the declaration.
        declared = re.compile(rf"(['\"]{g}:{a})(?::[\w.+-]+)?(['\"])")
        for f in files:
            if f.suffix == ".toml" or f.name == "gradle.properties":
                continue
            text = f.read_text()
            new_text = declared.sub(rf"\g<1>:{new}\g<2>", text)
            if new_text != text:
                f.write_text(new_text)
                edits.append(f"{f.relative_to(root)}: {package} -> {new}")
                # A versionless "g:a" (one colon) takes its version from a BOM or plugin.
                managed |= any(m.group(0).count(":") == 1 for m in declared.finditer(text))
    if not edits:
        # Transitive only: pin it with the build's own mechanism. Spring's
        # dependency-management plugin forces its BOM's versions over plain
        # Gradle constraints, so under it the pin is a managed dependency.
        build = root / rel_dir / _gradle_manifest(root, rel_dir)
        if build.is_file():
            coord = f"{package}:{new}"
            kts = build.suffix == ".kts"
            spring_dm = any("io.spring.dependency-management" in f.read_text()
                            for f in files if f.suffix in (".gradle", ".kts"))
            if spring_dm:
                line = f'        dependency("{coord}")' if kts else f"        dependency '{coord}'"
                block, what = f"dependencyManagement {{\n    dependencies {{\n{line}\n    }}\n}}", "managed"
            else:
                line = f'        implementation("{coord}")' if kts else f"        implementation '{coord}'"
                block, what = f"dependencies {{\n    constraints {{\n{line}\n    }}\n}}", "constraint"
            text = build.read_text()
            sep = "" if text.endswith("\n") else "\n"
            build.write_text(f"{text}{sep}\n{block}\n")
            edits.append(f"{build.relative_to(root)}: + {what} {coord}")
            managed = spring_dm
    if not edits:
        return BumpResult(False, reason="not-declared")
    relock = ""
    if _files(root, "gradle.lockfile"):
        relock = "./gradlew dependencies --write-locks --no-daemon -q"
    return BumpResult(True, edits, relock, managed=managed)


def _gradle_manifest(root: Path, rel_dir: Path) -> str:
    for name in ("build.gradle.kts", "build.gradle"):
        if (root / rel_dir / name).is_file():
            return name
    return "build.gradle"


_HANDLERS = {
    "npm": _bump_npm,
    "yarn": _bump_yarn,
    "poetry": _bump_poetry,
    "pip": _bump_pip,
    "maven": _bump_maven,
    "gradle": _bump_gradle,
}
