import copy
import json
from pathlib import Path

from harness.benchmark import _paths_cleared, _paths_moved, _target_instances
from harness.fix_plan import FixGroup, FixPlan
from harness.snyk import split_new_projects, vuln_instances, vuln_paths

GHOST = json.loads((Path(__file__).parent / "fixtures" / "ghost_before_trimmed.json").read_text())
UUID = "SNYK-JS-UUID-16133035"


def _drop_paths(scan, pred):
    after = copy.deepcopy(scan)
    after["vulnerabilities"] = [v for v in after["vulnerabilities"] if not pred(v)]
    return after


def _group(plan, pkg):
    return next(g for g in plan.groups if g.from_package == pkg)


def _score(group, before, after):
    """Mirror run_attempt's single-upgrade clearing: (targets, cleared instances)."""
    targets = _target_instances(vuln_instances(before), [group])
    bp, ap = vuln_paths(before), vuln_paths(after)
    gone = {k for k in targets if _paths_cleared(group, bp.get(k, []), ap.get(k, []))}
    return targets, gone


def test_shared_id_cleared_for_errors_group_only():
    plan = FixPlan.from_scan(GHOST)
    errors, validator = _group(plan, "@tryghost/errors"), _group(plan, "@tryghost/validator")
    assert UUID in errors.vuln_ids and UUID in validator.vuln_ids

    # Only the direct @tryghost/errors path is gone; validator still pulls errors@1.3.2.
    after = _drop_paths(GHOST, lambda v: v["id"] == UUID and v["from"][1].startswith("@tryghost/errors@"))

    targets, gone = _score(errors, GHOST, after)
    assert targets == gone == {("package-lock.json", UUID)}

    targets, gone = _score(validator, GHOST, after)
    assert ("package-lock.json", UUID) in targets
    assert ("package-lock.json", UUID) not in gone


def test_still_vulnerable_after_upgrade_is_not_cleared():
    plan = FixPlan.from_scan(GHOST)
    errors = _group(plan, "@tryghost/errors")
    after = copy.deepcopy(GHOST)
    for v in after["vulnerabilities"]:
        if v["from"][1] == "@tryghost/errors@1.3.2":
            v["from"][1] = "@tryghost/errors@2.0.0"  # bumped, but not far enough
    _, gone = _score(errors, GHOST, after)
    assert gone == set()


def test_pin_owns_every_path_to_the_package():
    pin = FixGroup(index=0, strategy="pin", from_dep="urllib3@1.26.0", to_dep="urllib3@1.26.18",
                   vuln_ids=("X",))
    assert pin.owns_path(["app@0", "requests@2.25.0", "urllib3@1.26.0"])
    assert pin.owns_path(["app@0", "urllib3@1.26.0"])
    assert not pin.owns_path(["app@0", "urllib3-extra@1.0"])


MAVEN = {
    "packageManager": "gradle",
    "displayTargetFile": "build.gradle",
    "vulnerabilities": [
        {"id": "SNYK-JAVA-ORGTESTNG-3040285", "severity": "medium",
         "from": ["rxjava@3.0.0-SNAPSHOT", "org.testng:testng@7.5"]},
        {"id": "SNYK-JAVA-ORGTESTNG-3040285", "severity": "medium",
         "from": ["rxjava@3.0.0-SNAPSHOT", "org.reactivestreams:reactive-streams-tck@1.0.4",
                  "org.testng:testng@7.5"]},
    ],
    "remediation": {"upgrade": {"org.testng:testng@7.5": {
        "upgradeTo": "org.testng:testng@7.5.1",
        "vulns": ["SNYK-JAVA-ORGTESTNG-3040285"]}}, "pin": {}, "unresolved": []},
}


def test_maven_direct_path_cleared_despite_unfixable_transitive():
    (group,) = FixPlan.from_scan(MAVEN).groups
    assert group.from_package == "org.testng:testng"
    after = _drop_paths(MAVEN, lambda v: len(v["from"]) == 2)
    targets, gone = _score(group, MAVEN, after)
    assert targets == gone == {("build.gradle", "SNYK-JAVA-ORGTESTNG-3040285")}

    _, gone = _score(group, MAVEN, MAVEN)
    assert gone == set()


def test_falls_back_to_all_paths_when_no_path_matches_group():
    group = FixGroup(index=0, strategy="upgrade", from_dep="unrelated@1.0", to_dep="unrelated@2.0",
                     vuln_ids=(UUID,), manifest="package-lock.json")
    bp = vuln_paths(GHOST)[("package-lock.json", UUID)]
    assert not _paths_cleared(group, bp, bp[:1])
    assert _paths_cleared(group, bp, [])


def _upgrade(dep):
    return FixGroup(index=0, strategy="upgrade", from_dep=dep, to_dep=dep, vuln_ids=("X",))


def test_vuln_moved_onto_new_direct_dep_is_not_cleared():
    group = _upgrade("a@1.0")
    before = [["app@0", "a@1.0", "t@1.0"]]
    after = [["app@0", "t@1.1"]]  # agent declared t directly, still vulnerable
    assert not _paths_cleared(group, before, after)
    assert _paths_moved(group, before, after)


def test_relocated_maven_coordinate_is_not_cleared():
    group = _upgrade("org.apache.activemq:artemis-jms-client@2.28.0")
    before = [["a@1", "org.apache.activemq:artemis-jms-client@2.28.0", "io.netty:netty-codec-http@4.1.0"]]
    after = [["a@1", "org.apache.artemis:artemis-jms-client@2.57.0",
              "org.apache.artemis:artemis-core-client@2.57.0", "io.netty:netty-codec-http@4.1.137"]]
    assert not _paths_cleared(group, before, after)
    assert _paths_moved(group, before, after)


def test_untouched_path_no_group_can_clear_does_not_block():
    group = _upgrade("bcrypt@5.0.1")
    unowned = ["app@0", "parser@1.0.16", "npm@7.23.0", "strip-ansi@4.0.0", "ansi-regex@3.0.0"]
    before = [["app@0", "bcrypt@5.0.1", "ansi-regex@5.0.0"], unowned]
    assert _paths_cleared(group, before, [unowned])
    # Versions churning inside that path are still the same direct dependency.
    churned = ["app@0", "parser@1.0.16", "npm@7.24.0", "strip-ansi@6.0.0", "ansi-regex@3.0.0"]
    assert _paths_cleared(group, before, [churned])
    assert not _paths_moved(group, before, [churned])


def test_own_path_still_present_is_not_moved():
    group = _upgrade("a@1.0")
    before = [["app@0", "a@1.0", "t@1.0"]]
    after = [["app@0", "a@1.0", "t@1.0"], ["app@0", "t@1.1"]]
    assert not _paths_cleared(group, before, after)
    assert not _paths_moved(group, before, after)


def test_scratch_manifests_are_flagged_not_scored():
    before = [{"displayTargetFile": "pom.xml", "vulnerabilities": []}]
    after = [
        {"displayTargetFile": "pom.xml", "vulnerabilities": [{"id": "A"}]},
        {"displayTargetFile": "tmp-extract/META-INF/maven/x/y/pom.xml",
         "vulnerabilities": [{"id": "B"}]},
    ]
    kept, new = split_new_projects(before, after)
    assert set(vuln_instances(kept)) == {("pom.xml", "A")}
    assert new == ["tmp-extract/META-INF/maven/x/y/pom.xml"]
    assert split_new_projects(before, None) == (None, [])
