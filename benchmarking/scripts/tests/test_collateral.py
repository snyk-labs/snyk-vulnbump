from harness.collateral import same_family, unrelated_bumps
from harness.fix_plan import FixGroup, FixPlan
from harness.outcome import DepChange


def _scan(edges: dict[str, list[str]]) -> dict:
    """A one-project scan whose depGraph has `root` plus the given name@version edges."""
    ids = set(edges) | {d for deps in edges.values() for d in deps}
    return {"depGraph": {
        "pkgs": [{"id": i, "info": {"name": i.rpartition("@")[0] or i}} for i in ids],
        "graph": {"rootNodeId": "root", "nodes": [
            {"nodeId": n, "pkgId": n, "deps": [{"nodeId": d} for d in deps]}
            for n, deps in edges.items()
        ]},
    }}


def test_same_family():
    assert same_family("com.fasterxml.jackson.core:jackson-core",
                       "com.fasterxml.jackson.datatype:jackson-datatype-jsr310")
    assert same_family("io.netty:netty-handler", "io.netty:netty-common")
    assert same_family("@nestjs/core", "@nestjs/common")
    assert not same_family("org.springframework:spring-core",
                           "org.springframework.boot:spring-boot")
    assert not same_family("express", "body-parser")


def test_only_direct_out_of_lane_bumps_are_unrelated():
    before = _scan({
        "root": ["express@4.17.1", "pandas@2.0.3", "@nestjs/common@11.0.0"],
        "express@4.17.1": ["bytes@3.0.0"],
    })
    after = _scan({
        "root": ["express@4.22.3", "pandas@2.2.3", "@nestjs/common@11.2.0", "debug@4.0.0"],
        "express@4.22.3": ["bytes@3.1.2", "depd@2.0.0"],
    })
    group = FixGroup(index=0, strategy="upgrade", from_dep="express@4.17.1",
                     to_dep="express@4.22.3", vuln_ids=("V",))
    plan = FixPlan(groups=(group,))
    changed = [
        DepChange(name="express", before="4.17.1", after="4.22.3"),
        DepChange(name="bytes", before="3.0.0", after="3.1.2"),   # in express's subtree
        DepChange(name="depd", after="2.0.0"),                    # added, not a bump
        DepChange(name="debug", after="4.0.0"),                   # added direct dep
        DepChange(name="pandas", before="2.0.3", after="2.2.3"),  # unrelated
        DepChange(name="lodash", before="4.17.20", after="4.17.21"),  # transitive
    ]
    assert unrelated_bumps(before, after, changed, plan, group, group) == ("pandas",)
