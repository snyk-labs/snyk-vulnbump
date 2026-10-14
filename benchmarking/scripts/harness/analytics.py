"""Parse the agent's analytics JSONL.

The Evo Remediation Agent writes one analytics event per line to a file the
harness configures in env. The typed event payload lives under
`data.attributes.interaction.extension`; status / errors / interaction-id
sit one level up on `interaction`. Each line is `pick_round`, `summary`,
`discuss`, or `test_failure`.

The harness only reads `pick_round` and `summary`: token counts and the
run's summary facts for each attempt.
"""

from __future__ import annotations

import json
from pathlib import Path


def parse_jsonl(path: Path) -> list[dict]:
    """One JSON object per line, as written by the agent's fileEmitter."""
    events: list[dict] = []
    try:
        text = path.read_text()
    except FileNotFoundError:
        return events
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def analytics_facts(events: list[dict]) -> dict:
    """Pull every field we care about from the analytics JSONL envelopes.

    Event types we read:
      pick_round    per-cycle apply totals (counts + tokens). Emitted only
                    when the user picks interactively — auto-approve runs
                    skip pick_round; their apply totals live on summary.
      summary       run-level inventory (start + end), tokens, run metadata.
    """
    facts: dict = {
        "approved": None,
        "input_tokens": 0,
        "output_tokens": 0,
        # plan inventory — summary.fixable_start / unresolved_start
        "vulns_fixable": None,
        "vulns_unresolved": None,
        # summary
        "projects_count": None,
        "vulns_remediated": None,
        "vulns_new": None,
        "agent_iterations": None,
        "provider_model": None,
        "approval_count": None,
        # pick_round aggregates
        "applies_total": 0,
        "applies_success": 0,
        "applies_advisory": 0,
        "applies_error": 0,
        "fix_cycles": 0,
    }
    saw_any = False
    for envelope in events:
        interaction = (
            envelope.get("data", {}).get("attributes", {}).get("interaction", {})
        )
        ext = interaction.get("extension", {})
        if not ext:
            continue
        saw_any = True
        match ext.get("event_type"):
            case "pick_round":
                facts["fix_cycles"] += 1
                s = ext.get("apply_success_count", 0) or 0
                a = ext.get("apply_advisory_count", 0) or 0
                er = ext.get("apply_error_count", 0) or 0
                facts["applies_success"] += s
                facts["applies_advisory"] += a
                facts["applies_error"] += er
                facts["applies_total"] += s + a + er
                if facts["approved"] is None:
                    facts["approved"] = True
            case "summary":
                facts["input_tokens"] = ext.get("agent_input_tokens", facts["input_tokens"])
                facts["output_tokens"] = ext.get("agent_output_tokens", facts["output_tokens"])
                facts["agent_iterations"] = ext.get("agent_iterations", facts["agent_iterations"])
                facts["provider_model"] = ext.get("provider_model", facts["provider_model"])
                facts["approval_count"] = ext.get("approval_count", facts["approval_count"])
                facts["projects_count"] = ext.get("projects_scanned", facts["projects_count"])
                facts["vulns_fixable"] = ext.get("fixable_start", facts["vulns_fixable"])
                facts["vulns_unresolved"] = ext.get("unresolved_start", facts["vulns_unresolved"])
                facts["vulns_remediated"] = ext.get("issues_remediated", facts["vulns_remediated"])
                facts["vulns_new"] = ext.get("issues_new", facts["vulns_new"])
                # `interaction.status` is "success" iff the workflow exit was clean.
                if interaction.get("status") == "success":
                    facts["approved"] = True
    if not saw_any:
        facts["fix_cycles"] = None
    return facts
