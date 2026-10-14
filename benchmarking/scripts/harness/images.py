"""Resolve fixture Docker images from Scenario.images in cases.yaml."""

from __future__ import annotations

from dataclasses import replace

from .mode import EvalMode, image_key
from .scenario import Scenario


def resolve_image(scenario: Scenario, *, mode: EvalMode = "release") -> str:
    """Return the Docker image for a scenario."""
    key = image_key(mode)
    image = scenario.images.get(key)
    if not image:
        raise KeyError(
            f"case {scenario.name!r} missing inputs.images.{key} in cases.yaml"
        )
    return image


def apply_scenario_image(scenario: Scenario, *, mode: EvalMode = "release") -> Scenario:
    """Return a copy of scenario with image set from inputs.images."""
    return replace(scenario, image=resolve_image(scenario, mode=mode))
