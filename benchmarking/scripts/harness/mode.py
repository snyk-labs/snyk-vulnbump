"""Eval run modes — which CLI and Docker image each case uses.

Terminology (used consistently across the repo):

- **release** — latest GA CLI, baked into official ``snyk/snyk`` images.
- **preview** — latest preview CLI published on downloads.snyk.io (preview channel),
  mounted into the cases' own images. The default: ``snyk fix --agentic`` is a
  preview feature.
- **local** — a CLI build at ``build/snyk-local``, mounted like preview.
"""

from __future__ import annotations

from typing import Literal

EvalMode = Literal["release", "preview", "local"]


def mount_snyk_binary(mode: EvalMode) -> bool:
    """True when a host snyk binary is bind-mounted over /usr/local/bin/snyk."""
    return mode in ("preview", "local")


def image_key(mode: EvalMode) -> str:
    """``cases.yaml`` ``inputs.images`` key for this mode."""
    return "release" if mode == "release" else "local"
