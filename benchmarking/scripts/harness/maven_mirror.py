"""Preflight: does the Maven mirror serve Central's bytes unchanged?

A mirror that caches compressed bodies makes Maven drop transitive
dependencies without failing, so every Java result after it is quietly wrong.
Probed from a container, the same network path the attempts take.
"""

from __future__ import annotations

import subprocess

# The POM nginx once cached brotli-encoded. Central never changes a release,
# so its checksum is a constant.
CANARY = "net/sourceforge/htmlunit/htmlunit/2.70.0/htmlunit-2.70.0.pom"
CANARY_SHA1 = "0325616b2b9f61a63f0193e9814fd8110a8081cd"
PROBE_IMAGE = "nginx:stable"   # the mirror's own image, which ships curl

# One request straight through to Central (X-Mirror-Check bypasses the cache)
# and one from the cache, both asking for encodings Maven cannot all decode.
# Prints "<status> <content-encoding> <sha1>" per request.
_PROBE = r"""
for bypass in 1 ""; do
  code=$(curl -sS -o /tmp/p -D /tmp/h -w '%{http_code}' -H 'Accept-Encoding: br, gzip' \
         -H "X-Mirror-Check: $bypass" "$URL") || code=000
  enc=$(grep -i '^content-encoding:' /tmp/h 2>/dev/null | tr -d '\r' | cut -d' ' -f2)
  echo "$code ${enc:-identity} $(sha1sum /tmp/p 2>/dev/null | cut -d' ' -f1)"
done
"""


def problems(probe_output: str) -> list[str]:
    lines = probe_output.strip().splitlines()
    if len(lines) != 2:
        return [f"unexpected probe output: {probe_output.strip()[-300:]!r}"]
    found = []
    for path, line in zip(("upstream", "cached"), lines):
        code, enc, sha1 = (line.split() + ["", "", ""])[:3]
        if code != "200":
            found.append(f"{path} fetch returned HTTP {code}")
        elif enc != "identity":
            found.append(f"{path} fetch came back Content-Encoding: {enc}")
        elif sha1 != CANARY_SHA1:
            found.append(f"{path} fetch has sha1 {sha1}, Central's is {CANARY_SHA1}")
    return found


def check_mirror(mirror_url: str) -> list[str]:
    """Problems with the mirror at mirror_url; empty when it is healthy."""
    url = f"{mirror_url.rstrip('/')}/{CANARY}"
    try:
        out = subprocess.run(
            ["docker", "run", "--rm", "--add-host=host.docker.internal:host-gateway",
             "-e", f"URL={url}", "--entrypoint", "sh", PROBE_IMAGE, "-c", _PROBE],
            capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return [f"probe container failed: {exc}"]
    if out.returncode != 0:
        return [f"probe container exited {out.returncode}: {out.stderr.strip()[-300:]}"]
    return problems(out.stdout)
