#!/bin/sh
# Shared entrypoint for every fixture container. The harness mounts an empty
# host directory at /out; this script writes structured artefacts there for the
# harness to parse back into an outcome.
#
# One script, three phases, selected by PHASE:
#
#   PHASE=baseline  install -> scan -> build -> test -> boot -> plan
#                   Establishes that the pristine fixture is green and emits
#                   the fix plan that becomes the benchmark's denominator.
#                   If this phase is not green the case is INVALID: no fix
#                   verdict derived from an already-broken baseline means
#                   anything.
#
#   PHASE=agent     install -> AGENT_CMD
#   PHASE=verify    install -> scan -> build -> test -> boot
#                   ONE agent's attempt at ONE fix group, then independent
#                   verification, in two containers over the same /app bind
#                   mount (a fresh copy of the pristine fixture every time, so
#                   there is nothing to revert). Verify runs as root with a
#                   fresh /out, like the baseline: nothing the agent left
#                   outside /app (PATH shims, ~/.m2, a pre-written scan file)
#                   reaches it. Snyk is mounted in the agent container unless
#                   the agent must not have it (claude-code-unaided). The agent
#                   container mirrors Evo's production sandbox for every
#                   agent: non-root, read-only root filesystem, HOME=/tmp and
#                   only /app, /out and /tmp writable (docker.py).
#
# Per-fixture inputs (set by the harness via -e):
#   INSTALL_CMD     installs the project's dependencies. Runs before the scan
#                   and again after the agent so the post-scan sees manifest
#                   changes.
#   BUILD_CMD       compile-only command: the build gate. A case without one
#                   reads n/a for that gate.
#   TEST_CMD        the project's own tests (e.g. "npm test").
#   BOOT_CMD        starts the app. With BOOT_CHECK set it is backgrounded and
#                   killed once the probe resolves; without, it runs to
#                   completion and its exit code is the boot result. Empty
#                   means the fixture is a library with no entry point, and
#                   boot is recorded as not-applicable rather than failed.
#   BOOT_CHECK      readiness probe, polled until it exits 0 or BOOT_TIMEOUT_S.
#   BOOT_TIMEOUT_S  default 30.
#   STEP_TIMEOUT_S  wall-clock cap on install/build/test, default 600. Stops a
#                   step that hangs (e.g. a load check that ends up starting a
#                   server) from eating the whole case budget.
#   AGENT_CMD       (PHASE=agent) the agent's command line. The harness composes
#                   it so this script stays agent-agnostic: Evo, Claude Code
#                   with a findings list, or Claude Code with nothing.
#   PLAN_CMD        (PHASE=baseline) the command that emits the fix plan.
#   SCAN_EXCLUDE    comma-separated directory names the scan skips.
#
# Outputs (per phase, whichever ran):
#   /out/install-{before,after}.log
#   /out/build.log        /out/build.exit
#   /out/test-{before,after}.log   /out/test-{before,after}.exit
#   /out/boot.log         /out/boot.exit      (absent when BOOT_CMD is empty)
#   /out/snyk-test-{before,after}.json   scan output incl. depGraph
#   /out/snyk-test-{before,after}.txt    the same scan's human-readable CLI report
#   /out/snyk-test-after-wrapper.{txt,log,json}  the ./mvnw scan, when it failed and
#                         the after-scan was retried without the Maven wrapper
#   /out/fix-plan.json    (PHASE=baseline)
#   /out/agent-debug.log  /out/agent.exit     (PHASE=agent)
#   /out/agent.log        agent stdout only: its CLI output without debug logs
#   /out/agent.seconds    agent wall-clock time, excluding the harness's checks
#   /out/evo-run.log     Evo's own run log (cap_out events); absent for Claude Code
#
# The script never `set -e`s — every step's exit code must be captured. Snyk
# itself exits non-zero when it finds vulns, which is informational.

set -u
OUT=/out
mkdir -p "$OUT"
cd /app

if [ -n "${SUBDIR:-}" ]; then
  cd "$SUBDIR"
fi

PHASE="${PHASE:-baseline}"

# Per-user tool bin directories.
#
# Every agent runs as the host user, not root, in a sandbox shaped like Evo's
# production one (and Claude Code refuses --dangerously-skip-permissions under
# root anyway). Package managers then install
# console scripts under $HOME instead of a system prefix: pip puts them in
# $HOME/.local/bin, gem in $HOME/.gem/.../bin, npm -g in $HOME/.npm-global/bin.
#
# The failure this prevents is nasty because it looks like a real result: the
# LIBRARIES import fine, so build and boot pass, but `pytest` is not on PATH,
# the test step exits 127, and the attempt is recorded as tests-regressed. That
# is a harness artifact scored as the agent breaking the app.
# Added UNCONDITIONALLY, not gated on the directory existing: pip creates
# $HOME/.local/bin during install_cmd, which runs after this point. Checking
# for it here would always miss. A PATH entry that never materialises is inert.
if [ -n "${HOME:-}" ]; then
  PATH="$HOME/.local/bin:$HOME/.npm-global/bin:$HOME/bin:$PATH"
  # Ruby's gem bin path is version-scoped, so glob it — but only entries that
  # actually exist, since an unexpanded glob would land in PATH literally.
  for _bin in "$HOME"/.gem/ruby/*/bin; do
    [ -d "$_bin" ] && PATH="$_bin:$PATH"
  done
  export PATH
fi

# Extra CA certificates — see harness/setup-extra-certs.sh (mounted at /setup-extra-certs.sh).
if [ -f /setup-extra-certs.sh ]; then
  . /setup-extra-certs.sh
fi
# Re-assert this script's contract after sourcing. A sourced fragment's shell
# options persist in the caller, and an inherited `set -e` would abort the run
# at the first failing step — losing the exit code we came here to record.
set +e
set -u

# Run a command under a wall-clock cap, so a step that hangs cannot consume
# the whole case budget while doing nothing.
#
# This is not hypothetical. A load check like `node -e "require('./start')"`
# returns only because start.js guards its listen() with
# `require.main === module`. Agents rewrite this code — that is the entire
# point of the benchmark — and a fix that drops the guard turns the build step
# into a server that never exits. Timing out yields a real failure verdict
# instead of a silent stall.
#
# `timeout` is coreutils and present on every fixture image; fall back to
# running unguarded rather than failing if some image lacks it.
STEP_TIMEOUT_S="${STEP_TIMEOUT_S:-600}"

run_step() {
  cmd="$1"
  if command -v timeout >/dev/null 2>&1; then
    timeout --signal=TERM --kill-after=15 "$STEP_TIMEOUT_S" sh -c "$cmd"
  else
    sh -c "$cmd"
  fi
}

run_install() {
  # $1 = log suffix (before|after)
  [ -n "${INSTALL_CMD:-}" ] || return 0
  run_step "$INSTALL_CMD" > "$OUT/install-$1.log" 2>&1
  rc=$?
  [ "$rc" -eq 124 ] && echo "[harness] install exceeded ${STEP_TIMEOUT_S}s and was killed" >> "$OUT/install-$1.log"
  echo "$rc" > "$OUT/install-$1.exit"
}

run_build() {
  # Compile-only: the build gate (verdict.py).
  [ -n "${BUILD_CMD:-}" ] || return 0
  run_step "$BUILD_CMD" > "$OUT/build.log" 2>&1
  rc=$?
  # 124 is timeout's signal that it killed the command.
  [ "$rc" -eq 124 ] && echo "[harness] build exceeded ${STEP_TIMEOUT_S}s and was killed" >> "$OUT/build.log"
  echo "$rc" > "$OUT/build.exit"
}

run_tests() {
  # $1 = log suffix (before|after)
  [ -n "${TEST_CMD:-}" ] || return 0
  run_step "$TEST_CMD" > "$OUT/test-$1.log" 2>&1
  rc=$?
  [ "$rc" -eq 124 ] && echo "[harness] tests exceeded ${STEP_TIMEOUT_S}s and were killed" >> "$OUT/test-$1.log"
  echo "$rc" > "$OUT/test-$1.exit"
}

# run_boot proves the app still starts. The fixtures' unit tests hand the
# in-process app object to the test client and never bind a port, so a
# dependency bump that breaks startup (chalk 5's ESM-only export, Flask 3
# dropping the Markup symbol) can pass every test. This is the check that
# catches it.
#
# Writes /out/boot.exit only when BOOT_CMD is set. Its absence is how the
# harness distinguishes "not applicable" from "failed".
run_boot() {
  [ -n "${BOOT_CMD:-}" ] || return 0

  if [ -z "${BOOT_CHECK:-}" ]; then
    # Entry-point shape: run to completion, exit code is the answer.
    sh -c "$BOOT_CMD" > "$OUT/boot.log" 2>&1
    echo $? > "$OUT/boot.exit"
    return 0
  fi

  # Server shape: background it, poll until ready, then shut it down.
  sh -c "$BOOT_CMD" > "$OUT/boot.log" 2>&1 &
  boot_pid=$!

  timeout_s="${BOOT_TIMEOUT_S:-30}"
  deadline=$(( $(date +%s) + timeout_s ))
  rc=1
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if ! kill -0 "$boot_pid" 2>/dev/null; then
      # Died before becoming ready. Leave rc=1; boot.log has the reason.
      echo "[harness] boot process exited before readiness" >> "$OUT/boot.log"
      break
    fi
    if sh -c "$BOOT_CHECK" >/dev/null 2>&1; then
      rc=0
      break
    fi
    sleep 1
  done

  if [ "$rc" -ne 0 ] && kill -0 "$boot_pid" 2>/dev/null; then
    echo "[harness] readiness probe did not pass within ${timeout_s}s" >> "$OUT/boot.log"
  fi
  echo "$rc" > "$OUT/boot.exit"

  # Shut down: children first (the app is usually a grandchild of `sh -c`),
  # then the wrapper. Best-effort; the container is --rm either way.
  pkill -P "$boot_pid" 2>/dev/null || true
  kill "$boot_pid" 2>/dev/null || true
  wait "$boot_pid" 2>/dev/null || true
}

run_scan() {
  # $1 = before|after. --all-projects matches Evo's own scan scope, so the
  # denominator covers every manifest Evo acts on. --print-deps populates
  # depGraph, which the collateral check diffs. It also prints the tree to
  # stdout, not deduped, which reached 10GB on CocoaPods projects, so the tree
  # lines ("name @ version" roots and │├└ branches) are dropped as they stream
  # and snyk-test-$1.txt keeps just the usual CLI report.
  # SCAN_EXCLUDE skips directories whose tree never finishes building.
  # --ignore-policy: a .snyk file (e.g. from the agent running `snyk ignore`)
  # must not hide vulns from the harness's own scan. The stale-file rm means a
  # scan that fails to write its JSON reads as failed, never as a leftover.
  rm -f "$OUT/snyk-test-$1.json" "$OUT"/snyk-test-$1-wrapper.*
  scan_once "$1"
  # Snyk resolves Maven projects with the repo's ./mvnw. A fix that outgrows
  # the pinned Maven (e.g. a Spring Boot 3+ parent on a 3.5 wrapper) leaves the
  # rescan unable to build the tree, which hides whether the vulns are gone.
  # Re-scan once with the wrappers moved aside so snyk uses the image's mvn.
  # Install/build/test still run through ./mvnw, so the stale wrapper fails
  # there. The wrapper scan's output is kept as snyk-test-after-wrapper.*.
  if [ "$1" = after ] \
    && grep -qs "Cannot build Maven dependency tree" "$OUT/snyk-test-after.txt" "$OUT/snyk-test-after.log"; then
    wrappers=$(find . -name mvnw -type f -not -path '*/node_modules/*' 2>/dev/null)
    if [ -n "$wrappers" ]; then
      for ext in json txt log; do
        [ -f "$OUT/snyk-test-after.$ext" ] && mv "$OUT/snyk-test-after.$ext" "$OUT/snyk-test-after-wrapper.$ext"
      done
      for w in $wrappers; do mv "$w" "$w.harness-bak"; done
      scan_once after
      for w in $wrappers; do mv "$w.harness-bak" "$w"; done
    fi
  fi
}

scan_once() {
  snyk test --all-projects ${SCAN_EXCLUDE:+--exclude="$SCAN_EXCLUDE"} --ignore-policy --debug \
    --json-file-output="$OUT/snyk-test-$1.json" --print-deps \
    2> "$OUT/snyk-test-$1.log" \
    | LC_ALL=C grep -vE '^[[:space:]]*(│|├|└)|^[^[:space:]]+ @ [^[:space:]]+$' \
    > "$OUT/snyk-test-$1.txt" || true
}

# The agent's stdout (what a user sees in the terminal) goes to agent.log.
# agent-debug.log keeps stdout and stderr (Evo's --debug log) interleaved,
# since the harness parses it for claims, tokens and cost.
run_agent() {
  : > "$OUT/agent-debug.log"
  { start=$(date +%s); sh -c "${AGENT_CMD:-}"; echo $? > "$OUT/agent.exit"
    echo $(( $(date +%s) - start )) > "$OUT/agent.seconds"; } 2>> "$OUT/agent-debug.log" \
    | tee "$OUT/agent.log" >> "$OUT/agent-debug.log"
  # Evo's own run log (where it records hitting its iteration cap) is a file
  # under the container's config dir, not stdout; keep it before the
  # container goes. Claude Code has none.
  cp "${XDG_CONFIG_HOME:-$HOME/.config}/snyk/snyk-remediation.log" "$OUT/evo-run.log" \
    2>/dev/null || true
}

hand_back_ownership() {
  # Bind mounts are host-owned; toolchains run as root and leave root-owned
  # artefacts. Hand ownership back so the harness can read /out and /app.
  if [ -n "${HOST_UID:-}" ] && [ -n "${HOST_GID:-}" ]; then
    chown -R "${HOST_UID}:${HOST_GID}" "$OUT" /app 2>/dev/null || true
  fi
}

case "$PHASE" in
  baseline)
    run_install before
    # Scan before build/test: test suites can generate whole projects (remix
    # writes ~2800 apps to .tmp/) that --all-projects would then crawl.
    run_scan before
    run_build
    run_tests before
    run_boot
    # The fix plan: one entry per fix group, with the vuln ids it resolves and
    # its declared collateral. Every agent is scored against this one plan.
    if [ -n "${PLAN_CMD:-}" ]; then
      sh -c "$PLAN_CMD" > "$OUT/plan.log" 2>&1
      echo $? > "$OUT/plan.exit"
    fi
    ;;

  agent)
    # Agent ONLY. The harness follows this with PHASE=verify against the same
    # /app. For claude-code-unaided no snyk is mounted here, so the scanner is
    # absent rather than merely hidden, and Snyk's hosts are unreachable.
    # GitHub is unreachable for every agent (docker.py).
    # Seed the Gradle wrapper's distribution: its download redirects to GitHub.
    _dist=$(sed -n 's|^distributionUrl=.*/\(gradle-[^/]*\)\.zip$|\1|p' \
      /app/gradle/wrapper/gradle-wrapper.properties 2>/dev/null)
    if [ -n "$_dist" ] && [ -d "/gradle-dists/$_dist" ]; then
      _dists="${GRADLE_USER_HOME:-$HOME/.gradle}/wrapper/dists"
      mkdir -p "$_dists" && cp -r "/gradle-dists/$_dist" "$_dists/"
    fi
    run_install before
    # Composed by the harness so this script does not need to know which
    # agent is running.
    run_agent
    ;;

  verify)
    # Verification ONLY: no agent runs. Reads whatever state a previous
    # PHASE=agent container left in /app. Re-install so build/test/boot and
    # the scan all see the manifest change.
    run_install after
    run_scan after
    run_build
    run_tests after
    run_boot
    ;;

  *)
    echo "unknown PHASE: $PHASE" >&2
    hand_back_ownership
    exit 2
    ;;
esac

hand_back_ownership
exit 0
