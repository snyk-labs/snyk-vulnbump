#!/bin/sh
# Eval runtime trust for corporate TLS interception (bind-mount from $EXTRA_CA_CERT).
#
# This script is sourced from harness/entrypoint.sh when the harness bind-mounts
# the cert and this file into eval containers.
#
# Expects the cert at /etc/ssl/extra-ca.pem. No-op when missing.
#
# NODE_EXTRA_CA_CERTS must point at the extra PEM itself — the Go snyk CLI
# merges it with the system pool. Non-root eval images cannot run
# update-ca-certificates, so build a merged bundle under $HOME.

# NOTE: deliberately no `set -e`. This file is *sourced* by entrypoint.sh, so
# shell options set here persist in the caller — and the entrypoint depends on
# surviving non-zero steps in order to capture each one's exit code. With
# `set -e` leaking in, a failing build or test kills the container before
# `echo $? > /out/build.exit` runs, and a genuine failure is recorded as
# missing artefacts instead. `set -u` is fine and stays.
set -u

CERT=/etc/ssl/extra-ca.pem
BUNDLE=/etc/ssl/certs/ca-certificates.crt
MERGED="${HOME:-/tmp}/extra-ca-bundle.crt"

if [ ! -f "$CERT" ]; then
  return 0 2>/dev/null || exit 0
fi

# Some minimal images ship no system bundle. Fall back to the extra cert alone
# rather than producing an empty file or aborting the run.
if [ -f "$BUNDLE" ]; then
  cat "$BUNDLE" "$CERT" > "$MERGED" 2>/dev/null || cp "$CERT" "$MERGED"
else
  cp "$CERT" "$MERGED"
fi
chmod 644 "$MERGED" 2>/dev/null || true

export SSL_CERT_FILE="$MERGED"
export NODE_EXTRA_CA_CERTS="$CERT"
export PIP_CERT="$MERGED"
export GIT_SSL_CAINFO="$MERGED"

if command -v git >/dev/null 2>&1; then
  git config --global http.sslCAInfo "$MERGED"
fi

# JVM/Maven — the JDK truststore ignores both SSL_CERT_FILE and the system
# bundle, so the cert has to go in via keytool.
#
# keytool -importcert takes ONE certificate. Handed a multi-cert PEM bundle it
# imports at most the first entry, so a bundle that works perfectly for npm,
# pip and curl leaves the JVM untrusting and every maven build fails with a
# PKIX error that never mentions certificates. That is a real bug we shipped:
# switching the harness to accept $NODE_EXTRA_CA_CERTS (usually a bundle) fixed
# npm and silently broke maven. Split the file and import each cert separately
# so either form works.
if [ -n "${JAVA_HOME:-}" ] && command -v keytool >/dev/null 2>&1; then
  _ks="$JAVA_HOME/lib/security/cacerts"
  # The agent sandbox is non-root on a read-only root filesystem, so the JDK's
  # own store can't be written. Import into a private copy instead, as Evo's
  # production sandbox does.
  if [ -f "$_ks" ] && [ ! -w "$_ks" ] && cp "$_ks" "$HOME/jvm-truststore.jks" 2>/dev/null; then
    chmod 644 "$HOME/jvm-truststore.jks"
    _ks="$HOME/jvm-truststore.jks"
    export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:-} -Djavax.net.ssl.trustStore=$_ks"
  fi
  _split_dir="$(mktemp -d)"
  # csplit on each BEGIN line; one file per certificate.
  awk -v dir="$_split_dir" '
    /-----BEGIN CERTIFICATE-----/ { n++ }
    n > 0 { print > sprintf("%s/cert-%04d.pem", dir, n) }
  ' "$CERT" 2>/dev/null || true

  _imported=0
  _failed=0
  for _c in "$_split_dir"/cert-*.pem; do
    [ -f "$_c" ] || continue
    if keytool -importcert -noprompt -trustcacerts \
        -alias "extra-ca-$(basename "$_c" .pem)" \
        -keystore "$_ks" -storepass changeit -file "$_c" >/dev/null 2>&1; then
      _imported=$((_imported + 1))
    else
      _failed=$((_failed + 1))
    fi
  done
  rm -rf "$_split_dir"

  # Say what happened. The previous version swallowed every error into
  # `|| true`, which is why a totally untrusting JVM looked like a healthy
  # setup for an entire benchmark run.
  if [ "$_imported" -gt 0 ]; then
    echo "setup-extra-certs: imported $_imported cert(s) into the JVM truststore" >&2
    [ "$_failed" -gt 0 ] && echo "setup-extra-certs: $_failed cert(s) skipped (already present or unreadable)" >&2
  else
    echo "setup-extra-certs: WARNING - imported 0 certs into $_ks; maven/gradle TLS will fail with PKIX errors" >&2
  fi
fi
