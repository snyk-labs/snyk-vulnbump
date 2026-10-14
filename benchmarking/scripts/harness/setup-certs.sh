#!/usr/bin/env bash
# Extract the corporate root CA that is intercepting TLS on this machine and
# write it where the eval harness expects it.
#
# Why this exists: under an intercepting proxy (Zscaler, Netskope, a corporate
# Charles/mitmproxy setup) every package install inside the build containers
# fails, and the errors are actively misleading — npm reports "Exit handler
# never called!", apt reports "Unable to locate package". Nothing mentions
# certificates. This turns a lost hour into one command.
#
# Usage: benchmarking/scripts/harness/setup-certs.sh

set -eu

DEST_DIR="${HOME}/.extra-certs"
DEST="${DEST_DIR}/corporate-root-ca.crt"

# Roots we know are used for TLS interception, most common first. Matched
# against the System keychain by common-name substring.
KNOWN_INTERCEPTORS="Zscaler Root CA
Netskope Certificate Authority
Palo Alto Networks
Blue Coat
Forcepoint
McAfee Web Gateway
Charles Proxy CA
mitmproxy"

if [ "$(uname -s)" != "Darwin" ]; then
  cat >&2 <<'EOF'
This helper only automates extraction on macOS.

On Linux, your corporate root is usually already in
/usr/local/share/ca-certificates/ or /etc/pki/ca-trust/source/anchors/.
Point EXTRA_CA_CERT at that PEM file, e.g.:

  export EXTRA_CA_CERT=/usr/local/share/ca-certificates/corporate-root.crt
EOF
  exit 1
fi

mkdir -p "$DEST_DIR"

found=""
while IFS= read -r name; do
  [ -n "$name" ] || continue
  if security find-certificate -c "$name" -p /Library/Keychains/System.keychain \
       > "${DEST}.tmp" 2>/dev/null && [ -s "${DEST}.tmp" ]; then
    found="$name"
    mv "${DEST}.tmp" "$DEST"
    break
  fi
done <<EOF
$KNOWN_INTERCEPTORS
EOF
rm -f "${DEST}.tmp"

if [ -z "$found" ]; then
  cat >&2 <<'EOF'
No known interception root found in the System keychain.

If your proxy uses a root we don't know about, find its exact name with:

  security find-certificate -a /Library/Keychains/System.keychain | grep '"labl"'

then extract it yourself:

  security find-certificate -c "<EXACT NAME>" -p /Library/Keychains/System.keychain \
    > ~/.extra-certs/corporate-root-ca.crt
  export EXTRA_CA_CERT=~/.extra-certs/corporate-root-ca.crt
EOF
  exit 1
fi

echo "Extracted: $found"
echo "Wrote:     $DEST"
openssl x509 -in "$DEST" -noout -subject -dates 2>/dev/null || true
cat <<EOF

Add this to your shell profile so non-interactive shells see it too
(~/.zshenv rather than ~/.zshrc — the latter is skipped by non-interactive
shells, which is how \`make\` and CI invoke things):

  export EXTRA_CA_CERT="$DEST"
EOF
