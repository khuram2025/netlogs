#!/usr/bin/env bash
# =============================================================================
# build-zenai-release.sh — build + sign a ZenAI OTA update package (.zup)
#
# Usage:
#   ./build-zenai-release.sh <version> [--changelog "text"] [--severity normal|high|critical]
#
# Produces:
#   /tmp/zenai-update-<version>.zup
#
# Environment (required):
#   ZENTRYC_PRIVATE_KEY   Path to Ed25519 private key PEM     (e.g. /home/net/secure/zentryc-zenai.key)
#   ZENAI_SOURCE_DIR      Path to the source tree to package  (e.g. /home/net/net-logs)
#
# Environment (optional):
#   ZENAI_PUBLIC_KEY      Path to matching public key; if set, we re-verify the signature
#                         locally before emitting the .zup (strongly recommended).
#   ZENAI_RELEASE_NOTES   Path to a markdown file whose contents become the changelog.
#
# Notes:
# - The appliance agent interprets manifest.steps[] literally. The default set
#   is tailored for the Zentryc/netlogs appliance (systemd services on the host,
#   FastAPI at /api/health/simple, Python venv under venv/).
# - The build NEVER includes: .git, venv, node_modules, logs, backups, __pycache__.
#   These are runtime / developer state and must not ship to appliances.
# - Signing is done with raw 64-byte Ed25519 signatures (NOT ASCII-armoured),
#   matching what the OTA server + appliance agent expect.
# =============================================================================

set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" || "$VERSION" =~ ^- ]]; then
    echo "Usage: $0 <version> [--changelog \"text\"] [--severity normal|high|critical]" >&2
    exit 1
fi
shift

CHANGELOG="ZenAI appliance release ${VERSION}"
SEVERITY="normal"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --changelog) CHANGELOG="$2"; shift 2 ;;
        --severity)  SEVERITY="$2";  shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# --- Required env -----------------------------------------------------------
: "${ZENTRYC_PRIVATE_KEY:?ZENTRYC_PRIVATE_KEY is required}"
: "${ZENAI_SOURCE_DIR:?ZENAI_SOURCE_DIR is required}"

[[ -f "$ZENTRYC_PRIVATE_KEY" ]] || { echo "Private key not found: $ZENTRYC_PRIVATE_KEY" >&2; exit 1; }
[[ -d "$ZENAI_SOURCE_DIR"   ]] || { echo "Source dir not found: $ZENAI_SOURCE_DIR"   >&2; exit 1; }

if [[ -n "${ZENAI_RELEASE_NOTES:-}" && -f "$ZENAI_RELEASE_NOTES" ]]; then
    CHANGELOG="$(cat "$ZENAI_RELEASE_NOTES")"
fi

# --- Staging layout ---------------------------------------------------------
STAGING="$(mktemp -d -t zenai-build-XXXXXX)"
trap "rm -rf '$STAGING'" EXIT

PAYLOAD_DIR="$STAGING/payload"
mkdir -p "$PAYLOAD_DIR"

echo "[build] staging at:     $STAGING"
echo "[build] source dir:     $ZENAI_SOURCE_DIR"
echo "[build] version:        $VERSION"
echo "[build] severity:       $SEVERITY"

# --- Copy source tree (excluding runtime state) -----------------------------
rsync -a --delete \
    --exclude '.git' \
    --exclude 'venv' \
    --exclude 'node_modules' \
    --exclude '__pycache__' \
    --exclude '*.pyc' \
    --exclude 'logs' \
    --exclude 'backups' \
    --exclude 'netedr_env' \
    --exclude 'db.sqlite3' \
    --exclude '.env' \
    --exclude '*.log' \
    --exclude '.pytest_cache' \
    --exclude '.mypy_cache' \
    "$ZENAI_SOURCE_DIR/" "$PAYLOAD_DIR/"

# --- Write manifest.json ----------------------------------------------------
UPDATE_UUID="$(python3 -c 'import uuid; print(uuid.uuid4())')"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

export CHANGELOG

python3 - "$STAGING" "$VERSION" "$UPDATE_UUID" "$SEVERITY" "$TS" <<'PY'
import json, sys, pathlib
staging, version, update_id, severity, ts = sys.argv[1:6]
import os
changelog = os.environ.get("CHANGELOG", f"ZenAI release {version}")

manifest = {
    "format_version": 2,
    "product": "zenai",
    "update_id": update_id,
    "version": version,
    "severity": severity,
    "arch": "amd64",
    "released_at": ts,
    "changelog": changelog,
    "install_root": "/home/net/net-logs",
    "steps": [
        {"type": "stop_services",  "services": ["zentryc-web", "netlogs-web", "zentryc-syslog", "netlogs-syslog"], "best_effort": True},
        {"type": "backup",         "targets": ["code"], "keep": 5, "destination": "/var/lib/zenai/updater/backups"},
        {"type": "apply_code",     "source": "payload", "destination": "/home/net/net-logs",
         "preserve": [".env", "venv/", "node_modules/", "logs/", "backups/", "db.sqlite3", "netedr_env/"]},
        {"type": "pip_install",    "venv": "/home/net/net-logs/venv", "requirements": "/home/net/net-logs/fastapi_app/requirements.txt", "optional": True},
        {"type": "start_services", "services": ["zentryc-web", "netlogs-web", "zentryc-syslog", "netlogs-syslog"], "best_effort": True},
        {"type": "health_check",   "url": "http://127.0.0.1:8002/api/health/simple", "timeout": 60, "retries": 6}
    ],
    "rollback_steps": [
        {"type": "stop_services",  "services": ["zentryc-web", "netlogs-web", "zentryc-syslog", "netlogs-syslog"], "best_effort": True},
        {"type": "restore_backup", "source": "latest", "destination": "/home/net/net-logs"},
        {"type": "start_services", "services": ["zentryc-web", "netlogs-web", "zentryc-syslog", "netlogs-syslog"], "best_effort": True}
    ]
}

pathlib.Path(staging, "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=False))
print("[build] manifest.json written")
PY

# --- Generate checksums.sha256 over every file in staging -------------------
( cd "$STAGING" && find manifest.json payload -type f -print0 \
    | xargs -0 sha256sum > checksums.sha256 )
echo "[build] checksums.sha256 ($(wc -l < "$STAGING/checksums.sha256") files)"

# --- Sign manifest.json with Ed25519 (raw 64-byte signature) ---------------
python3 - "$STAGING/manifest.json" "$ZENTRYC_PRIVATE_KEY" "$STAGING/manifest.json.sig" <<'PY'
import sys, pathlib
from cryptography.hazmat.primitives.serialization import load_pem_private_key
manifest_path, key_path, sig_path = sys.argv[1:4]
key = load_pem_private_key(pathlib.Path(key_path).read_bytes(), password=None)
sig = key.sign(pathlib.Path(manifest_path).read_bytes())
assert len(sig) == 64, f"unexpected sig length {len(sig)}"
pathlib.Path(sig_path).write_bytes(sig)
print("[build] manifest.json.sig (64 bytes)")
PY

# --- Self-verify (catch key/code drift before upload) -----------------------
if [[ -n "${ZENAI_PUBLIC_KEY:-}" && -f "${ZENAI_PUBLIC_KEY}" ]]; then
python3 - "$STAGING/manifest.json" "$STAGING/manifest.json.sig" "$ZENAI_PUBLIC_KEY" <<'PY'
import sys, pathlib
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
m, s, p = sys.argv[1:4]
pub = load_pem_public_key(pathlib.Path(p).read_bytes())
try:
    pub.verify(pathlib.Path(s).read_bytes(), pathlib.Path(m).read_bytes())
    print("[build] signature verified locally")
except InvalidSignature:
    print("[build] SIGNATURE VERIFICATION FAILED — refusing to emit .zup", file=sys.stderr)
    sys.exit(1)
PY
else
    echo "[build] WARN: ZENAI_PUBLIC_KEY not set — skipped local self-verify"
fi

# --- Tar it up --------------------------------------------------------------
OUT="/tmp/zenai-update-${VERSION}.zup"
( cd "$STAGING" && tar -czf "$OUT" manifest.json manifest.json.sig checksums.sha256 payload )

SIZE=$(stat -c%s "$OUT")
SHA=$(sha256sum "$OUT" | awk '{print $1}')

echo ""
echo "[build] ----------------------------------------------------------------"
echo "[build] OK  ZenAI release built:"
echo "[build]     file:    $OUT"
echo "[build]     size:    $SIZE bytes"
echo "[build]     sha256:  $SHA"
echo "[build]     version: $VERSION"
echo "[build]     product: zenai"
echo "[build] ----------------------------------------------------------------"
echo "[build] Next: upload with  -F product=zenai  per UPDATE_SERVER_HANDOFF.md §3.5"
