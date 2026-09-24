#!/usr/bin/env bash
# Self-check for setup.sh: env-key sync semantics and the Laya tree-hash rule.
# No root, no network, no venv. Run: bash tests/check_setup_sh.sh
set -euo pipefail

cd "$(dirname "$0")/.."
SETUP=setup.sh
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

bash -n "$SETUP"
echo "ok  syntax"

# _sync_env_key is extracted from setup.sh, never copied: a copy stops testing the
# script the moment the script changes.
eval "$(awk '/^_sync_env_key\(\)/,/^}/' "$SETUP")"

f="$TMP/config.env"
printf '# export USE_TF="0"\n# export OMP_NUM_THREADS="8"\nBLUETEAM_LAYA_ENABLED="true"\n' > "$f"
_sync_env_key "$f" "USE_TF" "0"
_sync_env_key "$f" "OMP_NUM_THREADS" "2"
_sync_env_key "$f" "BLUETEAM_LAYA_ENABLED" "false"
_sync_env_key "$f" "BLUETEAM_CLUSTER_ENABLED" "false"

grep -qx 'USE_TF="0"' "$f"                    || { echo "FAIL commented key not replaced"; exit 1; }
grep -qx 'OMP_NUM_THREADS="2"' "$f"           || { echo "FAIL thread cap not applied"; exit 1; }
grep -qx 'BLUETEAM_LAYA_ENABLED="false"' "$f" || { echo "FAIL existing key not replaced"; exit 1; }
grep -qx 'BLUETEAM_CLUSTER_ENABLED="false"' "$f" || { echo "FAIL missing key not appended"; exit 1; }
! grep -qx 'USE_FLAX="0"' "$f"                || { echo "FAIL USE_TF matched USE_FLAX"; exit 1; }
[ "$(grep -c 'BLUETEAM_LAYA_ENABLED=' "$f")" = 1 ] || { echo "FAIL duplicate key"; exit 1; }

# Second pass must be a no-op: setup.sh re-runs against an existing install.
cp "$f" "$f.before"
_sync_env_key "$f" "USE_TF" "0"
_sync_env_key "$f" "BLUETEAM_CLUSTER_ENABLED" "false"
cmp -s "$f" "$f.before" || { echo "FAIL sync is not idempotent"; exit 1; }
echo "ok  sync"

# The real sync block, extracted from setup.sh and run against fixture env files.
# LAYA_* are resolved by the vendor block above it, so the harness supplies them.
CONFIG_FILE="$TMP/sync-config.env"; ENV_FILE="$TMP/sync.env"
LAYA_ENABLED=false; LAYA_MODEL_PATH=""; LAYA_SHA=""
: > "$CONFIG_FILE"; : > "$ENV_FILE"
eval "$(sed -n '/^# Cluster + Laya blocks/,/^unset -f _sync_env_key/p' "$SETUP")"
for _f in "$CONFIG_FILE" "$ENV_FILE"; do
  for _k in BLUETEAM_CLUSTER_ENABLED BLUETEAM_CLUSTER_STORE BLUETEAM_LAYA_ENABLED USE_TF \
            HF_HUB_OFFLINE OMP_NUM_THREADS MKL_NUM_THREADS OPENBLAS_NUM_THREADS NUMEXPR_NUM_THREADS; do
    grep -qE "^${_k}=\".+\"" "$_f" || { echo "FAIL $_f missing $_k"; exit 1; }
  done
done
# Allow-download off means the hub stays offline.
grep -qx 'HF_HUB_OFFLINE="1"' "$ENV_FILE" || { echo "FAIL offline default"; exit 1; }
echo "ok  cpu hardening"

# Laya tree hash: built from relative paths, so a moved directory keeps its pin.
mkdir -p "$TMP/m1/sub" "$TMP/m2"
printf w > "$TMP/m1/sub/w.bin"; printf '{}' > "$TMP/m1/config.json"
cp -r "$TMP/m1/." "$TMP/m2/"
tree_sha() { (cd "$1" && find . -type f -printf '%P\0' | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}'); }
[ "$(tree_sha "$TMP/m1")" = "$(tree_sha "$TMP/m2")" ] || { echo "FAIL hash is path dependent"; exit 1; }
printf x >> "$TMP/m2/sub/w.bin"
[ "$(tree_sha "$TMP/m1")" != "$(tree_sha "$TMP/m2")" ] || { echo "FAIL hash ignores content"; exit 1; }
# The pipeline above is a copy of setup.sh's by necessity; assert it still matches.
# setup.sh wraps it across a line continuation, so match the two fragments.
[ "$(grep -c 'LC_ALL=C sort -z' "$SETUP")" = 1 ] \
  || { echo "FAIL setup.sh hash rule changed - resync this test"; exit 1; }
[ "$(grep -c 'xargs -0 sha256sum' "$SETUP")" = 1 ] \
  || { echo "FAIL setup.sh hash rule changed - resync this test"; exit 1; }
echo "ok  laya hash"

echo "all checks passed"
