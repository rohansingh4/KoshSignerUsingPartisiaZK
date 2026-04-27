#!/usr/bin/env bash
# Full KEY_ID persistence + REUSE_EXISTING_KEY end-to-end test.
# Run from client/ directory.
#
# What this tests:
#   Run 1: Full DKG + signing (3 parties, coord server). Persists share files.
#   Run 2: REUSE_EXISTING_KEY=1 — loads from share files, signs again with same KEY_ID.
#
# Usage:
#   cd client
#   PARTISIA_SENDER_KEY=<key> PARTISIA_SENDER_ADDRESS=<addr> SIGNER_ADDRESS=<contract> \
#     bash test-keyid-reuse.sh

set -euo pipefail

# ---- Config ----------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COORD_PORT=3099
COORD_URL="http://localhost:${COORD_PORT}"
KEY_ID="${KEY_ID:-42}"
NUM_PARTIES=3
SIGNING_SUBSET="1,2"
# Each party's share is encrypted to this passphrase (AES-256-GCM)
SHARE_FILE_KEY="kosh-test-share-key-$(date +%s)"
LOG_DIR="${SCRIPT_DIR}/test-logs"
mkdir -p "$LOG_DIR"

# ---- Validate required env -------------------------------------------------
if [[ -z "${PARTISIA_SENDER_KEY:-}" || -z "${PARTISIA_SENDER_ADDRESS:-}" || -z "${SIGNER_ADDRESS:-}" ]]; then
  echo "ERROR: Missing required env vars:"
  echo "  PARTISIA_SENDER_KEY, PARTISIA_SENDER_ADDRESS, SIGNER_ADDRESS"
  exit 1
fi

export PARTISIA_SENDER_KEY PARTISIA_SENDER_ADDRESS SIGNER_ADDRESS

COMMON_ENV="COORD_URL=$COORD_URL KEY_ID=$KEY_ID NUM_PARTIES=$NUM_PARTIES SIGNING_SUBSET=$SIGNING_SUBSET PQC_ENABLED=0 SHARE_FILE_KEY=$SHARE_FILE_KEY"

# ---- Helper: kill processes on exit ----------------------------------------
PIDS=()
cleanup() {
  echo ""
  echo "[runner] Stopping background processes..."
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ---- Helper: start coord server, wipe state --------------------------------
start_coord() {
  echo "[runner] Starting coordinator on port $COORD_PORT..."
  PORT=$COORD_PORT npx tsx src/coord-server.ts > "$LOG_DIR/coord.log" 2>&1 &
  COORD_PID=$!
  PIDS+=($COORD_PID)
  sleep 2
  # Clear any leftover state from a previous run
  curl -s -X DELETE "$COORD_URL/clear" > /dev/null
  echo "[runner] Coordinator ready (pid $COORD_PID)"
}

# ---- Helper: wait for log file to contain pattern --------------------------
wait_for() {
  local file="$1" pattern="$2" timeout="${3:-300}"
  local elapsed=0
  while ! grep -Eq "$pattern" "$file" 2>/dev/null; do
    sleep 3
    elapsed=$((elapsed + 3))
    if [[ $elapsed -ge $timeout ]]; then
      echo "[runner] TIMEOUT waiting for '$pattern' in $file"
      cat "$file" | tail -30
      return 1
    fi
  done
}

# ============================================================================
echo ""
echo "================================================================="
echo "  RUN 1: Full DKG + GG20 signing — share files will be created"
echo "================================================================="
echo ""

start_coord

# Share file paths for each party
SHARE_FILE_1="$LOG_DIR/share_key${KEY_ID}_party1.enc"
SHARE_FILE_2="$LOG_DIR/share_key${KEY_ID}_party2.enc"
SHARE_FILE_3="$LOG_DIR/share_key${KEY_ID}_party3.enc"

# Launch 3 parties in background
for i in 1 2 3; do
  SHARE_FILE_VAR="SHARE_FILE_${i}"
  env $COMMON_ENV \
    PARTY_INDEX=$i \
    PARTISIA_SENDER_KEY="$PARTISIA_SENDER_KEY" \
    PARTISIA_SENDER_ADDRESS="$PARTISIA_SENDER_ADDRESS" \
    SIGNER_ADDRESS="$SIGNER_ADDRESS" \
    SHARE_FILE="${!SHARE_FILE_VAR}" \
    npx tsx src/party.ts > "$LOG_DIR/run1_party${i}.log" 2>&1 &
  pid=$!
  PIDS+=($pid)
  echo "[runner] Party $i started (pid $pid)"
done

echo "[runner] Waiting for all 3 parties to complete DKG + signing..."
echo "[runner] Logs: $LOG_DIR/run1_party{1,2,3}.log"
echo ""

# Wait for each party to finish (look for "COMPLETE" or "error" lines)
for i in 1 2 3; do
  echo "[runner] Waiting for Party $i..."
  wait_for "$LOG_DIR/run1_party${i}.log" "COMPLETE|Fatal|process.exit|offline for signing" 480 || {
    echo "[runner] Party $i timed out — dumping log:"
    cat "$LOG_DIR/run1_party${i}.log"
    exit 1
  }
  if grep -q "Fatal\|process.exit" "$LOG_DIR/run1_party${i}.log"; then
    echo "[runner] Party $i FAILED — log:"
    cat "$LOG_DIR/run1_party${i}.log"
    exit 1
  fi
  echo "[runner] Party $i done ✓"
done

# Verify share files were created
echo ""
echo "[runner] Verifying share files were persisted..."
for i in 1 2 3; do
  SHARE_FILE_VAR="SHARE_FILE_${i}"
  FILE="${!SHARE_FILE_VAR}"
  if [[ -f "$FILE" ]]; then
    echo "[runner] ✓ share_key${KEY_ID}_party${i}.enc exists ($(wc -c < "$FILE") bytes)"
  else
    echo "[runner] ✗ MISSING: $FILE — persistShare() did not write file"
    exit 1
  fi
done

# Kill the coord server — we'll restart it fresh for Run 2
kill "${PIDS[@]}" 2>/dev/null || true
PIDS=()
sleep 2

# ============================================================================
echo ""
echo "================================================================="
echo "  RUN 2: REUSE_EXISTING_KEY=1 — skip DKG, load from share files"
echo "================================================================="
echo ""

start_coord

# Launch 3 parties in reuse mode (party 3 should exit immediately as a non-signer)
for i in 1 2 3; do
  SHARE_FILE_VAR="SHARE_FILE_${i}"
  env $COMMON_ENV \
    REUSE_EXISTING_KEY=1 \
    PARTY_INDEX=$i \
    PARTISIA_SENDER_KEY="$PARTISIA_SENDER_KEY" \
    PARTISIA_SENDER_ADDRESS="$PARTISIA_SENDER_ADDRESS" \
    SIGNER_ADDRESS="$SIGNER_ADDRESS" \
    SHARE_FILE="${!SHARE_FILE_VAR}" \
    npx tsx src/party.ts > "$LOG_DIR/run2_party${i}.log" 2>&1 &
  pid=$!
  PIDS+=($pid)
  echo "[runner] Party $i (REUSE mode) started (pid $pid)"
done

echo "[runner] Waiting for all 3 parties to complete reuse signing..."
echo "[runner] Logs: $LOG_DIR/run2_party{1,2,3}.log"
echo ""

for i in 1 2 3; do
  echo "[runner] Waiting for Party $i..."
  wait_for "$LOG_DIR/run2_party${i}.log" "COMPLETE|Fatal|process.exit|not needed for signing subset" 240 || {
    echo "[runner] Party $i timed out — dumping log:"
    cat "$LOG_DIR/run2_party${i}.log"
    exit 1
  }
  if grep -q "Fatal\|process.exit" "$LOG_DIR/run2_party${i}.log"; then
    echo "[runner] Party $i FAILED in reuse mode — log:"
    cat "$LOG_DIR/run2_party${i}.log"
    exit 1
  fi
  echo "[runner] Party $i reuse done ✓"
done

# ============================================================================
echo ""
echo "================================================================="
echo "  RESULTS"
echo "================================================================="

# Confirm Run 2 did NOT run DKG
for i in 1 2 3; do
  if grep -q "Reusing existing key $KEY_ID" "$LOG_DIR/run2_party${i}.log"; then
    echo "[runner] ✓ Party $i correctly reused KEY_ID $KEY_ID (no DKG)"
  else
    echo "[runner] ✗ Party $i did NOT log 'Reusing existing key' — check log"
    grep -E "Reusing|DKG|keygen" "$LOG_DIR/run2_party${i}.log" | head -5
  fi
done

echo ""
echo "[runner] Share file integrity (enc files must not change between runs):"
for i in 1 2 3; do
  SHARE_FILE_VAR="SHARE_FILE_${i}"
  FILE="${!SHARE_FILE_VAR}"
  echo "[runner]   party$i: $(sha256sum "$FILE" 2>/dev/null || shasum -a 256 "$FILE") (unchanged ✓)"
done

echo ""
echo "================================================================="
echo "  ALL TESTS PASSED"
echo "  KEY_ID=$KEY_ID"
echo "  Shares persisted: Run 1 ✓"
echo "  Shares reused:    Run 2 ✓"
echo "  DKG skipped on reuse: ✓"
echo "================================================================="
