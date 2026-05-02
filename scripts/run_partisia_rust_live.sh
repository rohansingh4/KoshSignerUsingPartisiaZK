#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

KEY_ID="${KEY_ID:-62020}"
CONTRACT_ADDRESS="${CONTRACT_ADDRESS:-032645d750cacf93c6fbe7479774ca9d51e8a51faa}"
BACKEND_PORT="${BACKEND_PORT:-8081}"
BACKEND_ADDR="127.0.0.1:${BACKEND_PORT}"
BACKEND_URL="http://127.0.0.1:${BACKEND_PORT}"
KEYSTORE_ROOT_DIR="${KOSH_KEYSTORE_ROOT_DIR:-/tmp/kosh-rust-backend-live}"
KOSH_KEYSTORE_MASTER_KEY="${KOSH_KEYSTORE_MASTER_KEY:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
PARTISIA_NODE_URL="${PARTISIA_NODE_URL:-https://node1.testnet.partisiablockchain.com,https://node2.testnet.partisiablockchain.com,https://node3.testnet.partisiablockchain.com,https://node4.testnet.partisiablockchain.com}"
PARTISIA_SENDER_KEY="${PARTISIA_SENDER_KEY:-cea538ce0bc3b7f4bcbb3bbea6eb2d26d76c9ddeab77938128ffb46828d42822}"
PARTISIA_SENDER_ADDRESS="${PARTISIA_SENDER_ADDRESS:-0070df8630bd853487c025e6e2b0eac733aa79481d}"
MSG_HASH_HEX="${MSG_HASH_HEX:-0xc9b03991a1a3fa025eebe1fe2c9186e0a4d1b275f5eb8369e4f4429416655735}"
GAS_TOPUPS="${GAS_TOPUPS:-5}"
SEPOLIA_TO="${SEPOLIA_TO:-}"
SEPOLIA_VALUE_WEI="${SEPOLIA_VALUE_WEI:-1000000000000000}"
SEPOLIA_RPC_URL="${SEPOLIA_RPC_URL:-}"
KEEP_BACKEND_RUNNING="${KEEP_BACKEND_RUNNING:-0}"
SKIP_CREATE="${SKIP_CREATE:-0}"
LOG_DIR="${LOG_DIR:-/tmp/kosh-rust-backend-live}"
mkdir -p "$LOG_DIR"
BACKEND_LOG="$LOG_DIR/backend-${KEY_ID}.log"
UNSIGNED_TX_JSON="$LOG_DIR/unsigned-${KEY_ID}.json"

json_field() {
  local field="$1"
  python3 - "$field" <<'PY'
import json,sys
field=sys.argv[1]
data=json.load(sys.stdin)
cur=data
for part in field.split('.'):
    if isinstance(cur, dict):
        cur=cur.get(part)
    else:
        cur=None
        break
print("" if cur is None else (json.dumps(cur) if isinstance(cur,(dict,list,bool)) else cur))
PY
}

poll_job() {
  local job_id="$1"
  local label="$2"
  while true; do
    local body
    body="$(curl -sS "$BACKEND_URL/api/v1/jobs/$job_id")"
    local status phase error
    status="$(printf '%s' "$body" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("status",""))')"
    phase="$(printf '%s' "$body" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("phase",""))')"
    echo "[$label] status=$status phase=$phase" >&2
    if [[ "$status" == "completed" ]]; then
      printf '%s\n' "$body"
      return 0
    fi
    if [[ "$status" == "failed" || "$status" == "cancelled" ]]; then
      printf '%s\n' "$body"
      return 1
    fi
    sleep 8
  done
}

cleanup() {
  if [[ "$KEEP_BACKEND_RUNNING" == "1" ]]; then
    return 0
  fi
  if [[ -n "${BACKEND_PID:-}" ]] && kill -0 "$BACKEND_PID" 2>/dev/null; then
    kill "$BACKEND_PID" || true
    wait "$BACKEND_PID" || true
  fi
}
trap cleanup EXIT

echo "[1/7] Topping up Partisia gas $GAS_TOPUPS times"
for _ in $(seq 1 "$GAS_TOPUPS"); do
  cargo pbc account --net=testnet mintgas "$PARTISIA_SENDER_ADDRESS"
done

echo "[2/7] Sender balance"
cargo pbc account --net=testnet show "$PARTISIA_SENDER_ADDRESS"

if lsof -i tcp:"$BACKEND_PORT" >/dev/null 2>&1; then
  echo "[3/7] Killing existing backend on port $BACKEND_PORT"
  lsof -ti tcp:"$BACKEND_PORT" | xargs -r kill
  sleep 2
fi

echo "[4/7] Starting Rust backend on $BACKEND_ADDR"
export KOSH_BACKEND_BIND_ADDR="$BACKEND_ADDR"
export KOSH_KEYSTORE_ROOT_DIR
export KOSH_KEYSTORE_MASTER_KEY
export PARTISIA_NODE_URL
export PARTISIA_SENDER_KEY
export PARTISIA_SENDER_ADDRESS
export KOSH_SEPOLIA_RPC_URL="$SEPOLIA_RPC_URL"
export KOSH_SEPOLIA_CHAIN_ID="11155111"
cargo run -p kosh-backend >"$BACKEND_LOG" 2>&1 &
BACKEND_PID=$!

echo "backend pid=$BACKEND_PID log=$BACKEND_LOG"
for _ in $(seq 1 30); do
  if curl -sS "$BACKEND_URL/api/v1/health" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
curl -sS "$BACKEND_URL/api/v1/health"
echo

if [[ "$SKIP_CREATE" != "1" ]]; then
  echo "[5/7] create-key key_id=$KEY_ID"
  CREATE_RESP="$(curl -sS -X POST "$BACKEND_URL/api/v1/workflows/create-key" -H 'Content-Type: application/json' -d "{"contract_address":"$CONTRACT_ADDRESS","key_id":$KEY_ID,"num_parties":3}")"
  echo "$CREATE_RESP"
  CREATE_JOB_ID="$(printf '%s' "$CREATE_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["job"]["id"])')"
  CREATE_RESULT="$(poll_job "$CREATE_JOB_ID" create-key)" || {
    echo "$CREATE_RESULT"
    echo "create-key failed; backend log: $BACKEND_LOG"
    exit 1
  }
  echo "$CREATE_RESULT"
else
  echo "[5/7] skipping create-key and reusing existing key_id=$KEY_ID"
fi

echo "[6/7] threshold key status"
KEY_STATUS="$(curl -sS "$BACKEND_URL/api/v1/threshold/key-status?contract_address=$CONTRACT_ADDRESS&key_id=$KEY_ID")"
echo "$KEY_STATUS"
EXISTS="$(printf '%s' "$KEY_STATUS" | python3 -c 'import json,sys; print(str(json.load(sys.stdin).get("exists", False)).lower())')"
if [[ "$EXISTS" != "true" ]]; then
  echo "key $KEY_ID does not exist on-chain" >&2
  exit 1
fi

if [[ -n "$SEPOLIA_TO" ]]; then
  echo "[6.5/7] building unsigned Sepolia transaction"
  EVM_FROM="$(printf '%s' "$KEY_STATUS" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("evmAddress",""))')"
  BUILD_JSON="$(SEPOLIA_RPC_URL="$SEPOLIA_RPC_URL" node scripts/sepolia_tx.mjs build "$EVM_FROM" "$SEPOLIA_TO" "$SEPOLIA_VALUE_WEI")"
  echo "$BUILD_JSON"
  printf '%s' "$BUILD_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["signing_hash"])' > "$LOG_DIR/signing-hash-${KEY_ID}.txt"
  printf '%s' "$BUILD_JSON" | python3 -c 'import json,sys; json.dump(json.load(sys.stdin)["unsigned_tx"], sys.stdout)' > "$UNSIGNED_TX_JSON"
  MSG_HASH_HEX="$(cat "$LOG_DIR/signing-hash-${KEY_ID}.txt")"
  echo "using Sepolia signing hash: $MSG_HASH_HEX"
fi

echo "[7/7] reuse-sign same key_id=$KEY_ID"
REUSE_RESP="$(curl -sS -X POST "$BACKEND_URL/api/v1/workflows/reuse-sign" -H 'Content-Type: application/json' -d "{\"contract_address\":\"$CONTRACT_ADDRESS\",\"key_id\":$KEY_ID,\"tx_tag\":\"eth_transfer\",\"signing_parties\":[1,2],\"threshold\":2,\"msg_hash_hex\":\"$MSG_HASH_HEX\",\"session_id\":1}")"
echo "$REUSE_RESP"
REUSE_JOB_ID="$(printf '%s' "$REUSE_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["job"]["id"])')"
REUSE_RESULT="$(poll_job "$REUSE_JOB_ID" reuse-sign)" || {
  echo "$REUSE_RESULT"
  echo "reuse-sign failed; backend log: $BACKEND_LOG"
  exit 1
}
echo "$REUSE_RESULT"

TASK_ID="$(printf '%s' "$REUSE_RESULT" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("result",{}).get("task_id_used",0))')"
SIG_HEX="$(printf '%s' "$REUSE_RESULT" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("result",{}).get("onchain_signature_hex") or "")')"
SIG_VERIFIED="$(printf '%s' "$REUSE_RESULT" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(str(d.get("result",{}).get("onchain_signature_verified", False)).lower())')"
echo "[final] threshold task signature"
curl -sS "$BACKEND_URL/api/v1/threshold/task-signature?contract_address=$CONTRACT_ADDRESS&key_id=$KEY_ID&task_id=$TASK_ID"
echo

if [[ -n "$SEPOLIA_TO" ]]; then
  if [[ "$SIG_VERIFIED" != "true" || -z "$SIG_HEX" ]]; then
    echo "verified on-chain signature missing; not broadcasting to Sepolia" >&2
    exit 1
  fi
  echo "[8/7] broadcasting to Sepolia"
  BROADCAST_JSON="$(SEPOLIA_RPC_URL="$SEPOLIA_RPC_URL" node scripts/sepolia_tx.mjs sign-submit "$UNSIGNED_TX_JSON" "$SIG_HEX")"
  echo "$BROADCAST_JSON"
fi
