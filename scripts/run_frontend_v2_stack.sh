#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
FRONTEND_DIR="$ROOT_DIR/frontend/KoshSignerUsingPartisiaZK/client"

BACKEND_PORT="${BACKEND_PORT:-8080}"
FRONTEND_PORT="${FRONTEND_PORT:-5173}"
BACKEND_ADDR="127.0.0.1:${BACKEND_PORT}"
BACKEND_URL="http://127.0.0.1:${BACKEND_PORT}"
FRONTEND_URL="http://127.0.0.1:${FRONTEND_PORT}"
KOSH_KEYSTORE_ROOT_DIR="${KOSH_KEYSTORE_ROOT_DIR:-/tmp/kosh-rust-backend-live}"
KOSH_KEYSTORE_MASTER_KEY="${KOSH_KEYSTORE_MASTER_KEY:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
PARTISIA_NODE_URL="${PARTISIA_NODE_URL:-https://node1.testnet.partisiablockchain.com,https://node2.testnet.partisiablockchain.com,https://node3.testnet.partisiablockchain.com,https://node4.testnet.partisiablockchain.com}"
PARTISIA_SENDER_KEY="${PARTISIA_SENDER_KEY:-cea538ce0bc3b7f4bcbb3bbea6eb2d26d76c9ddeab77938128ffb46828d42822}"
PARTISIA_SENDER_ADDRESS="${PARTISIA_SENDER_ADDRESS:-0070df8630bd853487c025e6e2b0eac733aa79481d}"
KOSH_PARTISIA_POLL_INTERVAL_MS="${KOSH_PARTISIA_POLL_INTERVAL_MS:-500}"
KOSH_CORS_ALLOWED_ORIGINS="${KOSH_CORS_ALLOWED_ORIGINS:-http://localhost:${FRONTEND_PORT},http://127.0.0.1:${FRONTEND_PORT}}"
LOG_DIR="${LOG_DIR:-/tmp/kosh-frontend-v2-stack}"
mkdir -p "$LOG_DIR"
BACKEND_LOG="$LOG_DIR/backend.log"
FRONTEND_LOG="$LOG_DIR/frontend.log"

cleanup() {
  if [[ -n "${BACKEND_PID:-}" ]] && kill -0 "$BACKEND_PID" 2>/dev/null; then
    kill "$BACKEND_PID" || true
  fi
  if [[ -n "${FRONTEND_PID:-}" ]] && kill -0 "$FRONTEND_PID" 2>/dev/null; then
    kill "$FRONTEND_PID" || true
  fi
}
trap cleanup EXIT INT TERM

backend_healthy() {
  curl -sS "$BACKEND_URL/api/v1/health" >/dev/null 2>&1
}

if lsof -i tcp:"$BACKEND_PORT" >/dev/null 2>&1; then
  echo "backend port $BACKEND_PORT already in use; killing existing process"
  lsof -ti tcp:"$BACKEND_PORT" | xargs -r kill
  sleep 1
fi

if lsof -i tcp:"$FRONTEND_PORT" >/dev/null 2>&1; then
  echo "frontend port $FRONTEND_PORT already in use; killing existing process"
  lsof -ti tcp:"$FRONTEND_PORT" | xargs -r kill
  sleep 1
fi

export KOSH_BACKEND_BIND_ADDR="$BACKEND_ADDR"
export KOSH_KEYSTORE_ROOT_DIR
export KOSH_KEYSTORE_MASTER_KEY
export PARTISIA_NODE_URL
export PARTISIA_SENDER_KEY
export PARTISIA_SENDER_ADDRESS
export KOSH_PARTISIA_POLL_INTERVAL_MS
export KOSH_CORS_ALLOWED_ORIGINS

cd "$ROOT_DIR"
echo "starting Rust backend on $BACKEND_URL"
cargo run -p kosh-backend >"$BACKEND_LOG" 2>&1 &
BACKEND_PID=$!

for _ in $(seq 1 60); do
  if backend_healthy; then
    break
  fi
  sleep 0.5
done

if ! backend_healthy; then
  echo "backend failed to start; see $BACKEND_LOG" >&2
  exit 1
fi

echo "backend is healthy"
echo "relay health:"
curl -sS "$BACKEND_URL/api/v1/relay/health"
echo

echo "starting frontend on $FRONTEND_URL"
cd "$FRONTEND_DIR"
npm run dev -- --host 127.0.0.1 --port "$FRONTEND_PORT" >"$FRONTEND_LOG" 2>&1 &
FRONTEND_PID=$!

for _ in $(seq 1 60); do
  if curl -sS "$FRONTEND_URL" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

if ! curl -sS "$FRONTEND_URL" >/dev/null 2>&1; then
  echo "frontend failed to start; see $FRONTEND_LOG" >&2
  exit 1
fi

echo
echo "frontend ready: $FRONTEND_URL"
echo "backend ready:  $BACKEND_URL"
echo "logs:"
echo "  backend  -> $BACKEND_LOG"
echo "  frontend -> $FRONTEND_LOG"
echo

echo "press Ctrl+C to stop both"
wait "$FRONTEND_PID"
