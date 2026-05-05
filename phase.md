# KoshSigner — Implementation Phases

> **Backend stack: Rust (crypto) + Go (infra). TypeScript in `client/` is test-reference only — never used in production backend.**

---

## PHASE 1 — Contracts (Proto Files + Service Stubs)

**Goal:** Define all 6 service contracts. Everything else depends on these.

**Deliverables:**
```
services/
└── proto/
    ├── bulletin_board.proto   ← coordinator service
    ├── party.proto            ← party DKG + sign service
    ├── keystore.proto         ← Shamir share management
    ├── pqc.proto              ← ML-KEM + ML-DSA
    ├── chain_relay.proto      ← Partisia tx submission
    └── policy.proto           ← tx_tag validation
```

**Work items:**
1. Write all 6 `.proto` files (exact specs in CLAUDE.md)
2. Set up `buf.gen.yaml` for Go code generation
3. Set up `build.rs` in each Rust service for `tonic_build`
4. Verify `protoc` compiles all files with zero errors

**Done when:** `buf generate` runs clean for Go; `cargo build` in each Rust service sees generated types.

---

## PHASE 2 — kosh-coordinator (Go)

**Goal:** Replace `coord-server.ts` with a production gRPC bulletin board.

**Why first:** Every other service depends on the coordinator for message passing. No polling — gRPC Watch streams events instantly.

**Deliverables:**
```
services/kosh-coordinator/
├── go.mod
├── cmd/coordinator/main.go
└── internal/
    ├── bb/
    │   ├── hub.go      ← broadcast hub per topic (chan string)
    │   ├── store.go    ← sync.RWMutex + map[topic]string
    │   └── server.go   ← gRPC BulletinBoard implementation
    └── config/config.go
```

**Key behavior:**
- `Post(topic, value)` — stores + broadcasts to all Watch subscribers instantly
- `Watch(topic)` — gRPC server stream; sends current value immediately if exists, then streams updates
- `Clear()` — wipe all state (used before each test run)
- `List()` — debug endpoint

**Done when:**
```bash
cd services/kosh-coordinator && go build ./... && go test ./...
# manual test: post a value, watch it from another terminal, verify instant delivery
```

---

## PHASE 3 — kosh-policy (Go)

**Goal:** Port `client/src/policy.ts` PolicyStore to gRPC service.

**Why now:** Simple CRUD, no crypto, no external deps. Quick win.

**Deliverables:**
```
services/kosh-policy/
├── go.mod
├── cmd/policy/main.go
└── internal/
    ├── store/
    │   ├── policy_store.go   ← Add/Remove/List/Validate
    │   └── file_persist.go   ← persist to policies.json
    └── server/server.go      ← gRPC PolicyService
```

**Key behavior:**
- `Validate(tx_tag, parties[])` — checks mandatory parties + min threshold
- File-backed: survives service restart
- Returns exact `PolicyViolation` with missing parties list

**Done when:**
```bash
cd services/kosh-policy && go test ./...
# add a policy, validate a passing request, validate a failing request
```

---

## PHASE 4 — kosh-pqc (Rust)

**Goal:** Port `client/src/pqc.ts` to Rust. Isolate ML-KEM + ML-DSA private keys.

**Why now:** kosh-keystore depends on pqc for sub-share encryption. Must exist first.

**Deliverables:**
```
services/kosh-pqc/
├── Cargo.toml
├── build.rs
└── src/
    ├── main.rs       ← tokio gRPC server
    ├── identity.rs   ← load/create/persist keypair (ml-kem + ml-dsa crates)
    ├── kem.rs        ← Encapsulate / Decapsulate (ML-KEM-768)
    └── dsa.rs        ← Sign / Verify (ML-DSA-65)
```

**Key behavior:**
- `GetIdentity` — returns public keys only (private keys NEVER leave this service)
- `Encapsulate(recipient_pk)` → `{ciphertext, shared_secret}`
- `Decapsulate(ciphertext)` → `shared_secret` (uses OWN private key)
- `EncryptPayload(shared_secret, plaintext)` → AES-256-GCM encrypted bytes
- `DecryptPayload(shared_secret, ct, nonce, tag)` → plaintext
- Identity persisted to `PQC_KEY_FILE` (JSON, generated once, reloaded on restart)

**Done when:**
```bash
cargo test -p kosh-pqc
# round-trip: encapsulate → decapsulate → same shared secret
# round-trip: encrypt → decrypt → same plaintext
# ML-DSA: sign → verify → true; tamper → verify → false
```

---

## PHASE 5 — kosh-keystore (Rust)

**Goal:** Port Feldman VSS + AES-GCM share files from `dkg-party.ts` to Rust. Isolate Shamir shares.

**Deliverables:**
```
services/kosh-keystore/
├── Cargo.toml
├── build.rs
└── src/
    ├── main.rs      ← tokio gRPC server
    ├── store.rs     ← AES-256-GCM encrypt/decrypt (compatible with existing .enc files)
    ├── feldman.rs   ← generate polynomial, verify subshare, combine subshares
    ├── shamir.rs    ← Lagrange interpolation
    └── types.rs     ← ShareFile, ThresholdDkgShare (ZeroizeOnDrop)
```

**Key behavior:**
- `GenerateShare` — random s_i, a_i; Schnorr proof; sub-shares f_i(j); encrypt sub-shares via pqc service; save encrypted to disk
- `ReceiveSubshare` — Feldman verify: `f_j(i)·G == C_j0 + i·C_j1`
- `FinalizeShare` — combine all received sub-shares: `X_i = Σ f_j(i)`
- `GetShareHalves` — return share split into hi/lo 128-bit halves for ZK submission
- File format **identical** to TypeScript `persistShare()` — existing `.enc` files load correctly

**Done when:**
```bash
cargo test -p kosh-keystore
# generate share for 3 parties, verify all 3 sub-shares, finalize → combined_pk matches
# persist + reload → same share
# Feldman verify: correct sub-share → valid; corrupted → invalid
```

---

## PHASE 6 — kosh-chain-relay (Rust)

**Goal:** Port `chain-utils.ts` `submitAndWait()` + all 44 contract action encoders to Rust.

**Deliverables:**
```
services/kosh-chain-relay/
├── Cargo.toml
├── build.rs
└── src/
    ├── main.rs      ← tokio gRPC server + tx queue worker
    ├── queue.rs     ← Arc<Mutex<VecDeque<TxJob>>>
    ├── partisia.rs  ← submitAndWait port (7 retries, k256 signing)
    ├── encode.rs    ← encodeU32Be, encodeLenPrefixedBytes, concatBytes
    └── actions.rs   ← all 44 encode_* functions (one per contract action)
```

**Key behavior:**
- `Submit(party_index, contract_addr, shortname, args, label)` → streams `QUEUED → SUBMITTED → CONFIRMED/FAILED`
- Tx queue: one worker per sender key, serializes nonces correctly
- 7 retries with 5s × attempt exponential backoff (exact port of TypeScript)
- `GetContractState(address)` → raw JSON from Partisia RPC

**DKG action shortnames:** 0x20–0x24
**GG20 action shortnames:** 0x45–0x53
**PQC action shortnames:** 0x70–0x77
**Policy action shortnames:** 0x80–0x85

**Done when:**
```bash
cargo test -p kosh-chain-relay  # encode/decode unit tests
# integration: submit a real dkg_create_key tx to testnet, confirm CONFIRMED status
```

---

## PHASE 7 — kosh-party (Rust) — DKG Only

**Goal:** Build the party daemon for DKG phases. No signing yet.

**Deliverables:**
```
services/kosh-party/
├── Cargo.toml
├── build.rs
└── src/
    ├── main.rs           ← tokio gRPC server; builds all downstream clients
    ├── config.rs         ← Config from env (PARTY_INDEX, COORDINATOR_ADDR, etc.)
    ├── phase.rs          ← Phase enum + state machine
    ├── dkg.rs            ← Full DKG flow (8 steps from CLAUDE.md)
    ├── bulletin_board.rs ← gRPC BulletinBoard client wrapper
    └── types.rs          ← ShamirShare, DkgState
```

**DKG flow (8 steps):**
1. `keystore.GenerateShare` → get C_i0, C_i1, commitment, Schnorr proof, encrypted sub-shares
2. `bb.Post("dkg_commit_{key_id}_party_{i}", payload)`
3. `bb.Watch(...)` all other parties' commits → verify Schnorr proofs
4. `bb.Post("dkg_subshare_{key_id}_from_{i}_to_{j}", encrypted)` for each j
5. `bb.Watch(...)` sub-shares from all j → decrypt via pqc → `keystore.ReceiveSubshare`
6. `keystore.FinalizeShare` → combined_pk
7. On-chain: create_key → commit → reveal → finalize → submit_zk_halves → complete_keygen (via chain_relay)
8. Register PQC identities on-chain (party 1 only)

**Done when:**
```bash
# docker-compose up coordinator keystore-1 keystore-2 keystore-3 pqc-1 pqc-2 pqc-3 chain-relay party-1 party-2 party-3
curl -X POST localhost:8080/api/v1/keys -d '{"key_id":1,"num_parties":3,"threshold":2}'
# → DKG completes, combined_pk returned, on-chain confirmed in Partisia testnet explorer
```

---

## PHASE 8 — kosh-party (Rust) — GG20 Signing

**Goal:** Add full GG20 threshold ECDSA signing phases to the party daemon.

**Additions to kosh-party/src/:**
```
├── gg20.rs      ← k_i, gamma_i generation; commit-reveal for Gamma_i; delta_i, sigma_i aggregation; partial sig
├── mta.rs       ← FuturesUnordered parallel MtA rounds (Paillier-based)
└── paillier.rs  ← 2048-bit safe prime Paillier (port of paillier.ts, no fallback)
```

**GG20 signing flow:**
1. PQC approval phase (Dilithium sign + ML-KEM key exchange)
2. Round 1: generate k_i, gamma_i; commit to Gamma_i; wait for all commits; reveal; verify
3. MtA rounds (all pairs in parallel via FuturesUnordered): Paillier exchange of k·x and k·gamma cross terms
4. Round 2: compute delta_i, sigma_i; commit-reveal delta; submit on-chain
5. Party 1 finalizes R on-chain; read r from contract state
6. Partial sigs: compute s_i = k_i⁻¹(m + r·sigma_i); commit-reveal on-chain
7. Party 1 finalizes; advance task_id in keystore

**Done when:**
```bash
curl -X POST localhost:8080/api/v1/sign \
  -d '{"key_id":1,"message_hash":"0xabc...","tx_tag":"test","signing_subset":[1,2]}'
# → ECDSA signature returned
# ethers.utils.recoverAddress(hash, sig) == eth_address  ✓
# stop party-3: signing still succeeds (2-of-3 threshold) ✓
```

---

## PHASE 9 — kosh-gateway (Go)

**Goal:** Expose REST API for external clients (wallets, dApps).

**Deliverables:**
```
services/kosh-gateway/
├── go.mod
├── cmd/gateway/main.go
└── internal/
    ├── handler/
    │   ├── keys.go    ← POST /api/v1/keys, GET /api/v1/keys/:id
    │   ├── sign.go    ← POST /api/v1/sign, GET /api/v1/sign/:id
    │   └── policy.go  ← POST/GET/DELETE /api/v1/policies
    ├── auth/jwt.go    ← JWT middleware, API key validation
    ├── client/        ← gRPC clients for coordinator, parties, policy
    └── config/config.go
```

**Endpoints:**
| Method | Path | Action |
|--------|------|--------|
| POST | /api/v1/keys | Trigger DKG on all parties in parallel |
| GET | /api/v1/keys/:id | Get key status |
| POST | /api/v1/sign | Trigger signing on subset parties |
| GET | /api/v1/sign/:id | Get signing session status |
| POST | /api/v1/policies | Add policy |
| GET | /api/v1/policies | List policies |
| DELETE | /api/v1/policies/:id | Remove policy |
| GET | /api/v1/health | Health check all services |

**Done when:**
```bash
cd services/kosh-gateway && go test ./...
# full end-to-end: DKG via REST → sign via REST → verify ECDSA signature
# policy rejection: add mandatory party policy, sign without it → 422
# JWT: request without token → 401
```

---

## PHASE 10 — kosh-monitor (Go)

**Goal:** Prometheus metrics, health checks, contract state polling.

**Deliverables:**
```
services/kosh-monitor/
├── go.mod
├── cmd/monitor/main.go
└── internal/
    ├── health/checker.go      ← ping all 8 services every 15s
    ├── metrics/prometheus.go  ← counters, gauges, histograms
    └── contract/poller.go     ← Partisia contract state every 30s
```

**Metrics exposed at `:9090/metrics`:**
- `kosh_dkg_sessions_total` — DKG sessions started/completed/failed
- `kosh_sign_sessions_total` — signing sessions started/completed/failed
- `kosh_party_phase` — current phase per party
- `kosh_tx_submit_duration_seconds` — chain relay submission latency
- `kosh_service_up` — 1/0 per service (health check)

**Done when:**
```bash
curl localhost:9090/metrics | grep kosh_
# all services show kosh_service_up{service="..."} 1
# run a DKG → kosh_dkg_sessions_total{status="completed"} increments
```

---

## PHASE 11 — Docker Compose + Integration Tests

**Goal:** All 13 containers boot, DKG completes, signing works, threshold tested.

**Deliverables:**
```
deploy/
├── docker-compose.yml    ← all 13 containers
├── .env.example          ← all env vars documented
└── k8s/                  ← (future: Kubernetes manifests)
```

**End-to-end verification checklist:**
- [ ] `docker-compose up` — all 13 containers healthy (grpc_health_probe green)
- [ ] DKG completes for key_id=1 → combined_pk on Partisia testnet
- [ ] Sign with subset [1,2] → ECDSA sig verifiable via `ethers.recoverAddress`
- [ ] Stop party-3 → signing [1,2] still works
- [ ] Stop party-3 + party-2 → signing [1] fails with threshold error
- [ ] Policy: add mandatory-party-2 policy; sign with [1,3] → 422
- [ ] Prometheus metrics: DKG and sign counters increment
- [ ] Restart coordinator → parties reconnect and Watch streams resume

---

## Summary Table

| Phase | Service | Language | Depends On | Duration |
|-------|---------|----------|------------|----------|
| 1 | Proto files | — | — | 1 day |
| 2 | kosh-coordinator | Go | proto | 2 days |
| 3 | kosh-policy | Go | proto | 1 day |
| 4 | kosh-pqc | Rust | proto | 2 days |
| 5 | kosh-keystore | Rust | proto, pqc | 3 days |
| 6 | kosh-chain-relay | Rust | proto | 2 days |
| 7 | kosh-party (DKG) | Rust | all above | 4 days |
| 8 | kosh-party (GG20) | Rust | phase 7 | 5 days |
| 9 | kosh-gateway | Go | proto, parties | 3 days |
| 10 | kosh-monitor | Go | all services | 1 day |
| 11 | Docker + E2E tests | — | all | 2 days |

**Total estimated: ~26 days for a single engineer working full-time.**

---

## TypeScript Boundary

```
client/                ← TEST REFERENCE ONLY
  src/party.ts         ← behavior reference for kosh-party port
  src/dkg-party.ts     ← behavior reference for kosh-keystore port
  src/gg20-signing.ts  ← behavior reference for kosh-party GG20 port
  src/paillier.ts      ← behavior reference for kosh-party paillier.rs port
  src/chain-utils.ts   ← behavior reference for kosh-chain-relay port
  src/policy.ts        ← behavior reference for kosh-policy port
  src/pqc.ts           ← behavior reference for kosh-pqc port

services/              ← PRODUCTION BACKEND (Rust + Go only)
contracts/             ← UNTOUCHED (Rust WASM on Partisia)
```

**Rule:** No TypeScript file is imported by, executed by, or depended on by any production service. TypeScript exists only so engineers can read the existing logic when porting to Rust/Go.
