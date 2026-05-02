
# KoshSigner — Complete Microservices Architecture Plan (Rust + Go)

---

## WHY THIS ARCHITECTURE

The current system is a monolithic TypeScript script (`party.ts`, 1339 lines) that runs
all protocol phases in a single process. This works for testing but has these problems
in production:

- A crash at any phase restarts the entire protocol from scratch
- All crypto (DKG, MtA, PQC, key storage) runs in the same OS process — any bug leaks
  key material to other components
- No way to scale individual bottlenecks (e.g., Paillier keygen is CPU-heavy)
- No external API — you can only drive it via env vars and a bash script
- `coord-server.ts` has no auth, no persistence — restart wipes all party state

The microservices design solves all of these:
- Each service has a single responsibility; crash one, don't lose the others
- Key material is isolated in `kosh-keystore` — the party daemon NEVER writes secrets to
  its own memory; it calls keystore over gRPC and secrets are `ZeroizeOnDrop`
- The chain relay is a separate queue — retries, nonce management, and backoff don't
  block the MPC math
- gRPC streaming Watch replaces HTTP long-poll — parties are notified the instant a
  message arrives, with no 30-second polling delays
- The gateway exposes a REST API that any EVM wallet or dApp can call

---

## LANGUAGE DECISIONS

**Rust** is used for all services that touch cryptographic material or secrets:
- `kosh-party` — generates k_i, gamma_i, sigma_i, delta_i during GG20
- `kosh-keystore` — holds AES-256-GCM encrypted Shamir shares on disk
- `kosh-pqc` — holds ML-KEM private key and ML-DSA signing key
- `kosh-chain-relay` — holds the Partisia private key for tx signing

Rust guarantees: memory safety, no GC pauses during crypto, `ZeroizeOnDrop` clears
secrets, `Arc<Mutex<>>` prevents data races on shared state.

**Go** is used for all infra/coordination services that have no secret material:
- `kosh-coordinator` — bulletin board, gRPC streaming, pure data routing
- `kosh-gateway` — REST API, JWT middleware, request routing
- `kosh-policy` — policy CRUD rules, in-memory + file backed
- `kosh-monitor` — Prometheus metrics, health checks, contract state polling

Go advantages here: goroutines are perfect for "many concurrent connections" (coordinator),
fast compile times for iteration, excellent stdlib for HTTP/JSON (gateway).

---

## FULL SERVICE MAP

```
                          ┌─────────────────────────────┐
                          │     EXTERNAL CLIENT          │
                          │ (wallet, dApp, admin UI)     │
                          └──────────────┬──────────────┘
                                         │ HTTPS REST / WebSocket
                                         ▼
                    ┌────────────────────────────────────────┐
                    │           kosh-gateway  (Go)           │
                    │   port 8080                            │
                    │                                        │
                    │  POST /api/v1/keys          → DKG      │
                    │  POST /api/v1/sign          → Signing  │
                    │  GET  /api/v1/keys/:id      → Status   │
                    │  GET  /api/v1/sign/:id      → Status   │
                    │  POST /api/v1/policies      → Policy   │
                    │  GET  /api/v1/health        → Health   │
                    │                                        │
                    │  JWT auth on all routes                │
                    │  Rate limiting per API key             │
                    │  Translates REST → gRPC internally     │
                    └───┬────────────────────┬──────────────┘
                        │ gRPC               │ gRPC
                        ▼                    ▼
          ┌─────────────────────┐  ┌─────────────────────┐
          │  kosh-policy  (Go)  │  │kosh-coordinator (Go)│
          │  port 50052         │  │  port 50051         │
          │                     │  │                     │
          │  PolicyStore:       │  │  BulletinBoard:     │
          │  Add / Remove /     │  │  Post(topic,value)  │
          │  List / Validate    │  │  Read(topic)        │
          │                     │  │  Watch(topic)       │
          │  Policy{            │  │   → gRPC stream     │
          │    txTag string     │  │  Clear()            │
          │    mandatoryParties │  │                     │
          │    minThreshold     │  │  State:             │
          │  }                  │  │   sync.RWMutex      │
          │                     │  │   map[topic]string  │
          │  Validate(tag,      │  │   broadcast hub     │
          │    parties) →       │  │   per topic         │
          │    ok / violation   │  │                     │
          └─────────────────────┘  └──────┬──────────────┘
                                          │ gRPC Watch stream
                    ┌─────────────────────┼──────────────────────┐
                    │                     │                       │
                    ▼                     ▼                       ▼
          ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
          │  kosh-party-1    │  │  kosh-party-2    │  │  kosh-party-3    │
          │  (Rust) port     │  │  (Rust) port     │  │  (Rust) port     │
          │  50060           │  │  50061           │  │  50062           │
          │                  │  │                  │  │                  │
          │  Phase machine:  │  │  Phase machine:  │  │  Phase machine:  │
          │  DKG_COMMIT      │  │  DKG_COMMIT      │  │  DKG_COMMIT      │
          │  DKG_REVEAL      │  │  DKG_REVEAL      │  │  DKG_REVEAL      │
          │  DKG_ONCHAIN     │  │  DKG_ONCHAIN     │  │  DKG_ONCHAIN     │
          │  PQC_REGISTER    │  │  PQC_REGISTER    │  │  PQC_REGISTER    │
          │  PQC_APPROVAL    │  │  PQC_APPROVAL    │  │  PQC_APPROVAL    │
          │  GG20_ROUND1     │  │  GG20_ROUND1     │  │  GG20_ROUND1     │
          │  GG20_MTA        │  │  GG20_MTA        │  │  GG20_MTA        │
          │  GG20_ROUND2     │  │  GG20_ROUND2     │  │  GG20_ROUND2     │
          │  GG20_PARTIAL    │  │  GG20_PARTIAL    │  │  GG20_PARTIAL    │
          │  COMPLETE        │  │  COMPLETE        │  │  COMPLETE        │
          │                  │  │                  │  │                  │
          │  tokio::mpsc     │  │  tokio::mpsc     │  │  tokio::mpsc     │
          │  FuturesUnord.   │  │  FuturesUnord.   │  │  FuturesUnord.   │
          │  tokio::select!  │  │  tokio::select!  │  │  tokio::select!  │
          └──┬──────────┬───┘  └──┬──────────┬───┘  └──┬──────────┬───┘
             │ gRPC     │ gRPC    │ gRPC     │ gRPC    │ gRPC     │ gRPC
             ▼          ▼         ▼          ▼         ▼          ▼
       ┌──────────┐ ┌──────┐ ┌──────────┐ ┌──────┐ ┌──────────┐ ┌──────┐
       │keystore-1│ │pqc-1 │ │keystore-2│ │pqc-2 │ │keystore-3│ │pqc-3 │
       │(Rust)    │ │(Rust)│ │(Rust)    │ │(Rust)│ │(Rust)    │ │(Rust)│
       │port 50070│ │50080 │ │port 50071│ │50081 │ │port 50072│ │50082 │
       │          │ │      │ │          │ │      │ │          │ │      │
       │AES-GCM   │ │ML-KEM│ │AES-GCM   │ │ML-KEM│ │AES-GCM   │ │ML-KEM│
       │Shamir    │ │ML-DSA│ │Shamir    │ │ML-DSA│ │Shamir    │ │ML-DSA│
       │ZeroizeDr.│ │Zeroiz│ │ZeroizeDr.│ │Zeriz │ │ZeroizeDr.│ │Zeriz │
       └──────────┘ └──────┘ └──────────┘ └──────┘ └──────────┘ └──────┘

                    ┌────────────────────────────────────┐
                    │      kosh-chain-relay  (Rust)      │
                    │      port 50053                    │
                    │                                    │
                    │  Tx queue: VecDeque<TxRequest>     │
                    │  Mutex<Nonce> per sender           │
                    │  7 retries + exponential backoff   │
                    │  submitAndWait() logic from        │
                    │    chain-utils.ts exactly          │
                    │  k256 signing for Partisia txs     │
                    │  All 44 contract actions routed    │
                    │    through here                    │
                    └──────────────┬─────────────────────┘
                                   │ HTTPS
                                   ▼
                    ┌────────────────────────────────────┐
                    │    Partisia Testnet / Mainnet      │
                    │                                    │
                    │  kosh-zk-signer contract           │
                    │  (Rust WASM — UNTOUCHED)           │
                    │                                    │
                    │  DKG actions (0x20–0x24)           │
                    │  GG20 actions (0x45–0x52)          │
                    │  PQC actions  (0x70–0x77)          │
                    │  Policy actions (0x80–0x85)        │
                    └────────────────────────────────────┘

                    ┌────────────────────────────────────┐
                    │      kosh-monitor  (Go)            │
                    │      port 9090                     │
                    │                                    │
                    │  Prometheus /metrics endpoint      │
                    │  Poll contract state every 30s     │
                    │  Health check all 8 services       │
                    │  Alert: phase stuck > 5 min        │
                    │  Dashboard: DKG/sign session count │
                    └────────────────────────────────────┘
```

---

## COMPLETE FOLDER STRUCTURE

```
KoshSignerUsingPartisiaZK/
│
├── contracts/                         # UNTOUCHED — Partisia ZK WASM contracts
│   ├── kosh-zk-signer/
│   ├── kosh-vault/
│   └── kosh-account-registry/
│
├── client/                            # UNTOUCHED — TypeScript (still works for testing)
│
├── services/                          # ALL NEW — microservices
│   │
│   ├── proto/                         # Shared protobuf definitions
│   │   ├── bulletin_board.proto       # BulletinBoard service (coordinator)
│   │   ├── party.proto                # Party service (DKG, signing sessions)
│   │   ├── keystore.proto             # KeyStore service (share management)
│   │   ├── pqc.proto                  # PQC service (ML-KEM + ML-DSA)
│   │   ├── chain_relay.proto          # ChainRelay service (Partisia txs)
│   │   └── policy.proto               # Policy service (tx_tag validation)
│   │
│   ├── kosh-coordinator/              # Go
│   │   ├── go.mod
│   │   ├── go.sum
│   │   ├── cmd/
│   │   │   └── coordinator/
│   │   │       └── main.go            # server startup, signal handling
│   │   └── internal/
│   │       ├── bb/
│   │       │   ├── store.go           # sync.RWMutex + map[topic]string
│   │       │   ├── hub.go             # broadcast hub per topic (chan string)
│   │       │   └── server.go          # gRPC BulletinBoard implementation
│   │       └── config/
│   │           └── config.go          # PORT, LOG_LEVEL env vars
│   │
│   ├── kosh-gateway/                  # Go
│   │   ├── go.mod
│   │   ├── cmd/
│   │   │   └── gateway/
│   │   │       └── main.go
│   │   └── internal/
│   │       ├── handler/
│   │       │   ├── keys.go            # POST /api/v1/keys, GET /api/v1/keys/:id
│   │       │   ├── sign.go            # POST /api/v1/sign, GET /api/v1/sign/:id
│   │       │   └── policy.go          # POST/GET /api/v1/policies
│   │       ├── auth/
│   │       │   └── jwt.go             # JWT middleware, API key validation
│   │       ├── client/
│   │       │   ├── coordinator.go     # gRPC client for coordinator
│   │       │   ├── party.go           # gRPC client for parties
│   │       │   └── policy.go          # gRPC client for policy service
│   │       └── config/
│   │           └── config.go
│   │
│   ├── kosh-policy/                   # Go
│   │   ├── go.mod
│   │   ├── cmd/
│   │   │   └── policy/
│   │   │       └── main.go
│   │   └── internal/
│   │       ├── store/
│   │       │   ├── policy_store.go    # Policy struct, Add/Remove/List/Validate
│   │       │   └── file_persist.go    # JSON file persistence (policies.json)
│   │       └── server/
│   │           └── server.go          # gRPC PolicyService implementation
│   │
│   ├── kosh-monitor/                  # Go
│   │   ├── go.mod
│   │   ├── cmd/
│   │   │   └── monitor/
│   │   │       └── main.go
│   │   └── internal/
│   │       ├── health/
│   │       │   └── checker.go         # ping all 8 services every 15s
│   │       ├── metrics/
│   │       │   └── prometheus.go      # counters: dkg_started, sign_completed, etc.
│   │       └── contract/
│   │           └── poller.go          # HTTP poll Partisia contract state every 30s
│   │
│   ├── kosh-party/                    # Rust — one binary, PARTY_INDEX env selects identity
│   │   ├── Cargo.toml
│   │   ├── build.rs                   # tonic_build proto compilation
│   │   └── src/
│   │       ├── main.rs                # tokio::main; builds all gRPC clients; starts phase loop
│   │       ├── config.rs              # Config struct from env vars
│   │       ├── phase.rs               # Phase enum + state machine loop
│   │       ├── dkg.rs                 # Feldman VSS DKG phases (commit/reveal/subshare)
│   │       ├── gg20.rs                # GG20 state: k_i, gamma_i, delta_i, sigma_i
│   │       ├── mta.rs                 # Paillier MtA rounds (FuturesUnordered)
│   │       ├── paillier.rs            # Paillier keygen / encrypt / decrypt (num-bigint)
│   │       ├── bulletin_board.rs      # Wrapper around gRPC BulletinBoard client
│   │       └── types.rs               # ShamirShare, GG20State, MtAOutput, etc.
│   │
│   ├── kosh-keystore/                 # Rust
│   │   ├── Cargo.toml
│   │   ├── build.rs
│   │   └── src/
│   │       ├── main.rs                # tokio::main; starts gRPC KeyStore server
│   │       ├── store.rs               # AES-256-GCM encrypt/decrypt share files
│   │       ├── feldman.rs             # Feldman VSS polynomial ops (generate + verify)
│   │       ├── shamir.rs              # Lagrange interpolation, sub-share combination
│   │       └── types.rs               # ShamirShare, ThresholdDkgShare (ZeroizeOnDrop)
│   │
│   ├── kosh-pqc/                      # Rust
│   │   ├── Cargo.toml
│   │   ├── build.rs
│   │   └── src/
│   │       ├── main.rs                # tokio::main; starts gRPC PqcService server
│   │       ├── identity.rs            # load/create/persist ML-KEM + ML-DSA keypair
│   │       ├── kem.rs                 # ML-KEM-768 encapsulate / decapsulate
│   │       └── dsa.rs                 # ML-DSA-65 sign / verify
│   │
│   └── kosh-chain-relay/              # Rust
│       ├── Cargo.toml
│       ├── build.rs
│       └── src/
│           ├── main.rs                # tokio::main; starts gRPC ChainRelay server
│           ├── queue.rs               # Tx queue: Arc<Mutex<VecDeque<TxJob>>>
│           ├── partisia.rs            # HTTP client, k256 tx signing, waitForSpawnedEvents
│           ├── encode.rs              # encodeU32Be, encodeLenPrefixedBytes, concatBytes
│           └── actions.rs             # one function per contract action (shortname + args)
│
├── deploy/
│   ├── docker-compose.yml             # local dev: all 13 containers
│   ├── .env.example                   # all env vars documented
│   └── k8s/                           # Kubernetes manifests (future)
│
└── Cargo.toml                         # workspace — adds Rust service crates
```

---

## PROTO FILE SPECIFICATIONS (complete)

### proto/bulletin_board.proto
```protobuf
syntax = "proto3";
package kosh.bb;
option go_package = "github.com/kosh/coordinator/pb";

service BulletinBoard {
  // Post a value under a topic. Idempotent — re-posting the same topic is allowed.
  rpc Post(PostRequest) returns (PostResponse);
  // Read a value immediately. Returns found=false if topic not set yet.
  rpc Read(ReadRequest) returns (ReadResponse);
  // Watch a topic. Server streams ONE WatchEvent immediately if value already exists,
  // then continues streaming whenever the value is updated.
  // Client receives events until stream is cancelled.
  rpc Watch(WatchRequest) returns (stream WatchEvent);
  // Wipe all state. Used at start of each test run.
  rpc Clear(ClearRequest) returns (ClearResponse);
  // List all topics (debug/admin only).
  rpc List(ListRequest) returns (ListResponse);
}

message PostRequest  { string topic = 1; string value = 2; }
message PostResponse { bool ok = 1; }
message ReadRequest  { string topic = 1; }
message ReadResponse { string value = 1; bool found = 2; }
message WatchRequest { string topic = 1; }
message WatchEvent   { string topic = 1; string value = 2; }
message ClearRequest {}
message ClearResponse { int32 keys_cleared = 1; }
message ListRequest  {}
message ListResponse { repeated string topics = 1; }
```

### proto/keystore.proto
```protobuf
syntax = "proto3";
package kosh.ks;
option go_package = "github.com/kosh/keystore/pb";

service KeyStore {
  // Generate a new Feldman VSS polynomial for a given key_id and party_index.
  // Stores encrypted to disk. Returns public commitments (NOT the secret).
  rpc GenerateShare(GenerateShareRequest) returns (GenerateShareResponse);
  // Load and decrypt an existing share from disk. Returns sub-shares for other parties.
  rpc LoadShare(LoadShareRequest) returns (LoadShareResponse);
  // Receive and store a sub-share f_j(i) from party j, verify Feldman commitment.
  rpc ReceiveSubshare(ReceiveSubshareRequest) returns (ReceiveSubshareResponse);
  // Combine all received sub-shares into the final adjusted Shamir share.
  rpc FinalizeShare(FinalizeShareRequest) returns (FinalizeShareResponse);
  // Get the Shamir share value (high/low halves) for signing. Secret leaves keystore
  // only for the ZK share submission step.
  rpc GetShareHalves(GetShareHalvesRequest) returns (GetShareHalvesResponse);
  // Get the combined public key for a key_id.
  rpc GetPublicKey(GetPublicKeyRequest) returns (GetPublicKeyResponse);
  // Advance nextTaskId after a completed signing session.
  rpc AdvanceTaskId(AdvanceTaskIdRequest) returns (AdvanceTaskIdResponse);
  // Get the next task_id for a key_id.
  rpc GetNextTaskId(GetNextTaskIdRequest) returns (GetNextTaskIdResponse);
}

message GenerateShareRequest {
  uint32 key_id     = 1;
  uint32 party_index = 2;
  uint32 num_parties = 3;
  // Optional deterministic seed (test only). Empty = random.
  string seed = 4;
}
message GenerateShareResponse {
  // C_i0 = s_i·G (33 bytes compressed, hex)
  string c_i0_hex = 1;
  // C_i1 = a_i·G (33 bytes compressed, hex)
  string c_i1_hex = 2;
  // SHA-256(C_i0) — used as DKG commitment hash
  string commitment_hash_hex = 3;
  // Schnorr proof: R and z scalars (for rogue-key prevention)
  string schnorr_r_hex = 4;
  string schnorr_z_hex = 5;
  // Sub-share f_i(j) for each party j (encrypted with j's Kyber pubkey)
  // Key: "j=1", "j=2", "j=3". Value: hex-encoded ciphertext.
  map<string, string> encrypted_subshares = 6;
}

message LoadShareRequest  { uint32 key_id = 1; }
message LoadShareResponse { bool found = 1; string combined_pk_hex = 2; }

message ReceiveSubshareRequest {
  uint32 key_id       = 1;
  uint32 from_party   = 2;
  // Encrypted sub-share (decrypted by PQC service before calling here)
  string subshare_hex = 3;
  string c_j0_hex     = 4;
  string c_j1_hex     = 5;
}
message ReceiveSubshareResponse { bool valid = 1; string error = 2; }

message FinalizeShareRequest  { uint32 key_id = 1; }
message FinalizeShareResponse { string combined_pk_hex = 1; }

message GetShareHalvesRequest  { uint32 key_id = 1; }
message GetShareHalvesResponse {
  // High 128 bits of Shamir share (as signed int string)
  string share_hi = 1;
  // Low 128 bits of Shamir share (as signed int string)
  string share_lo = 2;
}

message GetPublicKeyRequest  { uint32 key_id = 1; }
message GetPublicKeyResponse { string combined_pk_hex = 1; }

message AdvanceTaskIdRequest  { uint32 key_id = 1; }
message AdvanceTaskIdResponse { uint32 next_task_id = 1; }

message GetNextTaskIdRequest  { uint32 key_id = 1; }
message GetNextTaskIdResponse { uint32 next_task_id = 1; }
```

### proto/pqc.proto
```protobuf
syntax = "proto3";
package kosh.pqc;
option go_package = "github.com/kosh/pqc/pb";

service PqcService {
  // Get or generate the ML-KEM + ML-DSA identity for this party.
  // Returns public keys only. Private keys never leave this service.
  rpc GetIdentity(GetIdentityRequest) returns (GetIdentityResponse);
  // ML-KEM-768: encrypt a shared secret to recipient's public key.
  rpc Encapsulate(EncapsulateRequest) returns (EncapsulateResponse);
  // ML-KEM-768: decrypt a ciphertext using this party's private key.
  rpc Decapsulate(DecapsulateRequest) returns (DecapsulateResponse);
  // Encrypt a payload using the shared secret (AES-256-GCM).
  rpc EncryptPayload(EncryptPayloadRequest) returns (EncryptPayloadResponse);
  // Decrypt a payload using the shared secret (AES-256-GCM).
  rpc DecryptPayload(DecryptPayloadRequest) returns (DecryptPayloadResponse);
  // ML-DSA-65: sign a message with this party's dilithium private key.
  rpc Sign(SignRequest) returns (SignResponse);
  // ML-DSA-65: verify a signature with a given dilithium public key.
  rpc Verify(VerifyRequest) returns (VerifyResponse);
}

message GetIdentityRequest  {}
message GetIdentityResponse {
  string kyber_pk_b64    = 1;
  string dilithium_pk_b64 = 2;
}

message EncapsulateRequest  { string recipient_kyber_pk_b64 = 1; }
message EncapsulateResponse {
  string ciphertext_b64  = 1;
  string shared_secret_b64 = 2;
}

message DecapsulateRequest  { string ciphertext_b64 = 1; }
message DecapsulateResponse { string shared_secret_b64 = 1; }

message EncryptPayloadRequest {
  string shared_secret_b64 = 1;
  bytes  plaintext = 2;
}
message EncryptPayloadResponse { bytes ciphertext = 1; bytes nonce = 2; bytes tag = 3; }

message DecryptPayloadRequest {
  string shared_secret_b64 = 1;
  bytes  ciphertext = 2;
  bytes  nonce = 3;
  bytes  tag = 4;
}
message DecryptPayloadResponse { bytes plaintext = 1; }

message SignRequest  { bytes message = 1; }
message SignResponse { bytes signature = 1; }

message VerifyRequest {
  string dilithium_pk_b64 = 1;
  bytes  message = 2;
  bytes  signature = 3;
}
message VerifyResponse { bool valid = 1; }
```

### proto/chain_relay.proto
```protobuf
syntax = "proto3";
package kosh.relay;
option go_package = "github.com/kosh/relay/pb";

service ChainRelay {
  // Submit a contract action and wait for on-chain confirmation.
  // Streams status events back: QUEUED → SUBMITTED → CONFIRMED / FAILED.
  rpc Submit(SubmitRequest) returns (stream TxEvent);
  // Read raw contract state (JSON deserialized from Partisia RPC).
  rpc GetContractState(GetContractStateRequest) returns (GetContractStateResponse);
}

message SubmitRequest {
  // Which party's key to use for signing the transaction.
  uint32 party_index = 1;
  // Deployed contract address (hex).
  string contract_address = 2;
  // Action shortname (e.g. 0x20 for dkg_create_key).
  uint32 shortname = 3;
  // Pre-encoded action arguments (matches existing chain-utils.ts encoding).
  bytes  args = 4;
  // Human-readable label for logging/tracing.
  string label = 5;
}

message TxEvent {
  enum Status {
    QUEUED    = 0;
    SUBMITTED = 1;
    CONFIRMED = 2;
    FAILED    = 3;
  }
  Status status = 1;
  string tx_id  = 2;
  string error  = 3;
}

message GetContractStateRequest  { string contract_address = 1; }
message GetContractStateResponse { string state_json = 1; }
```

### proto/policy.proto
```protobuf
syntax = "proto3";
package kosh.policy;
option go_package = "github.com/kosh/policy/pb";

service PolicyService {
  rpc AddPolicy(AddPolicyRequest) returns (AddPolicyResponse);
  rpc RemovePolicy(RemovePolicyRequest) returns (RemovePolicyResponse);
  rpc ListPolicies(ListPoliciesRequest) returns (ListPoliciesResponse);
  rpc Validate(ValidateRequest) returns (ValidateResponse);
}

message Policy {
  uint32 id = 1;
  string name = 2;
  string tx_tag = 3;
  repeated uint32 mandatory_parties = 4;
  uint32 min_threshold = 5;
  string created_at = 6;
}

message AddPolicyRequest  { Policy policy = 1; }
message AddPolicyResponse { uint32 id = 1; }

message RemovePolicyRequest  { uint32 id = 1; }
message RemovePolicyResponse { bool ok = 1; }

message ListPoliciesRequest  {}
message ListPoliciesResponse { repeated Policy policies = 1; }

message ValidateRequest {
  string   tx_tag  = 1;
  repeated uint32 signing_parties = 2;
}
message ValidateResponse {
  bool   ok = 1;
  string violation_message = 2;
  repeated uint32 missing_parties = 3;
}
```

### proto/party.proto
```protobuf
syntax = "proto3";
package kosh.party;
option go_package = "github.com/kosh/party/pb";

service PartyService {
  // Trigger DKG for a key_id. Streams phase events back to the gateway.
  rpc StartDkg(DkgRequest) returns (stream DkgEvent);
  // Trigger signing. Streams phase events back.
  rpc StartSign(SignRequest) returns (stream SignEvent);
  // Get current status of this party.
  rpc GetStatus(StatusRequest) returns (StatusResponse);
}

message DkgRequest {
  uint32 key_id      = 1;
  uint32 num_parties = 2;
  uint32 threshold   = 3;
}

message DkgEvent {
  enum Phase {
    DKG_START        = 0;
    DKG_COMMITTED    = 1;
    DKG_REVEALED     = 2;
    DKG_SUBSHARES    = 3;
    DKG_FINALIZED    = 4;
    DKG_ZK_SUBMITTED = 5;
    DKG_COMPLETE     = 6;
    DKG_FAILED       = 7;
  }
  Phase  phase   = 1;
  string message = 2;
}

message SignRequest {
  uint32 key_id       = 1;
  bytes  message_hash = 2;
  string tx_tag       = 3;
  repeated uint32 signing_subset = 4;
}

message SignEvent {
  enum Phase {
    SIGN_START     = 0;
    PQC_APPROVED   = 1;
    GG20_ROUND1    = 2;
    MTA_COMPLETE   = 3;
    GG20_ROUND2    = 4;
    PARTIAL_SIGS   = 5;
    SIGN_COMPLETE  = 6;
    SIGN_FAILED    = 7;
  }
  Phase  phase     = 1;
  string message   = 2;
  bytes  signature = 3;   // set only on SIGN_COMPLETE
}

message StatusRequest  {}
message StatusResponse {
  uint32 party_index = 1;
  string current_phase = 2;
  repeated uint32 active_key_ids = 3;
}
```

---

## COMPLETE DKG FLOW — every function call traced

```
1. HTTP: POST /api/v1/keys  { key_id:42, num_parties:3, threshold:2 }
   Gateway parses request, validates JWT.
   Gateway calls: PolicyService.Validate(tx_tag="", parties=[1,2,3]) → ok

2. Gateway calls: PartyService(party-1).StartDkg({key_id:42, num_parties:3, threshold:2})
   Gateway calls: PartyService(party-2).StartDkg({key_id:42, num_parties:3, threshold:2})
   Gateway calls: PartyService(party-3).StartDkg({key_id:42, num_parties:3, threshold:2})
   (all three in parallel — Go goroutines)

3. INSIDE kosh-party-i  (for each party i ∈ {1,2,3}):

   phase_tx.send(Phase::DkgStart)
   
   ── STEP 1: Generate polynomial ──────────────────────────────────────────
   let gen_resp = keystore_client.GenerateShare({
     key_id: 42, party_index: i, num_parties: 3, seed: ""
   }).await?;
   // KeyStore internally:
   //   s_i = random scalar mod N
   //   a_i = random scalar mod N
   //   f_i(x) = s_i + a_i·x   (mod N)
   //   C_i0 = s_i·G            (compressed, 33 bytes)
   //   C_i1 = a_i·G            (compressed, 33 bytes)
   //   subshares[j] = f_i(j)   for j=1,2,3
   //   schnorr_proof = {R=r·G, z=r + e·s_i mod N}
   //     where e = SHA256(G || C_i0 || R || i)
   //   Encrypts each subshare[j] with kyber_pk_j:
   //     pqc_client.Encapsulate(kyber_pk_j) → {ciphertext, shared_secret}
   //     pqc_client.EncryptPayload(shared_secret, subshare_bytes) → encrypted
   //   Saves ShareFile{keyId:42, partyIndex:i, s_i, a_i} encrypted to disk (AES-256-GCM)
   // Returns: c_i0_hex, c_i1_hex, commitment_hash_hex, schnorr_r_hex, schnorr_z_hex,
   //          encrypted_subshares{j: "..."}

   ── STEP 2: Post commit to bulletin board ─────────────────────────────────
   let commit_payload = json!({
     "c_i0": gen_resp.c_i0_hex,
     "c_i1": gen_resp.c_i1_hex,
     "hash": gen_resp.commitment_hash_hex,
     "schnorr_r": gen_resp.schnorr_r_hex,
     "schnorr_z": gen_resp.schnorr_z_hex
   });
   bb_client.Post("dkg_commit_42_party_{i}", commit_payload.to_string()).await?;

   ── STEP 3: Watch for all other parties' commits ──────────────────────────
   // Uses gRPC streaming Watch — no polling. Each watch call opens a server stream.
   // tokio::select! races against 5-min timeout.
   let mut other_commits = HashMap::new();
   for j in 1..=3 { if j == i {
     let mut stream = bb_client.Watch("dkg_commit_42_party_{j}").await?;
     tokio::select! {
       event = stream.next() => {
         let commit = parse_commit(event?.value);
         // Verify Schnorr proof: z·G == R + e·C_j0
         verify_schnorr_proof(&commit.c_j0, &commit.schnorr_r, &commit.schnorr_z, j)?;
         other_commits.insert(j, commit);
       }
       _ = tokio::time::sleep(PHASE_TIMEOUT) => bail!("DKG commit timeout party {j}"),
     }
   }}

   ── STEP 4: Post encrypted sub-shares ─────────────────────────────────────
   for j in 1..=3 { if j != i {
     bb_client.Post(
       "dkg_subshare_42_from_{i}_to_{j}",
       gen_resp.encrypted_subshares["j={j}"].clone()
     ).await?;
   }}

   ── STEP 5: Receive and verify sub-shares from others ─────────────────────
   for j in 1..=3 { if j != i {
     let stream = bb_client.Watch("dkg_subshare_42_from_{j}_to_{i}").await?;
     let encrypted = stream.next().await?.value;
     
     // Decrypt: PQC service decapsulates using this party's kyber private key
     let decap = pqc_client.Decapsulate(kyber_ct_from_j).await?;
     let subshare_bytes = pqc_client.DecryptPayload(
       decap.shared_secret, encrypted_payload
     ).await?.plaintext;
     
     // Verify Feldman: f_j(i)·G == C_j0 + i·C_j1
     keystore_client.ReceiveSubshare({
       key_id: 42, from_party: j, subshare_hex: hex(subshare_bytes),
       c_j0_hex: other_commits[j].c_j0, c_j1_hex: other_commits[j].c_j1
     }).await?;
     // KeyStore verifies: subshare·G == C_j0 + j_scalar·C_j1
     // If mismatch: returns valid=false, party initiates blame protocol
   }}

   ── STEP 6: Finalize share (combine all sub-shares) ──────────────────────
   let finalize = keystore_client.FinalizeShare({key_id: 42}).await?;
   // KeyStore: X_i = Σ f_j(i) for all j  (Shamir share for party i)
   //          combined_pk = Σ C_j0  (sum of all parties' C_j0 points)
   // Saves final adjusted share + combined_pk to encrypted file
   // Returns: combined_pk_hex

   ── STEP 7: On-chain DKG ceremony (all via ChainRelay) ───────────────────
   // Party 1 only: create the key slot
   if i == 1 {
     chain_relay.Submit({party_index:1, shortname:0x20,
       args: encode_dkg_create_key(key_id=42, num_parties=3, threshold=2),
       label:"dkg_create_key"
     }).await?;
   }
   // Wait for Party 1 to post "dkg_created_42" signal
   bb_client.Watch("dkg_created_42_by_1").await?...;

   // All parties: commit
   chain_relay.Submit({party_index:i, shortname:0x21,
     args: encode_dkg_commit(key_id=42,
       commitment_hash=gen_resp.commitment_hash_hex,
       schnorr_r=gen_resp.schnorr_r_hex,
       schnorr_z=gen_resp.schnorr_z_hex,
       c_i1=gen_resp.c_i1_hex),
     label:"dkg_commit"
   }).await?;

   // All parties: reveal
   chain_relay.Submit({party_index:i, shortname:0x22,
     args: encode_dkg_reveal(key_id=42, pubkey_share=gen_resp.c_i0_hex),
     label:"dkg_reveal"
   }).await?;

   // Party 1 only: finalize (calls dkg_finalize → contract combines public keys)
   if i == 1 {
     chain_relay.Submit({party_index:1, shortname:0x23,
       args: encode_dkg_finalize(key_id=42),
       label:"dkg_finalize"
     }).await?;
   }

   // All parties: submit ZK share halves (the Shamir share to ZK nodes)
   let halves = keystore_client.GetShareHalves({key_id: 42}).await?;
   // share_hi and share_lo submitted as two separate ZK secret inputs
   submit_zk_share_half(hi=halves.share_hi, is_high_half=true, ...);
   submit_zk_share_half(lo=halves.share_lo, is_high_half=false, ...);

   // Party 1 only: complete keygen
   if i == 1 {
     chain_relay.Submit({party_index:1, shortname:0x24,
       args: encode_dkg_complete_keygen(key_id=42),
       label:"dkg_complete_keygen"
     }).await?;
   }

   ── STEP 8: Register PQC identities on-chain (Party 1 only) ──────────────
   if i == 1 {
     for j in 1..=3 {
       // Get party j's Kyber + Dilithium pubkeys from coordinator
       let pqc_info = bb_client.Read("pqc_identity_party_{j}").await?;
       chain_relay.Submit({party_index:1, shortname:0x73,
         args: encode_register_dilithium_pubkey(key_id:42, party:j, pk:pqc_info.dilithium_pk),
         label:"register_dilithium"
       }).await?;
       chain_relay.Submit({party_index:1, shortname:0x74,
         args: encode_register_kyber_pubkey(key_id:42, party:j, pk:pqc_info.kyber_pk),
         label:"register_kyber"
       }).await?;
     }
   }

   phase_tx.send(Phase::DkgComplete);
   stream DkgEvent{phase: DKG_COMPLETE, message: "combined_pk={finalize.combined_pk_hex}"}

4. Gateway receives DKG_COMPLETE from all 3 parties.
   HTTP response: 200 { key_id:42, combined_pk_hex:"03...", eth_address:"0x..." }
```

---

## COMPLETE SIGNING FLOW — every function call traced

```
1. HTTP: POST /api/v1/sign
   { key_id:42, message_hash:"0xabc...", tx_tag:"transfer", signing_subset:[1,2] }

2. Gateway:
   PolicyService.Validate(tx_tag:"transfer", parties:[1,2]) → ok
   Post to coordinator: BulletinBoard.Post("sign_request_42_session_7",
     json!{hash, tx_tag, subset:[1,2]})

3. kosh-party-1 and kosh-party-2 each watch "sign_request_42*" prefix (using Watch stream).

   ═══ PQC APPROVAL PHASE ══════════════════════════════════════════════════════

   Each party i:
   
   a) Post own PQC identity to coordinator (once per session):
      pqc_ident = pqc_client.GetIdentity({}).await?;
      bb_client.Post("pqc_identity_party_{i}", json!{kyber_pk, dilithium_pk}).await?;

   b) Watch for other signing party's PQC identity:
      other_pqc = bb_client.Watch("pqc_identity_party_{j}").await?;

   c) ML-KEM key exchange with each other party j:
      // Encapsulate to j's Kyber pubkey
      encap = pqc_client.Encapsulate(other_pqc.kyber_pk).await?;
      // shared_secret_ij = encap.shared_secret
      // Post ciphertext to coordinator for j to decapsulate
      bb_client.Post("pqc_kem_ct_42_from_{i}_to_{j}", encap.ciphertext).await?;
      // Receive j's ciphertext and decapsulate with own private key
      ct_from_j = bb_client.Watch("pqc_kem_ct_42_from_{j}_to_{i}").await?;
      decap = pqc_client.Decapsulate(ct_from_j).await?;
      // shared_secret_ji = decap.shared_secret

   d) Dilithium sign the approval message:
      approval_msg = sha256(message_hash || signing_subset_bytes || key_id_bytes);
      sig = pqc_client.Sign(approval_msg).await?;

   e) On-chain PQC approval (Party 1 initiates):
      if i == 1 {
        chain_relay.Submit({shortname:0x75,
          args: encode_start_pqc_approval_session(key_id:42, task_id:0, subset:[1,2]),
          label:"start_pqc_approval"}).await?;
      }
      // Both parties submit approval
      chain_relay.Submit({shortname:0x76,
        args: encode_submit_pqc_approval(key_id:42,
          dilithium_sig=sig, kyber_ciphertext=encap.ciphertext_b64),
        label:"submit_pqc_approval"}).await?;
      // Party 1 finalizes
      if i == 1 {
        chain_relay.Submit({shortname:0x77,
          args: encode_finalize_pqc_approval(key_id:42),
          label:"finalize_pqc_approval"}).await?;
      }

   ═══ GG20 ROUND 1 — generate nonce material ══════════════════════════════

   Each party i:
   
   a) Load Shamir share from keystore:
      share_halves = keystore_client.GetShareHalves({key_id:42}).await?;
      x_i = reconstruct_bigint(share_halves.share_hi, share_halves.share_lo);
   
   b) Generate k_i (deterministic HMAC-DRBG mixing x_i + message_hash + session_id):
      k_i = hmac_drbg_nonce(x_i, message_hash, session_id="42_7");
      gamma_i = random_scalar();
      Gamma_i = gamma_i * G;  // k256::ProjectivePoint::GENERATOR * gamma_i_scalar
   
   c) Commit to Gamma_i (prevent last-submitter bias):
      nonce_for_commit = random_bytes(32);
      gamma_commit_hash = sha256(Gamma_i_compressed || nonce_for_commit);
      bb_client.Post("gg20_gamma_commit_42_7_party_{i}", hex(gamma_commit_hash)).await?;
   
   d) Wait for all other parties' gamma commits:
      for j in signing_subset { if j != i {
        bb_client.Watch("gg20_gamma_commit_42_7_party_{j}").await?;
      }}
   
   e) Now reveal Gamma_i:
      bb_client.Post("gg20_gamma_reveal_42_7_party_{i}",
        json!{Gamma_i: hex(Gamma_i_compressed), nonce: hex(nonce_for_commit)}).await?;
   
   f) Wait for and verify other reveals:
      for j { other_Gamma_j = bb_client.Watch("gg20_gamma_reveal_42_7_party_{j}").await?;
        verify sha256(Gamma_j || nonce_j) == gamma_commit_j; }

   g) Party 1 starts GG20 signing on-chain:
      task_id = keystore_client.GetNextTaskId({key_id:42}).await?.next_task_id;
      if i == 1 {
        chain_relay.Submit({shortname:0x50,
          args: encode_gg20_start_signing(key_id:42, task_id, subset:[1,2],
            message_hash, tx_tag:"transfer"),
          label:"gg20_start_signing"}).await?;
      }

   ═══ GG20 MtA ROUNDS — all counterparty pairs run in parallel ═══════════

   // For 2-party signing (parties 1 and 2), there is exactly one MtA pair: (1,2).
   // For 3-party signing, there are 3 pairs: (1,2), (1,3), (2,3).
   // FuturesUnordered runs all pairs concurrently.

   struct MtAJob { i: u8, j: u8, x_i: Scalar, k_i: Scalar, gamma_i: Scalar }

   let mut mta_futures = FuturesUnordered::new();
   for j in signing_subset { if j != i {
     mta_futures.push(run_mta_pair(i, j, x_i, k_i, gamma_i, &bb, &pqc));
   }}
   let mta_outputs: Vec<MtAOutput> = mta_futures.collect::<Result<_>>().await?;
   // MtAOutput { alpha_ij, beta_ij, alpha_ji, beta_ji }

   // run_mta_pair(i, j, ...) does exactly this:
   //
   // PARTY i ACTS AS PARTY A (initiator):
   //   paillier_keys_i = paillier_keygen(2048);  // 2048-bit safe primes
   //   Post paillier pubkey: bb.Post("paillier_pk_42_7_party_{i}", json!{pk:n})
   //   Wait for j's paillier pubkey: paillier_pk_j = bb.Watch("paillier_pk_42_7_party_{j}")
   //
   //   MtA Round 1 (i enciphers k_i * x_i to j):
   //   beta_ij = random_scalar_in_range(N^2);  // masking term
   //   enc_ki_xi = paillier_encrypt(paillier_pk_j, k_i * x_i);
   //   enc_masking = paillier_scalar_mul(paillier_pk_j, enc_ki_xi, -beta_ij mod N);
   //   // This gives enc(k_i * x_i - beta_ij)
   //   // Encrypt message via PQC (shared secret from KEM exchange above):
   //   ct_a = pqc.EncryptPayload(shared_secret_ij, round1_msg_bytes)
   //   bb.Post("mta_kx_round1_42_7_from_{i}_to_{j}", ct_a)
   //
   //   Wait for j's response:
   //   ct_resp = bb.Watch("mta_kx_round2_42_7_from_{j}_to_{i}")
   //   alpha_ij_bytes = pqc.DecryptPayload(shared_secret_ij, ct_resp)
   //   alpha_ij = bytes_to_bigint(alpha_ij_bytes) mod N
   //   // Now: alpha_ij + beta_ij = k_i * x_j  (the cross term, split additively)
   //
   // PARTY j ACTS AS PARTY B (responder):
   //   Reads i's enc_masking
   //   dec = paillier_decrypt(enc_masking)  // = k_i * x_i - beta_ij
   //   alpha_ji = (dec + beta_ij) mod N = k_i * x_i ... wait no:
   //   Actually: alpha_ji = paillier_decrypt(paillier_encrypt(pk_i, k_j * x_i) + enc_from_i)
   //   // full MtA from GG20 paper section 3.2
   //   Post alpha_ji back to i encrypted
   //
   // SAME pattern for k·gamma cross-terms (mta_kgamma_round1/2):
   //   generates beta_gamma_ij, alpha_gamma_ij such that
   //   alpha_gamma_ij + beta_gamma_ij = k_i * gamma_j

   ═══ GG20 ROUND 2 — aggregate + on-chain ═════════════════════════════════

   Each party i:
   
   a) Compute delta_i:
      // delta_i = k_i * gamma_i + Σ_j (alpha_gamma_ij + beta_gamma_ji)
      delta_i = k_i * gamma_i;
      for output in &mta_outputs {
        delta_i = (delta_i + output.alpha_gamma + output.beta_gamma) % N;
      }
   
   b) Compute sigma_i (partial signing key):
      // sigma_i = k_i * x_i + Σ_j (alpha_kx_ij + beta_kx_ji)
      sigma_i = k_i * x_i;
      for output in &mta_outputs {
        sigma_i = (sigma_i + output.alpha_kx + output.beta_kx) % N;
      }
   
   c) Commit-reveal for delta (same pattern as gamma):
      delta_commit = sha256(delta_i_bytes || nonce_delta);
      bb.Post("gg20_delta_commit_42_7_party_{i}", delta_commit);
      // Wait for all delta commits, then reveal:
      bb.Post("gg20_delta_reveal_42_7_party_{i}", json!{delta: hex(delta_i), nonce: hex(nonce_delta)});
      // Wait for others' reveals, verify.
   
   d) On-chain: submit delta + gamma point
      chain_relay.Submit({shortname:0x45,
        args: encode_submit_delta(key_id:42, task_id, delta_bytes),
        label:"submit_delta"}).await?;
      chain_relay.Submit({shortname:0x46,
        args: encode_submit_gamma_point(key_id:42, task_id, Gamma_i_compressed),
        label:"submit_gamma_point"}).await?;
   
   e) Party 1 finalizes R (after all deltas + gammas submitted on-chain):
      if i == 1 {
        chain_relay.Submit({shortname:0x47,
          args: encode_gg20_finalize_r(key_id:42, task_id),
          label:"gg20_finalize_r"}).await?;
        // Contract computes: δ = Σδ_i, Γ = Σ Γ_i, R = (1/δ)·Γ, r = R.x mod N
      }
      // Wait for finalize to confirm, read r from contract state
      contract_state = chain_relay.GetContractState(SIGNER_ADDRESS).await?;
      r = parse_r_from_state(contract_state.state_json);

   ═══ PARTIAL SIGNATURES ══════════════════════════════════════════════════

   Each party i:
   
   a) Compute partial signature:
      // s_i = k_i^{-1} * (m + r * sigma_i)  mod N
      // where m = message_hash as scalar, r from contract state
      m = bytes_to_scalar(message_hash_bytes);
      kinv = mod_inverse(k_i, N);
      s_i = (kinv * (m + r * sigma_i)) % N;
   
   b) Commit, then submit:
      s_i_commit = sha256(s_i_bytes);
      chain_relay.Submit({shortname:0x51,
        args: encode_commit_partial_sig(key_id:42, task_id, s_i_commit),
        label:"commit_partial_sig"}).await?;
      // Wait for all parties to commit before revealing:
      chain_relay.Submit({shortname:0x52,
        args: encode_submit_partial_sig(key_id:42, task_id, s_i_bytes),
        label:"submit_partial_sig"}).await?;
   
   c) Party 1 finalizes:
      if i == 1 {
        chain_relay.Submit({shortname:0x53,
          args: encode_finalize_gg20_sig(key_id:42, task_id),
          label:"finalize_gg20_sig"}).await?;
        // Contract: s = Σ s_i, verifies secp256k1.verify(pk, hash, (r,s)) on-chain
      }
   
   d) Advance task counter in keystore:
      keystore_client.AdvanceTaskId({key_id:42}).await?;
   
   e) Stream final event:
      stream SignEvent{phase: SIGN_COMPLETE, signature: r||s||v bytes}

4. Gateway receives SIGN_COMPLETE from party-1.
   HTTP response: 200 { signature:"0x{r}{s}{v}", eth_address:"0x...", 
                         tx_hash:"0x...", key_id:42 }
```

---

## kosh-coordinator COMPLETE IMPLEMENTATION DETAIL (Go)

### internal/bb/hub.go
```go
// Hub is a per-topic broadcast channel. Multiple Watch subscribers each get
// their own chan string. When Post fires, all active subscribers receive the value.
type Hub struct {
    mu   sync.Mutex
    subs map[uint64]chan string
    next uint64
}

func NewHub() *Hub { return &Hub{subs: make(map[uint64]chan string)} }

func (h *Hub) Subscribe() (uint64, <-chan string) {
    h.mu.Lock(); defer h.mu.Unlock()
    id := h.next; h.next++
    ch := make(chan string, 4)
    h.subs[id] = ch
    return id, ch
}

func (h *Hub) Unsubscribe(id uint64) {
    h.mu.Lock(); defer h.mu.Unlock()
    if ch, ok := h.subs[id]; ok { close(ch); delete(h.subs, id) }
}

func (h *Hub) Broadcast(val string) {
    h.mu.Lock(); defer h.mu.Unlock()
    for _, ch := range h.subs {
        select { case ch <- val: default: } // non-blocking; slow subscribers miss nothing
    }
}
```

### internal/bb/store.go
```go
type Store struct {
    mu   sync.RWMutex
    data map[string]string
    hubs map[string]*Hub
}

func (s *Store) Post(topic, value string) {
    s.mu.Lock()
    s.data[topic] = value
    hub := s.hubs[topic]
    if hub == nil { hub = NewHub(); s.hubs[topic] = hub }
    s.mu.Unlock()
    hub.Broadcast(value) // broadcast outside the lock — no deadlock
}

func (s *Store) Read(topic string) (string, bool) {
    s.mu.RLock(); defer s.mu.RUnlock()
    v, ok := s.data[topic]; return v, ok
}

func (s *Store) Subscribe(topic string) (uint64, <-chan string) {
    s.mu.Lock()
    if s.hubs[topic] == nil { s.hubs[topic] = NewHub() }
    hub := s.hubs[topic]
    s.mu.Unlock()
    return hub.Subscribe()
}
```

### internal/bb/server.go
```go
// Watch: if value already exists, send it immediately, then keep streaming updates.
func (srv *Server) Watch(req *pb.WatchRequest, stream pb.BulletinBoard_WatchServer) error {
    topic := req.Topic

    // Send existing value immediately if present
    if val, ok := srv.store.Read(topic); ok {
        if err := stream.Send(&pb.WatchEvent{Topic: topic, Value: val}); err != nil {
            return err
        }
    }

    // Subscribe to future updates
    id, ch := srv.store.Subscribe(topic)
    defer srv.store.hub(topic).Unsubscribe(id)

    for {
        select {
        case val, open := <-ch:
            if !open { return nil }
            if err := stream.Send(&pb.WatchEvent{Topic: topic, Value: val}); err != nil {
                return err
            }
        case <-stream.Context().Done():
            return nil
        }
    }
}
```

---

## kosh-party COMPLETE IMPLEMENTATION DETAIL (Rust)

### src/phase.rs — complete state machine
```rust
#[derive(Debug, Clone, PartialEq)]
pub enum Phase {
    Idle,
    DkgCommit,
    DkgReveal,
    DkgSubshares,
    DkgOnchain,
    DkgComplete,
    PqcRegister,
    PqcApproval,
    Gg20Round1,
    Gg20Mta,
    Gg20Round2,
    Gg20PartialSigs,
    SignComplete { signature: [u8; 65] },
    Failed { reason: String },
}

pub struct PartySession {
    pub key_id:          u32,
    pub party_index:     u8,
    pub signing_subset:  Vec<u8>,
    pub message_hash:    [u8; 32],
    pub tx_tag:          String,
    pub task_id:         u32,
    // GG20 running state
    pub k_i:             Option<k256::Scalar>,
    pub gamma_i:         Option<k256::Scalar>,
    pub Gamma_i:         Option<k256::ProjectivePoint>,
    pub delta_i:         Option<k256::Scalar>,
    pub sigma_i:         Option<k256::Scalar>,
    pub mta_outputs:     Vec<MtAOutput>,
    pub r:               Option<k256::Scalar>,
}

// Phase loop in main:
// let (phase_tx, mut phase_rx) = mpsc::channel::<Phase>(32);
// tokio::spawn(async move { ... session.run(&mut phase_rx).await });
// stream back DkgEvent/SignEvent via the gRPC response stream
```

### src/mta.rs — FuturesUnordered parallel MtA
```rust
pub struct MtAOutput {
    pub counterparty:   u8,
    pub alpha_kx:       k256::Scalar,   // additive share of k_i · x_j
    pub beta_kx:        k256::Scalar,   // our masking term for k · x cross
    pub alpha_kgamma:   k256::Scalar,   // additive share of k_i · gamma_j
    pub beta_kgamma:    k256::Scalar,   // our masking term for k · gamma cross
}

pub async fn run_all_mta_rounds(
    party_index: u8,
    signing_subset: &[u8],
    k_i: k256::Scalar,
    gamma_i: k256::Scalar,
    x_i: k256::Scalar,
    bb: &BulletinBoardClient,
    pqc: &PqcClient,
    key_id: u32,
    session_id: u32,
) -> Result<Vec<MtAOutput>> {
    let futures: FuturesUnordered<_> = signing_subset
        .iter()
        .filter(|&&j| j != party_index)
        .map(|&j| {
            run_mta_pair(party_index, j, k_i, gamma_i, x_i,
                         bb.clone(), pqc.clone(), key_id, session_id)
        })
        .collect();

    futures.collect::<Result<Vec<_>>>().await
}

async fn run_mta_pair(i: u8, j: u8, k_i: Scalar, gamma_i: Scalar, x_i: Scalar,
                      bb: BulletinBoardClient, pqc: PqcClient,
                      key_id: u32, session: u32) -> Result<MtAOutput> {
    // 1. Exchange Paillier public keys via coordinator
    // 2. MtA Round 1: i sends Enc_pk_j(k_i * x_i) masked with beta_ij
    // 3. MtA Round 2: j homomorphically computes and responds with alpha_ji
    // 4. MtA Finalize: i decrypts alpha_ij
    // 5. Repeat for k·gamma cross-term
    // All network I/O is gRPC Watch (zero polling)
    // Paillier ops use num-bigint (2048-bit safe primes)
    ...
}
```

### src/paillier.rs — 2048-bit Paillier
```rust
// Direct port of client/src/paillier.ts, same math, same algorithms.
// num-bigint for arbitrary-precision arithmetic.
// PRIME_BITS = 2048 (upgraded from TypeScript's 1024).
// generateSafePrime: fails with Error if no safe prime found — NO fallback.

pub struct PaillierPublicKey  { pub n: BigUint, pub n2: BigUint, pub g: BigUint }
pub struct PaillierPrivateKey { pub lambda: BigUint, pub mu: BigUint }

pub fn keygen(prime_bits: usize) -> (PaillierPublicKey, PaillierPrivateKey) {
    let p = generate_safe_prime(prime_bits); // panics if no safe prime in 500*bits attempts
    let q = loop { let q = generate_safe_prime(prime_bits); if q != p { break q } };
    ...
}
pub fn encrypt(pk: &PaillierPublicKey, m: &BigUint) -> BigUint { ... }
pub fn decrypt(pk: &PaillierPublicKey, sk: &PaillierPrivateKey, c: &BigUint) -> BigUint { ... }
pub fn add_ciphertexts(pk: &PaillierPublicKey, c1: &BigUint, c2: &BigUint) -> BigUint {
    (c1 * c2) % &pk.n2
}
pub fn scalar_mul(pk: &PaillierPublicKey, c: &BigUint, k: &BigUint) -> BigUint {
    k.modpow(c, &pk.n2)  // note: k^c mod n2 in Paillier scalar mul
}
```

---

## kosh-keystore COMPLETE IMPLEMENTATION DETAIL (Rust)

### src/store.rs — AES-256-GCM share file
```rust
// Direct port of persistShare() / decryptShareFile() from party.ts.
// Same file format so existing .enc share files still load correctly.

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ShareFile {
    pub key_id:           u32,
    pub party_index:      u8,
    pub shamir_share_hex: String,   // final X_i = Σ f_j(i)
    pub combined_pk_hex:  String,   // Σ C_j0
    pub next_task_id:     u32,      // incremented after each signing session
}

#[derive(Serialize, Deserialize)]
struct EncryptedShareFile {
    version:    u8,       // always 1
    nonce:      String,   // base64, 12 bytes
    tag:        String,   // base64, 16 bytes
    ciphertext: String,   // base64
}

pub fn persist_share(share: &ShareFile, passphrase: &str, path: &Path) -> Result<()> {
    let key = Sha256::digest(passphrase.as_bytes());
    let nonce_bytes = rand::random::<[u8; 12]>();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = serde_json::to_vec(share)?;
    let mut ciphertext = plaintext.clone();
    let tag = cipher.encrypt_in_place_detached(nonce, b"", &mut ciphertext)?;
    let enc = EncryptedShareFile {
        version: 1,
        nonce: base64::encode(nonce_bytes),
        tag: base64::encode(tag),
        ciphertext: base64::encode(&ciphertext),
    };
    fs::write(path, serde_json::to_string_pretty(&enc)?)?;
    Ok(())
}

pub fn load_share(passphrase: &str, path: &Path) -> Result<ShareFile> {
    let raw = fs::read_to_string(path)?;
    let enc: EncryptedShareFile = serde_json::from_str(&raw)?;
    let key = Sha256::digest(passphrase.as_bytes());
    let nonce = base64::decode(&enc.nonce)?;
    let tag = base64::decode(&enc.tag)?;
    let mut ct = base64::decode(&enc.ciphertext)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    cipher.decrypt_in_place_detached(
        Nonce::from_slice(&nonce), b"", &mut ct, Tag::from_slice(&tag)
    )?;
    Ok(serde_json::from_slice(&ct)?)
}
```

### src/feldman.rs — Feldman VSS
```rust
// Port of generateThresholdDkgShare() + verifyFeldmanSubshare() from dkg-party.ts.

pub struct FeldmanShare {
    pub s_i:     k256::Scalar,  // secret constant term (ZeroizeOnDrop)
    pub a_i:     k256::Scalar,  // slope term
    pub c_i0:    [u8; 33],      // s_i * G (compressed)
    pub c_i1:    [u8; 33],      // a_i * G (compressed)
    pub sub_shares: Vec<k256::Scalar>,  // f_i(j) for j=1..num_parties
}

pub fn generate(party_index: u8, num_parties: u8) -> FeldmanShare {
    let s_i = random_scalar();
    let a_i = random_scalar();
    let c_i0 = (G * s_i).to_affine().to_bytes_compressed();
    let c_i1 = (G * a_i).to_affine().to_bytes_compressed();
    let sub_shares = (1..=num_parties)
        .map(|j| s_i + a_i * scalar_from_u8(j))  // f_i(j) = s_i + a_i·j
        .collect();
    FeldmanShare { s_i, a_i, c_i0, c_i1, sub_shares }
}

// verify: f_j(i)·G == C_j0 + i·C_j1
pub fn verify_subshare(subshare: &k256::Scalar, c_j0: &[u8;33], c_j1: &[u8;33], i: u8) -> bool {
    let lhs = G * subshare;
    let p_j0 = decode_point(c_j0);
    let p_j1 = decode_point(c_j1);
    let rhs = p_j0 + p_j1 * scalar_from_u8(i);
    lhs == rhs
}

// combine: X_i = Σ f_j(i) for all j  — nominal path: all n parties present
pub fn combine_subshares(received: &[(u8, k256::Scalar)]) -> k256::Scalar {
    received.iter().fold(k256::Scalar::ZERO, |acc, (_, s)| acc + s)
}

// Lagrange interpolation for t-of-n threshold reconstruction.
// Used when only a subset of parties is available (blame/recovery path).
// Nominal DKG uses combine_subshares; call this only if < n parties finalized.
//
// Formula: X = Σ λ_i · y_i  where λ_i = ∏_{j≠i} (0 - j) / (i - j)  mod N
pub fn lagrange_combine(shares: &[(u8, k256::Scalar)]) -> k256::Scalar {
    let mut result = k256::Scalar::ZERO;
    for (i, y_i) in shares {
        let mut num = k256::Scalar::ONE;
        let mut den = k256::Scalar::ONE;
        for (j, _) in shares {
            if j != i {
                num *= scalar_from_u8(*j).negate();              // (0 - j)
                den *= scalar_from_u8(*i) - scalar_from_u8(*j); // (i - j)
            }
        }
        let coeff = num * den.invert().unwrap(); // λ_i mod N
        result += coeff * y_i;
    }
    result
}
```

---

## kosh-chain-relay COMPLETE IMPLEMENTATION DETAIL (Rust)

### src/partisia.rs — submitAndWait port
```rust
// Direct port of submitAndWait() from client/src/chain-utils.ts.
// Same 7-retry logic, same error parsing from the spawned events tree.

pub async fn submit_and_wait(
    http:          &reqwest::Client,
    node_url:      &str,
    signing_key:   &k256::ecdsa::SigningKey,  // secp256k1 private key
    sender_addr:   &str,                       // 21-byte hex address
    contract_addr: &str,
    shortname:     u8,
    args:          &[u8],
    label:         &str,
) -> Result<TxReceipt> {
    let mut rpc = vec![shortname];
    rpc.extend_from_slice(args);
    // Partisia WASM action prefix: 0x09
    let payload = [&[0x09u8], rpc.as_slice()].concat();

    let mut last_err = None;
    for attempt in 1..=7u32 {
        let node = rotate_node(node_url, attempt);
        match try_submit(&http, &node, &signing_key, &sender_addr, &contract_addr,
                         &payload, label).await {
            Ok(receipt) => return Ok(receipt),
            Err(e) => {
                last_err = Some(e);
                if attempt < 7 {
                    warn!("{label}: transient failure attempt {attempt}/7, retrying");
                    tokio::time::sleep(Duration::from_secs(5 * attempt as u64)).await;
                }
            }
        }
    }
    Err(last_err.unwrap())
}

async fn try_submit(...) -> Result<TxReceipt> {
    // 1. Get account nonce from Partisia RPC
    // 2. Build transaction: { address, rpc, nonce, gas_cost:500000 }
    // 3. Sign with k256::ecdsa::SigningKey (same secp256k1 as TypeScript)
    // 4. POST /chain/transaction
    // 5. Poll /chain/transaction/{tx_id} until finalized
    // 6. Parse execution status from spawned events tree
    // 7. Return error if success=false (same logic as TypeScript chain-utils.ts)
}
```

### src/actions.rs — all 44 contract actions
```rust
// One encode_* function per contract action.
// Same encoding logic as the TypeScript buildXxx functions.
// All use encode_u32_be, encode_len_prefixed_bytes, concat_bytes from encode.rs.

pub fn encode_dkg_create_key(key_id: u32, num_parties: u8, threshold: u8) -> Vec<u8> {
    concat_bytes([encode_u32_be(key_id), &[num_parties], &[threshold]])
}

pub fn encode_dkg_commit(key_id: u32, commitment_hash: &[u8], schnorr_r: &[u8],
                          schnorr_z: &[u8], c_i1: &[u8]) -> Vec<u8> {
    concat_bytes([
        encode_u32_be(key_id),
        encode_len_prefixed_bytes(commitment_hash),
        encode_len_prefixed_bytes(schnorr_r),
        encode_len_prefixed_bytes(schnorr_z),
        encode_len_prefixed_bytes(c_i1),
    ])
}

pub fn encode_dkg_reveal(key_id: u32, pubkey_share: &[u8]) -> Vec<u8> { ... }
pub fn encode_dkg_finalize(key_id: u32) -> Vec<u8> { ... }
pub fn encode_dkg_complete_keygen(key_id: u32) -> Vec<u8> { ... }
pub fn encode_gg20_start_signing(key_id: u32, task_id: u32, parties: &[u8],
                                  msg_hash: &[u8], tx_tag: &str) -> Vec<u8> { ... }
pub fn encode_submit_delta(key_id: u32, task_id: u32, delta: &[u8]) -> Vec<u8> { ... }
pub fn encode_submit_gamma_point(key_id: u32, task_id: u32, gamma: &[u8]) -> Vec<u8> { ... }
pub fn encode_gg20_finalize_r(key_id: u32, task_id: u32) -> Vec<u8> { ... }
pub fn encode_commit_partial_sig(key_id: u32, task_id: u32, sig_hash: &[u8]) -> Vec<u8> { ... }
pub fn encode_submit_partial_sig(key_id: u32, task_id: u32, sig: &[u8]) -> Vec<u8> { ... }
pub fn encode_finalize_gg20_sig(key_id: u32, task_id: u32) -> Vec<u8> { ... }
pub fn encode_start_pqc_approval(key_id: u32, task_id: u32, parties: &[u8]) -> Vec<u8> { ... }
pub fn encode_submit_pqc_approval(key_id: u32, dilithium_sig: &[u8],
                                   kyber_ct: &[u8]) -> Vec<u8> { ... }
pub fn encode_finalize_pqc_approval(key_id: u32) -> Vec<u8> { ... }
pub fn encode_register_dilithium_pubkey(key_id: u32, party: u8, pk: &[u8]) -> Vec<u8> { ... }
pub fn encode_register_kyber_pubkey(key_id: u32, party: u8, pk: &[u8]) -> Vec<u8> { ... }
// ... all 44 actions follow the same pattern
```

---

## kosh-policy COMPLETE IMPLEMENTATION DETAIL (Go)

### internal/store/policy_store.go
```go
// Direct port of PolicyStore class from client/src/policy.ts.
// Same Policy struct, same Add/Remove/List/Check logic.
// Adds gRPC Validate endpoint.

type Policy struct {
    ID               int      `json:"id"`
    Name             string   `json:"name"`
    TxTag            string   `json:"txTag"`
    MandatoryParties []int    `json:"mandatoryParties"`
    MinThreshold     int      `json:"minThreshold"`
    CreatedAt        string   `json:"createdAt"`
}

type PolicyStore struct {
    mu       sync.RWMutex
    policies []Policy
    nextID   int
    filePath string  // if set, persist to JSON file on every Add/Remove
}

// Validate: for a given tx_tag and signing parties, return nil if all policies pass.
// Returns first PolicyViolation if any mandatory party is missing.
func (s *PolicyStore) Validate(txTag string, parties []int) *PolicyViolation {
    s.mu.RLock(); defer s.mu.RUnlock()
    for _, p := range s.policies {
        if p.TxTag != "" && p.TxTag != txTag { continue }
        if len(parties) < p.MinThreshold {
            return &PolicyViolation{...}
        }
        partySet := make(map[int]bool)
        for _, p := range parties { partySet[p] = true }
        var missing []int
        for _, m := range p.MandatoryParties {
            if !partySet[m] { missing = append(missing, m) }
        }
        if len(missing) > 0 {
            return &PolicyViolation{
                PolicyName:     p.Name,
                MissingParties: missing,
                Message: fmt.Sprintf("Policy '%s': parties %v are mandatory", p.Name, missing),
            }
        }
    }
    return nil
}
```

---

## kosh-gateway COMPLETE IMPLEMENTATION DETAIL (Go)

### internal/handler/sign.go
```go
func (h *Handler) HandleSign(w http.ResponseWriter, r *http.Request) {
    var req SignRequest
    json.NewDecoder(r.Body).Decode(&req)

    // 1. Validate policy
    vResp, _ := h.policyClient.Validate(ctx, &policyPb.ValidateRequest{
        TxTag: req.TxTag, SigningParties: req.SigningSubset,
    })
    if !vResp.Ok {
        http.Error(w, vResp.ViolationMessage, 422); return
    }

    // 2. Post sign request to coordinator
    sessionID := uuid.New().String()
    h.coordClient.Post(ctx, &bbPb.PostRequest{
        Topic: fmt.Sprintf("sign_request_%d_%s", req.KeyID, sessionID),
        Value: marshalSignRequest(req),
    })

    // 3. Start sign on each party in subset (parallel goroutines)
    var wg sync.WaitGroup
    events := make(chan *partyPb.SignEvent, 10)
    for _, p := range req.SigningSubset {
        wg.Add(1)
        go func(partyIdx int) {
            defer wg.Done()
            stream, _ := h.partyClients[partyIdx].StartSign(ctx, &partyPb.SignRequest{
                KeyId: req.KeyID, MessageHash: req.MessageHash,
                TxTag: req.TxTag, SigningSubset: req.SigningSubset,
            })
            for { ev, err := stream.Recv(); if err != nil { break }; events <- ev }
        }(p)
    }
    go func() { wg.Wait(); close(events) }()

    // 4. Wait for SIGN_COMPLETE from party 1
    var sig []byte
    for ev := range events {
        if ev.Phase == partyPb.SignEvent_SIGN_COMPLETE { sig = ev.Signature; break }
        if ev.Phase == partyPb.SignEvent_SIGN_FAILED   { http.Error(w, ev.Message, 500); return }
    }

    json.NewEncoder(w).Encode(SignResponse{
        Signature: hex.EncodeToString(sig),
        KeyID:     req.KeyID,
    })
}
```

---

## CARGO WORKSPACE (root Cargo.toml additions)

```toml
[workspace]
members = [
    "contracts/kosh-zk-signer",
    "contracts/kosh-vault",
    "contracts/kosh-account-registry",
    # --- NEW Rust microservices ---
    "services/kosh-party",
    "services/kosh-keystore",
    "services/kosh-pqc",
    "services/kosh-chain-relay",
]

[workspace.dependencies]
# Pinned versions for all Rust services — single version in the whole workspace
tokio       = { version = "1",      features = ["full"] }
tonic       = "0.12"
prost       = "0.13"
futures     = "0.3"
reqwest     = { version = "0.12",   features = ["json", "rustls-tls"] }
k256        = { version = "0.13.4", features = ["ecdsa", "arithmetic"] }
sha2        = "0.10"
aes-gcm     = "0.10"
serde       = { version = "1",      features = ["derive"] }
serde_json  = "1"
zeroize     = { version = "1",      features = ["derive"] }
num-bigint  = "0.4"
num-traits  = "0.2"
ml-kem      = "0.3"
ml-dsa      = "0.3"
tracing     = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
clap        = { version = "4",      features = ["derive"] }
rand        = "0.8"
hex         = "0.4"
base64      = "0.22"
anyhow      = "1"
thiserror   = "1"
uuid        = { version = "1",      features = ["v4"] }
```

### services/kosh-party/Cargo.toml
```toml
[package]
name = "kosh-party"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio.workspace        = true
tonic.workspace        = true
prost.workspace        = true
futures.workspace      = true
k256.workspace         = true
sha2.workspace         = true
serde.workspace        = true
serde_json.workspace   = true
zeroize.workspace      = true
num-bigint.workspace   = true
num-traits.workspace   = true
tracing.workspace      = true
tracing-subscriber.workspace = true
clap.workspace         = true
rand.workspace         = true
hex.workspace          = true
anyhow.workspace       = true
thiserror.workspace    = true
uuid.workspace         = true

[build-dependencies]
tonic-build = "0.12"
```

---

## DOCKER COMPOSE (complete, local dev)

```yaml
version: "3.9"

services:
  # ─── Go infra services ────────────────────────────────────────────────────
  coordinator:
    build: { context: services/kosh-coordinator, dockerfile: Dockerfile }
    ports: ["50051:50051"]
    environment:
      PORT: 50051
      LOG_LEVEL: info
    healthcheck:
      test: ["CMD", "grpc_health_probe", "-addr=:50051"]
      interval: 10s

  policy:
    build: { context: services/kosh-policy }
    ports: ["50052:50052"]
    volumes: ["./data/policy:/data"]
    environment:
      PORT: 50052
      POLICY_FILE: /data/policies.json
    healthcheck:
      test: ["CMD", "grpc_health_probe", "-addr=:50052"]

  gateway:
    build: { context: services/kosh-gateway }
    ports: ["8080:8080"]
    depends_on: [coordinator, policy, party-1, party-2, party-3]
    environment:
      PORT: 8080
      COORDINATOR_ADDR: coordinator:50051
      POLICY_ADDR: policy:50052
      PARTY_1_ADDR: party-1:50060
      PARTY_2_ADDR: party-2:50060
      PARTY_3_ADDR: party-3:50060
      JWT_SECRET: ${JWT_SECRET}

  monitor:
    build: { context: services/kosh-monitor }
    ports: ["9090:9090"]
    depends_on: [coordinator, policy, gateway]
    environment:
      COORDINATOR_ADDR: coordinator:50051
      GATEWAY_ADDR: gateway:8080
      SIGNER_ADDRESS: ${SIGNER_ADDRESS}
      PARTISIA_NODE_URL: ${PARTISIA_NODE_URL}

  # ─── Rust crypto services (per-party) ─────────────────────────────────────
  pqc-1:
    build: { context: services/kosh-pqc }
    ports: ["50080:50080"]
    volumes: ["./data/party1:/data"]
    environment:
      PORT: 50080
      PARTY_INDEX: 1
      PQC_KEY_FILE: /data/pqc-identity.json

  pqc-2:
    build: { context: services/kosh-pqc }
    ports: ["50081:50080"]
    volumes: ["./data/party2:/data"]
    environment:
      PORT: 50080
      PARTY_INDEX: 2
      PQC_KEY_FILE: /data/pqc-identity.json

  pqc-3:
    build: { context: services/kosh-pqc }
    ports: ["50082:50080"]
    volumes: ["./data/party3:/data"]
    environment:
      PORT: 50080
      PARTY_INDEX: 3
      PQC_KEY_FILE: /data/pqc-identity.json

  keystore-1:
    build: { context: services/kosh-keystore }
    ports: ["50070:50070"]
    volumes: ["./data/party1:/data"]
    environment:
      PORT: 50070
      PARTY_INDEX: 1
      SHARE_FILE_DIR: /data
      SHARE_FILE_KEY: ${SHARE_FILE_KEY_1}
    depends_on: [pqc-1]

  keystore-2:
    build: { context: services/kosh-keystore }
    ports: ["50071:50070"]
    volumes: ["./data/party2:/data"]
    environment:
      PORT: 50070
      PARTY_INDEX: 2
      SHARE_FILE_DIR: /data
      SHARE_FILE_KEY: ${SHARE_FILE_KEY_2}
    depends_on: [pqc-2]

  keystore-3:
    build: { context: services/kosh-keystore }
    ports: ["50072:50070"]
    volumes: ["./data/party3:/data"]
    environment:
      PORT: 50070
      PARTY_INDEX: 3
      SHARE_FILE_DIR: /data
      SHARE_FILE_KEY: ${SHARE_FILE_KEY_3}
    depends_on: [pqc-3]

  chain-relay:
    build: { context: services/kosh-chain-relay }
    ports: ["50053:50053"]
    env_file: .env
    environment:
      PORT: 50053
      PARTISIA_NODE_URLS: ${PARTISIA_NODE_URL}
      # One sender key per party (relay holds all 3 for the single-machine setup)
      PARTISIA_SENDER_KEY_1: ${PARTISIA_SENDER_KEY_1}
      PARTISIA_SENDER_KEY_2: ${PARTISIA_SENDER_KEY_2}
      PARTISIA_SENDER_KEY_3: ${PARTISIA_SENDER_KEY_3}
      PARTISIA_SENDER_ADDRESS_1: ${PARTISIA_SENDER_ADDRESS_1}
      PARTISIA_SENDER_ADDRESS_2: ${PARTISIA_SENDER_ADDRESS_2}
      PARTISIA_SENDER_ADDRESS_3: ${PARTISIA_SENDER_ADDRESS_3}
      SIGNER_ADDRESS: ${SIGNER_ADDRESS}

  party-1:
    build: { context: services/kosh-party }
    ports: ["50060:50060"]
    depends_on: [coordinator, keystore-1, pqc-1, chain-relay]
    environment:
      PORT: 50060
      PARTY_INDEX: 1
      COORDINATOR_ADDR: coordinator:50051
      KEYSTORE_ADDR: keystore-1:50070
      PQC_ADDR: pqc-1:50080
      CHAIN_RELAY_ADDR: chain-relay:50053
      SIGNER_ADDRESS: ${SIGNER_ADDRESS}
      NUM_PARTIES: 3
      SIGNING_SUBSET: "1,2"

  party-2:
    build: { context: services/kosh-party }
    ports: ["50061:50060"]
    depends_on: [coordinator, keystore-2, pqc-2, chain-relay]
    environment:
      PORT: 50060
      PARTY_INDEX: 2
      COORDINATOR_ADDR: coordinator:50051
      KEYSTORE_ADDR: keystore-2:50071
      PQC_ADDR: pqc-2:50081
      CHAIN_RELAY_ADDR: chain-relay:50053
      SIGNER_ADDRESS: ${SIGNER_ADDRESS}
      NUM_PARTIES: 3
      SIGNING_SUBSET: "1,2"

  party-3:
    build: { context: services/kosh-party }
    ports: ["50062:50060"]
    depends_on: [coordinator, keystore-3, pqc-3, chain-relay]
    environment:
      PORT: 50060
      PARTY_INDEX: 3
      COORDINATOR_ADDR: coordinator:50051
      KEYSTORE_ADDR: keystore-3:50072
      PQC_ADDR: pqc-3:50082
      CHAIN_RELAY_ADDR: chain-relay:50053
      SIGNER_ADDRESS: ${SIGNER_ADDRESS}
      NUM_PARTIES: 3
      SIGNING_SUBSET: "1,2"
```

---

## ENVIRONMENT VARIABLES (.env.example)

```bash
# ─── Partisia blockchain ──────────────────────────────────────────────────────
PARTISIA_NODE_URL=https://node1.testnet.partisiablockchain.com
SIGNER_ADDRESS=03...

# One Partisia key per party (held by chain-relay service)
PARTISIA_SENDER_KEY_1=500807...
PARTISIA_SENDER_ADDRESS_1=0087c0...
PARTISIA_SENDER_KEY_2=...
PARTISIA_SENDER_ADDRESS_2=...
PARTISIA_SENDER_KEY_3=...
PARTISIA_SENDER_ADDRESS_3=...

# ─── Share file encryption (one passphrase per party) ─────────────────────────
SHARE_FILE_KEY_1=party1-secret-passphrase-change-me
SHARE_FILE_KEY_2=party2-secret-passphrase-change-me
SHARE_FILE_KEY_3=party3-secret-passphrase-change-me

# ─── Gateway ──────────────────────────────────────────────────────────────────
JWT_SECRET=change-me-in-production

# ─── Optional ────────────────────────────────────────────────────────────────
LOG_LEVEL=info
```

---

## IMPLEMENTATION ORDER (what to build in sequence)

### Phase 1 — Foundation (no MPC math yet)
1. Write all 6 `.proto` files (defines all service contracts)
2. Build `kosh-coordinator` (Go) — simplest, needed by everything
3. Build `kosh-policy` (Go) — pure CRUD, no external deps
4. Write `services/proto/` compilation tooling (buf or protoc scripts)

### Phase 2 — Crypto isolation layer
5. Build `kosh-pqc` (Rust) — port pqc.ts: ML-KEM + ML-DSA, identity file
6. Build `kosh-keystore` (Rust) — port dkg-party.ts Feldman VSS + store.rs AES-GCM
7. Unit test pqc + keystore thoroughly (encrypt/decrypt round-trip, Feldman verify)

### Phase 3 — Chain layer
8. Build `kosh-chain-relay` (Rust) — port chain-utils.ts submitAndWait + all encode_* functions
9. Integration test: submit a dummy contract action via relay, confirm on testnet

### Phase 4 — Party daemon
10. Build `kosh-party` (Rust) — the big one
    - Start with DKG phases only (no signing)
    - Then add GG20 round 1 + MtA
    - Then add GG20 round 2 + partial sigs
    - Port paillier.ts → paillier.rs (2048-bit, no fallback)
11. End-to-end DKG test: docker-compose up, call gateway DKG endpoint, confirm on testnet

### Phase 5 — API layer + signing
12. Build `kosh-gateway` (Go) — REST handlers, gRPC clients to all services
13. Full signing test: docker-compose up, sign a real message, verify ECDSA

### Phase 6 — Observability
14. Build `kosh-monitor` (Go) — Prometheus metrics, health checks

---

## VERIFICATION

1. `cargo build --workspace` in services/ — zero errors for all 4 Rust services
2. `go build ./...` in each Go service — zero errors
3. `cargo test --workspace` — all unit tests pass (paillier, feldman, aes-gcm, encode)
4. `docker-compose up` — all 13 containers healthy (grpc_health_probe green)
5. `curl -X POST localhost:8080/api/v1/keys -d '{"key_id":1,"num_parties":3,"threshold":2}'`
   → DKG completes, combined_pk returned, on-chain confirmed
6. `curl -X POST localhost:8080/api/v1/sign -d '{"key_id":1,"message_hash":"0x...","tx_tag":"test","signing_subset":[1,2]}'`
   → ECDSA signature returned in < 90 seconds
7. Stop party-3 container → signing with subset [1,2] still succeeds (2-of-3 threshold)
8. Stop party-3 AND party-2 → signing with subset [1] FAILS with threshold error
9. Policy test: add policy {txTag:"treasury", mandatoryParties:[2], minThreshold:2},
   sign with subset [1,3] → 422 "Party 2 is mandatory"
10. Verify ECDSA signature client-side:
    `ethers.utils.recoverAddress(messageHash, signature) == ethAddress` → true
