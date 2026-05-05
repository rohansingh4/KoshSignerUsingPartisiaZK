# KoshSigner Backend Architecture

## 1. Executive Summary
KoshSigner should move from a script-driven TypeScript runtime to a production backend built as a **microservice system**.

The backend must support the complete protocol lifecycle:
- signer contract deployment on Partisia
- DKG key creation
- threshold signing
- PQC approval
- policy enforcement
- encrypted share persistence and reuse
- Ethereum Sepolia transaction broadcast

Recommended backend stack:
- **Rust** for protocol-critical and secret-handling services
- **Go** for API, coordination, policy shell, and monitoring services
- **gRPC** for internal service communication
- **HTTP + SSE/WebSocket** for external client communication
- **Postgres** for metadata and job state
- **encrypted local storage** for shares and PQC private material

This split matches the actual problem:
- Partisia and GG20 runtime logic is crypto-heavy and stateful
- secret persistence requires strong isolation boundaries
- API and ops services benefit from lighter operational tooling

---

## 2. Architecture Drivers
The current TypeScript flow is sufficient for testing but weak for production.

Main limitations today:
- DKG, signing, retries, and storage are tightly coupled in scripts
- a crash can interrupt the whole protocol session
- secret material is not isolated strongly enough from runtime orchestration
- there is no durable service boundary between coordination, chain relay, policy, and key storage
- observability and operational recovery are limited

The target backend should optimize for:
- fault isolation
- protocol correctness
- secret isolation
- replayable job state
- recoverable long-running workflows
- independent scaling of bottlenecks
- frontend-agnostic API access

---

## 3. Language Strategy
### 3.1 Rust Services
Rust should be used for all services that directly touch:
- secret material
- DKG and GG20 phases
- Paillier and MtA runtime state
- PQC private material
- Partisia transaction signing and retry logic
- protocol phase machines

Rust services:
- `kosh-party`
- `kosh-keystore`
- `kosh-pqc`
- `kosh-chain-relay`

Why Rust:
- strong state modeling
- memory safety
- explicit concurrency control
- suitable for channels, streams, actors, retries, and zeroization
- better safety boundary for secret-bearing code

### 3.2 Go Services
Go should be used for services that are primarily:
- API-facing
- policy/config oriented
- coordination or routing focused
- monitoring and health focused

Go services:
- `kosh-gateway`
- `kosh-coordinator`
- `kosh-policy`
- `kosh-monitor`

Why Go:
- good for service shells and infra endpoints
- good gRPC/HTTP ergonomics
- simple operational model
- fast iteration for non-crypto services

---

## 4. Service Topology
## 4.1 Service Map
```text
+-----------------------------------------------------------------------------------+
| External Clients                                                                  |
| wallets / dApps / admin UI                                                        |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          | HTTPS / SSE
                                          v
+-----------------------------------------------------------------------------------+
| kosh-gateway (Go)                                                                  |
| public API, auth, streaming, request validation                                   |
+---------------------------+----------------------------------+--------------------+
                            |                                  |
                            | gRPC                             | gRPC
                            v                                  v
                +--------------------------+        +------------------------------+
                | kosh-policy (Go)         |        | kosh-coordinator (Go)       |
                | policy CRUD / eval       |        | bulletin board / watch bus  |
                +--------------------------+        +---------------+--------------+
                                                                    |
                                                                    | gRPC watch/post/read
                                                                    v
         +--------------------------+--------------------------+--------------------------+
         |                          |                          |                          |
         v                          v                          v                          
+-------------------+     +-------------------+     +-------------------+
| kosh-party-1      |     | kosh-party-2      |     | kosh-party-3      |
| Rust party runtime|     | Rust party runtime|     | Rust party runtime|
+-----+--------+----+     +-----+--------+----+     +-----+--------+----+
      |        |                |        |                |        |
      |        |                |        |                |        |
      v        v                v        v                v        v
+---------+ +---------+    +---------+ +---------+    +---------+ +---------+
|keystore1| |  pqc1   |    |keystore2| |  pqc2   |    |keystore3| |  pqc3   |
|  Rust   | |  Rust   |    |  Rust   | |  Rust   |    |  Rust   | |  Rust   |
+----+----+ +----+----+    +----+----+ +----+----+    +----+----+ +----+----+
     \___________|______________/           \____________|______________/      
                     \                                      /                    
                      \                                    /                     
                       v                                  v                      
                +---------------------------------------------------+
                | kosh-chain-relay (Rust)                           |
                | deploy, nonce mgmt, retries, Partisia tx submit   |
                +---------------------------+-----------------------+
                                            |
                                            | HTTPS / RPC
                                            v
                                 +-------------------------+
                                 | Partisia Network        |
                                 | signer contract + ZK    |
                                 +-------------------------+

Side channels:
- kosh-monitor (Go) observes gateway, coordinator, parties, keystores, PQC, and relay.
- Gateway or relay submits final signed EIP-1559 transactions to Ethereum Sepolia.
```

### 4.2 Service Responsibilities
#### `kosh-gateway` (Go)
Owns:
- public REST API
- SSE or WebSocket streaming to clients
- auth, API keys, JWT, rate limiting
- request validation
- translation from external API calls to internal gRPC calls

Does not own:
- DKG logic
- threshold signing logic
- secret persistence
- Partisia write-path semantics

#### `kosh-policy` (Go)
Owns:
- policy CRUD
- evaluation of `txTag` and other signing constraints
- mandatory-party and threshold validation
- decision on whether PQC approval is required

#### `kosh-coordinator` (Go)
Owns:
- bulletin-board semantics
- `Post`, `Read`, `Watch`, `Clear`, and `List`
- routing protocol messages between parties
- gRPC streaming instead of HTTP long-polling

#### `kosh-party` (Rust)
Owns:
- local DKG execution
- commit/reveal/subshare validation
- Paillier and MtA execution
- GG20 local phase execution
- partial signature computation
- party-local runtime state machine

#### `kosh-keystore` (Rust)
Owns:
- encrypted Shamir share files
- encrypted persisted runtime artifacts
- binding secret material to contract/key/party/public key
- secure share retrieval and integrity checks

#### `kosh-pqc` (Rust)
Owns:
- ML-KEM and ML-DSA identity generation
- PQC approval signing
- PQC verification helper calls
- encrypted storage of PQC private material

#### `kosh-chain-relay` (Rust)
Owns:
- Partisia write path
- sender nonce management
- retries and exponential backoff
- multi-node rotation
- deploy transactions
- DKG actions
- signing actions
- PQC registration and approval actions
- authoritative submit-and-wait semantics

#### `kosh-monitor` (Go)
Owns:
- health checks
- metrics export
- contract polling if needed
- stuck-phase detection
- dashboard-friendly operational status

---

## 5. End-to-End Runtime Flows
### 5.1 Fresh DKG and Key Creation
```text
Client
  |
  | create-key request
  v
Gateway -----------------------> Policy
  |                               |
  | policy-approved request <-----+
  |
  +---------------------------> Party 1
  +---------------------------> Party 2
  +---------------------------> Party 3
                                  |
                                  | DKG session starts on all three parties
                                  v
                        +--------------------------+
                        | Coordinator bulletin bus |
                        | commitments / subshares  |
                        +------------+-------------+
                                     |
                                     v
Party 1 -----------------------> Chain Relay -----------------------> Partisia
                                 |                                     |
                                 | dkg_create_key                      |
                                 | dkg_commit (all parties)            |
                                 | dkg_reveal (all parties)            |
                                 | dkg_finalize                        |
                                 | submit encrypted ZK share halves    |
                                 | dkg_complete_keygen                 |
                                 v                                     v
                               success                            on-chain key ready

Party 1 ---------------> KeyStore 1
Party 2 ---------------> KeyStore 2
Party 3 ---------------> KeyStore 3
  |                         |            |
  | persist encrypted share | metadata   | PQC bootstrap material if needed
  v                         v            v
runtime persisted for reuse signing

Gateway -----------------------------------------------------------> Client
  key created: contract address, key id, public key, EVM address
```

### 5.2 Reuse Signing
```text
Client
  |
  | sign transaction request
  v
Gateway -----------------------> Policy
  |                               |
  | evaluate tx tag / threshold   |
  | mandatory parties / PQC need  |
  +<------------------------------+
  |
  | if denied -> return rejection to client
  |
  +---------------------------> Party 1
  +---------------------------> Party 2
                                  |
                                  | load existing runtime for contract + key id
                                  v
Party 1 -----------------------> KeyStore 1
Party 2 -----------------------> KeyStore 2
  |                               |
  | load encrypted shares         | load encrypted shares
  | restore runtime state         | restore runtime state
  v                               v
ready for signing              ready for signing

Optional PQC path:
Party 1 / Party 2 -----------> PQC Service -----------> Chain Relay -----------> Partisia
  generate PQC approvals         verify / package         submit approval txs      record approvals

Signing path:
Party 1 -----------------------> Chain Relay -----------------------> Partisia
                                 |                                     |
                                 | sign_message                        |
                                 | create on-chain signing task        |
                                 v                                     v
                              task queued                          signing session open

Party 1 <---------------------> Coordinator <---------------------> Party 2
  MtA exchange, Paillier exchange, GG20 round messages, partial state updates

Party 1 / Party 2 -----------> Chain Relay -----------------------> Partisia
  submit delta values            |                                   |
  submit gamma values            | threshold-sign actions            |
  submit partial signatures      v                                   v
                               final signature ready on-chain / retrievable

Chain Relay ------------------------------------------------------> Gateway
  return final threshold signature

Gateway or broadcast component ----------------------------------> Ethereum Sepolia
  assemble signed EIP-1559 transaction and broadcast

Gateway ----------------------------------------------------------> Client
  return success, signature metadata, and Sepolia tx hash
```

---

## 6. Rust Design Principles
### 6.1 Concurrency Model
Use Rust concepts deliberately where they fit the runtime.

Use:
- `tokio::spawn`
- `tokio::sync::mpsc`
- `tokio::sync::broadcast`
- `tokio::sync::watch`
- `tokio::sync::oneshot`
- `tokio::sync::Mutex`
- `tokio::sync::RwLock`
- `tokio::select!`
- `FuturesUnordered`
- gRPC streams

### 6.2 Mapping
- `mpsc`
  - command queues into party services and relay workers
- `broadcast`
  - fanout of logs and progress events
- `watch`
  - latest session or job snapshot
- `oneshot`
  - single-result completions
- `Mutex` / `RwLock`
  - in-memory session maps and sender state
- `select!`
  - timeout vs message vs cancellation paths
- `FuturesUnordered`
  - concurrent waiting on multiple parties or chain responses

### 6.3 Other Rust constructs
Use:
- traits for service boundaries
- enums for explicit phase models
- `thiserror` for domain error trees
- `Zeroize` / `ZeroizeOnDrop` for secret material
- actor-style loops where they improve runtime clarity

---

## 7. Data Model
### 7.1 Core Runtime Enums
Recommended core enums:
- `JobKind`
  - `Deploy`
  - `Dkg`
  - `ReuseSign`
  - `FreshSign`
  - `BroadcastSepolia`
- `JobPhase`
  - `Queued`
  - `Deploying`
  - `Committing`
  - `Revealing`
  - `SubmittingZkShares`
  - `KeygenComplete`
  - `PqcApproval`
  - `Signing`
  - `Broadcasting`
  - `Completed`
  - `Failed`
- `FailureStage`
  - `PartisiaWrite`
  - `PartisiaContract`
  - `DeployStateFetch`
  - `SharePersistence`
  - `PqcApproval`
  - `SepoliaBroadcast`

### 7.2 Persistence Model
#### Store in Postgres
- contracts
- keys
- jobs
- job events
- signing sessions
- party runtime metadata
- policies
- runtime instances

#### Store as encrypted files
- Shamir shares
- PQC identities
- optional Paillier persisted state
- runtime secret artifacts

#### Binding rules for secret artifacts
Every stored share set must be bound to:
- contract address
- key id
- party index
- public key
- runtime version

---

## 8. Internal Interfaces
### 8.1 Browser-Facing API
Recommended public routes:
- `POST /api/v1/keys`
- `GET /api/v1/keys/:id`
- `POST /api/v1/sign`
- `GET /api/v1/sign/:id`
- `POST /api/v1/policies`
- `GET /api/v1/policies`
- `GET /api/v1/health`

### 8.2 Internal gRPC Services
Use shared protobuf definitions for:
- `BulletinBoard`
- `PartyService`
- `KeyStoreService`
- `PqcService`
- `ChainRelayService`
- `PolicyService`

---

## 9. Protobuf Service Definitions
These are the recommended internal service boundaries.

### 9.1 `BulletinBoard`
```proto
service BulletinBoard {
  rpc Post(PostRequest) returns (PostResponse);
  rpc Read(ReadRequest) returns (ReadResponse);
  rpc Watch(WatchRequest) returns (stream WatchEvent);
  rpc Clear(ClearRequest) returns (ClearResponse);
  rpc List(ListRequest) returns (ListResponse);
}
```

Core messages:
- `PostRequest { string topic; bytes value; map<string,string> tags; }`
- `ReadRequest { string topic; bool wait; uint32 timeout_ms; }`
- `WatchRequest { string topic; }`
- `WatchEvent { string topic; bytes value; int64 sequence; }`

### 9.2 `PartyService`
```proto
service PartyService {
  rpc StartDkg(StartDkgRequest) returns (JobAck);
  rpc StartReuseSign(StartReuseSignRequest) returns (JobAck);
  rpc StartFreshSign(StartFreshSignRequest) returns (JobAck);
  rpc GetStatus(GetPartyStatusRequest) returns (PartyStatus);
  rpc StreamEvents(StreamPartyEventsRequest) returns (stream PartyEvent);
  rpc Cancel(CancelPartyRequest) returns (CancelPartyResponse);
}
```

### 9.3 `KeyStoreService`
```proto
service KeyStoreService {
  rpc StoreShare(StoreShareRequest) returns (StoreShareResponse);
  rpc LoadShare(LoadShareRequest) returns (LoadShareResponse);
  rpc StorePqcIdentity(StorePqcIdentityRequest) returns (StorePqcIdentityResponse);
  rpc LoadPqcIdentity(LoadPqcIdentityRequest) returns (LoadPqcIdentityResponse);
  rpc GetKeyMaterialMetadata(GetKeyMaterialMetadataRequest) returns (KeyMaterialMetadata);
}
```

### 9.4 `PqcService`
```proto
service PqcService {
  rpc GenerateIdentity(GenerateIdentityRequest) returns (GenerateIdentityResponse);
  rpc SignApproval(SignApprovalRequest) returns (SignApprovalResponse);
  rpc VerifyApproval(VerifyApprovalRequest) returns (VerifyApprovalResponse);
}
```

### 9.5 `ChainRelayService`
```proto
service ChainRelayService {
  rpc DeploySigner(DeploySignerRequest) returns (DeploySignerResponse);
  rpc SubmitAction(SubmitActionRequest) returns (SubmitActionResponse);
  rpc SubmitZkInput(SubmitZkInputRequest) returns (SubmitZkInputResponse);
  rpc PollContractState(PollContractStateRequest) returns (PollContractStateResponse);
  rpc FetchFinalSignature(FetchFinalSignatureRequest) returns (FetchFinalSignatureResponse);
  rpc GetRelayHealth(GetRelayHealthRequest) returns (GetRelayHealthResponse);
}
```

### 9.6 `PolicyService`
```proto
service PolicyService {
  rpc AddPolicy(AddPolicyRequest) returns (AddPolicyResponse);
  rpc RemovePolicy(RemovePolicyRequest) returns (RemovePolicyResponse);
  rpc ListPolicies(ListPoliciesRequest) returns (ListPoliciesResponse);
  rpc ValidateSignRequest(ValidateSignRequest) returns (ValidateSignResponse);
}
```

---

## 10. Database Schema
Use Postgres for durable metadata.

### 10.1 `contracts`
- `id` UUID PK
- `contract_address` TEXT UNIQUE
- `owner_sender_address` TEXT
- `network` TEXT
- `created_at` TIMESTAMP
- `status` TEXT

### 10.2 `keys`
- `id` UUID PK
- `contract_id` FK -> `contracts.id`
- `key_id` INTEGER
- `public_key_hex` TEXT
- `evm_address` TEXT
- `num_parties` INTEGER
- `threshold` INTEGER
- `created_at` TIMESTAMP
- `status` TEXT

Unique key:
- `(contract_id, key_id)`

### 10.3 `jobs`
- `id` UUID PK
- `job_kind` TEXT
- `job_phase` TEXT
- `failure_stage` TEXT NULL
- `contract_id` FK NULL
- `key_id` INTEGER NULL
- `tx_tag` TEXT NULL
- `request_payload_json` JSONB
- `result_payload_json` JSONB NULL
- `created_at` TIMESTAMP
- `updated_at` TIMESTAMP
- `completed_at` TIMESTAMP NULL

### 10.4 `job_events`
- `id` BIGSERIAL PK
- `job_id` UUID FK -> `jobs.id`
- `source_service` TEXT
- `source_instance` TEXT
- `phase` TEXT
- `level` TEXT
- `message` TEXT
- `payload_json` JSONB NULL
- `created_at` TIMESTAMP

### 10.5 `signing_sessions`
- `id` UUID PK
- `job_id` UUID FK -> `jobs.id`
- `contract_id` FK -> `contracts.id`
- `key_id` INTEGER
- `task_id` INTEGER
- `msg_hash_hex` TEXT
- `signing_subset` JSONB
- `latest_signature_hex` TEXT NULL
- `sepolia_tx_hash` TEXT NULL
- `status` TEXT
- `created_at` TIMESTAMP

### 10.6 `party_runtime_state`
- `id` UUID PK
- `job_id` UUID FK -> `jobs.id`
- `party_index` INTEGER
- `phase` TEXT
- `share_path` TEXT NULL
- `pqc_identity_path` TEXT NULL
- `paillier_state_path` TEXT NULL
- `latest_error` TEXT NULL
- `updated_at` TIMESTAMP

### 10.7 `policies`
- `id` UUID PK
- `tx_tag` TEXT UNIQUE
- `mandatory_parties` JSONB
- `min_threshold` INTEGER
- `requires_pqc` BOOLEAN
- `constraints_json` JSONB NULL
- `created_at` TIMESTAMP
- `updated_at` TIMESTAMP

### 10.8 `runtime_instances`
- `id` UUID PK
- `service_name` TEXT
- `instance_id` TEXT
- `status` TEXT
- `metadata_json` JSONB
- `last_heartbeat_at` TIMESTAMP

### 10.9 Never store these in Postgres
Do not store raw secret material in Postgres:
- Shamir shares
- PQC private keys
- Paillier private keys
- unencrypted runtime secret blobs

---

## 11. Deployment Topology
### 11.1 External ports
- `kosh-gateway`: `:8080`
- `kosh-monitor`: `:9090`

### 11.2 Internal gRPC ports
- `kosh-coordinator`: `:50051`
- `kosh-policy`: `:50052`
- `kosh-chain-relay`: `:50053`
- `kosh-party-1`: `:50060`
- `kosh-party-2`: `:50061`
- `kosh-party-3`: `:50062`
- `kosh-keystore-1`: `:50070`
- `kosh-keystore-2`: `:50071`
- `kosh-keystore-3`: `:50072`
- `kosh-pqc-1`: `:50080`
- `kosh-pqc-2`: `:50081`
- `kosh-pqc-3`: `:50082`

### 11.3 Single-machine development
Recommended initial setup:
- all services run on one machine
- Postgres local or in Docker
- encrypted share storage on local disk
- frontend talks only to `kosh-gateway`

### 11.4 Multi-machine or container deployment
Recommended production direction:
- only `kosh-gateway` is public
- secret-bearing Rust services stay internal
- `kosh-chain-relay` is tightly controlled
- each party and secret service is isolated by party identity

### 11.5 Runtime environment variables
#### Shared
- `LOG_LEVEL`
- `ENVIRONMENT`
- `POSTGRES_DSN`
- `GRPC_LISTEN_ADDR`
- `HTTP_LISTEN_ADDR`

#### Gateway
- `JWT_SECRET`
- `RATE_LIMIT_RPS`
- `POLICY_SERVICE_ADDR`
- `COORDINATOR_SERVICE_ADDR`
- `PARTY_SERVICE_ADDRS`

#### Coordinator
- `BULLETIN_BOARD_RETENTION_SECS`
- `MAX_WATCHERS_PER_TOPIC`

#### Policy
- `POLICY_STORE_PATH`

#### Party
- `PARTY_INDEX`
- `CHAIN_RELAY_ADDR`
- `COORDINATOR_ADDR`
- `KEYSTORE_ADDR`
- `PQC_ADDR`
- `ACTIVE_CONTRACT_ADDRESS`
- `ACTIVE_KEY_ID`

#### KeyStore
- `KEYSTORE_ROOT_DIR`
- `KEYSTORE_MASTER_KEY`

#### PQC
- `PQC_ROOT_DIR`
- `PQC_MASTER_KEY`

#### Chain relay
- `PARTISIA_NODE_URLS`
- `PARTISIA_SENDER_KEY`
- `PARTISIA_SENDER_ADDRESS`
- `PARTISIA_CONFIRM_TIMEOUT_MS`
- `PARTISIA_MAX_RETRIES`
- `PARTISIA_BACKOFF_BASE_MS`

#### Sepolia broadcast
- `SEPOLIA_RPC_URL`
- `SEPOLIA_CHAIN_ID=11155111`

---

## 12. Recommended Repo Layout
```text
services/
  proto/
    bulletin_board.proto
    party.proto
    keystore.proto
    pqc.proto
    chain_relay.proto
    policy.proto

  kosh-coordinator/
  kosh-gateway/
  kosh-policy/
  kosh-monitor/

  kosh-party/
  kosh-keystore/
  kosh-pqc/
  kosh-chain-relay/
```

---

## 13. Rollout Plan
### Phase 1
Build protobuf contracts and service skeletons.

### Phase 2
Implement Go services:
- gateway
- coordinator
- policy
- monitor

### Phase 3
Implement Rust secret/runtime services:
- keystore
- pqc
- chain relay

### Phase 4
Implement Rust party daemon and move DKG, GG20, and PQC flows into it.

### Phase 5
Integrate policy gating, PQC gating, and live Partisia submission.

### Phase 6
Integrate Ethereum Sepolia broadcast.

### Phase 7
Cut the frontend over to the gateway.

### Phase 8
Retire the TS backend runtime once parity is proven.

---



## 14. Phase-by-Phase Delivery Plan
This is the implementation order for the Rust backend. The phases are intentionally sequential. Do not start protocol migration before the infrastructure phases are stable.

### Phase 0 — Protocol Baseline
Goal:
- freeze the current system behavior before rewriting

Work:
- define source-of-truth files:
  - `contracts/kosh-zk-signer/src/lib.rs`
  - `contracts/kosh-zk-signer/src/dkg.rs`
  - `contracts/kosh-zk-signer/src/signing_state.rs`
  - `client/src/party.ts`
  - `client/src/coord-server.ts`
  - `client/src/deploy-zk-signer.ts`
  - `client/src/partisia.ts`
  - `client/src/chain-utils.ts`
  - `client/src/dkg-party.ts`
  - `client/src/gg20-signing.ts`
  - `client/src/mta.ts`
  - `client/src/paillier.ts`
  - `client/src/pqc.ts`
  - `client/src/pqc-identity.ts`
  - `client/src/pqc-auth.ts`
  - `client/src/policy.ts`
  - `client/src/evm.ts`
- document the current flows:
  - deploy signer contract
  - fresh DKG and key creation
  - reuse signing
  - policy evaluation
  - PQC approval
  - Sepolia broadcast
- extract the current protocol phases into explicit state-machine phases
- record the known-good baseline:
  - fresh contract `032645d750cacf93c6fbe7479774ca9d51e8a51faa`
  - working key `62003`
  - fresh DKG success
  - persisted share success
  - reuse-sign success
- define failure taxonomy:
  - Partisia write
  - Partisia contract rejection
  - deploy state fetch
  - owner mismatch
  - share persistence
  - coordinator timeout
  - PQC incomplete
  - Sepolia broadcast failure
- map current TS files to future Rust modules

Done when:
- another engineer can read the document and explain the current backend behavior without reading the TS runtime first

### Phase 1 — Rust Backend Skeleton
Goal:
- create a buildable Rust backend foundation

Work:
- create Rust backend crate
- add config loading
- add tracing and health route
- add app state and dependency wiring
- add in-memory job manager
- add SSE job event stream
- add placeholder job creation/read APIs
- add optional Postgres pool wiring

Done when:
- `cargo check -p kosh-backend` passes
- backend can boot and serve `GET /api/v1/health`
- backend can create and read jobs

### Phase 2 — Coordinator Module
Goal:
- replace `client/src/coord-server.ts`

Work:
- implement bulletin board in Rust:
  - `post(topic, value)`
  - `read(topic, wait, timeout)`
  - `watch(topic)`
  - `clear()`
  - `list()`
- use in-memory topic store with subscriber fanout
- define coordinator message/event types
- expose coordinator through internal module boundary
- connect job layer to coordinator sessions

Done when:
- Rust backend can coordinate topic exchange between party sessions without the TS HTTP coordinator

### Phase 3 — KeyStore Module
Goal:
- isolate share and PQC persistence

Work:
- design encrypted share file format
- design encrypted PQC identity file format
- store metadata binding:
  - contract address
  - key id
  - party index
  - public key
  - runtime version
- implement load/store APIs
- implement integrity checks
- make all share persistence go through one module

Done when:
- the backend can persist and reload party secret material without `party.ts` file handling

### Phase 4 — Chain Relay Module
Goal:
- replace Partisia write/deploy/runtime shell logic

Work:
- port current logic from:
  - `client/src/partisia.ts`
  - `client/src/chain-utils.ts`
  - `client/src/deploy-zk-signer.ts`
  - `client/src/zk-signer.ts`
- implement:
  - deploy signer contract
  - submit action tx
  - submit ZK share halves / delta material
  - state polling
  - signature polling
  - sender nonce handling
  - node rotation across configured Partisia endpoints
  - retry classification and backoff

Done when:
- all Partisia deploy/read/write behavior is available from the Rust backend without calling TS scripts

### Phase 5 — Policy and PQC Modules
Goal:
- isolate request admission logic and PQC runtime

Work:
- port policy rules from `client/src/policy.ts`
- define policy data structures and validation pipeline
- port PQC logic from:
  - `client/src/pqc.ts`
  - `client/src/pqc-identity.ts`
  - `client/src/pqc-auth.ts`
  - `client/src/testnet-pqc.ts`
- implement:
  - PQC identity generation
  - PQC approval material generation
  - PQC verification helpers
  - job-time PQC requirement checks

Done when:
- sign requests can be denied, approved directly, or routed into PQC-gated flow by the Rust backend alone

### Phase 6 — Party Runtime DKG
Goal:
- port fresh key creation local protocol logic

Work:
- port from `client/src/dkg-party.ts`
- implement:
  - polynomial generation
  - commitment generation
  - Schnorr proof generation
  - subshare creation
  - subshare verification
  - combined public key derivation
  - keygen argument builders translated into Rust structures/encoders
- connect DKG runtime to coordinator and chain relay

Done when:
- Rust backend can complete fresh DKG and key creation with three parties and persist the resulting shares

### Phase 7 — Party Runtime Reuse Loading
Goal:
- support persisted-key reuse without re-running DKG

Work:
- implement runtime restore for party sessions
- load persisted shares from keystore
- restore combined public key and next task id
- skip DKG phases automatically when reuse is requested

Done when:
- Rust backend can reuse an existing contract/key/share set and move directly into signing preparation

### Phase 8 — Party Runtime GG20 and MtA
Goal:
- port threshold signing runtime

Work:
- port from:
  - `client/src/paillier.ts`
  - `client/src/mta.ts`
  - `client/src/gg20-signing.ts`
- implement:
  - Paillier keygen
  - Paillier encrypt/decrypt helpers
  - MtA rounds and verification
  - delta/gamma computation
  - GG20 local partial signature computation
  - signing-phase argument encoding for Partisia contract actions
- connect to coordinator and chain relay submission flow

Done when:
- Rust backend can complete threshold signing and produce the final on-chain signature result

### Phase 9 — End-to-End Orchestration
Goal:
- replace `client/src/party.ts` orchestration behavior

Work:
- define job workflows:
  - fresh deploy + create key
  - fresh sign
  - reuse sign
- coordinate:
  - policy -> keystore -> PQC -> relay -> party runtime
- emit structured job phases and logs
- implement cancellation and timeout handling
- classify failures into explicit `FailureStage` values

Done when:
- one Rust backend job can drive a complete signing flow without spawning TS runtime scripts

### Phase 10 — Ethereum Sepolia Broadcaster
Goal:
- port EVM transaction assembly and broadcast

Work:
- port from `client/src/evm.ts`
- implement:
  - transfer tx build
  - signing hash derivation
  - final signature parsing
  - EIP-1559 tx assembly
  - Ethereum Sepolia broadcast
  - tx hash persistence

Done when:
- successful threshold signing can produce a real Sepolia tx hash from the Rust backend

### Phase 11 — Frontend Cutover
Goal:
- move the frontend to the Rust backend only

Work:
- replace frontend backend bridge dependency on TS orchestration
- point UI to Rust HTTP endpoints and SSE stream
- expose active runtime metadata:
  - contract
  - key id
  - sender
  - policy status
  - PQC status
  - Sepolia tx hash

Done when:
- frontend can create keys and sign via Rust backend only

### Phase 12 — Cleanup and Retirement
Goal:
- retire the script-driven backend runtime

Work:
- remove or archive TS orchestration paths
- keep TS only as historical protocol reference if still useful
- clean env vars and docs
- lock in the Rust backend as the only supported backend runtime

Done when:
- the system no longer depends on `client/src/party.ts`, `client/src/coord-server.ts`, or frontend shelling into the TS backend for normal operation

### Recommended execution order
1. Phase 0
2. Phase 1
3. Phase 2
4. Phase 3
5. Phase 4
6. Phase 5
7. Phase 6
8. Phase 7
9. Phase 8
10. Phase 9
11. Phase 10
12. Phase 11
13. Phase 12

## 14. Test Strategy
### 14.1 Unit tests
- policy evaluation
- share encryption and decryption
- nonce management
- retry logic
- phase machine transitions
- PQC file handling

### 14.2 Integration tests
- fresh deploy
- DKG end-to-end
- persisted share reuse
- PQC approval path
- threshold signing path
- Sepolia broadcast path
- failure classification by stage

### 14.3 Acceptance scenarios
1. Fresh key creation succeeds
2. Reuse sign skips DKG
3. Policy-denied transaction is blocked
4. PQC-gated transaction requires approval
5. Partisia retry path works across nodes
6. Sepolia broadcast returns transaction hash

---

## 15. Recommendation
Use this architecture as the primary backend plan.

It gives the project:
- stronger secret isolation
- better service boundaries
- scalable retry and relay behavior
- a production-suitable monitoring and API layer
- a clean place to use deep Rust concepts without forcing them unnaturally
