# stoa

A self-hosted unified messaging server that speaks NNTP, SMTP, JMAP, and IMAP over a shared content-addressed block store. Every message — whether posted via a newsreader, submitted by email, or injected by a peer — is stored as a CIDv1 SHA-256 IPFS block, operator-signed with Ed25519, and indexed in a per-group Merkle-CRDT log. Standard clients work without modification.

## Protocols

| Protocol | RFC | Daemon | Status |
|---|---|---|---|
| NNTP (Usenet newsreader) | RFC 3977, RFC 4644 | `stoa-reader` | Complete |
| SMTP (submission + relay) | RFC 5321, RFC 6409 | `stoa-smtp` | Complete |
| JMAP (modern email API) | RFC 8620, RFC 8621 | `stoa-mail` | Substantially complete |
| IMAP | RFC 3501, RFC 9051 | `stoa-imap` | In progress |

All four daemons read from and write to the same block store. A message posted via NNTP is immediately visible via JMAP. An email submitted over SMTP can be routed into a newsgroup via Sieve `fileinto`. The canonical identifier for any message is its CID — stable, content-derived, and the same regardless of which protocol or node introduced it.

## Why it exists

Traditional Usenet spools are opaque binary blobs. Traditional email stores are per-server silos. Stoa unifies them:

- **Content-addressed storage.** Articles are CIDv1 SHA-256 DAG-CBOR blocks. The CID is a cryptographic commitment to the content — you can verify any article without trusting the server that gave it to you.
- **Tamper-evident.** Every article is Ed25519-signed by the receiving operator at ingest before it touches the store. Forging or silently altering an article breaks the signature.
- **Eventual consistency without coordination.** Group state is a Merkle-CRDT append-only log. Peers exchange articles via IHAVE/TAKETHIS (RFC 4644). Partitions heal automatically; no quorum is required to make progress.
- **Horizontal scaling from the storage model.** Because the store is content-addressed, any number of reader daemons can point at the same shared backend (S3, GCS, Azure Blob, Ceph RADOS, or any other supported store) and serve identical, verified content. There is no primary, no replication lag, and no split-brain — two readers backed by the same object store are identical by definition. Scale out by adding reader instances; the block store is the coordination layer.
- **Standard clients, no plugins.** `slrn`, `tin`, `pan`, `gnus`, Thunderbird over NNTP; Fastmail, Thunderbird, iOS Mail over JMAP; any IMAP client over IMAP. No client modifications required.
- **Self-hostable with no required external services.** The default LMDB backend has zero external dependencies. A full NNTP server runs from a single binary and a config file.

## Quick start

See [`docs/ops/installation.md`](docs/ops/installation.md) for the full first-run guide, including config file examples and systemd units. The short version:

```bash
# Build
git clone https://github.com/MarkAtwood/stoa.git
cd stoa
cargo build --release

# Generate an operator signing key
target/release/stoa-ctl keygen --out /etc/stoa/operator.key

# Run transit (peering + store) and reader (NNTP)
target/release/stoa-transit --config /etc/stoa/transit.toml
target/release/stoa-reader  --config /etc/stoa/reader.toml

# Connect any RFC 3977 newsreader to localhost:119
```

For email access, also run `stoa-smtp` and `stoa-mail`. For the complete deployment reference — TLS, auth, peering, GC policy, JMAP client setup — see [`docs/RUNBOOK.md`](docs/RUNBOOK.md).

## How it works

### Article storage model

Every article is stored as a DAG-CBOR IPLD tree rooted at an `ArticleRootNode` (codec `0x71`, CIDv1 SHA-256). The root node links to separate raw blocks for the verbatim RFC 5536 headers, a lowercased/decoded header map, the body, and an optional MIME parse tree. Inline metadata on the root includes the Message-ID, group list, HLC timestamp, operator Ed25519 signature, and byte/line counts.

```
ArticleRootNode  ─── header_cid      →  raw block (RFC 5536 headers)
  (CIDv1 0x71)  ─── header_map_cid  →  DAG-CBOR (lowercase, RFC 2047 decoded)
                ─── body_cid        →  raw block (article body)
                ─── mime_cid        →  MIME parse tree (optional)
                └── metadata        →  inline (message_id, hlc, ed25519 sig, …)
```

The article CID is the same regardless of which backend stores it, which peer introduced it, or which protocol delivered it. JMAP uses article CIDs directly as `Email` IDs and blob IDs. The NNTP `XCID` and `XVERIFY` commands expose CIDs to CID-aware clients; standard clients see only normal article numbers and message IDs.

### Horizontal scaling

Because each block is identified solely by its SHA-256 digest, shared object-store backends (S3, GCS, Azure Blob, Ceph RADOS, WebDAV) are naturally consistent: two readers pointing at the same bucket always serve the same content. There is no replication protocol between readers. To scale read capacity, add reader instances and point them at the shared store:

```
                     ┌─────────────────┐
  stoa-reader ──────►│                 │
  stoa-reader ──────►│  shared backend │  (S3 / GCS / Ceph / LMDB / …)
  stoa-reader ──────►│                 │
                     └────────┬────────┘
                              │
                     ┌────────▼────────┐
                     │  stoa-transit   │  (single writer per group partition)
                     └─────────────────┘
```

The transit daemon is the write path. One transit node per network partition is sufficient; multiple transit nodes peer via IHAVE/TAKETHIS and converge through the Merkle-CRDT log.

### Group state: Merkle-CRDT

Each newsgroup has an append-only DAG log stored in SQLite. Every `LogEntry` contains:

- the article CID
- an HLC timestamp (Hybrid Logical Clock — preserves causal ordering across nodes with unsynchronised clocks)
- an Ed25519 operator signature over the canonical serialisation
- parent CIDs (linking it into the DAG)

The `LogEntryId` is `SHA-256(canonical_serialisation(entry))` — globally unique and self-authenticating. Merging two nodes' views is a set-union of log entries; the HLC establishes a consistent total order. Partitions heal without coordinator involvement.

### Peering

Transit daemons peer over direct TCP connections using the NNTP transit protocol (RFC 4644 MODE STREAM / IHAVE / CHECK / TAKETHIS). Connections are mutually authenticated with an Ed25519 challenge-response handshake. Per-peer reputation scoring and automatic blacklisting protect against flooding. There is no DHT, no gossip mesh, no libp2p — just direct TCP between configured peers.

### Protocol daemons

All four daemons share the same block store and SQLite databases:

```
newsreader clients (slrn, tin, Thunderbird …)
        │ NNTP :119 / NNTPS :563
        ▼
  ┌─────────────┐     ┌───────────────────────────────┐
  │ stoa-reader │────►│                               │
  └─────────────┘     │  shared block store           │
                      │  (LMDB / S3 / GCS / RADOS …)  │
  ┌─────────────┐     │                               │
  │ stoa-smtp   │────►│  + SQLite (group log,         │
  │ :25/:587    │     │    msgid↔CID map,             │
  └─────────────┘     │    overview index,            │
                      │    article numbers)           │
  ┌─────────────┐     │                               │
  │ stoa-mail   │────►│                               │
  │ JMAP HTTP   │     └───────────────────────────────┘
  └─────────────┘               ▲
                                │ IHAVE/TAKETHIS
  ┌─────────────┐               │ (TCP peering)
  │stoa-transit │───────────────┘
  │ peering +   │◄──── other transit nodes
  │ store-fwd   │
  └─────────────┘
```

SMTP→NNTP bridge: email submitted to `stoa-smtp` is evaluated by a native Sieve engine. A `fileinto("newsgroup:comp.lang.rust")` action routes the message into the NNTP store. JMAP Email IDs are article CIDs; thread IDs are the CID of the thread root. Newsgroups appear as JMAP mailboxes.

### Synthetic article numbers

NNTP article numbers are local and sequential per `(group, reader-instance)` — stored in SQLite, assigned with `SELECT MAX(n)+1`. They are never network-stable; do not use them as persistent identifiers. The stable identifiers are Message-ID (human-readable, RFC 5536) and CID (cryptographic, globally unique).

### Sieve filtering (SMTP)

`stoa-smtp` evaluates Sieve scripts (RFC 5228) using a native MIT-licensed Sieve engine (`stoa-sieve-native`). The AGPL dependency (`sieve-rs`) is used only as a test oracle and is never linked into production binaries — enforced at the Cargo dependency level (ADR-0010).

Supported actions: `fileinto` (into a mailbox or `newsgroup:X`), `keep`, `discard`, `reject`, `redirect`. Outbound relay includes Ed25519 DKIM signing (RFC 8463) and MTA-STS enforcement (RFC 8461).

## Block store backends

Both `stoa-transit` and `stoa-reader` select a backend via `[backend] type = "..."` in their config files. All backends implement the same `IpfsStore` trait; switching backends requires only a config change and a reindex.

| Backend | `type` | Notes |
|---|---|---|
| LMDB | `"lmdb"` | Default. Memory-mapped, zero external dependencies. |
| Kubo (go-ipfs) | `"kubo"` | Delegates to a running Kubo daemon via HTTP RPC. |
| S3 | `"s3"` | AWS S3 or compatible (MinIO, Backblaze B2, Cloudflare R2). |
| Azure Blob | `"azure"` | Azure Blob Storage. |
| GCS | `"gcs"` | Google Cloud Storage. |
| Ceph RADOS | `"rados"` | Transit only; requires `rados` feature + `librados-dev`. |
| WebDAV | `"web_dav"` | Any WebDAV server (Nextcloud, Hetzner Storage Box, …). |
| RocksDB | `"rocks_db"` | Embedded LSM-tree; higher write throughput than LMDB. |
| SQLite | `"sqlite"` | Embedded; useful for small deployments and testing. |
| Filesystem | `"filesystem"` | Plain directory; good for debugging and cold import. |
| PostgreSQL BYTEA | `"pg_blob"` | Reader only. |
| Git SHA-256 | `"git_sha256"` | Reader only; read-only git object store. |

Cloud backends (S3, GCS, Azure) are the primary scale-out path. All reader instances pointed at the same bucket serve identical content with no replication layer.

## Workspace layout

```
stoa/
├── Cargo.toml                    workspace (resolver = "2")
├── crates/
│   ├── core/                     shared rlib: article types, CID scheme, Merkle-CRDT,
│   │                             signing, canonical serialisation, audit log
│   ├── transit/                  peering daemon: IHAVE/TAKETHIS, GC, pinning, import
│   ├── reader/                   RFC 3977 NNTP server + CID extensions
│   ├── smtp/                     SMTP submission + relay, Sieve, DKIM, MTA-STS
│   ├── imap/                     IMAP4rev1/rev2 server (in progress)
│   ├── mail/                     JMAP server + ActivityPub federation
│   ├── auth/                     OIDC, client cert, bcrypt credential store
│   ├── tls/                      shared rustls configuration
│   ├── lmdb/                     LMDB FFI boundary (only crate with unsafe)
│   ├── sieve/                    sieve-rs wrapper (AGPL, test oracle only)
│   ├── sieve-native/             native MIT Sieve evaluator (production)
│   ├── verify/                   DKIM + X-Stoa-Sig verification
│   ├── ctl/                      operator CLI (stoa-ctl)
│   └── integration-tests/        end-to-end test harness
├── docs/
│   ├── adr/                      11 Architecture Decision Records
│   ├── architecture.md
│   ├── RUNBOOK.md                operator deployment guide
│   ├── ops/                      installation, config reference, peering, retention,
│   │                             backup/restore, DKIM, RADOS, WebDAV, git backends
│   ├── wire_format.md            DAG-CBOR schema + NNTP CID extension wire spec
│   ├── threat_model.md
│   └── observability.md
└── spikes/                       backend evaluation benchmarks
```

## Documentation

| Document | Contents |
|---|---|
| [`docs/ops/installation.md`](docs/ops/installation.md) | First-run guide: build, keygen, config, systemd units |
| [`docs/RUNBOOK.md`](docs/RUNBOOK.md) | Full operator reference: peering, GC, OIDC/SSO, troubleshooting |
| [`docs/ops/configuration_reference.md`](docs/ops/configuration_reference.md) | Every config field for all daemons |
| [`docs/architecture.md`](docs/architecture.md) | Detailed system architecture |
| [`docs/wire_format.md`](docs/wire_format.md) | DAG-CBOR schema, CID scheme, NNTP CID extension protocol |
| [`docs/adr/`](docs/adr/) | Architecture Decision Records (ADR-0001 through ADR-0011) |
| [`docs/threat_model.md`](docs/threat_model.md) | STRIDE threat model |
| [`docs/ops/peering_guide.md`](docs/ops/peering_guide.md) | Peering setup, reputation scoring, feed negotiation |
| [`docs/ops/retention_guide.md`](docs/ops/retention_guide.md) | Pin rules, GC scheduler, audit log |
| [`CHANGELOG.md`](CHANGELOG.md) | Change history |

## Building and testing

```bash
cargo build --workspace
cargo test --workspace
cargo fmt --all
cargo clippy --workspace --all-features -- -D warnings
```

MSRV: 1.80 for most crates; 1.85 for `stoa-imap`. Rust stable toolchain. No C build dependencies for the default LMDB backend.

## Contributing

Issue tracker: Beads. Run `bd ready` for available work. All non-trivial changes must trace to an open issue. See [`docs/contributing.md`](docs/contributing.md) for test requirements, coding conventions, and the PR workflow.

## License

MIT — except `stoa-sieve` (AGPL-3.0-only, never linked by production binaries).
