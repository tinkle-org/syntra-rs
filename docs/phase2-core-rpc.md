# Phase 2 — Core/RPC contract alignment

This working-tree implementation targets `syntra@8ede3810b29fbba4d0e6ae6751a0025ceedda140`.
It implements the baseline changes described here, not the entire accepted SDD
bundle. Commands and results are recorded in `AUDIT.md`; local regressions are
not formal `CONF-*` executions. Recovery, RFC 0010, suspend-aware platform
integration, full shutdown ownership/reporting, browser SC1 and ABI v2 remain
separate phases. No new wire field, profile identifier, fallback or capability
probe is introduced.

## Migration and API contracts

`RequestIdAllocator::next_candidate` now returns `Result<u64, SyntraError>`.
`u64::MAX` can be allocated once; every subsequent allocation fails permanently.
There is no reset method. `starting_at(NonZeroU64)` chooses a permitted initial
ID for a **new** namespace, not a way to recycle an existing connection's IDs.
The initiator serializes allocation through FIFO enqueue. A single ordered
writer must dequeue and emit in that order. Cancellation, overload, failed
encoding and dropped calls can leave permanent gaps. ID exhaustion closes the
connection and settles pending callers; it never falls back to zero.

The host keeps one high-water mark. A structurally valid, legal request consumes
its ID before method rejection, authorization or capacity checks. Any subsequent
request at or below that mark records local `FAILED_PRECONDITION`, dispatches no
new work and closes with no result for the offending request. Cancel/result IDs
do not advance the mark. Closure cannot roll back an earlier handler's effects.

Adapters must first-poll host ingest in received-frame order from one receiver.
Use `Host::ingest_received_at` with the complete-frame reconstruction time,
before validation, queueing or delivery of earlier frames. On native targets use
`tokio::time::Instant::now().into_std()`; on WASM use `web_time::Instant`.
The convenience `ingest` timestamps at first poll. The SC1 record pump eagerly
timestamps all frames extracted from a batch before awaiting delivery. A saved
timestamp is a local adapter value, never a peer-supplied clock. Future local
timestamps are rejected. Arbitrarily spawned/unordered ingest tasks do not
establish receive order.

Every pending terminal gate checks its absolute deadline first. At or after
the deadline it selects `DEADLINE_EXCEEDED`; before then the first eligible
observed candidate wins. A result selected before expiry remains terminal even
if its application future is polled later. Bytes merely buffered before expiry
have not won. Explicit `Initiator::cancel` now settles locally even after
handoff, while its wire Cancel remains advisory for remote execution. No already
emitting unit is rewritten or re-encrypted. Existing custom writers must still
use the original dequeued `Vec` with `prepare_outbound` exactly once.

Use `Initiator::try_new`, `try_new_with_proposal`, and the corresponding
`Host::try_new*` APIs for configuration errors. Legacy infallible constructors
panic on invalid configuration; valid native construction still requires an
executor. The shared implementation validates RPC capacity **16..=1024**,
writer/notification capacities **1..=1024**, and positive handshake/default/max
RPC durations no greater than 24 hours. Defaults remain 32 RPCs and 256 queue
entries. These upper bounds are implementation policy, not a new universal
protocol allocation. A stricter principal/execution quota does not lower the
supported Core concurrency floor.

`DEFAULT_CLOSE_GRACE` is five seconds, `MAX_CLOSE_GRACE` is 30 seconds, and zero
requests immediate teardown without drain. `try_close_gracefully` rejects an
invalid grace without changing the connection; the older runtime wrapper
records the configuration failure and closes. Native/browser WS configuration
uses the five-second default and validates 0..30 seconds. SC1's separate
`Limits::close_timeout` remains its owner-task/transport-close budget (default
one second), not an extension of application drain grace. These changes do not
establish the complete RFC 0008 D5 shutdown-incomplete API or drain/join reserve.

## Parsing and diagnostics

`frame.rs` performs the entire bounded structural walk before classifying raw
choices. It checks every occurrence of known scalar/message/string fields,
valid UTF-8, lengths, tags, bounded varints and groups, without interpreting
opaque payload or credential bytes as nested messages. Body tags 10..15 are
known, 16/17 are forbidden only at top-level Frame position, 18..31 are future
bodies, and 3..9/32+ are metadata. Result outcomes mirror known 1/2, future
3..15, metadata 16+. Multiple choices are invalid even when repeated identically;
a sole valid future choice is `UNIMPLEMENTED`; absent choice is invalid.

Receiver bounds are checked before generated field allocation: credential
8,192 bytes, connection ID 128 UTF-8 bytes, diagnostic 4,096 UTF-8 bytes. Every
consumed occurrence must fit its field bound, including an occurrence later
overwritten by a duplicate; otherwise generated merge processing could allocate
an oversized temporary value. In-bound singular duplicates retain protobuf
last-value semantics. Complete structural faults still take precedence. Received
text is rejected, never truncated. Locally produced diagnostics use
`bounded_diagnostic` on a UTF-8 boundary; this helper does not remove secrets or
make arbitrary application error strings safe to disclose. Public/generated
structs can still represent invalid values, so validation is required at wire
boundaries rather than assuming construction establishes validity.

`CONF-RPC-010` requires a validly correlated missing-outcome result to settle
that RPC locally. `missing_result_outcome_id` is a narrow helper: it permits
correlation only after complete structure, single known result body, exact
zero raw outcomes, bounds, version/state and nonzero-ID checks. It does not
weaken the normal decoder or admit correlation from malformed, duplicate,
reserved or future choices. No synthetic error result is sent to the peer.

## Execution and output ownership

`inflight_len` counts pending correlation, not live execution or output. The
host commits its terminal outcome before waiting for writer capacity.
`execution_len` and `worker_len` expose the separate retained resources.
Pending/selected response workers are bounded independently to
`max_outstanding + writer_capacity` slots, each limited to a complete 1 MiB
Frame; the writer channel separately holds at most `writer_capacity` frames.
These are upper bounds, not measured memory budgets. Exhausted output slots
close the connection with local `RESOURCE_EXHAUSTED`; ordinary call/execution
overload returns one lawful error and consumes the request ID. Bounded writer
waiting/backpressure is retained; full control/event queue separation belongs
with recovery and later lifecycle work.

Handlers whose work can outlive the returned future must override
`Handler::handle_with_execution` and transfer an `ExecutionLease` into the
external/blocking job **before spawning it**, retaining that lease until the job
actually stops. The default hook is for cooperative futures whose drop stops
their work. Timeout, cancellation, principal withdrawal and connection closure
do not release retained external leases. The library cannot discover or forcibly
stop arbitrary application tasks that bypass this contract.

Generic hosts spanning connections should share one `ExecutionBudget` via
`Host::try_new_with_execution_budget`. SC1 factories now provide
`AuthenticatorFactory::execution_budget`: the default is a process-wide shared
1024-execution budget across all default factories and replacement connections.
Override it to clone a retained host/principal budget, never construct a fresh
budget per connection. This default prevents unlimited connection-churn admission
but does not by itself establish per-principal fairness or all deployment quotas.

Withdrawal has one retained close owner with an absolute deadline. Cancellation
of a public withdrawal future or the initiating handler cannot cancel that close
continuation. Repeated calls share the same owner; already-selected results are
not replaced and external work remains accounted. Full owned-task join reporting
remains a Phase 5 gate; `close()` does not claim uncooperative work has stopped.

## Supplemental local verification map

| Contract | Source / regressions | Accepted trace |
| --- | --- | --- |
| Complete raw validation and future/duplicate choices | `syntra-core/src/frame.rs`, `tests/phase2_wire.rs`, `tests/codec_vectors.rs` | RFC 0008 D1; SNTR-SER-003/005/006/007/008/008A, SNTR-WIRE-002/004/005 |
| Bounds before allocation | `handshake.rs`, `error.rs`, `frame.rs`, `tests/encode_allocation.rs` | RFC 0005 D2; SNTR-AUTH-003/030, SNTR-HS-004, SNTR-ERR-003/020/021 |
| Permanent IDs and emission order/exhaustion | `rpc.rs`, `initiator/phase2_tests.rs`, local duplicate regressions in runtime integration/runner | RFC 0004 D1/D2; SNTR-RPC-002/020, SNTR-WIRE-010, SNTR-RPL-012 |
| Deadline-first result/cancel/loss gates | `emission.rs`, `initiator/phase2_tests.rs`, `host_phase2_tests.rs` | RFC 0004 D4, RFC 0008 D2; SNTR-RPC-004/005/031, SNTR-REL-006 |
| Received-order high-water and receipt-time expiry | `host.rs`, `host_phase2_tests.rs`, SC1 `pump/tests.rs` | RFC 0004 D2, RFC 0008 D2 |
| Sixteen outstanding, reverse completion, invalid config | host/initiator Phase 2 tests and transport config tests | RFC 0005 D2; SNTR-RPC-008, supplemental coverage toward CONF-RPC-013 |
| Retained executions and cross-replacement quota | `host_execution.rs`, host Phase 2 tests, actual record-pump replacement tests | RFC 0004 D2, RFC 0008 D5; SNTR-REL-007/008/030/031 |
| Selected output and cancellation-safe withdrawal | host Phase 2 and `runtime_defects` tests | RFC 0004 D4; SNTR-AUTH-008, SNTR-REL-030/031 |

All paths above are crate-relative under `crates/`. These tests are supplemental
local implementation evidence. Formal role/profile-selected manifests,
independent Go interoperability/crypto vectors, real suspend/device tests,
independent review, and release/freeze decisions are not established here.
