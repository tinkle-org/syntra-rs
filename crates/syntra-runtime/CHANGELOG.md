# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0-rc.4](https://github.com/tinkle-org/syntra-rs/compare/syntra-runtime-v1.0.0-rc.3...syntra-runtime-v1.0.0-rc.4) - 2026-11-08

### Added

- *(runtime)* implement lifecycle unlock checks for transient output readers ([#33](https://github.com/tinkle-org/syntra-rs/pull/33))
- *(runtime)* add request-wide host budgets ([#31](https://github.com/tinkle-org/syntra-rs/pull/31))

### Other

- *(runtime)* centralize request admission checks ([#32](https://github.com/tinkle-org/syntra-rs/pull/32))

## [1.0.0-rc.3](https://github.com/tinkle-org/syntra-rs/compare/syntra-runtime-v1.0.0-rc.2...syntra-runtime-v1.0.0-rc.3) - 2026-11-06

### Added

- add opt-in scoped terminal receipts over native TCP ([#28](https://github.com/tinkle-org/syntra-rs/pull/28))

### Added

- Default-disabled scoped terminal receipts through `Handler::handle_with_context`,
  `RequestContext::retire`, and `terminal::{Policy, Authority, Transition, Observation}`.
  The runtime fences ordinary dispatch/output, closes recovery attachments before
  transition, and requires fresh exact-owned evidence with a strictly newer,
  stable committed revision. Return the resulting `HandlerOutcome` promptly;
  it does not await its own output or prove peer receipt or joined cleanup.
- Retained authority execution and cleanup ownership across waiter loss and
  deadlines. Terminal output requires the coordinated native TCP driver; raw,
  WASM, FFI, and non-TCP paths are unsupported and refuse before terminal effects.
  Ordinary withdrawal and wire messages are unchanged. See the
  [SDK API and support boundaries](../../TERMINAL_RECEIPT_DESIGN.md).

## [1.0.0-rc.2](https://github.com/tinkle-org/syntra-rs/compare/syntra-runtime-v1.0.0-rc.1...syntra-runtime-v1.0.0-rc.2) - 2026-11-05

### Added

- [**breaking**] implement Phase 2 Core/RPC and Phase 3 recovery alignment to accepted SDD v1 ([#16](https://github.com/tinkle-org/syntra-rs/pull/16))
- align SC1 v1 with accepted RFC 0007 profile ([#15](https://github.com/tinkle-org/syntra-rs/pull/15))
- canonical SC1 WSS lifecycle with emission gate ([#11](https://github.com/tinkle-org/syntra-rs/pull/11))
- add SC1 connectivity and benchmarks ([#10](https://github.com/tinkle-org/syntra-rs/pull/10))

### Fixed

- pin committed candidate provenance and repair file-store lock release ([#21](https://github.com/tinkle-org/syntra-rs/pull/21))

### Other

- *(deps)* bump sha2 from 0.10.9 to 0.11.1 ([#19](https://github.com/tinkle-org/syntra-rs/pull/19))
- extract existing Rust implementation from syntra ([#1](https://github.com/tinkle-org/syntra-rs/pull/1))
