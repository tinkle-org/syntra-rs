# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0-rc.4](https://github.com/tinkle-org/syntra-rs/compare/syntra-net-v1.0.0-rc.3...syntra-net-v1.0.0-rc.4) - 2026-11-08

### Added

- *(runtime)* add request-wide host budgets ([#31](https://github.com/tinkle-org/syntra-rs/pull/31))

## [1.0.0-rc.3](https://github.com/tinkle-org/syntra-rs/compare/syntra-net-v1.0.0-rc.2...syntra-net-v1.0.0-rc.3) - 2026-11-06

### Added

- add opt-in scoped terminal receipts over native TCP ([#28](https://github.com/tinkle-org/syntra-rs/pull/28))

### Added

- Opt-in native TCP terminal receipts through
  `AuthenticatorFactory::terminal_receipt(&VerifiedIdentity)`. The per-binding
  typed authority replaces ordinary connection authorization; combining a policy
  with an independent generic connection guard is refused. Full-frame barriers,
  fresh authority gates, and retained ciphertext prevent new ordinary egress or
  receipt replay after fencing. Local writing is not a delivery guarantee.
- Native TCP receipt tests and a volatile loopback fixture. Raw/custom record,
  WS/WSS, HTTP/HTTPS, WASM, and FFI compositions have no terminal support and
  refuse before terminal effects. Defaults and wire inputs remain unchanged;
  loss never automatically retries the application mutation. See the
  [SDK API, support, and evidence limits](../../TERMINAL_RECEIPT_DESIGN.md).

## [1.0.0-rc.2](https://github.com/tinkle-org/syntra-rs/releases/tag/syntra-net-v1.0.0-rc.2) - 2026-11-05

### Added

- *(net)* enable crates.io publication ([#26](https://github.com/tinkle-org/syntra-rs/pull/26))
- [**breaking**] consolidate native networking in syntra-net ([#23](https://github.com/tinkle-org/syntra-rs/pull/23))

### Fixed

- harden RC release workflow and validation ([#24](https://github.com/tinkle-org/syntra-rs/pull/24))

### Other

- release v1.0.0-rc.2 ([#14](https://github.com/tinkle-org/syntra-rs/pull/14))
