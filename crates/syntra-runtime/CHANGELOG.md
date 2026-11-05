# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
