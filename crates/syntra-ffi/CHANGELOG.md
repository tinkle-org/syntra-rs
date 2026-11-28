# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0-rc.7](https://github.com/tinkle-org/syntra-rs/compare/syntra-ffi-v1.0.0-rc.6...syntra-ffi-v1.0.0-rc.7) - 2026-11-28

### Added

- *(wire)* [**breaking**] restore Protobuf with fewer allocations ([#55](https://github.com/tinkle-org/syntra-rs/pull/55))
- *(wire)* [**breaking**] adopt Bebop v3 for Syntra ([#54](https://github.com/tinkle-org/syntra-rs/pull/54))

### Other

- *(transport)* add mixed-traffic loopback baseline ([#59](https://github.com/tinkle-org/syntra-rs/pull/59))

## [1.0.0-rc.6](https://github.com/tinkle-org/syntra-rs/compare/syntra-ffi-v1.0.0-rc.5...syntra-ffi-v1.0.0-rc.6) - 2026-11-23

### Other

- update Cargo.toml dependencies

## [1.0.0-rc.2](https://github.com/tinkle-org/syntra-rs/compare/syntra-ffi-v1.0.0-rc.1...syntra-ffi-v1.0.0-rc.2) - 2026-11-05

### Added

- [**breaking**] implement Phase 2 Core/RPC and Phase 3 recovery alignment to accepted SDD v1 ([#16](https://github.com/tinkle-org/syntra-rs/pull/16))
- add SC1 connectivity and benchmarks ([#10](https://github.com/tinkle-org/syntra-rs/pull/10))

### Other

- extract existing Rust implementation from syntra ([#1](https://github.com/tinkle-org/syntra-rs/pull/1))
