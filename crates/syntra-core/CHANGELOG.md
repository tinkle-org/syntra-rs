# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0-rc.2](https://github.com/tinkle-org/syntra-rs/compare/syntra-core-v1.0.0-rc.1...syntra-core-v1.0.0-rc.2) - 2026-10-30

### Added

- add SC1 connectivity and benchmarks ([#10](https://github.com/tinkle-org/syntra-rs/pull/10))

### Other

- extract existing Rust implementation from syntra ([#1](https://github.com/tinkle-org/syntra-rs/pull/1))
## [1.0.0-rc.1] - 2026-10-22
### Changed
* reliable sessions with delivery reconciliation and recovery hardening ([#9](https://github.com/tinklehq/syntra/pull/9))
* replay-then-live recovery contract with fixed boundary and loss observability ([#8](https://github.com/tinklehq/syntra/pull/8))
* optional update/recovery profile with replay and snapshot recovery ([#7](https://github.com/tinklehq/syntra/pull/7))
* production runtime with native ABI and recovery boundary ([#6](https://github.com/tinklehq/syntra/pull/6))
* native Rust workspace with Go FFI and registry releases ([#4](https://github.com/tinklehq/syntra/pull/4))
