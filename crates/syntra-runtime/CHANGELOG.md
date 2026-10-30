# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

* Change `ConnectionConfig::default().max_outstanding` from 64 to 32 to align
  with SNTR-SCW-012. This shared default affects all runtime users that rely on
  it, including non-SC1 transports. Explicit overrides remain available; writer
  and notification capacities still default to 256 each. The `1..=1024` range
  is validated by SC1 `Limits::validate`, not universally by the runtime.

## [1.0.0-rc.1] - 2026-10-22
### Changed
* initialize v1.0.0-rc.1 for external Rust/Go imports
* reliable sessions with delivery reconciliation and recovery hardening ([#9](https://github.com/tinklehq/syntra/pull/9))
* replay-then-live recovery contract with fixed boundary and loss observability ([#8](https://github.com/tinklehq/syntra/pull/8))
* optional update/recovery profile with replay and snapshot recovery ([#7](https://github.com/tinklehq/syntra/pull/7))
* production runtime with native ABI and recovery boundary ([#6](https://github.com/tinklehq/syntra/pull/6))
* native Rust workspace with Go FFI and registry releases ([#4](https://github.com/tinklehq/syntra/pull/4))
