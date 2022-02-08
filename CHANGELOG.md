# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

This release will cause any Pods that already used it get stuck Terminating when they are next deleted.
The easiest way to fix this is to perform a rolling reboot of all nodes after the upgrade.

This is a one-time migration.

### Changed
- Store secrets on tmpfs ([#37]).
- Locked down secret permissions by default ([#37]).

### Bugfixes
- Fixed thread starvation and slow shutdowns ([#47]).

[#37]: https://github.com/stackabletech/secret-operator/pull/37
[#47]: https://github.com/stackabletech/secret-operator/pull/47

## [0.1.0] - 2022-02-03

### Added
- Initial release
