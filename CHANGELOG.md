# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- Pods that use autoTls volumes are now evicted when their certificates are about to expire ([#114], [commons-#20]).

### Changed

- `autoTls` CA generation now requires opt-in ([#77]).
  - The default `tls` `SecretClass` now has this opt-in by default.
  
### Removed

- `k8sSearch` backend's option `secretLabels` has been removed ([#123]).

[#77]: https://github.com/stackabletech/secret-operator/pull/77
[#114]: https://github.com/stackabletech/secret-operator/pull/114
[#123]: https://github.com/stackabletech/secret-operator/pull/123
[commons-#20]: https://github.com/stackabletech/commons-operator/pull/20

## [0.2.0] - 2022-02-14

This release will cause any Pods that already used it get stuck Terminating when they are next deleted.
The easiest way to fix this is to perform a rolling reboot of all nodes after the upgrade.

This is a one-time migration.

### Changed
- Store secrets on tmpfs ([#37]).
- Locked down secret permissions by default ([#37]).
- Operator-rs: 0.8.0 -> 0.10.0 ([#49]).

### Bugfixes
- Fixed thread starvation and slow shutdowns ([#47]).

[#37]: https://github.com/stackabletech/secret-operator/pull/37
[#47]: https://github.com/stackabletech/secret-operator/pull/47
[#49]: https://github.com/stackabletech/secret-operator/pull/49

## [0.1.0] - 2022-02-03

### Added
- Initial release
