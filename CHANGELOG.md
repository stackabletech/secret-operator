# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Changed

- operator-rs: 0.25.0 -> 0.27.1 ([#212]).

[#212]: https://github.com/stackabletech/secret-operator/pull/212

## [0.6.0] - 2022-11-07

### Changed

- Include chart name when installing with a custom release name ([#153]).
- operator-rs: 0.10.0 -> 0.25.0 ([#180]).

[#153]: https://github.com/stackabletech/secret-operator/pull/153
[#180]: https://github.com/stackabletech/secret-operator/pull/180

## [0.5.0] - 2022-06-30

### Added

- "privileged" security context constraints for OpenShift clusters ([#144])

[#144]: https://github.com/stackabletech/secret-operator/pull/144

## [0.4.0] - 2022-05-18

### Added

- Pods that consume Node-scoped `k8sSearch` secrets will now only be scheduled to Nodes that have the secret provisioned ([#125]).
  - This is only supported for pods that use the new-style `ephemeral` volume definitions rather than `csi`.

### Changed

- Pods that consume secrets should now use the `ephemeral` volume type rather than `csi` ([#125]).
  - `csi` volumes will keep working for now, but should be considered deprecated, and will not be compatible
    with all new features.

[#125]: https://github.com/stackabletech/secret-operator/pull/125

## [0.3.0] - 2022-05-05

### Added

- Pods that use `autoTls` volumes are now evicted when their certificates are about to expire ([#114], [commons-#20]).

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
