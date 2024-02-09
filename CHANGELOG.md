# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- Improved CRD documentation ([#333]).
- Helm: support labels in values.yaml ([#352]).

## Changed

- Use new annotation builder ([#341]).
- `autoTLS` certificate authorities can now be rotated regularly ([#350], [#363]).
  - [BREAKING] This changes the format of the CA secrets. Old secrets will be migrated automatically, but manual intervention will be required to downgrade back to 23.11.x.
- `autoTLS` certificate authority lifetimes are now configurable ([#357]).
- Certificate lifetimes are now jittered ([#361]).

[#333]: https://github.com/stackabletech/secret-operator/pull/333
[#341]: https://github.com/stackabletech/secret-operator/pull/341
[#350]: https://github.com/stackabletech/secret-operator/pull/350
[#352]: https://github.com/stackabletech/secret-operator/pull/352
[#357]: https://github.com/stackabletech/secret-operator/pull/357
[#361]: https://github.com/stackabletech/secret-operator/pull/361
[#363]: https://github.com/stackabletech/secret-operator/pull/363


## [23.11.0] - 2023-11-24

### Added

- Make certificate lifetime configurable ([#306]).
- Added support for encrypting PKCS#12 keystores ([#314]).
- Added listener scope for provisioned secrets ([#310]).

[#306]: https://github.com/stackabletech/secret-operator/pull/306
[#310]: https://github.com/stackabletech/secret-operator/pull/310
[#314]: https://github.com/stackabletech/secret-operator/pull/314

## [23.7.0] - 2023-07-14

### Added

- Generate OLM bundle for Release 23.4.0 ([#271]).
- Added support for converting secrets (including generating PKCS#12 bundles) ([#286]).

### Changed

- `operator-rs` `0.27.1` -> `0.44.0` ([#275], [#294]).
- Removed dummy key from generated Kerberos keytab ([#285]).
- [BREAKING] Daemonset for SecretOperator now assign resource requests and limits to all containers and init containers. Users who have configured resource limits previously in the 'values.yaml' file will need to move the configured limits from `.resources` to `.node.driver.resources` for them to be honored going forward ([#289]).

[#275]: https://github.com/stackabletech/secret-operator/pull/275
[#285]: https://github.com/stackabletech/secret-operator/pull/285
[#286]: https://github.com/stackabletech/secret-operator/pull/286
[#289]: https://github.com/stackabletech/secret-operator/pull/289
[#294]: https://github.com/stackabletech/secret-operator/pull/294

## [23.4.0] - 2023-04-17

### Added

- Added `kerberosKeytab` provisioner backend using MIT Kerberos ([#99], [#257]).
- Added experimental unprivileged mode ([#252]).

### Changed

- Shortened the registration socket path for Microk8s compatibility ([#231]).
  - The old CSI registration path will be automatically migrated during upgrade ([#258], [#260]).
  - You might need to manually remove `/var/lib/kubelet/plugins_registry/secrets.stackable.tech-reg.sock` when downgrading
- Made kubeletDir configurable ([#232]).
  - Microk8s users will need to `--set kubeletDir=/var/snap/microk8s/common/var/lib/kubelet`.

[#99]: https://github.com/stackabletech/secret-operator/pull/99
[#231]: https://github.com/stackabletech/secret-operator/pull/231
[#232]: https://github.com/stackabletech/secret-operator/pull/232
[#252]: https://github.com/stackabletech/secret-operator/pull/252
[#257]: https://github.com/stackabletech/secret-operator/pull/257
[#258]: https://github.com/stackabletech/secret-operator/pull/258
[#260]: https://github.com/stackabletech/secret-operator/pull/260

## [23.1.0] - 2023-01-23

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
