# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Changed

- OLM deployer doesn't add owner references to cluster scoped objects anymore ([#667]).
  Owner references ensure that objects are garbage collected by OpenShift upon operator removal but they cause problems when the operator is updated.
  This means that cluster wide objects are not removed anymore when the operator is uninstalled.
  This behaviour is in line with the default behaviour of Helm and OLM.
- Bump testing-tools to `0.3.0-stackable0.0.0-dev` ([#671]).

### Removed

- BREAKING: Removed support for ephemeral CSI volumes ([#481], [#670]).
  This means that the following form would no longer be supported:

  ```yaml
  volumes:
    - csi: # ...
  ```

  This has been deprecated since 0.4.0 because it doesn't support pod stickiness ([#125]).

  Ephemeral PersistentVolumes that use CSI would still be supported (and the recommended syntax):

  ```yaml
  volumes:
    - ephemeral:
        volumeClaimTemplate: # ...
  ```

[#481]: https://github.com/stackabletech/secret-operator/issues/481
[#667]: https://github.com/stackabletech/secret-operator/pull/667
[#670]: https://github.com/stackabletech/secret-operator/pull/670
[#671]: https://github.com/stackabletech/secret-operator/pull/671

## [25.11.0] - 2025-11-07

## [25.11.0-rc1] - 2025-11-06

### Added

- Add end-of-support checker which can be controlled with environment variables and CLI arguments ([#644]).
  - `EOS_CHECK_MODE` (`--eos-check-mode`) to set the EoS check mode. Currently, only "offline" is supported.
  - `EOS_INTERVAL` (`--eos-interval`) to set the interval in which the operator checks if it is EoS.
  - `EOS_DISABLED` (`--eos-disabled`) to disable the EoS checker completely.
- Support exporting the TrustStore CA certificate information to Secrets or ConfigMaps ([#597]).
- New helm value for `priorityClassName` ([#641]).
- CA certificates are retired one hour (configurable via
  `autoTls.ca.caCertificateRetirementDuration`) before they expire ([#650]).

### Changed

- Split operator deployment into Deployment and DaemonSet ([#645]).
  - Introduce two different modes: `csi-server` and `controller`.
  - The CSI server is deployed via a DaemonSet to be available on every node.
  - The controller is deployed via a Deployment with a single replica.
- Version CRD structs and enums as v1alpha1 ([#636]).
- BREAKING: Rearrange values to be somewhat consistent with the listener-operator value changes ([#641], [#645]).
  - `csiProvisioner` values have been moved to `csiNodeDriver.externalProvisioner`.
  - `csiNodeDriverRegistrar` values have been moved to `csiNodeDriver.nodeDriverRegistrar`.
  - `node.driver.resources` values have been split into `controllerService.resources` and `csiNodeDriver.nodeService.resources`.
  - `securityContext` values have been split into `controllerService.securityContext` and `.csiNodeDriver.nodeService.securityContext`.
  - `podAnnotations`, `podSecurityContext`, `nodeSelector`, `tolerations`, and `affinity` have been split into `controllerService` and `csiNodeDriver`.
  - `kubeletDir` has been move to `csiNodeDriver.kubeletDir`.
- Bump csi-node-driver-registrar to `v2.15.0` ([#642]).
- Bump csi-provisioner to `v5.3.0` ([#643]).
- OLM deployer: patch the new Deployment object too and other changes to align with the new operator structure ([#648]).
- BREAKING: Expired and retired CA certificates are no longer published in Volumes and TrustStores
  ([#650]).

[#597]: https://github.com/stackabletech/secret-operator/pull/597
[#636]: https://github.com/stackabletech/secret-operator/pull/636
[#641]: https://github.com/stackabletech/secret-operator/pull/641
[#642]: https://github.com/stackabletech/secret-operator/pull/642
[#643]: https://github.com/stackabletech/secret-operator/pull/643
[#644]: https://github.com/stackabletech/secret-operator/pull/644
[#645]: https://github.com/stackabletech/secret-operator/pull/645
[#648]: https://github.com/stackabletech/secret-operator/pull/648
[#650]: https://github.com/stackabletech/secret-operator/pull/650

## [25.7.0] - 2025-07-23

## [25.7.0-rc1] - 2025-07-18

### Added

- Add format-specific annotations to override secret file names ([#572]). The following new
  annotations are available:
  - `secrets.stackable.tech/format.tls-pkcs12.keystore-name`
  - `secrets.stackable.tech/format.tls-pkcs12.truststore-name`
  - `secrets.stackable.tech/format.tls-pem.cert-name`
  - `secrets.stackable.tech/format.tls-pem.key-name`
  - `secrets.stackable.tech/format.tls-pem.ca-name`
- Adds new telemetry CLI arguments and environment variables ([#591]).
  - Use `--file-log-max-files` (or `FILE_LOG_MAX_FILES`) to limit the number of log files kept.
  - Use `--file-log-rotation-period` (or `FILE_LOG_ROTATION_PERIOD`) to configure the frequency of rotation.
  - Use `--console-log-format` (or `CONSOLE_LOG_FORMAT`) to set the format to `plain` (default) or `json`.
- Added TrustStore CRD for requesting CA certificate information ([#557]).
- Add RBAC rule to helm template for automatic cluster domain detection ([#619]).

### Changed

- BREAKING: Replace stackable-operator `initialize_logging` with stackable-telemetry `Tracing` ([#581], [#587], [#591]).
  - operator-binary:
    - The console log level was set by `SECRET_PROVISIONER_LOG`, and is now set by `CONSOLE_LOG_LEVEL`.
    - The file log level was set by `SECRET_PROVISIONER_LOG`, and is now set by `FILE_LOG_LEVEL`.
    - The file log directory was set by `SECRET_PROVISIONER_LOG_DIRECTORY`, and is now set
      by `FILE_LOG_DIRECTORY` (or via `--file-log-directory <DIRECTORY>`).
  - olm-deployer:
    - The console log level was set by `STKBL_SECRET_OLM_DEPLOYER_LOG`, and is now set by `CONSOLE_LOG_LEVEL`.
    - The file log level was set by `STKBL_SECRET_OLM_DEPLOYER_LOG`, and is now set by `FILE_LOG_LEVEL`.
    - The file log directory was set by `STKBL_SECRET_OLM_DEPLOYER_LOG_DIRECTORY`, and is now set
      by `FILE_LOG_DIRECTORY` (or via `--file-log-directory <DIRECTORY>`).
  - Replace stackable-operator `print_startup_string` with `tracing::info!` with fields.
- Upgrade csi-provisioner to 5.2.0 ([#594]).
- Use versioned common structs ([e5224ab]).
- BREAKING: Bump stackable-operator to 0.94.0 and update other dependencies ([#619]).
  - The default Kubernetes cluster domain name is now fetched from the kubelet API unless explicitly configured.
  - This requires operators to have the RBAC permission to get nodes/proxy in the apiGroup "". The helm-chart takes care of this.
  - The CLI argument `--kubernetes-node-name` or env variable `KUBERNETES_NODE_NAME` needs to be set.
    It supersedes the old argument/env variable `NODE_NAME`.
    The helm-chart takes care of this.

### Fixed

- Use `json` file extension for log files ([#586]).
- Allow uppercase characters in domain names ([#619]).

### Removed

- Remove CSI registration path migration job ([#610]).
- Remove role binding to legacy service accounts ([#619]).

[#557]: https://github.com/stackabletech/secret-operator/pull/557
[#572]: https://github.com/stackabletech/secret-operator/pull/572
[#581]: https://github.com/stackabletech/secret-operator/pull/581
[#586]: https://github.com/stackabletech/secret-operator/pull/586
[#587]: https://github.com/stackabletech/secret-operator/pull/587
[#591]: https://github.com/stackabletech/secret-operator/pull/591
[#594]: https://github.com/stackabletech/secret-operator/pull/594
[e5224ab]: https://github.com/stackabletech/secret-operator/commit/e5224ab480e219e434ddc695c9361a16a56a43ed
[#610]: https://github.com/stackabletech/secret-operator/pull/610
[#619]: https://github.com/stackabletech/secret-operator/pull/619

## [25.3.0] - 2025-03-21

### Removed

- Removed CA secret migration job ([#548]).
  - BREAKING: This means that direct upgrades from 24.3 are no longer supported. Users of 24.3 must first upgrade to 24.7 or 24.11 before continuing. Bear in mind that we officially only support direct upgrades (24.3 -> 24.7 -> 24.11 -> ...).

### Added

- Made RSA key length configurable for certificates issued by cert-manager ([#528]).
- Kerberos principal backends now also provision principals for IP address, not just DNS hostnames ([#552]).
- OLM deployment helper ([#546]).
- Allow the specification of additional trust roots in autoTls SecretClasses ([#573]).

### Changed

- Bump `stackable-operator` to 0.87.0 and `rand` to 0.9 ([#569]).
- Default to OCI for image metadata ([#544]).
- [BREAKING] When using a fully qualified domain name, only the variant without the trailing dot is added to the SANs. This should only improve the behavior in scenarios where FQDNs are used and not affect anything else ([#564]).

### Fixed

- Underscores are now allowed in Kerberos principal names ([#563]).
- The issuer in generated TLS certificates is set to the subject of the issuing
  certificate ([#566]).
- Lookup KVNO from Active Directory rather than hard coding it ([#571]).

[#528]: https://github.com/stackabletech/secret-operator/pull/528
[#544]: https://github.com/stackabletech/secret-operator/pull/544
[#546]: https://github.com/stackabletech/secret-operator/pull/546
[#548]: https://github.com/stackabletech/secret-operator/pull/548
[#552]: https://github.com/stackabletech/secret-operator/pull/552
[#563]: https://github.com/stackabletech/secret-operator/pull/563
[#564]: https://github.com/stackabletech/secret-operator/pull/564
[#566]: https://github.com/stackabletech/secret-operator/pull/566
[#569]: https://github.com/stackabletech/secret-operator/pull/569
[#571]: https://github.com/stackabletech/secret-operator/pull/571
[#573]: https://github.com/stackabletech/secret-operator/pull/573

## [24.11.1] - 2025-01-10

### Fixed

- Helm chart: The secret migration job can be omitted via Helm values ([#536]).
- Helm chart: The tag of the tools image used for the secret migration job can
  be changed in the Helm values and defaults now to 1.0.0-stackable24.11.0
  rather than being hard-coded to 1.0.0-stackable24.7.0 ([#536]).

[#536]: https://github.com/stackabletech/secret-operator/pull/536

## [24.11.0] - 2024-11-18

### Added

- Active Directory's `samAccountName` generation can now be customized ([#454]).
- Added experimental cert-manager backend ([#482]).
- Make RSA key length configurable ([#506]).
- The operator can now run on Kubernetes clusters using a non-default cluster domain.
  Use the env var `KUBERNETES_CLUSTER_DOMAIN` or the operator Helm chart property `kubernetesClusterDomain` to set a non-default cluster domain` ([#510]).

### Changed

- Refactored hostname validation ([#494]).
  - BREAKING: Hostname validation is now somewhat stricter.
  - BREAKING: Hostname validation is now enforced in CRD.
- Remove custom `h2` patch, as Kubernetes 1.26 has fixed the invalid data from Kubernetes' side. Starting with 24.11 we only support at least 1.27 (as it's needed by OpenShift 4.14) ([#495]).

### Fixed

- Fixed Kerberos keytab provisioning reusing its credential cache ([#490]).
- Fixed listener volumes missing a required permission to inspect manually provisioned listeners ([#497]).
- test: Fixed cert-manager tests by installing cert-manager if it doesn't exist ([#505]).

[#454]: https://github.com/stackabletech/secret-operator/pull/454
[#482]: https://github.com/stackabletech/secret-operator/pull/482
[#490]: https://github.com/stackabletech/secret-operator/pull/490
[#494]: https://github.com/stackabletech/secret-operator/pull/494
[#495]: https://github.com/stackabletech/secret-operator/pull/495
[#497]: https://github.com/stackabletech/secret-operator/pull/497
[#505]: https://github.com/stackabletech/secret-operator/pull/505
[#506]: https://github.com/stackabletech/secret-operator/pull/506
[#510]: https://github.com/stackabletech/secret-operator/pull/510

## [24.7.0] - 2024-07-24

### Added

- The associated configuration is now logged for each issued secret ([#413]).
- Chore: Upgrade csi-provisioner to 5.0.1 and csi-node-driver-registrar to 2.11.1 ([#455])

### Changed

- [BREAKING] The TLS CA Secret is now installed into the Namespace of the operator (typically `stackable-operators`), rather than `default` ([#397]).
  - Existing users can either migrate by either:
    - (Recommended) Copying the CA into the new location
      (`kubectl -n default get secret/secret-provisioner-tls-ca -o json | jq '.metadata.namespace = "stackable-operators"' | kubectl create -f-`)
    - Setting the `secretClasses.tls.caSecretNamespace` Helm flag (`--set secretClasses.tls.caSecretNamespace=default`)
- Reduce CA default lifetime to one year ([#403])
- Update the image docker.stackable.tech/k8s/sig-storage/csi-provisioner
  in the Helm values to v4.0.1 ([#440]).
- Update the image docker.stackable.tech/k8s/sig-storage/csi-node-driver-registrar
  in the Helm values to v2.10.1 ([#440]).
- Bump `stackable-operator` to `0.70.0`, and other dependencies ([#467], [#470]).

### Removed

- Dead code ([#468]).

[#397]: https://github.com/stackabletech/secret-operator/pull/397
[#403]: https://github.com/stackabletech/secret-operator/pull/403
[#413]: https://github.com/stackabletech/secret-operator/pull/413
[#440]: https://github.com/stackabletech/secret-operator/pull/440
[#455]: https://github.com/stackabletech/secret-operator/pull/455
[#467]: https://github.com/stackabletech/secret-operator/pull/467
[#468]: https://github.com/stackabletech/secret-operator/pull/468
[#470]: https://github.com/stackabletech/secret-operator/pull/470

## [24.3.0] - 2024-03-20

### Added

- Improved CRD documentation ([#333]).
- Helm: support labels in values.yaml ([#352]).

## Changed

- Use new annotation builder ([#341]).
- `autoTLS` certificate authorities will now be rotated regularly ([#350]).
  - [BREAKING] This changes the format of the CA secrets. Old secrets will be migrated automatically, but manual intervention will be required to downgrade back to 23.11.x.
- `autoTLS` certificate authority lifetimes are now configurable ([#357]).
- Certificate lifetimes are now jittered ([#361]).

[#333]: https://github.com/stackabletech/secret-operator/pull/333
[#341]: https://github.com/stackabletech/secret-operator/pull/341
[#350]: https://github.com/stackabletech/secret-operator/pull/350
[#352]: https://github.com/stackabletech/secret-operator/pull/352
[#357]: https://github.com/stackabletech/secret-operator/pull/357
[#361]: https://github.com/stackabletech/secret-operator/pull/361

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
