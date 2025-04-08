# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Changed

- Replace stackable-operator `initialize_logging` with stackable-telemetry `Tracing` ([#703]).
  - BREAKING: The file log directory was set by `DRUID_OPERATOR_LOG_DIRECTORY`, and is now set by `ROLLING_LOGS`
    (or via `--rolling-logs <DIRECTORY>`).
  - Replace stackable-operator `print_startup_string` with `tracing::info!` with fields.

[#703]: https://github.com/stackabletech/druid-operator/pull/703

## [25.3.0] - 2025-03-21

### Added

- The lifetime of auto generated TLS certificates is now configurable with the role and roleGroup
  config property `requestedSecretLifetime`. This helps reducing frequent Pod restarts ([#660]).
- Run a `containerdebug` process in the background of each "druid" container to collect debugging information ([#667]).
- Aggregate emitted Kubernetes events on the CustomResources ([#677]).
- Support Apache Druid `31.0.1` and `30.0.1`, remove `26.0.0` ([#685]).
- BREAKING: Adjust default memory limits of coordinator from `512Mi` to `768Mi` and middlemanager from `1Gi` to `1500Mi` ([#685]).
- Support configuring JVM arguments ([#693]).
- Add `region.name` field in S3Connection.
  This field is **ignored** by this operator, see [ingestion] and [deep storage] documentation.
  A warning is emitted when a non-default endpoint is used ([#695], [#700]).

### Changed

- Bump `stackable-operator` to 0.87.0 and `stackable-versioned` to 0.6.0 ([#695]).
- Default to OCI for image metadata and product image selection ([#676]).

[#660]: https://github.com/stackabletech/druid-operator/pull/660
[#667]: https://github.com/stackabletech/druid-operator/pull/667
[#676]: https://github.com/stackabletech/druid-operator/pull/676
[#677]: https://github.com/stackabletech/druid-operator/pull/677
[#693]: https://github.com/stackabletech/druid-operator/pull/693
[#685]: https://github.com/stackabletech/druid-operator/pull/685
[#695]: https://github.com/stackabletech/druid-operator/pull/695
[#700]: https://github.com/stackabletech/druid-operator/pull/700

[ingestion]: https://docs.stackable.tech/home/nightly/druid/usage-guide/ingestion/
[deep storage]: https://docs.stackable.tech/home/nightly/druid/usage-guide/deep-storage/

## [24.11.1] - 2025-01-09

### Fixed

- Fix OIDC endpoint construction in case the `rootPath` does have a trailing slash ([#656]).
- BREAKING: Use distinct ServiceAccounts for the Stacklets, so that multiple Stacklets can be
  deployed in one namespace. Existing Stacklets will use the newly created ServiceAccounts after
  restart ([#657]).

[#656]: https://github.com/stackabletech/druid-operator/pull/656
[#657]: https://github.com/stackabletech/druid-operator/pull/657

## [24.11.0] - 2024-11-18

### Added

- The operator can now run on Kubernetes clusters using a non-default cluster domain.
  Use the env var `KUBERNETES_CLUSTER_DOMAIN` or the operator Helm chart property `kubernetesClusterDomain` to set a non-default cluster domain ([#637]).

### Changed

- Reduce CRD size from `2.4MB` to `183KB` by accepting arbitrary YAML input instead of the underlying schema for the following fields ([#584]):
  - `podOverrides`
  - `affinity`
  - `extraVolumes`
- Replace `lazy_static` with `std::cell::LazyCell` ([#604]).
- Promote Druid `30.0.0` to LTS, deprecate `26.0.0` ([#631]).

### Fixed

- BREAKING: The fields `connection` and `host` on `S3Connection` as well as `bucketName` on `S3Bucket`are now mandatory ([#632]).
- Failing to parse one `DruidCluster`/`AuthenticationClass` should no longer cause the whole operator to stop functioning ([#638]).

### Removed

- test: Remove ZooKeeper 3.8.4 ([#621]).
- Remove Druid `28.0.1` ([#631]).

[#584]: https://github.com/stackabletech/druid-operator/pull/584
[#604]: https://github.com/stackabletech/druid-operator/pull/604
[#621]: https://github.com/stackabletech/druid-operator/pull/621
[#631]: https://github.com/stackabletech/druid-operator/pull/631
[#632]: https://github.com/stackabletech/druid-operator/pull/632
[#637]: https://github.com/stackabletech/druid-operator/pull/637
[#638]: https://github.com/stackabletech/druid-operator/pull/638

## [24.7.0] - 2024-07-24

### Added

- Add support for specifying additional extensions to load ([#547], [#563]).
- Add support for OIDC as authentication method ([#573]).
- Support Apache Druid `30.0.0` as experimental version ([#583]).

### Changed

- Bump `stackable-operator` from `0.64.0` to `0.70.0` ([#585]).
- Bump `product-config` from `0.6.0` to `0.7.0` ([#585]).
- Bump other dependencies ([#587]).
- Deprecate support for Apache Druid `28.0.1` ([#583]).

### Fixed

- [BREAKING] Move the DB credentials `user` and `password` out of the CRD into a secret containing the keys `username` and `password` ([#557]).
- Processing of corrupted log events fixed; If errors occur, the error messages are added to the log event ([#572]).

### Removed

- Remove support for Apache Druid version 27.0.0 ([#583]).

[#547]: https://github.com/stackabletech/druid-operator/pull/547
[#557]: https://github.com/stackabletech/druid-operator/pull/557
[#563]: https://github.com/stackabletech/druid-operator/pull/563
[#572]: https://github.com/stackabletech/druid-operator/pull/572
[#583]: https://github.com/stackabletech/druid-operator/pull/583
[#585]: https://github.com/stackabletech/druid-operator/pull/585
[#587]: https://github.com/stackabletech/druid-operator/pull/587

## [24.3.0] - 2024-03-20

### Added

- Various documentation of the CRD ([#494]).
- Helm: support labels in values.yaml ([#509]).
- Support druid `28.0.1` ([#518]).

### Updated

- `operator-rs` `0.56.1` -> `0.57.0` ([#494]).

[#494]: https://github.com/stackabletech/druid-operator/pull/494
[#509]: https://github.com/stackabletech/druid-operator/pull/509
[#518]: https://github.com/stackabletech/druid-operator/pull/518

## [23.11.0] - 2023-11-24

### Added

- Default stackableVersion to operator version ([#458]).
- Configuration overrides for the JVM security properties, such as DNS caching ([#464]).
- Support PodDisruptionBudgets ([#477]).
- Add support for version 27.0.0 ([#480]).
- Add integration test for OpenID Connect with Keycloak ([#481]).
- Support graceful shutdown ([#486]).

### Changed

- `vector` `0.26.0` -> `0.33.0` ([#459], [#480]).
- `operator-rs` `0.44.0` -> `0.55.0` ([#458], [#474], [#477], [#480]).
- Let secret-operator handle certificate conversion ([#474]).

### Removed

- Remove support for version 0.23.0, 24.0.0 ([#480]).

[#458]: https://github.com/stackabletech/druid-operator/pull/458
[#459]: https://github.com/stackabletech/druid-operator/pull/459
[#464]: https://github.com/stackabletech/druid-operator/pull/464
[#474]: https://github.com/stackabletech/druid-operator/pull/474
[#477]: https://github.com/stackabletech/druid-operator/pull/477
[#480]: https://github.com/stackabletech/druid-operator/pull/480
[#481]: https://github.com/stackabletech/druid-operator/pull/481
[#486]: https://github.com/stackabletech/druid-operator/pull/486

## [23.7.0] - 2023-07-14

### Added

- Generate OLM bundle for Release 23.4.0 ([#436]).
- Missing CRD defaults for `status.conditions` field ([#439]).
- Support for Druid `26.0.0` ([#442]).
- Set explicit resources on all containers ([#444]).
- Support podOverrides ([#450]).

### Changed

- Operator-rs: `0.42.2` -> `0.44.0` ([#434], [#452]).
- Use 0.0.0-dev product images for tests and examples ([#435])
- Use testing-tools 0.2.0 ([#435])
- Tls tests now run on OpenShift ([#445])
- Added kuttl test suites ([#447])
- Increase the size limit of log volumes (#[452])

### Removed

- All usages of the minio/minio chart replace them with the bitnami/minio chart ([#445])

[#434]: https://github.com/stackabletech/druid-operator/pull/434
[#435]: https://github.com/stackabletech/druid-operator/pull/435
[#436]: https://github.com/stackabletech/druid-operator/pull/436
[#439]: https://github.com/stackabletech/druid-operator/pull/439
[#442]: https://github.com/stackabletech/druid-operator/pull/442
[#444]: https://github.com/stackabletech/druid-operator/pull/444
[#445]: https://github.com/stackabletech/druid-operator/pull/445
[#447]: https://github.com/stackabletech/druid-operator/pull/447
[#450]: https://github.com/stackabletech/druid-operator/pull/450
[#452]: https://github.com/stackabletech/druid-operator/pull/452

## [23.4.0] - 2023-04-17

### Added

- Add support for non-TLS LDAP authentication. ([#374])
- Add support for TLS LDAP authentication ([#408])
- Deploy default and support custom affinities ([#406])
- Log aggregation added ([#407])
- Added the ability to mount extra volumes for files that may be needed for ingestion tasks to work ([#415])
- Cluster status conditions ([#421])
- Extend cluster resources for status and cluster operation (paused, stopped) ([#422])
- Use operator-rs `build_rbac_resources` method ([#425])
- Openshift compatibility ([#425])

### Changed

- [BREAKING] Support specifying Service type.
  This enables us to later switch non-breaking to using `ListenerClasses` for the exposure of Services.
  This change is breaking, because - for security reasons - we default to the `cluster-internal` `ListenerClass`.
  If you need your cluster to be accessible from outside of Kubernetes you need to set `clusterConfig.listenerClass`
  to `external-unstable` or `external-stable` ([#423]).
- Upgrade to `operator-rs` `0.40.2` ([#374], [#380], [#404], [#406], [#408], [#422], [#425])
- Merging and validation of the configuration refactored ([#404])

### Fixed

- Configuration overrides for certain properties did not work and now work again ([#387])
- Fix OOM error with manual buffer size specification ([#380])

[#374]: https://github.com/stackabletech/druid-operator/pull/374
[#380]: https://github.com/stackabletech/druid-operator/pull/380
[#387]: https://github.com/stackabletech/druid-operator/pull/387
[#404]: https://github.com/stackabletech/druid-operator/pull/404
[#406]: https://github.com/stackabletech/druid-operator/pull/406
[#407]: https://github.com/stackabletech/druid-operator/pull/407
[#408]: https://github.com/stackabletech/druid-operator/pull/408
[#415]: https://github.com/stackabletech/druid-operator/pull/415
[#421]: https://github.com/stackabletech/druid-operator/pull/421
[#422]: https://github.com/stackabletech/druid-operator/pull/422
[#423]: https://github.com/stackabletech/druid-operator/pull/423
[#425]: https://github.com/stackabletech/druid-operator/pull/425

## [23.1.0] - 2023-01-23

### Added

- BREAKING: Support for TLS encryption (activated per default -> port changes) and TLS authentication ([#333])
- Use emptyDir for segment cache on historicals ([#342])

### Changed

- BREAKING: Use Product image selection instead of version. `spec.version` has been replaced by `spec.image` ([#356])
- BREAKING: Reworked top level configuration. Deep storage, Ingestion spec, discovery config maps, authentication etc. are now subfields of `spec.clusterConfig` instead of being top level under `spec` ([#333], [#366])
- BREAKING: Removed tools image from init container and replaced with Druid product image. This means the latest stackable version has to be used in the product image selection ([#358])
- Updated stackable image versions ([#339])
- Upgrade to `operator-rs` `0.30.1` ([#340], [#347], [#362])
- Do not run init container as root anymore and avoid chmod and chown ([#353])
- Fixed role group node selector ([#362])
- Bitnami Helm chart 12.1.5 for kuttl tests. ([#363])

### Removed

- Retired support for 0.22.1 as it is not build anymore via the docker actions ([#339])

[#333]: https://github.com/stackabletech/druid-operator/pull/333
[#339]: https://github.com/stackabletech/druid-operator/pull/339
[#340]: https://github.com/stackabletech/druid-operator/pull/340
[#342]: https://github.com/stackabletech/druid-operator/pull/342
[#347]: https://github.com/stackabletech/druid-operator/pull/347
[#353]: https://github.com/stackabletech/druid-operator/pull/353
[#356]: https://github.com/stackabletech/druid-operator/pull/356
[#358]: https://github.com/stackabletech/druid-operator/pull/358
[#362]: https://github.com/stackabletech/druid-operator/pull/362
[#363]: https://github.com/stackabletech/druid-operator/pull/363
[#366]: https://github.com/stackabletech/druid-operator/pull/366

## [0.8.0] - 2022-11-07

### Added

- Cpu and memory limits are now configurable ([#298])
- Stale resources are now deleted ([#310])
- Support Druid 24.0.0 ([#317])
- Refactor role configuration with per role structs like `BrokerConfig`, `HistoricalConfig`, etc ([#332])
- Added `HistoricalStorage` and `DruidStorage` (as catch-all storage configuration) ([#332])

### Changed

- `operator-rs` `0.22.0` -> `0.25.2` ([#310])

[#298]: https://github.com/stackabletech/druid-operator/pull/298
[#310]: https://github.com/stackabletech/druid-operator/pull/310
[#317]: https://github.com/stackabletech/druid-operator/pull/317
[#332]: https://github.com/stackabletech/druid-operator/pull/332

## [0.7.0] - 2022-09-06

### Changed

- BREAKING: HDFS deep storage now configurable via HDFS discovery config map instead of an url to a HDFS name node ([#262])
- Include chart name when installing with a custom release name ([#263], [#264])

### Fixed

- Add missing role to read S3Connection and S3Bucket objects ([#281])

[#262]: https://github.com/stackabletech/druid-operator/pull/262
[#263]: https://github.com/stackabletech/druid-operator/pull/263
[#264]: https://github.com/stackabletech/druid-operator/pull/264
[#281]: https://github.com/stackabletech/druid-operator/pull/281

## [0.6.0] - 2022-06-30

### Added

- Readiness probe added ([#241])
- Support S3 path style access ([#245])
- Support S3 TLS verification ([#255])
- Support Druid 0.23.0 ([#255])

### Changed

- BREAKING: The deep storage on s3 and the s3 config for ingestion have been changed to use the operator-rs commons::s3 structs ([#228])
- `operator-rs` `0.15.0` -> `0.21.0` ([#228])
- [BREAKING] Specifying the product version has been changed to adhere to [ADR018](https://docs.stackable.tech/home/contributor/adr/ADR018-product_image_versioning.html) instead of just specifying the product version you will now have to add the Stackable image version as well, so `version: 3.5.8` becomes (for example) `version: 3.5.8-stackable0.1.0` ([#238])

### Fixed

- Fixed wrong file permissions on mounted secrets ([#244])

[#228]: https://github.com/stackabletech/druid-operator/pull/228
[#238]: https://github.com/stackabletech/druid-operator/pull/238
[#241]: https://github.com/stackabletech/druid-operator/pull/241
[#244]: https://github.com/stackabletech/druid-operator/pull/244
[#245]: https://github.com/stackabletech/druid-operator/pull/245
[#255]: https://github.com/stackabletech/druid-operator/pull/255

## [0.5.0] - 2022-03-15

### Added

- Reconciliation errors are now reported as Kubernetes events ([#178])
- Use cli argument `watch-namespace` / env var `WATCH_NAMESPACE` to specify
  a single namespace to watch ([#183])
- BREAKING: Local backend storage (deep-storage) has been replaced with HDFS-storage, affecting the CRD ([#187])
- BREAKING: The corresponding local-storage label has been removed, affecting the CRD ([#124])
- Make the inclusion of the druid-s3-extension dependent on the Custom Resource definition ([#192])

### Changed

- Many configuration properties are not hardcoded anymore, product-config expanded ([#195])
- `operator-rs` `0.10.0` -> `0.15.0` ([#178], [#183], [#195], [#187])
- `snafu` `0.6` -> `0.7` ([#178])

[#124]: https://github.com/stackabletech/druid-operator/pull/124
[#178]: https://github.com/stackabletech/druid-operator/pull/178
[#183]: https://github.com/stackabletech/druid-operator/pull/183
[#187]: https://github.com/stackabletech/druid-operator/pull/187
[#192]: https://github.com/stackabletech/druid-operator/pull/192
[#195]: https://github.com/stackabletech/druid-operator/pull/195

## [0.4.0] - 2022-02-14

### Added

- Monitoring scraping label `prometheus.io/scrape: true` ([#155])

### Changed

- Removed the option to set a namespace for the zookeeper reference ([#140])
- `operator-rs` `0.8.0` → `0.10.0` ([#155])

[#140]: https://github.com/stackabletech/druid-operator/pull/140
[#155]: https://github.com/stackabletech/druid-operator/pull/155

## [0.3.0] - 2022-01-27

### Changed

- `operator-rs` `0.7.0` → `0.8.0` ([#123])
- Fixed a port reference in the role services ([#102])
- Shut down gracefully ([#101])

### Added

- Added the discovery ConfigMap creation ([#102])

[#101]: https://github.com/stackabletech/druid-operator/pull/101
[#102]: https://github.com/stackabletech/druid-operator/pull/102
[#123]: https://github.com/stackabletech/druid-operator/pull/123

## [0.2.0] - 2021-12-23

### Changed

- Migrated to StatefulSet rather than direct Pod management ([#59])
- Ports are not configurable anymore ([#76])
- Updated to operator-rs 0.7.0 ([#76])

[#59]: https://github.com/stackabletech/druid-operator/pull/59
[#76]: https://github.com/stackabletech/druid-operator/pull/76

## [0.1.0] - 2021-12-06

### Changed

- Initial Implementation ([#13])
- Enabled monitoring using the Prometheus emitter extension. ([#27])

[#13]: https://github.com/stackabletech/druid-operator/pull/13
[#27]: https://github.com/stackabletech/druid-operator/pull/27
