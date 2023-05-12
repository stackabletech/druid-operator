# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [23.4.1] - 2023-05-17

### Added

- Missing CRD defaults for `status.conditions` field ([#439]).

[#439]: https://github.com/stackabletech/druid-operator/pull/439

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
