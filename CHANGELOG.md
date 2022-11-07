# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- Cpu and memory limits are now configurable ([#298]).
- Stale resources are now deleted ([#310]).
- Support Druid 24.0.0 ([#317]).
- Refactor role configuration with per role structs like `BrokerConfig`, `HistoricalConfig`, etc ([#332])
- Added `HistoricalStorage` and `DruidStorage` (as catch-all storage configuration) ([#332])
- BREAKING: Support for TLS encryption (activated per default -> port changes) and TLS authentication ([#333]).
- BREAKING: Reworked top level configuration. Deep storage, Ingestion spec, discovery config maps etc. are now subfields of `spec.clusterConfig` instead of being top level under `spec` ([#333]).

### Changed

- `operator-rs` `0.22.0` -> `0.25.2` ([#310])

[#298]: https://github.com/stackabletech/druid-operator/pull/298
[#310]: https://github.com/stackabletech/druid-operator/pull/310
[#317]: https://github.com/stackabletech/druid-operator/pull/317
[#332]: https://github.com/stackabletech/druid-operator/pull/332
[#333]: https://github.com/stackabletech/druid-operator/pull/333

## [0.7.0] - 2022-09-06

### Changed

- BREAKING: HDFS deep storage now configurable via HDFS discovery config map instead of an url to a HDFS name node ([#262]).
- Include chart name when installing with a custom release name ([#263], [#264]).

### Fixed

- Add missing role to read S3Connection and S3Bucket objects ([#281]).

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

- Reconciliation errors are now reported as Kubernetes events ([#178]).
- Use cli argument `watch-namespace` / env var `WATCH_NAMESPACE` to specify
  a single namespace to watch ([#183]).
- BREAKING: Local backend storage (deep-storage) has been replaced with HDFS-storage, affecting the CRD ([#187]).
- BREAKING: The corresponding local-storage label has been removed, affecting the CRD ([#124]).
- Make the inclusion of the druid-s3-extension dependent on the Custom Resource definition ([#192]).

### Changed

- Many configuration properties are not hardcoded anymore, product-config expanded ([#195])
- `operator-rs` `0.10.0` -> `0.15.0` ([#178], [#183], [#195], [#187]).
- `snafu` `0.6` -> `0.7` ([#178]).

[#124]: https://github.com/stackabletech/druid-operator/pull/124
[#178]: https://github.com/stackabletech/druid-operator/pull/178
[#183]: https://github.com/stackabletech/druid-operator/pull/183
[#186]: https://github.com/stackabletech/druid-operator/pull/186
[#187]: https://github.com/stackabletech/druid-operator/pull/187
[#192]: https://github.com/stackabletech/druid-operator/pull/192
[#195]: https://github.com/stackabletech/druid-operator/pull/195

## [0.4.0] - 2022-02-14

### Added

- Monitoring scraping label `prometheus.io/scrape: true` ([#155]).

### Changed

- Removed the option to set a namespace for the zookeeper reference ([#140])
- `operator-rs` `0.8.0` → `0.10.0` ([#155])

[#140]: https://github.com/stackabletech/druid-operator/pull/140
[#155]: https://github.com/stackabletech/druid-operator/pull/155

## [0.3.0] - 2022-01-27

### Changed

- `operator-rs` `0.7.0` → `0.8.0` ([#123])
- Fixed a port reference in the role services ([#102])
- Shut down gracefully ([#101]).

### Added

- Added the discovery ConfigMap creation ([#102])

[#101]: https://github.com/stackabletech/druid-operator/pull/101
[#102]: https://github.com/stackabletech/druid-operator/pull/102
[#123]: https://github.com/stackabletech/druid-operator/pull/123

## [0.2.0] - 2021-12-23

### Changed

- Migrated to StatefulSet rather than direct Pod management ([#59]).
- Ports are not configurable anymore ([#76]).
- Updated to operator-rs 0.7.0 ([#76]).

[#59]: https://github.com/stackabletech/druid-operator/pull/59
[#76]: https://github.com/stackabletech/druid-operator/pull/76

## [0.1.0] - 2021-12-06

### Changed

- Initial Implementation ([#13])
- Enabled monitoring using the Prometheus emitter extension. ([#27])

[#13]: https://github.com/stackabletech/druid-operator/pull/13
[#27]: https://github.com/stackabletech/druid-operator/pull/27
