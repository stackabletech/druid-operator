# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- Reconciliation errors are now reported as Kubernetes events ([#178]).
- Use cli argument `watch-namespace` / env var `WATCH_NAMESPACE` to specify
  a single namespace to watch ([#183]).
- BREAKING: Local backend storage (deep-storage) has been replaced with HDFS-storage, affecting the CRD ([#187]).
- BREAKING: The corresponding local-storage label has been removed, affecting the CRD ([#124]).
- Make the inclusion of the druid-s3-extension dependent on the Custom Resource definition ([#71]).

### Changed

- Many configuration properties are not hardcoded anymore, product-config expanded ([#195])
- `operator-rs` `0.10.0` -> `0.13.0` ([#178],[#183]).
- `snafu` `0.6` -> `0.7` ([#178]).

[#195]: https://github.com/stackabletech/druid-operator/pull/195
[#124]: https://github.com/stackabletech/druid-operator/pull/124
[#178]: https://github.com/stackabletech/druid-operator/pull/178
[#183]: https://github.com/stackabletech/druid-operator/pull/183
[#187]: https://github.com/stackabletech/druid-operator/pull/187
[#71]: https://github.com/stackabletech/druid-operator/issues/71

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
