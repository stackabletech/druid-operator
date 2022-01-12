# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Changed

- Shut down gracefully ([#101]).

[#101]: https://github.com/stackabletech/druid-operator/pull/101

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

