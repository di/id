# Changelog

All notable changes to `id` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Changed

* CircleCI: default to --root-issuer when generating OIDC Token ([[#438](https://github.com/di/id/pull/438)])

* Drop dependency on `requests` in favor of underlying
  `urllib3` ([#333](https://github.com/di/id/pull/333))

## [1.5.0]

### Changed

* Drop dependency on `pydantic` ([#320](https://github.com/di/id/pull/320))

## [1.4.0]

### Added

* Add `pipx run` entry point ([#217](https://github.com/di/id/pull/217))

## [1.3.0]

### Added

* Add support for decoding tokens with `-d`/`--decode` ([#162](https://github.com/di/id/pull/162))

## [1.2.1]

### Misc

* This release fixes a deployment bug in the 1.2.0 release.

## [1.2.0]

### Added

* Added support for GitLab CI/CD ([#123](https://github.com/di/id/pull/123))
* Added support for CircleCI ([#144](https://github.com/di/id/pull/144))

### Changed

* The minimum supported Python version is now 3.8 ([#141](https://github.com/di/id/pull/141))

## [1.1.0]

### Added

* Added support for Buildkite OIDC tokens
  ([#21](https://github.com/di/id/pull/21))

### Fixed

* Improved the quality of error messages when an underlying
  request fails ([#93](https://github.com/di/id/pull/93))

## [1.0.0]

### Added

* Initial split from https://github.com/sigstore/sigstore-python

<!--Release URLs -->
[Unreleased]: https://github.com/di/id/compare/v1.5.0...HEAD
[1.5.0]: https://github.com/di/id/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/di/id/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/di/id/compare/v1.2.1...v1.3.0
[1.2.1]: https://github.com/di/id/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/di/id/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/di/id/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/di/id/compare/v1.0.0a2...v1.0.0
