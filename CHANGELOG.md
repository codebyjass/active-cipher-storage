# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.3] - 2026-04-25

### Changed

- Update the README with clearer usage guidance and improved readability.

## [1.0.2] - 2026-04-25

### Changed

- Publish updated RubyGems metadata for Rails Active Storage encryption, Ruby encryption/decryption, S3 streaming, multipart uploads, AES-256-GCM, and AWS KMS discoverability.

## [1.0.1] - 2026-04-25

### Changed

- Back gem configuration with Rails-style ActiveSupport options while preserving the existing public configuration API.
- Document the Active Storage upload encryption flag and plaintext read compatibility behavior.

### Fixed

- Reject reordered streaming frames and trailing bytes after the final encrypted frame.
- Validate S3 multipart chunk sizes before upload so invalid part sizes fail early.
- Mark plaintext Active Storage uploads explicitly when encryption is disabled.

## [1.0.0] - 2026-04-25

### Added

- Initial public ActiveCipherStorage gem release.
- Transparent Rails Active Storage encryption service.
- Direct S3 encrypted upload, download, streaming, and multipart support.
- Backend-managed encrypted multipart uploads for frontend chunk upload flows.
- AES-256-GCM envelope encryption with self-describing payload headers.
- Environment-variable and AWS KMS providers, plus a custom provider interface.
- Header-only key rotation for re-wrapping encrypted DEKs.
- Unit and integration coverage for crypto, providers, Active Storage, S3, multipart upload, streaming, metadata, and key rotation.

[Unreleased]: https://github.com/codebyjass/active-cipher-storage/compare/v1.0.3...HEAD
[1.0.3]: https://github.com/codebyjass/active-cipher-storage/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/codebyjass/active-cipher-storage/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/codebyjass/active-cipher-storage/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/codebyjass/active-cipher-storage/releases/tag/v1.0.0
