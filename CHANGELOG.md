# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/codebyjass/active-cipher-storage/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/codebyjass/active-cipher-storage/releases/tag/v1.0.0
