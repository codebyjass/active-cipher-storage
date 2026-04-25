# Contributing

Thanks for your interest in contributing to ActiveCipherStorage.

This gem handles encryption and storage, so changes should be small, well-tested, and conservative. Prefer clear behavior and strong tests over clever abstractions.

## Development Setup

```bash
git clone https://github.com/codebyjass/active-cipher-storage.git
cd active-cipher-storage
bundle install
bundle exec rspec
```

The test suite uses in-memory fakes for Active Storage and S3. You do not need AWS credentials to run the tests.

## Before Opening a Pull Request

- Run `bundle exec rspec`.
- Add or update specs for behavior changes.
- Keep public APIs backward-compatible unless the change is clearly marked as breaking.
- Do not commit secrets, credentials, `.env` files, local coverage output, or generated gems.
- Update `README.md` and `CHANGELOG.md` when user-facing behavior changes.

## Testing Expectations

Use focused tests for:

- Encryption format compatibility.
- Authentication and tamper failures.
- Large-file chunk boundaries.
- Active Storage legacy plaintext fallback.
- S3 multipart and streaming behavior.
- Provider error handling.
- Key rotation behavior.

Security-sensitive fixes should include a regression test that fails without the fix.

## Security Changes

Please do not open public issues for vulnerabilities. Follow `SECURITY.md` instead.

## Code of Conduct

Be respectful and constructive. Assume good intent, keep feedback specific, and help keep the project welcoming for maintainers and contributors.
