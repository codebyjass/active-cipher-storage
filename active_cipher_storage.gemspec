require_relative "lib/active_cipher_storage/version"

Gem::Specification.new do |spec|
  spec.name    = "active_cipher_storage"
  spec.version = ActiveCipherStorage::VERSION
  spec.authors = ["Jaspreet Singh"]
  spec.email   = ["codebyjass@users.noreply.github.com"]

  spec.summary     = "Transparent file encryption for Active Storage and S3 with pluggable KMS providers"
  spec.description = <<~DESC
    active_cipher_storage provides AES-256-GCM envelope encryption for files stored
    via Rails Active Storage or directly via the AWS S3 SDK. Key management is
    delegated to pluggable KMS providers: environment-variable keys, AWS KMS,
    or any custom provider implementing the base interface.
  DESC

  spec.homepage              = "https://github.com/codebyjass/active-cipher-storage"
  spec.license               = "MIT"
  spec.required_ruby_version = ">= 3.0"

  spec.metadata["bug_tracker_uri"]   = "#{spec.homepage}/issues"
  spec.metadata["changelog_uri"]     = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["documentation_uri"] = spec.homepage
  spec.metadata["homepage_uri"]      = spec.homepage
  spec.metadata["rubygems_mfa_required"] = "true"
  spec.metadata["source_code_uri"]   = spec.homepage

  spec.files = Dir[
    "lib/**/*.rb",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "active_cipher_storage.gemspec"
  ]

  spec.require_paths = ["lib"]

  # Core — no runtime dep on Rails or AWS
  spec.add_dependency "concurrent-ruby", "~> 1.2"

  # Optional integrations — loaded only when the relevant adapter is used
  spec.add_development_dependency "activestorage",    ">= 6.1", "< 9.0"
  spec.add_development_dependency "aws-sdk-kms",      "~> 1.0"
  spec.add_development_dependency "aws-sdk-s3",       "~> 1.0"

  # Dev/test
  spec.add_development_dependency "rspec",            "~> 3.12"
  spec.add_development_dependency "rspec-mocks",      "~> 3.12"
  spec.add_development_dependency "simplecov",        "~> 0.22"
  spec.add_development_dependency "faker",            "~> 3.0"
  spec.add_development_dependency "rake",             "~> 13.0"
end
