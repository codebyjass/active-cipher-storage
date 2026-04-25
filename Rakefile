require "bundler/gem_tasks"
require "rspec/core/rake_task"

RSpec::Core::RakeTask.new(:spec)
RSpec::Core::RakeTask.new("spec:unit")    { |t| t.pattern = "spec/unit/**/*_spec.rb" }
RSpec::Core::RakeTask.new("spec:integration") { |t| t.pattern = "spec/integration/**/*_spec.rb" }

task default: :spec
