require "bundler/gem_tasks"
require "rake/testtask"
require "standard/rake"

# Pushing to rubygems is handled by a github workflow
ENV["gem_push"] = "false"

Rake::TestTask.new do |t|
  t.pattern = "test/**/*_test.rb"
  t.verbose = false
  t.warning = true
end

task default: [:test, :standard]
