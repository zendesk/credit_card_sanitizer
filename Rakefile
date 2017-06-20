require 'bundler/setup'
require 'bundler/gem_tasks'
require 'bump/tasks'
require 'rake/testtask'
require 'rubocop/rake_task'

RuboCop::RakeTask.new

Rake::TestTask.new do |t|
  t.pattern = 'test/**/*_test.rb'
  t.verbose = false
  t.warning = true
end

task default: [:test, :rubocop]
