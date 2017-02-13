require 'bundler/setup'

require 'single_cov'
SingleCov.setup :minitest

require 'maxitest/autorun'

require 'credit_card_sanitizer'
require 'scrub_rb' if RUBY_VERSION < '2.1.0'
