Gem::Specification.new 'credit_card_sanitizer', '0.6.3' do |gem|
  gem.authors       = ['Eric Chapweske', 'Gary Grossman', 'Victor Kmita']
  gem.email         = ['ggrossman@zendesk.com']
  gem.description   = 'Credit card sanitizer'
  gem.summary       = 'Credit card sanitizer'
  gem.homepage      = 'https://github.com/zendesk/credit_card_sanitizer'
  gem.license       = 'Apache License Version 2.0'
  gem.files         = `git ls-files lib`.split($\)

  gem.add_development_dependency('rake')
  gem.add_development_dependency('bundler')
  gem.add_development_dependency('luhnacy')
  gem.add_development_dependency('byebug')
  gem.add_runtime_dependency('luhn_checksum', '~> 0.1')
  gem.add_runtime_dependency('tracking_number', '~> 0.10.2')
end
