Gem::Specification.new "credit_card_sanitizer", '0.2.0' do |gem|
  gem.authors       = ["Eric Chapweske", "Gary Grossman"]
  gem.email         = ["ggrossman@zendesk.com"]
  gem.description   = "Credit card sanitizer"
  gem.summary       = "Credit card sanitizer"
  gem.homepage      = "https://github.com/zendesk/credit_card_sanitizer"
  gem.license       = "Apache License Version 2.0"
  gem.files         = `git ls-files lib`.split($\)
  gem.add_runtime_dependency("luhn_checksum")
end
