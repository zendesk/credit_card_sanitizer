require "bundler/setup"
require "credit_card_sanitizer"

# Generates a random card of a specified type that passes
# a Luhn checksum.
def self.generate_card(type:, count: 1)
  [].tap do |numbers|
    while numbers.length < count
      candidate = generate_card_candiate(type: type)
      numbers << candidate if LuhnChecksum.valid?(candidate)
    end
  end
end

# The formats for each card type are from the
# CreditCardSanitizer::CARD_COMPANIES regexs
def self.generate_card_candiate(type:)
  case type
  when :visa
    digits = [4] + Array.new(14) { Random.rand(10) }
  when :jcb
    digits = [3528] + Array.new(11) { Random.rand(10) }
  when :switch
    digits = [6759] + Array.new(11) { Random.rand(10) }
  when :solo
    digits = [6767] + Array.new(11) { Random.rand(10) }
  when :forbrugsforeningen
    digits = [600722] + Array.new(9) { Random.rand(10) }
  when :laser
    digits = [6304] + Array.new(7) { Random.rand(10) }
  else
    raise "unhandled type: #{type}"
  end

  total = 0
  digits.reverse.each_with_index do |x, i|
    x *= 3 if i.even?
    total += x
  end
  check = total % 10
  check = (10 - check) unless check.zero?
  (digits + [check]).join
end

type = ARGV.first

if type
  puts generate_card(type: ARGV.first.to_sym)
else
  puts "type not specified: ruby scripts/generate_card.rb visa"
end
