# encoding: utf-8

require 'luhn_checksum'

class CreditCardSanitizer

  # 12-19 digits explanation: https://en.wikipedia.org/wiki/Primary_Account_Number#Issuer_identification_number_.28IIN.29
  NUMBERS_WITH_LINE_NOISE = /\d(?:[^\w_\n,]{0,8}\d[^\w_\n,]{0,8}){10,}\d/x

  def self.parameter_filter
    Proc.new { |_, value| new.sanitize!(value) if value.is_a?(String) }
  end

  def initialize(replacement_token = 'X', replace_first = 6, replace_last = 4)
    @replacement_token, @replace_first, @replace_last = replacement_token, replace_first, replace_last
  end

  def sanitize!(text)
    to_utf8!(text)

    text.gsub!(NUMBERS_WITH_LINE_NOISE) do |match|
      numbers = match.gsub(/\D/, '')
      detected_cc_metadata = find_cc_numbers(numbers)

      replace_numbers!(match, detected_cc_metadata) if detected_cc_metadata.any?

      match
    end

    @replaced && text
  end

  private

  def find_cc_numbers(numbers, precalculated_index = 0, detected_cc_metadata = [])
    return detected_cc_metadata if (size = numbers.size) < 12
    limit = (size < 19 && size || 19)
    (12..limit).reverse_each do |size|
      if LuhnChecksum.valid?(numbers[0...size])
        @replaced = true
        detected_cc_metadata << [precalculated_index, size]
        return find_cc_numbers(numbers[size..-1], (precalculated_index + size + 1), detected_cc_metadata)
      end
    end
    find_cc_numbers(numbers[1..-1], precalculated_index + 1, detected_cc_metadata)
  end

  def replace_numbers!(text, tuples)
    digit_index = 0
    tuple = tuples.shift
    text.gsub!(/\d/) do |number|
      return number unless tuple
      if (digit_index - tuple[0]) >= @replace_first && (digit_index - tuple[0]) < tuple[1] - @replace_last
        tuple = tuples.shift if digit_index >= tuple[0] + tuple[1]
        digit_index += 1
        @replacement_token
      else
        digit_index += 1
        number
      end
    end
  end

  if ''.respond_to?(:scrub)
    def to_utf8!(str)
      str.force_encoding(Encoding::UTF_8)
      str.scrub! unless str.valid_encoding?
    end
  elsif ''.respond_to?(:encoding)
    def to_utf8!(str)
      str.force_encoding(Encoding::UTF_8)
      unless str.valid_encoding?
        str.encode!(Encoding::UTF_16, :invalid => :replace, :replace => '�')
        str.encode!(Encoding::UTF_8, Encoding::UTF_16)
      end
    end
  else
    def to_utf8!(str)
      # No-op for Ruby 1.8
    end
  end
end
