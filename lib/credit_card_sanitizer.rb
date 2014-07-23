require 'luhn_checksum'

class CreditCardSanitizer

  # 12-19 digits explanation: https://en.wikipedia.org/wiki/Primary_Account_Number#Issuer_identification_number_.28IIN.29
  NUMBERS_WITH_LINE_NOISE = /\d(?:\W*\d\W*){10,17}\d/x

  def self.parameter_filter
    Proc.new { |_, value| new.sanitize!(value) if value.is_a?(String) }
  end

  def initialize(replacement_token = 'X', replace_first = 6, replace_last = 4)
    @replacement_token, @replace_first, @replace_last = replacement_token, replace_first, replace_last
  end

  def sanitize!(text)
    replaced = nil

    text.force_encoding(Encoding::UTF_8)
    replace_invalid_characters(text) if !text.valid_encoding?

    text.gsub!(NUMBERS_WITH_LINE_NOISE) do |match|
      numbers = match.gsub(/\D/, '')

      if LuhnChecksum.valid?(numbers)
        replaced = true
        replace_numbers!(match, numbers.size - @replace_last)
      end

      match
    end

    replaced && text
  end

  private

  def replace_numbers!(text, replacement_limit)
    # Leave the first @replace_first and last @replace_last numbers visible
    digit_index = 0

    text.gsub!(/\d/) do |number|
      digit_index += 1
      if digit_index > @replace_first && digit_index <= replacement_limit
        @replacement_token
      else
        number
      end
    end
  end

  def replace_invalid_characters(str)
    for i in (0...str.size)
      if !str[i].valid_encoding?
        str[i] = "?"
      end
    end
  end
end
