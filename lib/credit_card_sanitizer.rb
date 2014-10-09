# encoding: utf-8

require 'active_merchant'

class CreditCardSanitizer

  LINE_NOISE = /[^\w_\n,()\/:]{0,8}/x
  # 12-19 digits explanation: https://en.wikipedia.org/wiki/Primary_Account_Number#Issuer_identification_number_.28IIN.29
  NUMBERS_WITH_LINE_NOISE = /\d(?:#{LINE_NOISE}\d#{LINE_NOISE}){10,17}\d/x

  include ActiveMerchant::Billing::CreditCardMethods

  def self.parameter_filter
    Proc.new { |_, value| new.sanitize!(value) if value.is_a?(String) }
  end

  def initialize(replacement_token = 'X', replace_first = 6, replace_last = 4)
    @replacement_token, @replace_first, @replace_last = replacement_token, replace_first, replace_last
  end

  def sanitize!(text)
    replaced = nil

    to_utf8!(text)

    text.gsub!(NUMBERS_WITH_LINE_NOISE) do |match|
      numbers = match.gsub(/\D/, '')

      if self.class.send(:valid_checksum?, numbers) && self.class.brand?(numbers)
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

  if ''.respond_to?(:scrub)
    def to_utf8!(str)
      str.force_encoding(Encoding::UTF_8)
      str.scrub! unless str.valid_encoding?
    end
  else
    def to_utf8!(str)
      str.force_encoding(Encoding::UTF_8)
      unless str.valid_encoding?
        str.encode!(Encoding::UTF_16, :invalid => :replace, :replace => '�')
        str.encode!(Encoding::UTF_8, Encoding::UTF_16)
      end
    end
  end
end
