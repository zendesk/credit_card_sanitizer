# encoding: utf-8

require 'luhn_checksum'

class CreditCardSanitizer

  LINE_NOISE = /[^\w_\n,()\/:]{0,8}/
  # 12-19 digits explanation: https://en.wikipedia.org/wiki/Primary_Account_Number#Issuer_identification_number_.28IIN.29
  NUMBERS_WITH_LINE_NOISE = /\d(?:#{LINE_NOISE}\d#{LINE_NOISE}){10,17}\d/

  # Taken from https://github.com/Shopify/active_merchant/blob/master/lib/active_merchant/billing/credit_card_methods.rb#L7-L20
  CARD_COMPANIES = {
    'visa'               => /^4\d{12}(\d{3})?$/,
    'master'             => /^(5[1-5]\d{4}|677189)\d{10}$/,
    'discover'           => /^(6011|65\d{2}|64[4-9]\d)\d{12}|(62\d{14})$/,
    'american_express'   => /^3[47]\d{13}$/,
    'diners_club'        => /^3(0[0-5]|[68]\d)\d{11}$/,
    'jcb'                => /^35(28|29|[3-8]\d)\d{12}$/,
    'switch'             => /^6759\d{12}(\d{2,3})?$/,
    'solo'               => /^6767\d{12}(\d{2,3})?$/,
    'dankort'            => /^5019\d{12}$/,
    'maestro'            => /^(5[06-8]|6\d)\d{10,17}$/,
    'forbrugsforeningen' => /^600722\d{10}$/,
    'laser'              => /^(6304|6706|6709|6771(?!89))\d{8}(\d{4}|\d{6,7})?$/
  }
  VALID_COMPANY_PREFIXES = Regexp.union(*CARD_COMPANIES.values)

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

      if LuhnChecksum.valid?(numbers) && valid_prefix?(numbers)
        replaced = true
        replace_numbers!(match, numbers.size - @replace_last)
      end

      match
    end

    replaced && text
  end

  def valid_prefix?(numbers)
    !!(numbers =~ VALID_COMPANY_PREFIXES)
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
