# encoding: utf-8

require 'luhn_checksum'
require 'securerandom'

class CreditCardSanitizer

  # https://github.com/Shopify/active_merchant/blob/master/lib/active_merchant/billing/credit_card_methods.rb#L5-L18
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
  EXPIRATION_DATE = /\s(?:0?[1-9]|1[0-2])(?:\/|-)(?:\d{4}|\d{2})(?:\s|$)/
  LINE_NOISE = /[^\w_\n,()\/:]{,5}/
  SCHEME_OR_PLUS = /(\+|(?:[a-zA-Z][\-+.a-zA-Z\d]{,9}):\S+)/
  NUMBERS_WITH_LINE_NOISE = /#{SCHEME_OR_PLUS}?\d(?:#{LINE_NOISE}\d){10,18}/

  attr_reader :replacement_token, :expose_first, :expose_last

  # Create a new CreditCardSanitizer
  #
  # Options
  #
  # :replacement_character - the character that will replace digits for redaction.
  # :expose_first - the number of leading digits that will not be redacted.
  # :expose_last - the number of ending digits that will not be redacted.
  #
  def initialize(options = {})
    @replacement_token = options.fetch(:replacement_token, '▇')
    @expose_first = options.fetch(:expose_first, 6)
    @expose_last = options.fetch(:expose_last, 4)
  end

  # Finds credit card numbers and redacts digits from them
  #
  # text - the text containing potential credit card numbers
  #
  # Examples
  #
  #   # If the text contains a credit card number:
  #   sanitize!("4111 1111 1111 1111")
  #   #=> "4111 11▇▇ ▇▇▇▇ 1111"
  #
  #   # If the text does not contain a credit card number:
  #   sanitize!("I want all your credit card numbers!")
  #   #=> nil
  #
  # Returns a String of the redacted text if a credit card number was detected.
  # Returns nil if no credit card numbers were detected.
  def sanitize!(text)
    text.scrub!('�')

    redacted = nil

    without_expiration(text) do
      text.gsub!(NUMBERS_WITH_LINE_NOISE) do |match|
        next match if $1
        @numbers = match.tr('^0-9', '')

        if valid_numbers?
          redacted = true
          redact_numbers!(match)
        end

        match
      end
    end

    redacted && text
  end

  # A proc that can be used
  #
  # text - the text containing potential credit card numbers
  #
  # Examples
  #
  #  Rails.app.config.filter_parameters = [:password, CreditCardSanitizer.parameter_filter]
  #
  #  env = {
  #    "action_dispatch.request.parameters" => {"credit_card_number" => "4111 1111 1111 1111", "password" => "123"},
  #    "action_dispatch.parameter_filter" => Rails.app.config.filter_parameters
  #  }
  #
  #  >> ActionDispatch::Request.new(env).filtered_parameters
  #  => {"credit_card_number" => "4111 11▇▇ ▇▇▇▇ 1111", "password" => "[FILTERED]"}
  #
  # Returns a Proc that takes the key/value of the request parameter.
  def self.parameter_filter
    Proc.new { |_, value| new.sanitize!(value) if value.is_a?(String) }
  end

  private

  def valid_prefix?(numbers)
    !!(numbers =~ VALID_COMPANY_PREFIXES)
  end

  def valid_numbers?
    LuhnChecksum.valid?(@numbers) && valid_prefix?(@numbers)
  end

  def redact_numbers!(text)
    text.gsub!(/\d/).with_index do |number, digit_index|
      if within_redaction_range?(digit_index)
        replacement_token
      else
        number
      end
    end
  end

  def within_redaction_range?(digit_index)
    digit_index >= expose_first && digit_index < @numbers.size - expose_last
  end

  def without_expiration(text)
    expiration_date_boundary = SecureRandom.hex.tr('0123456789', 'ABCDEFGHIJ')
    text.gsub!(EXPIRATION_DATE) { |expiration_date| "#{expiration_date_boundary}#{expiration_date}#{expiration_date_boundary}"  }
    yield
    text.gsub!(expiration_date_boundary, '')
  end
end
