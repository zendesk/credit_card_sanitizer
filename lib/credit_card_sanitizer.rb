# encoding: utf-8

require 'luhn_checksum'
require 'securerandom'
require 'scrub_rb'

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

  CARD_NUMBER_GROUPINGS = {
    'visa'               => [[4, 4, 4, 4]],
    'master'             => [[4, 4, 4, 4]],
    'discover'           => [[4, 4, 4, 4]],
    'american_express'   => [[4, 6, 5]],
    'diners_club'        => [[4, 6, 4]],
    'jcb'                => [[4, 4, 4, 4]],
    'switch'             => [[4, 4, 4, 4]],
    'solo'               => [[4, 4, 4, 4]],
    'dankort'            => [[4, 4, 4, 4]],
    'maestro'            => [[4], [5]],
    'forbrugsforeningen' => [[4, 4, 4, 4]],
    'laser'              => [[4, 4, 4, 4]]
  }

  VALID_COMPANY_PREFIXES = Regexp.union(*CARD_COMPANIES.values)
  EXPIRATION_DATE = /\s(?:0?[1-9]|1[0-2])(?:\/|-)(?:\d{4}|\d{2})(?:\s|$)/
  LINE_NOISE_CHAR = /[^\w_\n,().\/:;<>]/
  LINE_NOISE = /#{LINE_NOISE_CHAR}{,5}/
  NONEMPTY_LINE_NOISE = /#{LINE_NOISE_CHAR}{1,5}/
  SCHEME_OR_PLUS = /((?:&#43;|\+)|(?:[a-zA-Z][\-+.a-zA-Z\d]{,9}):\S+)/
  NUMBERS_WITH_LINE_NOISE = /#{SCHEME_OR_PLUS}?\d(?:#{LINE_NOISE}\d){10,18}/

  DEFAULT_OPTIONS = {
    replacement_token: '▇',
    expose_first: 6,
    expose_last: 4,
    use_groupings: false
  }

  attr_reader :settings

  Candidate = Struct.new(:text, :numbers)

  # Create a new CreditCardSanitizer
  #
  # Options
  #
  # :replacement_character - the character that will replace digits for redaction.
  # :expose_first - the number of leading digits that will not be redacted.
  # :expose_last - the number of ending digits that will not be redacted.
  # :use_groupings - require card number groupings to match to redact.
  #
  def initialize(options = {})
    @settings = DEFAULT_OPTIONS.merge(options)
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
  def sanitize!(text, options = {})
    options = @settings.merge(options)

    text.force_encoding(Encoding::UTF_8)
    text.scrub!('�')

    redacted = nil

    without_expiration(text) do
      text.gsub!(NUMBERS_WITH_LINE_NOISE) do |match|
        next match if $1

        candidate = Candidate.new(match, match.tr('^0-9', ''))

        if valid_numbers?(candidate, options)
          redacted = true
          redact_numbers(candidate, options)
        else
          match
        end
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
  def self.parameter_filter(options = {})
    Proc.new { |_, value| new(options).sanitize!(value) if value.is_a?(String) }
  end

  private

  def valid_prefix?(numbers)
    !!(numbers =~ VALID_COMPANY_PREFIXES)
  end

  def find_company(numbers)
    CARD_COMPANIES.each do |company, pattern|
      return company if numbers =~ pattern
    end
  end

  def valid_grouping?(candidate, options)
    if options[:use_groupings]
      if company = find_company(candidate.numbers)
        groupings = candidate.text.split(NONEMPTY_LINE_NOISE).map(&:length)
        return true if groupings.length == 1
        if company_groupings = CARD_NUMBER_GROUPINGS[company]
          company_groupings.each do |company_grouping|
            return true if groupings.take(company_grouping.length) == company_grouping
          end
        end
      end
      false
    else
      true
    end
  end

  def valid_numbers?(candidate, options)
    LuhnChecksum.valid?(candidate.numbers) && valid_prefix?(candidate.numbers) && valid_grouping?(candidate, options)
  end

  def redact_numbers(candidate, options)
    candidate.text.gsub(/\d/).with_index do |number, digit_index|
      if within_redaction_range?(candidate, digit_index, options)
        options[:replacement_token]
      else
        number
      end
    end
  end

  def within_redaction_range?(candidate, digit_index, options)
    digit_index >= options[:expose_first] && digit_index < candidate.numbers.size - options[:expose_last]
  end

  def without_expiration(text)
    expiration_date_boundary = SecureRandom.hex.tr('0123456789', 'ABCDEFGHIJ')
    text.gsub!(EXPIRATION_DATE) { |expiration_date| "#{expiration_date_boundary}#{expiration_date}#{expiration_date_boundary}"  }
    yield
    text.gsub!(expiration_date_boundary, '')
  end
end
