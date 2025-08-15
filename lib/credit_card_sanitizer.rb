require "luhn_checksum"
require "securerandom"
require "tracking_number"

class CreditCardSanitizer
  CARD_COMPANIES = {
    "visa" => /^4\d{12}(\d{3})?(\d{3})?$/,
    "master" => /^(5[1-5]\d{4}|677189|222[1-9]\d{2}|22[3-9]\d{3}|2[3-6]\d{4}|27[01]\d{3}|2720\d{2})\d{10}$/,
    "discover" => /^((6011\d{12})|(65[4-9]\d{13})|(64[4-9]\d{13})|(622(?:12[6-9]|1[3-9]\d|[2-8]\d{2}|9[01]\d|92[0-5])\d{10}))$/,
    "american_express" => /^3[47]\d{13}$/,
    "diners_club" => /^3(0[0-5]|[68]\d)\d{11}$/,
    "jcb" => /^35(28|29|[3-8]\d)\d{12}$/,
    "switch" => /^(6759\d{12}(\d{2,3})?|(4903|4905|4911|4936|6333|6759)\d{12}|(4903|4905|4911|4936|6333|6759)\d{14}|(4903|4905|4911|4936|6333|6759)\d{15}|564182\d{10}|564182\d{12}|564182\d{13}|633110\d{10}|633110\d{12}|633110\d{13})$/,
    "solo" => /^(6767\d{12}(\d{2,3})?|6334\d{12}|6334\d{14}|6334\d{15}|6767\d{14}|6767\d{15})$/,
    "dankort" => /^5019\d{12}$/,
    "maestro" => /^(5[06-8]\d{10,17}|6\d\d{10,17}|5018|5020|5038|5893|6304|6759|6761|6762|6763\d{8,15})$/,
    "forbrugsforeningen" => /^600722\d{10}$/,
    "laser" => /^(6304|6706|6709|6771(?!89))(\d{12,15}|\d{8}(\d{4}|\d{6,7})?)$/,
    "bc_global" => /^(6541|6556)\d{12}$/,
    "carte_blanche" => /^389\d{11}$/,
    "insta_payment" => /^63[7-9]\d{13}$/,
    "korean_local" => /^9\d{15}$/,
    "union_pay" => /^62\d{14,17}$/,
    "visa_master" => /^(4\d{12}(\d{3})?|5[1-5]\d{14})$/
  }.freeze

  CARD_NUMBER_GROUPINGS = {
    "visa" => [[4, 4, 4, 4]],
    "master" => [[4, 4, 4, 4]],
    "discover" => [[4, 4, 4, 4]],
    "american_express" => [[4, 6, 5]],
    "diners_club" => [[4, 6, 4]],
    "jcb" => [[4, 4, 4, 4]],
    "switch" => [[4, 4, 4, 4]],
    "solo" => [[4, 4, 4, 4], [4, 4, 4, 4, 2], [4, 4, 4, 4, 3]],
    "dankort" => [[4, 4, 4, 4]],
    "maestro" => [[4], [5], [4, 4, 4, 4], [4, 4, 4, 4, 1], [4, 4, 4, 4, 2], [4, 4, 4, 4, 3]],
    "forbrugsforeningen" => [[4, 4, 4, 4]],
    "laser" => [[4, 4, 4, 4], [4, 4, 4, 4, 1], [4, 4, 4, 4, 2], [4, 4, 4, 4, 3]],
    "bc_global" => [[4, 4, 4, 4]],
    "carte_blanche" => [[4, 6, 4]],
    "insta_payment" => [[4, 4, 4, 4]],
    "korean_local" => [[4, 4, 4, 4]],
    "union_pay" => [[4, 4, 4, 4], [4, 4, 4, 4, 1], [4, 4, 4, 4, 2], [4, 4, 4, 4, 3]],
    "visa_master" => [[4, 4, 4, 4], [4, 4, 4, 4, 3]]
  }.freeze
  
  SAFE_CHAR_LENGTH = 10000

  ACCEPTED_PREFIX = /(?:cc|card|visa|amex)\z/i
  ACCEPTED_POSTFIX = /\Aex/i
  ALPHANUMERIC = /[[:alnum:]]/i
  VALID_COMPANY_PREFIXES = Regexp.union(*CARD_COMPANIES.values)
  EXPIRATION_DATE = /\s(?:0?[1-9]|1[0-2])(?:\/|-)(?:\d{4}|\d{2})(?:\D|$)/
  LINE_NOISE_CHAR = /[^\w\n,()&.\/:;<>]/
  LINE_NOISE = /#{LINE_NOISE_CHAR}{,5}/
  NONEMPTY_LINE_NOISE = /#{LINE_NOISE_CHAR}{1,5}/
  SCHEME_OR_PLUS = /((?:&#43;|\+|\/)|(?:[a-zA-Z][-+.a-zA-Z\d]{,9}):[^\s>]+)/
  NUMBERS_WITH_LINE_NOISE = /#{SCHEME_OR_PLUS}?\d(?:#{LINE_NOISE}\d){10,30}/

  DEFAULT_OPTIONS = {
    replacement_token: "▇",
    expose_first: 6,
    expose_last: 4,
    use_groupings: false,
    exclude_tracking_numbers: false,
    parse_flanking: false
  }.freeze

  attr_reader :settings

  Candidate = Struct.new(:text, :numbers, :prefix, :postfix)

  # Create a new CreditCardSanitizer
  #
  # Options
  #
  # :replacement_character - the character that will replace digits for redaction.
  # :expose_first - the number of leading digits that will not be redacted.
  # :expose_last - the number of ending digits that will not be redacted.
  # :use_groupings - require card number groupings to match to redact.
  # :exclude_tracking_numbers - do not redact valid shipping company tracking numbers.
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
  # If options[:return_changes] is false, returns nil if no redaction happened,
  # else the full text after redaction.
  #
  # If options[:return_changes] is true, returns nil if no redaction happened,
  # else an array of [old_text, new_text] indicating what substrings were redacted.
  def sanitize!(text, options = {})
    return nil if text.lenght > SAFE_CHAR_LENGTH

    options = @settings.merge(options)

    text = text.dup if text.frozen?
    text.force_encoding(Encoding::UTF_8)
    text.scrub!("�")
    changes = nil

    without_expiration(text) do
      text.gsub!(NUMBERS_WITH_LINE_NOISE) do |match|
        next match if $1

        candidate = Candidate.new(match, match.tr("^0-9", ""), $`, $')

        if valid_context?(candidate, options) && valid_numbers?(candidate, options)
          redact_numbers(candidate, options).tap do |redacted_text|
            changes ||= []
            changes << [candidate.text, redacted_text]
          end
        else
          match
        end
      end
    end

    if options[:return_changes]
      changes
    else
      changes && text
    end
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
    proc { |_, value| new(options).sanitize!(value) if value.is_a?(String) }
  end

  private

  def valid_company_prefix?(numbers)
    !!(numbers =~ VALID_COMPANY_PREFIXES)
  end

  def find_company(numbers)
    CARD_COMPANIES.each do |company, pattern|
      return company if pattern.match?(numbers)
    end
  end

  def valid_grouping?(candidate, options)
    if options[:use_groupings]
      if (company = find_company(candidate.numbers))
        groupings = candidate.text.split(NONEMPTY_LINE_NOISE).map(&:length)
        return true if groupings.length == 1
        if (company_groupings = CARD_NUMBER_GROUPINGS[company])
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

  def tracking?(candidate, options)
    options[:exclude_tracking_numbers] && TrackingNumber.new(candidate.numbers).valid?
  end

  def valid_numbers?(candidate, options)
    LuhnChecksum.valid?(candidate.numbers) && valid_company_prefix?(candidate.numbers) && valid_grouping?(candidate, options) && !tracking?(candidate, options)
  end

  def valid_context?(candidate, options)
    !options[:parse_flanking] || valid_prefix?(candidate.prefix) && valid_postfix?(candidate.postfix)
  end

  def valid_prefix?(prefix)
    return true if prefix.nil? || !!ACCEPTED_PREFIX.match(prefix)
    !ALPHANUMERIC.match(prefix[-1])
  end

  def valid_postfix?(postfix)
    return true if postfix.nil? || !!ACCEPTED_POSTFIX.match(postfix)
    !ALPHANUMERIC.match(postfix[0])
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
    expiration_date_boundary = SecureRandom.hex.tr("0123456789", "ABCDEFGHIJ")
    text.gsub!(EXPIRATION_DATE) do |expiration_date|
      match = expiration_date.match(/(?<whitespace>\s*)(?<rest>.*)/m)
      "#{match[:whitespace]}#{expiration_date_boundary}#{match[:rest]}#{expiration_date_boundary}"
    end
    yield
    text.gsub!(expiration_date_boundary, "")
  end
end
