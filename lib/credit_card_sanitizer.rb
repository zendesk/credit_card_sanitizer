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
    puts "CreditCardSanitizer#sanitize! - Starting method with text: #{text.inspect}, options: #{options.inspect}"
    options = @settings.merge(options)
    puts "CreditCardSanitizer#sanitize! - Merged options: #{options.inspect}, @settings: #{@settings.inspect}"

    text = text.dup if text.frozen?
    puts "CreditCardSanitizer#sanitize! - After dup check, text: #{text.inspect}, text.frozen?: #{text.frozen?}"
    text.force_encoding(Encoding::UTF_8)
    puts "CreditCardSanitizer#sanitize! - After force_encoding UTF_8, text: #{text.inspect}, encoding: #{text.encoding}"
    text.scrub!("�")
    puts "CreditCardSanitizer#sanitize! - After scrub!, text: #{text.inspect}"
    changes = nil
    puts "CreditCardSanitizer#sanitize! - Initialized changes: #{changes.inspect}"

    without_expiration(text) do
      puts "CreditCardSanitizer#sanitize! - Inside without_expiration block, text: #{text.inspect}"
      text.gsub!(NUMBERS_WITH_LINE_NOISE) do |match|
        puts "CreditCardSanitizer#sanitize! - gsub! block with match: #{match.inspect}, $1: #{$1.inspect}"
        next match if $1

        puts "CreditCardSanitizer#sanitize! - Processing match (not skipping), match: #{match.inspect}"
        candidate = Candidate.new(match, match.tr("^0-9", ""), $`, $')
        puts "CreditCardSanitizer#sanitize! - Created candidate: #{candidate.inspect}, numbers: #{candidate.numbers.inspect}, prefix: #{candidate.prefix.inspect}, postfix: #{candidate.postfix.inspect}"

        valid_context_result = valid_context?(candidate, options)
        valid_numbers_result = valid_numbers?(candidate, options)
        puts "CreditCardSanitizer#sanitize! - Validation results - valid_context?: #{valid_context_result}, valid_numbers?: #{valid_numbers_result}"

        if valid_context_result && valid_numbers_result
          puts "CreditCardSanitizer#sanitize! - Both validations passed, calling redact_numbers"
          redact_numbers(candidate, options).tap do |redacted_text|
            puts "CreditCardSanitizer#sanitize! - redact_numbers returned: #{redacted_text.inspect}"
            changes ||= []
            puts "CreditCardSanitizer#sanitize! - After changes ||= [], changes: #{changes.inspect}"
            changes << [candidate.text, redacted_text]
            puts "CreditCardSanitizer#sanitize! - After adding to changes array, changes: #{changes.inspect}"
          end
        else
          puts "CreditCardSanitizer#sanitize! - Validation failed, returning original match: #{match.inspect}"
          match
        end
      end
      puts "CreditCardSanitizer#sanitize! - After gsub! completed, text: #{text.inspect}"
    end
    puts "CreditCardSanitizer#sanitize! - After without_expiration block, text: #{text.inspect}, changes: #{changes.inspect}"

    if options[:return_changes]
      puts "CreditCardSanitizer#sanitize! - return_changes is true, returning changes: #{changes.inspect}"
      changes
    else
      result = changes && text
      puts "CreditCardSanitizer#sanitize! - return_changes is false, returning result: #{result.inspect} (changes: #{changes.inspect}, text: #{text.inspect})"
      result
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
    puts "CreditCardSanitizer#valid_company_prefix? - Input numbers: #{numbers.inspect}"
    result = !!(numbers =~ VALID_COMPANY_PREFIXES)
    puts "CreditCardSanitizer#valid_company_prefix? - Result: #{result}, pattern match: #{numbers =~ VALID_COMPANY_PREFIXES}"
    result
  end

  def find_company(numbers)
    puts "CreditCardSanitizer#find_company - Input numbers: #{numbers.inspect}"
    CARD_COMPANIES.each do |company, pattern|
      puts "CreditCardSanitizer#find_company - Checking company #{company.inspect} with pattern: #{pattern.inspect}"
      if pattern.match?(numbers)
        puts "CreditCardSanitizer#find_company - Found match for company: #{company.inspect}"
        return company
      end
    end
    puts "CreditCardSanitizer#find_company - No company match found, returning nil"
    nil
  end

  def valid_grouping?(candidate, options)
    puts "CreditCardSanitizer#valid_grouping? - Input candidate.text: #{candidate.text.inspect}, candidate.numbers: #{candidate.numbers.inspect}, options[:use_groupings]: #{options[:use_groupings]}"

    if options[:use_groupings]
      puts "CreditCardSanitizer#valid_grouping? - use_groupings is enabled, checking company and groupings"
      if (company = find_company(candidate.numbers))
        puts "CreditCardSanitizer#valid_grouping? - Found company: #{company.inspect}"
        groupings = candidate.text.split(NONEMPTY_LINE_NOISE).map(&:length)
        puts "CreditCardSanitizer#valid_grouping? - Extracted groupings: #{groupings.inspect} (split by NONEMPTY_LINE_NOISE)"

        if groupings.length == 1
          puts "CreditCardSanitizer#valid_grouping? - Single grouping detected, returning true"
          return true
        end

        if (company_groupings = CARD_NUMBER_GROUPINGS[company])
          puts "CreditCardSanitizer#valid_grouping? - Company groupings available: #{company_groupings.inspect}"
          company_groupings.each do |company_grouping|
            puts "CreditCardSanitizer#valid_grouping? - Checking company_grouping: #{company_grouping.inspect} against groupings.take(#{company_grouping.length}): #{groupings.take(company_grouping.length).inspect}"
            if groupings.take(company_grouping.length) == company_grouping
              puts "CreditCardSanitizer#valid_grouping? - Grouping match found, returning true"
              return true
            end
          end
          puts "CreditCardSanitizer#valid_grouping? - No matching company groupings found"
        else
          puts "CreditCardSanitizer#valid_grouping? - No company groupings available for company: #{company.inspect}"
        end
      else
        puts "CreditCardSanitizer#valid_grouping? - No company found"
      end
      puts "CreditCardSanitizer#valid_grouping? - use_groupings enabled but validation failed, returning false"
      false
    else
      puts "CreditCardSanitizer#valid_grouping? - use_groupings is disabled, returning true"
      true
    end
  end

  def tracking?(candidate, options)
    puts "CreditCardSanitizer#tracking? - Input candidate.numbers: #{candidate.numbers.inspect}, options[:exclude_tracking_numbers]: #{options[:exclude_tracking_numbers]}"

    if options[:exclude_tracking_numbers]
      puts "CreditCardSanitizer#tracking? - exclude_tracking_numbers is enabled, checking if number is a tracking number"
      tracking_number = TrackingNumber.new(candidate.numbers)
      is_valid_tracking = tracking_number.valid?
      puts "CreditCardSanitizer#tracking? - TrackingNumber.valid? result: #{is_valid_tracking}"
      is_valid_tracking
    else
      puts "CreditCardSanitizer#tracking? - exclude_tracking_numbers is disabled, returning false"
      false
    end
  end

  def valid_numbers?(candidate, options)
    puts "CreditCardSanitizer#valid_numbers? - Input candidate.numbers: #{candidate.numbers.inspect}"

    luhn_valid = LuhnChecksum.valid?(candidate.numbers)
    puts "CreditCardSanitizer#valid_numbers? - LuhnChecksum.valid? result: #{luhn_valid}"

    company_prefix_valid = valid_company_prefix?(candidate.numbers)
    puts "CreditCardSanitizer#valid_numbers? - valid_company_prefix? result: #{company_prefix_valid}"

    grouping_valid = valid_grouping?(candidate, options)
    puts "CreditCardSanitizer#valid_numbers? - valid_grouping? result: #{grouping_valid}"

    tracking_result = tracking?(candidate, options)
    puts "CreditCardSanitizer#valid_numbers? - tracking? result: #{tracking_result}"

    final_result = luhn_valid && company_prefix_valid && grouping_valid && !tracking_result
    puts "CreditCardSanitizer#valid_numbers? - Final result: #{final_result} (luhn: #{luhn_valid}, company_prefix: #{company_prefix_valid}, grouping: #{grouping_valid}, !tracking: #{!tracking_result})"

    final_result
  end

  def valid_context?(candidate, options)
    puts "CreditCardSanitizer#valid_context? - Input candidate.prefix: #{candidate.prefix.inspect}, candidate.postfix: #{candidate.postfix.inspect}, options[:parse_flanking]: #{options[:parse_flanking]}"

    if options[:parse_flanking]
      puts "CreditCardSanitizer#valid_context? - parse_flanking is enabled, checking prefix and postfix"
      prefix_valid = valid_prefix?(candidate.prefix)
      puts "CreditCardSanitizer#valid_context? - valid_prefix? result: #{prefix_valid}"

      postfix_valid = valid_postfix?(candidate.postfix)
      puts "CreditCardSanitizer#valid_context? - valid_postfix? result: #{postfix_valid}"

      result = prefix_valid && postfix_valid
      puts "CreditCardSanitizer#valid_context? - Final result: #{result} (prefix_valid: #{prefix_valid}, postfix_valid: #{postfix_valid})"
      result
    else
      puts "CreditCardSanitizer#valid_context? - parse_flanking is disabled, returning true"
      true
    end
  end

  def valid_prefix?(prefix)
    puts "CreditCardSanitizer#valid_prefix? - Input prefix: #{prefix.inspect}"

    if prefix.nil?
      puts "CreditCardSanitizer#valid_prefix? - Prefix is nil, returning true"
      return true
    end

    accepted_prefix_match = ACCEPTED_PREFIX.match(prefix)
    puts "CreditCardSanitizer#valid_prefix? - ACCEPTED_PREFIX pattern match result: #{accepted_prefix_match.inspect}"

    if accepted_prefix_match
      puts "CreditCardSanitizer#valid_prefix? - Prefix matches ACCEPTED_PREFIX pattern, returning true"
      return true
    end

    last_char = prefix[-1]
    alphanumeric_match = ALPHANUMERIC.match(last_char)
    puts "CreditCardSanitizer#valid_prefix? - Last character: #{last_char.inspect}, ALPHANUMERIC match: #{alphanumeric_match.inspect}"

    result = !alphanumeric_match
    puts "CreditCardSanitizer#valid_prefix? - Final result: #{result} (last char is NOT alphanumeric)"
    result
  end

  def valid_postfix?(postfix)
    puts "CreditCardSanitizer#valid_postfix? - Input postfix: #{postfix.inspect}"

    if postfix.nil?
      puts "CreditCardSanitizer#valid_postfix? - Postfix is nil, returning true"
      return true
    end

    accepted_postfix_match = ACCEPTED_POSTFIX.match(postfix)
    puts "CreditCardSanitizer#valid_postfix? - ACCEPTED_POSTFIX pattern match result: #{accepted_postfix_match.inspect}"

    if accepted_postfix_match
      puts "CreditCardSanitizer#valid_postfix? - Postfix matches ACCEPTED_POSTFIX pattern, returning true"
      return true
    end

    first_char = postfix[0]
    alphanumeric_match = ALPHANUMERIC.match(first_char)
    puts "CreditCardSanitizer#valid_postfix? - First character: #{first_char.inspect}, ALPHANUMERIC match: #{alphanumeric_match.inspect}"

    result = !alphanumeric_match
    puts "CreditCardSanitizer#valid_postfix? - Final result: #{result} (first char is NOT alphanumeric)"
    result
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
