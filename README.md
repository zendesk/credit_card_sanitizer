[![Build Status](https://travis-ci.org/zendesk/credit_card_sanitizer.png)](https://travis-ci.org/zendesk/credit_card_sanitizer)

credit_card_sanitizer
=====================

Users sometimes enter sensitive information such as credit card numbers into Web sites where they shouldn't. 
If a credit card number is entered into a form on a Web site, it may get stored in a database and logged
to log files. This is probably undesirable for the business running the Web site. Once the credit card
number is stored in multiple places on your systems, it can be hard to get rid of it.

Removal of credit card information is an important element in [PCI compliance](https://www.pcisecuritystandards.org).

`credit_card_sanitizer` scans text for credit card numbers by applying the Luhn checksum algorithm,
implemented by the [luhn_checksum](https://github.com/zendesk/luhn_checksum) gem, and by validating that the
number matches a known credit card number pattern. Numbers in text that appear to be valid credit card numbers
are "sanitized" by replacing some or all of the digits with a replacement character.

Example:

```ruby
text = "Hello my card is 4111 1111 1111 1111  maybe you should not store that in your database!"
CreditCardSanitizer.new(replacement_character: '▇').sanitizer.sanitize!(text)
text == "Hello my card is 4111 11▇▇ ▇▇▇▇ 1111 maybe you should not store that in your database!"
```

### Configuration

Name                       | Description
-------------------------- | -----------
`replacement_token`        | The character used to replace digits of the credit number.  The default is `▇`.
`expose_first`             | The number of leading digits of the credit card number to leave intact. The default is `6`.
`expose_last`              | The number of trailing digits of the credit card number to leave intact. The default is `4`.
`use_groupings`            | Use known card number groupings to reduce false positives. The default is `false`.
`exclude_tracking_numbers` | Identify shipping tracking numbers and don't redact them. The default is `false`.

### Default Replacement Level

The default configuration of `credit_card_sanitizer` leaves the first 6 and last 4 digits of credit card
numbers intact, and replaces all the digits in between with `replacement_token`.

This level of sanitization is sufficient for PCI compliance. At this level of removal, the resulting data
is no longer considered credit card data under the PCI standard.

### Line noise

`credit_card_sanitizer` allows for "line noise" between the digits of a credit card number.  Line noise
is a sequence of non-numeric characters. For example, all of the following numbers will be sanitized
successfully:

```
4111 1111 1111 1111
4111-1111-1111-1111
4111*1111***1111*****1111
```

We occasionally tweak the regular expression that defines line noise to reduce the rate of false positives.

### Card number length and valid prefixes

Numbers are sanitized if they are a minimum of 12 digits long and a maximum of 19 digits long, and have a proper
prefix that matches an IIN range of an issuing network like Visa or MasterCard
(https://en.wikipedia.org/wiki/Primary_Account_Number). We have borrowed the regex used in [active_merchant](https://github.com/Shopify/active_merchant/blob/master/lib/active_merchant/billing/credit_card_methods.rb#L5-L18)
to validate these prefixes.

### Card number groupings

Some false positives are inevitable when using this gem, and they can be a nuisance.

To reduce the false positive rate, you can specify `use_groupings: true` when configuring the sanitizer. This causes
the sanitizer to pay attention to the groupings of numbers as it scans them, only sanitizing numbers that

* have a valid Luhn checksum
* match a pattern for a known credit card type
* are either a single contiguous string of digits, or digits in groups matching that known credit card type

Example: Visa cards are 4 groups of 4 digits, `XXXX XXXX XXXX XXXX`. `4111 1111 1111 1111` is a number that matches
the Visa pattern (starts with `4`) and passes Luhn checksum.

With `use_groupings: true`, the sanitizer would sanitize `4111111111111111` and `4111 1111 1111 1111` but not
`41 11 11 11 11 11 11 11` or `41111111 11111111`.

With `use_groupings: false`, the sanitizer would sanitize all of the above strings.

### Exclude Tracking Numbers

Occasionally, a number will match a known credit card pattern and pass Luhn checksum, but will actually
be a shipping company tracking number, such as a FedEx tracking number.

The `exclude_tracking_numbers` option runs candidate numbers about to be redacted through the
[tracking_number gem](https://github.com/jkeen/tracking_number) by Jeff Keen.

Turning on this option reduces the likelihood of a tracking number being identified as a false positive
and redacted. However, it runs the risk of an actual credit card number being incorrectly identified as
a shipping tracking number, and not redacted.

### Rails filtering parameters

The `#parameter_filter` is meant to be used with ActionDispatch to automatically redact parameters that are to
be logged before getting flushed.

```Ruby
Rails.app.config.filter_parameters = [:password, CreditCardSanitizer.parameter_filter]

env = {
  "action_dispatch.request.parameters" => {"credit_card_number" => "4111 1111 1111 1111", "password" => "123"},
  "action_dispatch.parameter_filter" => Rails.app.config.filter_parameters
}

>> ActionDispatch::Request.new(env).filtered_parameters
=> {"credit_card_number" => "4111 11▇▇ ▇▇▇▇ 1111", "password" => "[FILTERED]"}
```

### Authors

[Victor Kmita](https://github.com/vkmita)

[Gary Grossman](https://github.com/ggrossman)

[Eric Chapweske](https://github.com/eac)

### License

Apache License 2.0
