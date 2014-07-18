[![Build Status](https://travis-ci.org/zendesk/credit_card_sanitizer.png)](https://travis-ci.org/zendesk/credit_card_sanitizer)

credit_card_sanitizer
=====================

Users sometimes enter sensitive information such as credit card numbers into Web sites where they shouldn't. 
If a credit card number is entered into a form on a Web site, it may get stored in a database and logged
to log files. This is probably undesirable for the business running the Web site. Once the credit card
number is stored in multiple places on your systems, it can be hard to get rid of it.

Removal of credit card information is an important element in [PCI compliance](https://www.pcisecuritystandards.org).

`credit_card_sanitizer` scans text for credit card numbers by applying the Luhn checksum algorithm
implemented by the [luhn_checksum](https://github.com/eac/luhn_checksum) gem. Numbers in text that appear to be valid
credit card numbers are "sanitized" by replacing some or all of the digits with a replacement character such as `X`.

Example:

```Ruby
a = "Hello my card is 12 345123 451234 8 maybe you should not store that in your database!"
CreditCardSanitizer.new('X').sanitizer.sanitize!(a)
a == "Hello my card is XX XXXXX XXX234 8 maybe you should not store that in your database!"
```

### Configuration

`replacement_token`: The character used to replace digits of the credit number.  The default is `X`.

`replace_first`: The number of leading digits of the credit card number to leave intact. The default is `6`.

`replace_last`: The number of trailing digits of the credit card number to leave intact. The default is `4`.

### Default Replacement Level

The default configuration of `credit_card_sanitizer` leaves the first 6 and last 4 digits of credit card
numbers intact, and replaces all the digits in between with `replacement_token`.

This level of sanitization is sufficient for PCI compliance. At this level of removal, the resulting data
is no longer considered credit card data under the PCI standard.

### Line noise

`credit_card_sanitizer` allows for "line noise" between the digits of a credit card number.  Line noise
is any sequence of non-numeric characters. For example, all of the following numbers will be sanitized
successfully:

```1234512345123483
1234-5123-4512-3483
1234 5123 4512 3483
1/2 3-4 **5123** 451!2348@3
```

### Card number length

Numbers are sanitized if they are a minimum of 12 digits long and a maximum of 19 digits long.
Most bank card numbers are within this length range. (https://en.wikipedia.org/wiki/Primary_Account_Number)

### Rails filtering parameters

```Ruby
Rails.app.config.filter_parameters = [:password, CreditCardSanitizer.parameter_filter]

env = {
  "action_dispatch.request.parameters" => {"credit_card_number" => "123 4512 3451 2348", "password" => "123"},
  "action_dispatch.parameter_filter" => Rails.app.config.filter_parameters
}

>> ActionDispatch::Request.new(env).filtered_parameters
=> {"credit_card_number" => "123 451X XXXX 2348", "password" => "[FILTERED]"}
```

### License

Apache License 2.0
