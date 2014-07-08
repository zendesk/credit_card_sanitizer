require 'luhn_checksum'

class CreditCardSanitizer

  NUMBERS_WITH_LINE_NOISE = /(
    \d       # starts with a number
    [\d|\W]+ # number or non-word character
    \d       # ends with a number
   )/x

   def initialize(replacement_token='X', replace_first=6, replace_last=4)
     @replacement_token = replacement_token
     @replace_first = replace_first
     @replace_last = replace_last
   end

   def sanitize!(text)
     replaced = false

     text.gsub!(NUMBERS_WITH_LINE_NOISE) do |match|
       numbers = match.gsub(/\D/, '')

       if valid_length?(numbers) && LuhnChecksum.valid?(numbers)
         replaced = true
         replace_numbers!(match, numbers)
       end

       match
     end

     replaced ? text : nil
   end

  # From https://en.wikipedia.org/wiki/Primary_Account_Number#Issuer_identification_number_.28IIN.29
   def valid_length?(numbers)
    numbers.size.between?(13,19)
   end

   def replace_numbers!(text, numbers)
     # Leave the first @replace_first and last @replace_last numbers visible
     replacement_limit = numbers.size - @replace_last
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
end
