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

       if !too_short?(numbers) && LuhnChecksum.valid?(numbers)
         replaced = true
         replace_numbers!(match, numbers)
       end

       match
     end

     replaced ? text : nil
   end

   def too_short?(numbers)
     13 > numbers.size
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
