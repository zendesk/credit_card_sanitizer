# encoding: utf-8
require File.expand_path '../helper', __FILE__

class CreditCardSanitizerTest < MiniTest::Test
  describe CreditCardSanitizer do
    before do
      @sanitizer = CreditCardSanitizer.new
    end

    describe "#sanitize!" do
      it "sanitizes text keeping first 6 and last 4 digits by default" do
        assert_equal 'Hello 4111 11▇▇ ▇▇▇▇ 1111 there',     @sanitizer.sanitize!('Hello 4111 1111 1111 1111 there')
        assert_equal 'Hello 4111 11▇▇ ▇▇▇▇ 1111 z 3 there', @sanitizer.sanitize!('Hello 4111 1111 1111 1111 z 3 there')
        assert_equal 'Hello 4111-11▇▇-▇▇▇▇-1111 there', @sanitizer.sanitize!('Hello 4111-1111-1111-1111 there')
        assert_equal 'Hello 411111▇▇▇▇▇▇1111 there', @sanitizer.sanitize!('Hello 4111111111111111 there')
      end

      it "sanitizes large amount of Japanese text" do
        path = File.expand_path('../samples/japanese_text.txt', __FILE__)
        text = File.open(path).read
        @sanitizer.sanitize!(text)
      end

      it "sanitizes text with other numbers in it" do
        assert_equal 'Hello, I ordered 6 items. My cc is 411111▇▇▇▇▇▇1111', @sanitizer.sanitize!('Hello, I ordered 6 items. My cc is 4111111111111111')
        assert_equal 'Hello 411111▇▇▇▇▇▇1111 expiration 12/16 there', @sanitizer.sanitize!('Hello 4111111111111111 expiration 12/16 there')
      end

      it "sanitizes text with multiple credit card numbers in it" do
        assert_equal 'My cc is 411111▇▇▇▇▇▇1111, I repeat, 411111▇▇▇▇▇▇1111', @sanitizer.sanitize!('My cc is 4111111111111111, I repeat, 4111111111111111')
      end

      it "has a configurable replacement character" do
        sanitizer = CreditCardSanitizer.new(replacement_token: '*')
        assert_equal 'Hello 4111 11**** **111 1 there', sanitizer.sanitize!('Hello 4111 111111 11111 1 there')
      end

      it "has configurable replacement digits" do
        @sanitizer = CreditCardSanitizer.new(expose_first: 0, expose_last: 4)
        assert_equal 'Hello ▇▇▇▇ ▇▇▇▇ ▇▇▇▇ 1111 there',     @sanitizer.sanitize!('Hello 4111 1111 1111 1111 there')
        assert_equal 'Hello ▇▇▇▇ ▇▇▇▇ ▇▇▇▇ 1111 z 3 there', @sanitizer.sanitize!('Hello 4111 1111 1111 1111 z 3 there')
        assert_equal 'Hello ▇▇▇▇-▇▇▇▇-▇▇▇▇-1111 there', @sanitizer.sanitize!('Hello 4111-1111-1111-1111 there')
        assert_equal 'Hello ▇▇▇▇▇▇▇▇▇▇▇▇1111 there', @sanitizer.sanitize!('Hello 4111111111111111 there')
      end

      it "does not sanitize invalid credit card numbers" do
        invalid_luhn = 'Hello 12 345123 451234 81 there'
        assert_nil @sanitizer.sanitize!(invalid_luhn)
        assert_equal 'Hello 12 345123 451234 81 there', invalid_luhn

        too_short = 'Hello 49 9273 987 16 there'
        assert_nil @sanitizer.sanitize!(too_short)
      end

      it "doesn't fail if the text contains invalid utf-8 characters" do
        if ''.respond_to?(:encoding)
          invalid_characters = "你好 4111 1111 1111 1111 \255there"
          assert_equal "你好 4111 11▇▇ ▇▇▇▇ 1111 \ufffdthere", @sanitizer.sanitize!(invalid_characters)
        end
      end

      it "sanitizes credit card numbers separated by newlines" do
        assert_equal "4111 11▇▇ ▇▇▇▇ 1111 \n 4111 11▇▇ ▇▇▇▇ 1111", @sanitizer.sanitize!("4111 1111 1111 1111 \n 4111 1111 1111 1111")
      end

      it "does not sanitize a credit card number separated by newlines" do
        assert_nil @sanitizer.sanitize!("4111\n1111\n1111\n1111")
      end

      it "does not sanitize a credit card number separated by commas" do
        assert_nil @sanitizer.sanitize!("4111,1111,1111,1111")
      end

      it "does not sanitize credit card numbers separated by parenthesis" do
        assert_nil @sanitizer.sanitize!("(411)111-111111-1111")
      end

      it "does not sanitize credit card numbers separated by forward slashes" do
        assert_nil @sanitizer.sanitize!("4111/1111/1111/1111")
      end

      it "does not sanitize credit card numbers separated by colons" do
        assert_nil @sanitizer.sanitize!("4111:1111:1111:1111")
      end

      it "does not sanitize credit card numbers that are part of a url" do
        assert_nil @sanitizer.sanitize!("http://support.zendesk.com/tickets/4111111111111111")
        assert_nil @sanitizer.sanitize!("blah blah  http://support.zendesk.com/tickets/4111111111111111.json")
        assert_nil @sanitizer.sanitize!("\"http://support.zendesk.com/tickets/4111111111111111\"")
        assert_nil @sanitizer.sanitize!("(http://support.zendesk.com/tickets/4111111111111111)")
      end

      it "does not mutate the text when there is a url" do
        url = "http://support.zendesk.com/tickets/4111111111111111"
        assert_nil @sanitizer.sanitize!(url)
        assert_equal "http://support.zendesk.com/tickets/4111111111111111", url
      end

      it "should sanitize a credit card number with an expiration date" do
        assert_equal "4111 11▇▇ ▇▇▇▇ 1111 03/2015", @sanitizer.sanitize!("4111 1111 1111 1111 03/2015")
        assert_equal "4111 11▇▇ ▇▇▇▇ 1111 03/15", @sanitizer.sanitize!("4111 1111 1111 1111 03/15")
        assert_equal "4111 11▇▇ ▇▇▇▇ 1111 3/15", @sanitizer.sanitize!("4111 1111 1111 1111 3/15")
        assert_equal "4111 11▇▇ ▇▇▇▇ 1111 3/2015", @sanitizer.sanitize!("4111 1111 1111 1111 3/2015")
        assert_equal "4111 11▇▇ ▇▇▇▇ 1111 03/2015 asdbhasd", @sanitizer.sanitize!("4111 1111 1111 1111 03/2015 asdbhasd")

        assert_equal "4111 11▇▇ ▇▇▇▇ 1111    03/2015", @sanitizer.sanitize!("4111 1111 1111 1111    03/2015")

        assert_equal "4111 11▇▇ ▇▇▇▇ 1111 03-2015", @sanitizer.sanitize!("4111 1111 1111 1111 03-2015")
        assert_equal "4111 11▇▇ ▇▇▇▇ 1111 03-15", @sanitizer.sanitize!("4111 1111 1111 1111 03-15")
        assert_equal "4111 11▇▇ ▇▇▇▇ 1111 3-15", @sanitizer.sanitize!("4111 1111 1111 1111 3-15")
        assert_equal "4111 11▇▇ ▇▇▇▇ 1111 3-2015", @sanitizer.sanitize!("4111 1111 1111 1111 3-2015")
        assert_equal "4111 11▇▇ ▇▇▇▇ 1111 03-2015 asdbhasd", @sanitizer.sanitize!("4111 1111 1111 1111 03-2015 asdbhasd")
      end
    end

    describe "#parameter_filter" do
      before do
        @proc = CreditCardSanitizer.parameter_filter
      end

      it "returns a proc that will sanitize that will envoke #sanitize on the second parameter" do
        assert_equal 'Hello 4111 11▇▇ ▇▇▇▇ 1111 there', @proc.call(:key, 'Hello 4111 1111 1111 1111 there')
      end

      it "does not blow up on non strings" do
        assert_nil @proc.call(:key, 1)
      end
    end

    describe "#valid_prefix?" do
      it "returns true for dankort" do
        assert @sanitizer.send(:valid_prefix?, '5019717010103742')
      end

      it "returns true for dankort as visa" do
        assert @sanitizer.send(:valid_prefix?, '4571100000000000')
      end

      it "returns true for electron dk as visa" do
        assert @sanitizer.send(:valid_prefix?, '4175001000000000')
      end

      it "returns true for diners club" do
        assert @sanitizer.send(:valid_prefix?, '36148010000000')
      end

      it "returns true for diners club uk" do
        assert @sanitizer.send(:valid_prefix?, '30401000000000')
      end

      it "returns true for maestro dk as maestro" do
        assert @sanitizer.send(:valid_prefix?, '6769271000000000')
      end

      it "returns true for maestro" do
        assert @sanitizer.send(:valid_prefix?, '5020100000000000')
      end

      it "returns true for master cards" do
        assert @sanitizer.send(:valid_prefix?, '6771890000000000')
        assert @sanitizer.send(:valid_prefix?, '5413031000000000')
      end

      it "returns true for forbrugsforeningen cards" do
        assert @sanitizer.send(:valid_prefix?, '6007221000000000')
      end

      it "returns true for full range laser cards" do
        assert @sanitizer.send(:valid_prefix?, '6304985028090561')    #    16 digits
        assert @sanitizer.send(:valid_prefix?, '6706123456789012')    # V2 16 digits
        assert @sanitizer.send(:valid_prefix?, '6709123456789012')    # V3 16 digits
        assert @sanitizer.send(:valid_prefix?, '630498502809056151')  #    18 digits
        assert @sanitizer.send(:valid_prefix?, '6304985028090561515') # 19 digits
        assert @sanitizer.send(:valid_prefix?, '63049850280905615')   # 17 digits
        assert @sanitizer.send(:valid_prefix?, '630498502809056')     # 15 digits
        assert @sanitizer.send(:valid_prefix?, '6706950000000000000') # Alternate format
        assert @sanitizer.send(:valid_prefix?, '677117111234') # Ulster bank (Ireland) with 12 digits
      end

      it "returns full range for maestro cards (12-18)" do
        maestro = '50000000000'

        while maestro.length < 19
          maestro << '0'
          assert @sanitizer.send(:valid_prefix?, maestro)
        end
      end

      it "returns true for discover cards" do
        assert @sanitizer.send(:valid_prefix?, '6011000000000000')
        assert @sanitizer.send(:valid_prefix?, '6500000000000000')
        assert @sanitizer.send(:valid_prefix?, '6221260000000000')
        assert @sanitizer.send(:valid_prefix?, '6450000000000000')
      end

      it "returns true for 16 digit maestro uk" do
        number = '6759000000000000'
        assert_equal 16, number.length
        assert @sanitizer.send(:valid_prefix?, number)
      end

      it "returns true for 18 digit maestro uk" do
        number = '675900000000000000'
        assert_equal 18, number.length
        assert @sanitizer.send(:valid_prefix?, number)
      end

      it "returns true for 19 digit maestro uk" do
        number = '6759000000000000000'
        assert_equal 19, number.length
        assert @sanitizer.send(:valid_prefix?, number)
      end
    end
  end
end
