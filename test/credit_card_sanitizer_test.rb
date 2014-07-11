require_relative 'helper'

class CreditCardSanitizerTest < MiniTest::Test

  describe CreditCardSanitizer do
    before do
      @sanitizer = CreditCardSanitizer.new('X')
    end

    describe "#sanitize!" do
      it "sanitizes text keeping first 6 and last 4 digits by default" do
        assert_equal 'Hello 12 3451XX XXX234 8 there',     @sanitizer.sanitize!('Hello 12 345123 451234 8 there')
        assert_equal 'Hello 12 3451XX XXX234 8 z 3 there', @sanitizer.sanitize!('Hello 12 345123 451234 8 z 3 there')
        assert_equal 'Hello 1234-51XX-XXXX-3483 there', @sanitizer.sanitize!('Hello 1234-5123-4512-3483 there')
        assert_equal 'Hello 123451XXXXXX3483 there', @sanitizer.sanitize!('Hello 1234512345123483 there')
      end

      it "sanitizes text with other numbers in it" do
        assert_equal 'Hello, I ordered 6 items. My cc is 123451XXXXXX3483', @sanitizer.sanitize!('Hello, I ordered 6 items. My cc is 1234512345123483')
        assert_equal 'Hello 123451XXXXXX3483 expiration 12/16 there', @sanitizer.sanitize!('Hello 1234512345123483 expiration 12/16 there')
      end

      it "sanitizes text with multiple credit card numbers in it" do
        assert_equal 'My cc is 123451XXXXXX3483, I repeat, 123451XXXXXX3483', @sanitizer.sanitize!('My cc is 1234512345123483, I repeat, 1234512345123483')
      end

      it "has a configurable replacement character" do
        sanitizer = CreditCardSanitizer.new('*')
        assert_equal 'Hello 12 3451** ***234 8 there', sanitizer.sanitize!('Hello 12 345123 451234 8 there')
      end

      it "has configurable replacement digits" do
        @sanitizer = CreditCardSanitizer.new('X', 0, 4)
        assert_equal 'Hello XX XXXXXX XXX234 8 there',     @sanitizer.sanitize!('Hello 12 345123 451234 8 there')
        assert_equal 'Hello XX XXXXXX XXX234 8 z 3 there', @sanitizer.sanitize!('Hello 12 345123 451234 8 z 3 there')
        assert_equal 'Hello XXXX-XXXX-XXXX-3483 there', @sanitizer.sanitize!('Hello 1234-5123-4512-3483 there')
        assert_equal 'Hello XXXXXXXXXXXX3483 there', @sanitizer.sanitize!('Hello 1234512345123483 there')
      end

      it "does not sanitize invalid credit card numbers" do
        invalid_luhn = 'Hello 12 345123 451234 81 there'
        assert_equal nil, @sanitizer.sanitize!(invalid_luhn)
        assert_equal 'Hello 12 345123 451234 81 there', invalid_luhn

        too_short = 'Hello 49 9273 987 16 there'
        assert_equal nil, @sanitizer.sanitize!(too_short)
      end
    end

    describe "#parameter_filter" do
      before do
        @proc = CreditCardSanitizer.parameter_filter
      end

      it "returns a proc that will sanitize that will envoke #sanitize on the second parameter" do
        assert_equal 'Hello 12 3451XX XXX234 8 there', @proc.call(:key, 'Hello 12 345123 451234 8 there')
      end

      it "does not blow up on non strings" do
        assert_nil @proc.call(:key, 1)
      end
    end
  end
end
