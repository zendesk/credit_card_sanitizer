require_relative 'helper'

class CreditCardSanitizerTest < MiniTest::Test

  describe "Credit card sanitizer" do
    before do
      @sanitizer = CreditCardSanitizer.new('X')
    end

    it "sanitizes text" do
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

    it "has configurable replacement characters" do
      sanitizer = CreditCardSanitizer.new('*')
      assert_equal 'Hello 12 3451** ***234 8 there', sanitizer.sanitize!('Hello 12 345123 451234 8 there')
    end

    it "does not sanitize invalid credit card numbers" do
      invalid_luhn = 'Hello 12 345123 451234 81 there'
      assert_equal nil, @sanitizer.sanitize!(invalid_luhn)
      assert_equal 'Hello 12 345123 451234 81 there', invalid_luhn

      too_short = 'Hello 49 9273 987 16 there'
      assert_equal nil, @sanitizer.sanitize!(too_short)
    end

  end

  describe "Credit card sanitizer replacing only last 4 digits" do
    before do
      @sanitizer = CreditCardSanitizer.new('X', replace_first=0, replace_last=4)
    end

    it "sanitizes text" do
      assert_equal 'Hello XX XXXXXX XXX234 8 there',     @sanitizer.sanitize!('Hello 12 345123 451234 8 there')
      assert_equal 'Hello XX XXXXXX XXX234 8 z 3 there', @sanitizer.sanitize!('Hello 12 345123 451234 8 z 3 there')
      assert_equal 'Hello XXXX-XXXX-XXXX-3483 there', @sanitizer.sanitize!('Hello 1234-5123-4512-3483 there')
      assert_equal 'Hello XXXXXXXXXXXX3483 there', @sanitizer.sanitize!('Hello 1234512345123483 there')
    end

    it "sanitizes text with other numbers in it" do
      assert_equal 'Hello, I ordered 6 items. My cc is XXXXXXXXXXXX3483', @sanitizer.sanitize!('Hello, I ordered 6 items. My cc is 1234512345123483')
      assert_equal 'Hello XXXXXXXXXXXX3483 expiration 12/16 there', @sanitizer.sanitize!('Hello 1234512345123483 expiration 12/16 there')
    end

    it "sanitizes text with multiple credit card numbers in it" do
      assert_equal 'My cc is XXXXXXXXXXXX3483, I repeat, XXXXXXXXXXXX3483', @sanitizer.sanitize!('My cc is 1234512345123483, I repeat, 1234512345123483')
    end
  end

end
