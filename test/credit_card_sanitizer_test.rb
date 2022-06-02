require_relative 'helper'
require 'luhnacy'
require 'timeout'

SingleCov.covered!

describe CreditCardSanitizer do
  # make Luhnacy produce the same order of numbers every time, but do not influence test ordering
  around do |test|
    begin
      old = srand 1234
      test.call
    ensure
      srand old
    end
  end

  before do
    @sanitizer = CreditCardSanitizer.new(parse_flanking: true)
  end

  describe 'credit card patterns' do
    it 'should match between CARD_NUMBER_GROUPINGS and CARD_COMPANIES' do
      a = CreditCardSanitizer::CARD_COMPANIES.keys
      b = CreditCardSanitizer::CARD_NUMBER_GROUPINGS.keys
      assert_equal [], (a - b) | (b - a)
    end
  end

  describe '#sanitize!' do
    it 'sanitizes text keeping first 6 and last 4 digits by default' do
      assert_equal 'Hello 4111 11▇▇ ▇▇▇▇ 1111 there',     @sanitizer.sanitize!('Hello 4111 1111 1111 1111 there')
      assert_equal 'Hello 4111 11▇▇ ▇▇▇▇ 1111 z 3 there', @sanitizer.sanitize!('Hello 4111 1111 1111 1111 z 3 there')
      assert_equal 'Hello 4111-11▇▇-▇▇▇▇-1111 there', @sanitizer.sanitize!('Hello 4111-1111-1111-1111 there')
      assert_equal 'Hello 411111▇▇▇▇▇▇1111 there', @sanitizer.sanitize!('Hello 4111111111111111 there')
    end

    it 'sanitizes large amount of Japanese text' do
      path = File.expand_path('../samples/japanese_text.txt', __FILE__)
      text = File.open(path).read
      @sanitizer.sanitize!(text)
    end

    it 'sanitizes lots of random Visa cards' do
      10000.times do
        candidate = Luhnacy.generate(16, prefix: '4')
        assert_equal candidate[0..5] + '▇▇▇▇▇▇' + candidate[12..-1], @sanitizer.sanitize!(candidate)
      end
    end

    it 'sanitizes visa cards of various length' do
      assert_equal 'Hello 436548▇▇▇9682 there', @sanitizer.sanitize!("Hello #{Luhnacy.generate(13, prefix: '4')} there")
      assert_equal 'Hello 405096▇▇▇▇▇▇7099 there', @sanitizer.sanitize!("Hello #{Luhnacy.generate(16, prefix: '4')} there")
      assert_equal 'Hello 403231▇▇▇▇▇▇▇▇▇1590 there', @sanitizer.sanitize!("Hello #{Luhnacy.generate(19, prefix: '4')} there")
    end

    it 'sanitizes lots of random MasterCard cards' do
      ['2221', '23', '26', '270', '271', '2720', '51', '52', '53', '54', '55', '677189'].each do |prefix|
        10000.times do
          candidate = Luhnacy.generate(16, prefix: prefix)
          assert_equal candidate[0..5] + '▇▇▇▇▇▇' + candidate[12..-1], @sanitizer.sanitize!(candidate)
        end
      end
    end

    it 'sanitizes text with other numbers in it' do
      assert_equal 'Hello, I ordered 6 items. My cc is 411111▇▇▇▇▇▇1111', @sanitizer.sanitize!('Hello, I ordered 6 items. My cc is 4111111111111111')
      assert_equal 'Hello 411111▇▇▇▇▇▇1111 expiration 12/16 there', @sanitizer.sanitize!('Hello 4111111111111111 expiration 12/16 there')
    end

    it 'sanitizes text with multiple credit card numbers in it' do
      assert_equal 'My cc is 411111▇▇▇▇▇▇1111, I repeat, 411111▇▇▇▇▇▇1111', @sanitizer.sanitize!('My cc is 4111111111111111, I repeat, 4111111111111111')
    end

    it 'finishes in a reasonable amount of time with spacey input' do
      input = 'Hello  0      0      0     14     20      1      1     20     34      9      1      0      0      0      0      0'
      Timeout.timeout(3) do
        assert_nil @sanitizer.sanitize!(input)
      end
    end

    it 'has a configurable replacement character' do
      sanitizer = CreditCardSanitizer.new(replacement_token: '*')
      assert_equal 'Hello 4111 11** **** 1111 there', sanitizer.sanitize!('Hello 4111 1111 1111 1111 there')
    end

    it 'can configure replacement character on a per-call basis' do
      assert_equal 'Hello 4111 11** **** 1111 there', @sanitizer.sanitize!('Hello 4111 1111 1111 1111 there', replacement_token: '*')
    end

    it 'has configurable replacement digits' do
      sanitizer = CreditCardSanitizer.new(expose_first: 0, expose_last: 4)
      assert_equal 'Hello ▇▇▇▇ ▇▇▇▇ ▇▇▇▇ 1111 there', sanitizer.sanitize!('Hello 4111 1111 1111 1111 there')
      assert_equal 'Hello ▇▇▇▇ ▇▇▇▇ ▇▇▇▇ 1111 z 3 there', sanitizer.sanitize!('Hello 4111 1111 1111 1111 z 3 there')
      assert_equal 'Hello ▇▇▇▇-▇▇▇▇-▇▇▇▇-1111 there', sanitizer.sanitize!('Hello 4111-1111-1111-1111 there')
      assert_equal 'Hello ▇▇▇▇▇▇▇▇▇▇▇▇1111 there', sanitizer.sanitize!('Hello 4111111111111111 there')
    end

    it 'does not sanitize invalid credit card numbers' do
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

    it "doesn't fail if text is not utf-8 encoded" do
      ascii_text = '41111111111111112'.force_encoding(Encoding::ASCII)
      assert_nil @sanitizer.sanitize!(ascii_text)
    end

    it 'sanitizes credit card numbers separated by newlines' do
      assert_equal "4111 11▇▇ ▇▇▇▇ 1111 \n 4111 11▇▇ ▇▇▇▇ 1111", @sanitizer.sanitize!("4111 1111 1111 1111 \n 4111 1111 1111 1111")
    end

    it 'sanitizes credit card numbers that are preceded by html tag containing colon' do
      assert_equal '<span style="display:none;">411111▇▇▇▇▇▇1111</span>', @sanitizer.sanitize!('<span style="display:none;">4111111111111111</span>')
    end

    it 'does not sanitize a credit card number separated by newlines' do
      assert_nil @sanitizer.sanitize!("4111\n1111\n1111\n1111")
    end

    it 'does not sanitize a credit card number separated by commas' do
      assert_nil @sanitizer.sanitize!('4111,1111,1111,1111')
    end

    it 'does not sanitize a credit card number separated by periods' do
      assert_nil @sanitizer.sanitize!('4111.1111.1111.1111')
    end

    it 'does not sanitize credit card numbers separated by parentheses' do
      assert_nil @sanitizer.sanitize!('(411)111-111111-1111')
    end

    it 'does not sanitize credit card numbers separated by forward slashes' do
      assert_nil @sanitizer.sanitize!('4111/1111/1111/1111')
    end

    it 'does not sanitize credit card numbers separated by colons' do
      assert_nil @sanitizer.sanitize!('4111:1111:1111:1111')
    end

    it 'does not sanitize credit card numbers that are part of a url' do
      assert_nil @sanitizer.sanitize!('http://support.zendesk.com/tickets/4111111111111111')
      assert_nil @sanitizer.sanitize!('blah blah  http://support.zendesk.com/tickets/4111111111111111.json')
      assert_nil @sanitizer.sanitize!('"http://support.zendesk.com/tickets/4111111111111111"')
      assert_nil @sanitizer.sanitize!('(http://support.zendesk.com/tickets/4111111111111111)')
    end

    it 'does not sanitize credit card numbers that are part of an html tag' do
      assert_nil @sanitizer.sanitize!('<a href="/tickets/40004595">#40004595</a>')
    end

    it 'does not sanitize credit card numbers that start with +' do
      assert_nil @sanitizer.sanitize!('+4111111111111111')
      assert_nil @sanitizer.sanitize!('blah blah  +4111111111111111.json')
      assert_nil @sanitizer.sanitize!('"+4111111111111111"')
      assert_nil @sanitizer.sanitize!('(+4111111111111111)')
    end

    it 'does not sanitize relative URLs containing numbers' do
      assert_nil @sanitizer.sanitize!('/knowledge/articles/4402126792468/en-us')
    end

    it 'does not sanitize relative URLs embedded within HTML text' do
      assert_nil @sanitizer.sanitize!('<div style=\"padding:8px 8px 8px 20px\"><a style=\"vertical-align:middle\" href=\"/knowledge/articles/4402126792468/en-us\">Edit article</a><ul class=\"guide-markup\"><li class=\"guide-markup\">Search the Help Center without leaving the ticket</li><li class=\"guide-markup\">Insert links to relevant Help Center articles in ticket comments</li><li class=\"guide-markup\">Add inline feedback to existing articles that need updates</li><li class=\"guide-markup\">Create new articles while answering tickets using a pre-defined template</li></ul></div>')
    end

    it 'does not sanitize numbers that include a numeric html entity' do
      assert_nil @sanitizer.sanitize!('&#43; 1 936 321 1111')
    end

    it 'does not mutate the text when there is a url' do
      url = 'http://support.zendesk.com/tickets/4111111111111111'
      assert_nil @sanitizer.sanitize!(url)
      assert_equal 'http://support.zendesk.com/tickets/4111111111111111', url
    end

    it 'does not sanitize groups of numbers with & in them such as shipping numbers' do
      assert_nil @sanitizer.sanitize!('Hello 4111 1111&1111 1111 there')
    end

    it 'does not sanitize a valid credit card number followed by additional numbers that invalidate the credit card number' do
      assert_nil @sanitizer.sanitize!('612999921404471347800000')
    end

    it 'should sanitize a credit card number with an expiration date' do
      assert_equal '4111 11▇▇ ▇▇▇▇ 1111 03/2015', @sanitizer.sanitize!('4111 1111 1111 1111 03/2015')
      assert_equal '4111 11▇▇ ▇▇▇▇ 1111 03/15', @sanitizer.sanitize!('4111 1111 1111 1111 03/15')
      assert_equal '4111 11▇▇ ▇▇▇▇ 1111 3/15', @sanitizer.sanitize!('4111 1111 1111 1111 3/15')
      assert_equal '4111 11▇▇ ▇▇▇▇ 1111 3/2015', @sanitizer.sanitize!('4111 1111 1111 1111 3/2015')
      assert_equal '4111 11▇▇ ▇▇▇▇ 1111 03/2015 asdbhasd', @sanitizer.sanitize!('4111 1111 1111 1111 03/2015 asdbhasd')

      assert_equal '4111 11▇▇ ▇▇▇▇ 1111    03/2015', @sanitizer.sanitize!('4111 1111 1111 1111    03/2015')

      assert_equal '4111 11▇▇ ▇▇▇▇ 1111 03-2015', @sanitizer.sanitize!('4111 1111 1111 1111 03-2015')
      assert_equal '4111 11▇▇ ▇▇▇▇ 1111 03-15', @sanitizer.sanitize!('4111 1111 1111 1111 03-15')
      assert_equal '4111 11▇▇ ▇▇▇▇ 1111 3-15', @sanitizer.sanitize!('4111 1111 1111 1111 3-15')
      assert_equal '4111 11▇▇ ▇▇▇▇ 1111 3-2015', @sanitizer.sanitize!('4111 1111 1111 1111 3-2015')
      assert_equal '4111 11▇▇ ▇▇▇▇ 1111 03-2015 asdbhasd', @sanitizer.sanitize!('4111 1111 1111 1111 03-2015 asdbhasd')
    end

    describe 'parse_flanking option' do
      describe 'when false' do
        before do
          @sanitizer = CreditCardSanitizer.new(parse_flanking: false)
        end

        it 'sanitizes credit card number prefixed by CREDIT CARD' do
          assert_equal 'CREDIT CARD4111 11▇▇ ▇▇▇▇ 1111 exp06/17', @sanitizer.sanitize!('CREDIT CARD4111 1111 1111 1111 exp06/17')
        end

        it 'sanitizes credit card number prefixed by cc' do
          assert_equal 'cc4111 11▇▇ ▇▇▇▇ 1111 exp06/17', @sanitizer.sanitize!('cc4111 1111 1111 1111 exp06/17')
        end

        it 'sanitizes credit card numbers followed by exp' do
          assert_equal 'creditcard 4111 11▇▇ ▇▇▇▇ 1111exp06/17', @sanitizer.sanitize!('creditcard 4111 1111 1111 1111exp06/17')
        end

        it 'sanitizes credit card numbers flanked by letters' do
          assert_equal 'a411111▇▇▇▇▇▇1111b', @sanitizer.sanitize!('a4111111111111111b')
        end
      end

      describe 'when true' do
        before do
          @sanitizer = CreditCardSanitizer.new(parse_flanking: true)
        end

        it 'sanitizes credit card number prefixed by CARD' do
          assert_equal 'CREDIT CARD4111 11▇▇ ▇▇▇▇ 1111 exp06/17', @sanitizer.sanitize!('CREDIT CARD4111 1111 1111 1111 exp06/17')
        end

        it 'sanitizes credit card number prefixed by cc' do
          assert_equal 'cc4111 11▇▇ ▇▇▇▇ 1111 exp06/17', @sanitizer.sanitize!('cc4111 1111 1111 1111 exp06/17')
        end

        it 'sanitizes credit card numbers followed by a ex' do
          assert_equal 'creditcard 4111 11▇▇ ▇▇▇▇ 1111exp06/17', @sanitizer.sanitize!('creditcard 4111 1111 1111 1111exp06/17')
        end

        it 'sanitizes numbers followed by a newline, expiry, and another newline' do
          assert_equal "creditcard 4111 11▇▇ ▇▇▇▇ 1111\n06/17\n111", @sanitizer.sanitize!("creditcard 4111 1111 1111 1111\n06/17\n111")
        end

        it 'sanitizes numbers followed by a newline and random string' do
          assert_equal "creditcard 4111 11▇▇ ▇▇▇▇ 1111\nasdfasdf", @sanitizer.sanitize!("creditcard 4111 1111 1111 1111\nasdfasdf")
        end

        it 'does not sanitize credit card numbers flanked by letters' do
          assert_nil @sanitizer.sanitize!('a4111111111111111b')
        end
      end
    end

    describe 'exclude tracking numbers' do
      before do
        @fedex_ccs = generate_fedex_ccs(100)
      end

      describe 'exclude_tracking_numbers is false' do
        before do
          refute @sanitizer.settings[:exclude_tracking_numbers]
        end

        it 'sanitizes credit card numbers which also may be tracking numbers' do
          @fedex_ccs.each do |candidate|
            assert_equal candidate[0..5] + '▇▇▇▇▇' + candidate[11..-1], @sanitizer.sanitize!(candidate)
          end
        end
      end

      describe 'exclude_tracking_numbers is true' do
        before do
          @sanitizer = CreditCardSanitizer.new(exclude_tracking_numbers: true)
        end

        it 'does not sanitize credit card numbers which also may be tracking numbers' do
          @fedex_ccs.each do |candidate|
            assert_nil @sanitizer.sanitize!(candidate)
          end
        end

        it 'still sanitizes lots of random Visa cards' do
          10000.times do
            candidate = Luhnacy.generate(16, prefix: '4')
            assert_equal candidate[0..5] + '▇▇▇▇▇▇' + candidate[12..-1], @sanitizer.sanitize!(candidate)
          end
        end

        it 'still sanitizes lots of random MasterCard cards' do
          ['51', '52', '53', '54', '55', '677189'].each do |prefix|
            10000.times do
              candidate = Luhnacy.generate(16, prefix: prefix)
              assert_equal candidate[0..5] + '▇▇▇▇▇▇' + candidate[12..-1], @sanitizer.sanitize!(candidate)
            end
          end
        end
      end
    end

    describe 'card number grouping' do
      describe 'use_groupings is false' do
        before do
          refute @sanitizer.settings[:use_groupings]
        end

        it 'sanitizes cards grouped any which way' do
          assert_equal 'Hello 4111 11▇▇ ▇▇▇▇ 1111 there', @sanitizer.sanitize!('Hello 4111 1111 1111 1111 there')
          assert_equal 'Hello 41 11 11 ▇▇ ▇▇ ▇▇ 11 11 there', @sanitizer.sanitize!('Hello 41 11 11 11 11 11 11 11 there')
          assert_equal 'Hello 411111▇▇▇▇▇▇1111 there', @sanitizer.sanitize!('Hello 4111111111111111 there')
          assert_equal 'Hello 3782 82▇▇▇▇ ▇0005 there', @sanitizer.sanitize!('Hello 3782 822463 10005 there')
          assert_equal 'Hello 378282▇▇▇▇▇0005 there', @sanitizer.sanitize!('Hello 378282246310005 there')
          assert_equal 'Hello 37 828 2▇▇▇▇▇0 005 there', @sanitizer.sanitize!('Hello 37 828 2246310 005 there')
        end
      end

      describe 'use_groupings is true' do
        before do
          @sanitizer = CreditCardSanitizer.new(use_groupings: true)
        end

        it 'sanitizes visa card grouped 4-4-4-4' do
          assert_equal 'Hello 4111 11▇▇ ▇▇▇▇ 1111 there', @sanitizer.sanitize!('Hello 4111 1111 1111 1111 there')
        end

        it 'does not sanitize visa card grouped oddly' do
          assert_nil @sanitizer.sanitize!('Hello 41 11 11 11 11 11 11 11 there')
        end

        it 'sanitizes mastercard grouped 4-4-4-4' do
          assert_equal 'Hello 5555 55▇▇ ▇▇▇▇ 4444 there', @sanitizer.sanitize!('Hello 5555 5555 5555 4444 there')
        end

        it 'does not sanitize mastercard grouped oddly' do
          assert_nil @sanitizer.sanitize!('Hello 55555 55555 554444 there')
        end

        it 'sanitizes amex card grouped 4-6-5' do
          assert_equal 'Hello 3782 82▇▇▇▇ ▇0005 there', @sanitizer.sanitize!('Hello 3782 822463 10005 there')
        end

        it 'does not sanitize amex card grouped oddly' do
          assert_nil @sanitizer.sanitize!('Hello 3782 8224 6310 005 there')
        end

        it 'sanitizes diners club grouped 4-6-4' do
          assert_equal 'Hello 3056 93▇▇▇▇ 5904 there', @sanitizer.sanitize!('Hello 3056 930902 5904 there')
        end

        it 'does not sanitize diners club grouped oddly' do
          assert_nil @sanitizer.sanitize!('Hello 3056 9309 0259 04 there')
        end

        it 'sanitizes maestro if first group is 4 or 5 digits' do
          assert_equal 'Hello 6799 99▇▇▇▇▇ ▇▇▇▇0 019 there', @sanitizer.sanitize!('Hello 6799 9901000 00000 019 there')
          assert_equal 'Hello 67999 9▇▇▇▇▇ ▇▇▇▇0 019 there', @sanitizer.sanitize!('Hello 67999 901000 00000 019 there')
        end

        it 'does not sanitize maestro if first group is not 4 or 5 digits' do
          assert_nil @sanitizer.sanitize!('Hello 679 99901000 00000 019 there')
          assert_nil @sanitizer.sanitize!('Hello 67 999901000 00000 019 there')
          assert_nil @sanitizer.sanitize!('Hello 679999 01000 00000 019 there')
        end

        # these numbers were generated via scripts/generate_card.rb
        it 'does not santitize a visa credit card number embedded in a number' do
          assert_nil @sanitizer.sanitize!('04881621594644972')
        end

        it 'does not santitize a mastercard number embedded in a number' do
          assert_nil @sanitizer.sanitize!('05555555555554444')
        end

        it 'does not santitize a discover card number embedded in a number' do
          assert_nil @sanitizer.sanitize!('06011000000000000')
        end

        it 'does not santitize an amex number embedded in a number' do
          assert_nil @sanitizer.sanitize!('0378282246310005')
        end

        it 'does not santitize a diners club number embedded in a number' do
          assert_nil @sanitizer.sanitize!('030569309025904')
        end

        it 'does not santitize a jcb card number embedded in a number' do
          assert_nil @sanitizer.sanitize!('03528154373040254')
        end

        it 'does not santitize a switch number embedded in a number' do
          assert_nil @sanitizer.sanitize!('06759982158418979')
        end

        it 'does not santitize a solo card number embedded in a number' do
          assert_nil @sanitizer.sanitize!('06767859394986987')
        end

        it 'does not santitize a dankort card number embedded in a number' do
          assert_nil @sanitizer.sanitize!('05019717010103742')
        end

        it 'does not santitize a maestro card number embedded in a number' do
          assert_nil @sanitizer.sanitize!('06799990100000000019')
        end

        it 'does not santitize a forbrugsforeningen card number embedded in a number' do
          assert_nil @sanitizer.sanitize!('06007228728677953')
        end

        it 'does not santitize a laser card number embedded in a number' do
          assert_nil @sanitizer.sanitize!('0630487115747')
        end

        it 'does not sanitize ARN numbers' do
          assert_nil @sanitizer.sanitize!('74537606287640125960797 and 74537606281640124230958')
        end
      end
    end
  end

  describe '#parameter_filter' do
    before do
      @proc = CreditCardSanitizer.parameter_filter
    end

    it 'returns a proc that will sanitize that will envoke #sanitize on the second parameter' do
      assert_equal 'Hello 4111 11▇▇ ▇▇▇▇ 1111 there', @proc.call(:key, 'Hello 4111 1111 1111 1111 there')
    end

    it 'does not blow up on non strings' do
      assert_nil @proc.call(:key, 1)
    end
  end

  describe '#valid_company_prefix?' do
    it 'returns true for dankort' do
      assert @sanitizer.send(:valid_company_prefix?, '5019717010103742')
    end

    it 'returns true for dankort as visa' do
      assert @sanitizer.send(:valid_company_prefix?, '4571100000000000')
    end

    it 'returns true for electron dk as visa' do
      assert @sanitizer.send(:valid_company_prefix?, '4175001000000000')
    end

    it 'returns true for diners club' do
      assert @sanitizer.send(:valid_company_prefix?, '36148010000000')
    end

    it 'returns true for diners club uk' do
      assert @sanitizer.send(:valid_company_prefix?, '30401000000000')
    end

    it 'returns true for maestro dk as maestro' do
      assert @sanitizer.send(:valid_company_prefix?, '6769271000000000')
    end

    it 'returns true for maestro' do
      assert @sanitizer.send(:valid_company_prefix?, '5020100000000000')
    end

    it 'returns true for master cards' do
      assert @sanitizer.send(:valid_company_prefix?, '6771890000000000')
      assert @sanitizer.send(:valid_company_prefix?, '5413031000000000')
    end

    it 'returns true for forbrugsforeningen cards' do
      assert @sanitizer.send(:valid_company_prefix?, '6007221000000000')
    end

    it 'returns true for full range laser cards' do
      assert @sanitizer.send(:valid_company_prefix?, '6304985028090561')    #    16 digits
      assert @sanitizer.send(:valid_company_prefix?, '6706123456789012')    # V2 16 digits
      assert @sanitizer.send(:valid_company_prefix?, '6709123456789012')    # V3 16 digits
      assert @sanitizer.send(:valid_company_prefix?, '630498502809056151')  #    18 digits
      assert @sanitizer.send(:valid_company_prefix?, '6304985028090561515') # 19 digits
      assert @sanitizer.send(:valid_company_prefix?, '63049850280905615')   # 17 digits
      assert @sanitizer.send(:valid_company_prefix?, '630498502809056')     # 15 digits
      assert @sanitizer.send(:valid_company_prefix?, '6706950000000000000') # Alternate format
      assert @sanitizer.send(:valid_company_prefix?, '677117111234') # Ulster bank (Ireland) with 12 digits
    end

    it 'returns full range for maestro cards (12-18)' do
      maestro = '50000000000'

      while maestro.length < 19
        maestro << '0'
        assert @sanitizer.send(:valid_company_prefix?, maestro)
      end
    end

    it 'returns true for discover cards' do
      assert @sanitizer.send(:valid_company_prefix?, '6011000000000000')
      assert @sanitizer.send(:valid_company_prefix?, '6500000000000000')
      assert @sanitizer.send(:valid_company_prefix?, '6221260000000000')
      assert @sanitizer.send(:valid_company_prefix?, '6450000000000000')
    end

    it 'returns true for 16 digit maestro uk' do
      number = '6759000000000000'
      assert_equal 16, number.length
      assert @sanitizer.send(:valid_company_prefix?, number)
    end

    it 'returns true for 18 digit maestro uk' do
      number = '675900000000000000'
      assert_equal 18, number.length
      assert @sanitizer.send(:valid_company_prefix?, number)
    end

    it 'returns true for 19 digit maestro uk' do
      number = '6759000000000000000'
      assert_equal 19, number.length
      assert @sanitizer.send(:valid_company_prefix?, number)
    end
  end

  private

  # Generates a random FedEx tracking number (15 digits with check digit)
  # Prefix with "6" to give it a chance of conflicting with Maestro.
  # Check digit code is derived from https://github.com/jkeen/tracking_number/blob/master/lib/tracking_number/fedex.rb
  def generate_fedex
    digits = [6] + Array.new(13) { Random.rand(10) }
    total = 0
    digits.reverse.each_with_index do |x, i|
      x *= 3 if i.even?
      total += x
    end
    check = total % 10
    check = (10 - check) unless check.zero?
    (digits + [check]).join
  end

  # Generate "count" random FedEx tracking numbers that definitely pass
  # Luhn checksum.
  def generate_fedex_ccs(count)
    [].tap do |numbers|
      while numbers.length < count
        candidate = generate_fedex
        numbers << candidate if LuhnChecksum.valid?(candidate)
      end
    end
  end
end
