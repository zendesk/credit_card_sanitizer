# Changelog

## Unreleased

## v1.3.0

- Introduce a new `protect_placeholders` option (default: `false`), `placeholder_open` and `placeholder_close` options (default: `{{` and `}}`) to prevent sanitization of credit card numbers within placeholders `{{...}}`.

## v1.2.0

- **BREAKING**: Introduce a new `allow_flanking_by_no_space_languages` option to explicitly control sanitization of credit card numbers flanked by Japanese/Chinese characters. When using default options (`parse_flanking: false`), these numbers are no longer sanitized by default. Set `allow_flanking_by_no_space_languages: true` to restore the previous behavior.

## v1.1.0

- Ensure the gem works when using frozen strings.
- Test with Ruby 3.4.
- Stop testing with Ruby 3.0, 3.1.
