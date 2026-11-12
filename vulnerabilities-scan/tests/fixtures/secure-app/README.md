# Secure look-alike fixture app

The mirror image of `tests/fixtures/vulnerable-app`: the same tasks, the same
languages, and the same shapes a scanner looks for, but each one is protected by
a control the analyzer is expected to recognise (a bound parameter, an argument
vector, `secure_filename`, an origin allow-list, `yaml.safe_load`, bcrypt,
a pinned base image, a SHA-pinned action, and so on).

This tree exists to measure false positives. The test suite asserts that a scan
of this directory reports **no** findings; a finding here is a precision defect
in the analyzer, not a problem to be worked around in the fixture.

Where a look-alike deliberately keeps the risky shape on the line (for example
`HttpResponse(f"...{html.escape(...)}")`), the compensating control is on that
same line on purpose: the analyzer resolves guards per line, so the suppression
is exercised rather than avoided. Those hits appear in the scan's `suppressed`
list, which is where the tests look for them.

Nothing here reads a credential from a literal: `python/orders/config.py` takes
every value from the environment.
