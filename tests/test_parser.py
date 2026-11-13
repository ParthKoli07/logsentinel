from logsentinel.parser import parse_line, parse_lines

GOOD = (
    '203.0.113.5 - - [10/Oct/2026:13:55:36 +0530] "GET /index.html HTTP/1.1" 200 2326 '
    '"http://example.com/" "Mozilla/5.0"'
)


def test_parses_valid_line():
    e = parse_line(GOOD)
    assert e is not None
    assert e.ip == "203.0.113.5"
    assert e.method == "GET"
    assert e.path == "/index.html"
    assert e.status == 200
    assert e.size == 2326
    assert e.user_agent == "Mozilla/5.0"
    assert e.timestamp.year == 2026


def test_dash_size_becomes_zero():
    line = '10.0.0.1 - - [10/Oct/2026:13:55:36 +0000] "GET / HTTP/1.1" 304 - "-" "curl/8"'
    e = parse_line(line)
    assert e is not None and e.size == 0 and e.referrer is None


def test_malformed_line_returns_none():
    assert parse_line("this is not a log line") is None


def test_bad_request_field_is_kept_without_method():
    line = '10.0.0.2 - - [10/Oct/2026:13:55:36 +0000] "-" 408 0 "-" "-"'
    e = parse_line(line)
    assert e is not None and e.method is None and e.status == 408


def test_parse_lines_counts_malformed_and_skips_blank():
    entries, malformed = parse_lines([GOOD, "", "garbage", GOOD])
    assert len(entries) == 2
    assert malformed == 1
