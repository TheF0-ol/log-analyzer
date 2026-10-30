"""
Tests for log_analyzer.py, run against the fixture logs in ../fixtures/.

Run with:  python -m pytest tests/test_log_analyzer.py -v
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from log_analyzer import parse_line, parse_log, analyze, Alert

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
YEAR = 2026


def test_parse_line_failed_password():
    line = "Jan 11 02:10:01 webserver sshd[2001]: Failed password for root from 203.0.113.9 port 44110 ssh2"
    event = parse_line(line, year=YEAR)
    assert event is not None
    assert event.ip == "203.0.113.9"
    assert event.user == "root"
    assert event.event_type == "failed"
    assert event.invalid_user is False


def test_parse_line_invalid_user():
    line = "Jan 11 03:00:00 webserver sshd[2050]: Failed password for invalid user admin from 198.51.100.22 port 33011 ssh2"
    event = parse_line(line, year=YEAR)
    assert event is not None
    assert event.user == "admin"
    assert event.invalid_user is True


def test_parse_line_accepted():
    line = "Jan 10 08:15:01 webserver sshd[1021]: Accepted password for deploy from 10.0.0.5 port 51322 ssh2"
    event = parse_line(line, year=YEAR)
    assert event is not None
    assert event.event_type == "accepted"
    assert event.user == "deploy"


def test_parse_line_rejects_malformed_and_unrelated_lines():
    assert parse_line("this is not a log line at all", year=YEAR) is None
    assert parse_line("Jan 12 05:00:02webserver sshd[3002] missing brackets", year=YEAR) is None
    # A recognized sshd line type this tool doesn't track should also return None
    assert parse_line("Jan 10 18:10:03 webserver sshd[1099]: Disconnected from 10.0.0.12 port 50111",
                       year=YEAR) is None


def test_parse_log_normal_traffic_has_no_alerts():
    events, skipped = parse_log(FIXTURES / "normal.log", year=YEAR)
    alerts = analyze(events)
    assert len(events) == 3
    assert skipped == 3  # the session-opened / disconnected lines
    assert alerts == []


def test_parse_log_malformed_skips_bad_lines_but_keeps_good_ones():
    events, skipped = parse_log(FIXTURES / "malformed.log", year=YEAR)
    assert len(events) == 3
    assert skipped == 2  # the garbage line and the missing-brackets line


def test_analyze_detects_brute_force():
    events, _ = parse_log(FIXTURES / "brute_force.log", year=YEAR)
    alerts = analyze(events, threshold=5, window_seconds=60)
    brute_force_alerts = [a for a in alerts if a.alert_type == "brute_force"]
    assert len(brute_force_alerts) == 1
    assert brute_force_alerts[0].ip == "203.0.113.9"
    assert brute_force_alerts[0].severity == "high"


def test_analyze_detects_invalid_user_attempts():
    events, _ = parse_log(FIXTURES / "brute_force.log", year=YEAR)
    alerts = analyze(events)
    invalid_alerts = [a for a in alerts if a.alert_type == "invalid_user"]
    users_flagged = {a.detail for a in invalid_alerts}
    assert len(invalid_alerts) == 2
    assert any("admin" in d for d in users_flagged)
    assert any("test" in d for d in users_flagged)


def test_analyze_flags_successful_login_after_brute_force():
    events, _ = parse_log(FIXTURES / "brute_force.log", year=YEAR)
    alerts = analyze(events)
    success_alerts = [a for a in alerts if a.alert_type == "possible_successful_brute_force"]
    assert len(success_alerts) == 1
    assert success_alerts[0].severity == "critical"


def test_analyze_threshold_is_configurable():
    events, _ = parse_log(FIXTURES / "brute_force.log", year=YEAR)
    # With a threshold higher than the attack's 6 failures, nothing should fire
    alerts = analyze(events, threshold=10, window_seconds=60)
    assert [a for a in alerts if a.alert_type == "brute_force"] == []


def test_analyze_window_is_configurable():
    events, _ = parse_log(FIXTURES / "brute_force.log", year=YEAR)
    # A 1-second window is too tight for the fixture's 2-second-spaced attempts
    alerts = analyze(events, threshold=5, window_seconds=1)
    assert [a for a in alerts if a.alert_type == "brute_force"] == []


def test_analyze_empty_event_list_returns_no_alerts():
    assert analyze([]) == []
