# SSH Log Analyzer

Parses a Linux SSH authentication log (`/var/log/auth.log` on Debian/Ubuntu,
`/var/log/secure` on RHEL-based systems) and flags suspicious activity:

- **Brute force** — an IP with 5+ failed logins within 60 seconds (both configurable)
- **Invalid user attempts** — logins tried against usernames that don't exist
- **Possible successful brute force** — a successful login from an IP that
  was also flagged for brute force

## Usage

```bash
python log_analyzer.py fixtures/brute_force.log
python log_analyzer.py /var/log/auth.log --threshold 5 --window 60 --output results.csv
```

Example output:

```
Parsed 10 event(s) from fixtures/brute_force.log (1 line(s) skipped/unrecognized)
Found 4 alert(s):
  brute_force: 1
  invalid_user: 2
  possible_successful_brute_force: 1

Saved to fixtures/brute_force.alerts.csv
```

## Sample fixtures

| File | What it contains |
|---|---|
| `fixtures/normal.log` | Ordinary logins, no alerts expected |
| `fixtures/brute_force.log` | A brute-force attack, invalid-username attempts, and a follow-on successful login |
| `fixtures/malformed.log` | Valid lines mixed with garbage/malformed lines, to test that bad input is skipped and counted, not silently dropped or crashing the tool |

## Tests

```bash
python -m pytest tests/test_log_analyzer.py -v
```

12 tests covering line parsing, malformed-line handling, and all three
detection rules, run against the fixture logs above.

## How it works

- `parse_line()` — matches one sshd syslog line against known patterns
  (`Failed password`, `Accepted password/publickey`). Lines that don't
  match (garbage, or sshd message types this tool doesn't track, like
  "session opened" or "Disconnected from") return `None`.
- `parse_log()` — reads a file line by line, returns `(events, skipped_count)`
  so malformed input is visible in the summary rather than silently dropped.
- `analyze()` — applies the three detection rules over the parsed events
  using a sliding time window per source IP.
- Output is a CSV with one row per alert: timestamp, alert type, IP, detail,
  severity.

## Limitations

- SSH auth.log format only; does not parse web server or Windows event logs.
- Syslog lines have no year field, so the current year is assumed unless
  `--year` is given, this matters when analyzing logs from a previous year.
- No log rotation or live-tailing support, it reads a single file once.
- This is a learning / portfolio tool, not a production SIEM. It has no
  persistence, alerting integration, or allow-listing of known-good IPs.

## Disclaimer

For learning and authorized testing only. The sample logs are fabricated
for demonstration; run this only against logs you own or have permission
to analyze.
