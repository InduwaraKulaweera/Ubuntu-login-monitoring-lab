# Ubuntu Login Monitoring Lab

A small defensive lab that detects repeated SSH password failures from exported Linux journal logs using a Python rule, with automated tests, a file integrity check and a documented investigation.

This is an offline log-analysis project, not a SIEM deployment.

## Environment

- Ubuntu 24.04.4 LTS (x86_64) in VirtualBox
- OpenSSH server restricted to 127.0.0.1 (local-only)
- Python 3, standard library only
- Test account: labuser (disposable, no sudo)

## Flow

Ubuntu SSH -> journal -> exported JSON -> Python detector -> alert -> investigation report

## Setup

1. Configure SSH to listen on 127.0.0.1 only and verify with `sudo ss -ltnp | grep ':22'`.
2. Create the test account: `sudo adduser labuser`.
3. Generate six controlled failed logins against labuser on 127.0.0.1.

## Collect evidence

    sudo journalctl -t sshd --since '2026-11-14 18:23:00' --until '2026-11-14 18:29:00' -o json --no-pager > evidence/ssh-events.jsonl

## Run the detector

    python3 detect_failed_logins.py evidence/ssh-events.jsonl --output evidence/alerts.json

Default rule: 5 Failed password events from one source IP within 300 seconds.

Sample output:

    1 alert(s); 0 malformed line(s) skipped

    source_ip: 127.0.0.1, failure_count: 5, window_seconds: 300, usernames: ["labuser"]

Comparison: `--threshold 3 --window 120` produced 2 alerts (more sensitive, higher false-positive risk).

## Run the tests

    python3 -m unittest -v test_detector.py

Result: 7 tests, all pass (threshold, below threshold, expired events, separate sources, unordered input, accepted login ignored, IPv6).

## File integrity check

    sha256sum integrity/demo.conf > integrity/baseline.sha256
    sha256sum -c integrity/baseline.sha256

Unmodified file: OK. After appending a line: FAILED. This shows the bytes changed, not what caused the change.

## Limitations

- Offline analysis of exported logs, not a continuously running service
- Counts only Failed password messages
- Does not block IPs
- Cannot tell a forgetful user from an attacker; multiple users behind one IP can cause false positives
- Clearing the window after an alert is batching, not full deduplication

## Files

- detect_failed_logins.py, test_detector.py
- incident-report.md
- evidence/ (synthetic lab data from my own VM)
