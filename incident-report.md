# Controlled SSH Login Failure Investigation

## Scope

Own Ubuntu 24.04 VM, local SSH test against 127.0.0.1 using a disposable account (labuser). No external target.

## Timeline

All times are UTC, taken from journal timestamps.
- 2026-11-14 18:23:57: first controlled failed password
- 2026-11-14 18:27:59: last controlled failed password
- 2026-11-14 18:27:59: detector alert raised (five-in-300s rule)

## Evidence

- Journal export: evidence/ssh-events.jsonl (10 journal events, 6 of them Failed password)
- Readable copy: evidence/ssh-events-readable.txt
- Alert output: evidence/alerts.json
- Source IP: 127.0.0.1
- Username: labuser
- Failed password events in export: 6
- Alert failure_count: 5 (the alert fires when the fifth failure arrives, then the window is cleared)

## Detection

Five Failed password events from one source IP within 300 seconds. Baseline result: 1 alert.
Comparison: threshold 3 with a 120-second window produced 2 alerts, because the lower threshold and shorter window fire on each round of three failures.

## Investigation

The failures match the known test activity: two rounds of three deliberately wrong passwords for labuser, about four minutes apart. A separate earlier round of three wrong passwords (18:09 to 18:10) was an accidental typing mistake and is outside the exported time range.

## Assessment

Controlled simulation. In a real environment, repeated failures from one source could indicate password guessing, a misconfigured service, or a user who forgot a password.

## Response

Review access to the account, preserve the logs, and check whether any Accepted password event followed the failures (which would suggest the account may be compromised).

## Limitations

Offline analysis of exported logs, not a running service. Only Failed password messages are counted. Multiple users behind one IP can cause false positives, and a forgetful user can look like an attacker. Clearing the window after an alert is batching, not full deduplication.
