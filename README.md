# Security Event Detection Lab

A small Python project for spotting unusual Windows sign-in activity. It reads a CSV of authentication events, looks for repeated failed logins, and flags a successful login that happens right after several failures.

**Important:** The sample events are made up for testing. They use Windows event IDs, but they did not come from a real investigation. This is a practice lab, not a production security tool.

## Why this project

I've worked on network troubleshooting, device deployments, and IT support, but I wanted to spend more time on the *security investigation* side of things. My starting question was pretty simple: **If someone keeps trying to sign in to an account, what would I look for in the logs?**

I chose two Windows Security event IDs:

- **4625:** A login attempt failed.
- **4624:** A login succeeded.

Neither event tells the whole story by itself. The useful part is looking at the timing, account, device, and source address together.

## What the script does

It reads `data/sample_security_events.csv`, sorts the events by time, and checks each combination of computer, source IP, and username.

It currently looks for two patterns:

| Pattern | Rule | Why I'd review it |
|---|---|---|
| Repeated failures | 5 or more failed logins within 10 minutes | Could be someone repeatedly guessing a password, or just a user having trouble signing in |
| Failures followed by success | A successful login after 5 or more recent failures | Worth checking to see whether the account owner recognizes the activity |

The results are saved to `reports/alerts.json`. **An alert means “look into this,” not “an attack definitely happened.”**

## Run it yourself

You need Python 3.10 or newer. Open a terminal in the project folder and run:

```bash
python -m unittest discover -s tests -v
python src/detect_suspicious_logins.py --input data/sample_security_events.csv --output reports/alerts.json
```

To try a different threshold:

```bash
python src/detect_suspicious_logins.py --threshold 3 --window 15
```

The first command runs the tests. The second reads the sample events and prints the alerts it finds. The optional command checks for three failures over fifteen minutes instead of five over ten.

## What happened with the sample data

The provided CSV contains **16 simulated events**. With the default settings, the script produces **three alerts**. One account has a series of failed logins followed by a successful login. A second account triggers the repeated-failures rule.

I wrote up the main finding in [`reports/incident_investigation.md`](reports/incident_investigation.md). There is also an example screenshot in [`screenshots/detection_results.png`](screenshots/detection_results.png).

## Project files

```text
security-event-detection-lab/
├── .github/workflows/tests.yml
├── data/sample_security_events.csv
├── reports/alerts.json
├── reports/incident_investigation.md
├── screenshots/detection_results.png
├── src/detect_suspicious_logins.py
├── tests/test_detection.py
├── requirements.txt
└── README.md
```

The project uses Python's standard library, so there is nothing extra to install.

## What I'd change next

This version is intentionally small. Actual Windows logs contain more useful details than this CSV, especially **logon type**, which helps distinguish an interactive login from a service or network logon. The current rules also don't identify password spraying across many accounts or rule out legitimate automated activity.

My next steps would be to:

1. Add Windows event-log import from a machine I own or have permission to test.
2. Include logon type and account-lockout events (ID 4740).
3. Check for password spraying across multiple accounts.
4. Review false positives before assigning alert severity.

## A note on the data

The IP addresses in this project are from documentation-only ranges, and the accounts are fictional. I would not upload actual workplace security logs or account information to a public repository.

## How I'd describe this in an interview

> This was a learning lab where I worked through how security analysts can spot suspicious login patterns. I used Python to group Windows authentication events by account and source, built two simple detection rules, tested them with simulated data, and wrote up what I'd investigate before treating an alert as a real incident.
