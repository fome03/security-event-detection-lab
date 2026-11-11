# Investigating a suspicious sign-in pattern

**Type:** Practice investigation using made-up logs  
**Date in sample:** November 10, 2026 (UTC)  
**Device:** LAB-PC-01  
**Account:** alex  
**Source:** 192.0.2.10 (example/documentation IP)  
**Alert:** High, based on the lab's rule

## What caught my attention

In the sample data, the account `alex` has six failed sign-in attempts from the same IP address between 12:00 and 12:05. At 12:06, there is a successful sign-in from that same source.

A person mistyping a password could produce this pattern. So could someone guessing credentials and eventually getting in. I can't tell which one happened from these events alone, so I treated it as something to investigate rather than confirmed unauthorized access.

## Events I reviewed

| Time (UTC) | Windows event ID | What the sample shows |
|---|---|---|
| 12:00–12:05 | 4625 | Six failed logins for `alex` from `192.0.2.10` |
| 12:06 | 4624 | A successful login for the same account and source |

The script flags the failed-login burst and then generates a higher-severity alert after the successful event.

## What I'd check next in a real environment

1. **Confirm the log details.** Check the original records, their timestamps, and the Windows logon type. The simplified CSV leaves those details out.
2. **Check the source.** Is this a known workstation or network address? Was the person using a VPN or another expected access method?
3. **Ask about the activity.** Does the account owner recognize these attempts? Are there matching MFA or identity-provider events?
4. **Look for follow-on activity.** A successful login matters more if there are unusual changes, new access attempts, or other alerts afterward.
5. **Escalate if the evidence supports it.** Keep the relevant logs and follow the organization's incident-handling procedures rather than taking disruptive action based on one rule.

## Outcome and limitations

With the default settings, the detector processed 16 synthetic events and generated three alerts in total: two associated with `alex` and one repeated-failures alert for `sam`. The script behaved as expected against the test cases.

**No real account was accessed, no live incident was investigated, and no remediation was performed.** The lab shows how a detection rule can guide triage; it does not prove an attack occurred.

If I expanded this project, I'd start by adding logon type and account-lockout data, then test how often the rules flag harmless activity.
