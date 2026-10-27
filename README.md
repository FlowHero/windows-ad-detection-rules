# Windows & AD Detection Rules

Detection rules and SIEM queries for Windows and Active Directory attacks, covering Splunk, LogPoint, and Suricata.

## Files

### `windows_splunk_logpoint.md`
Side-by-side Splunk and LogPoint detection queries for the core AD attack chain. Also includes Suricata rules for network-layer detections.

| Attack | Splunk | LogPoint | Suricata |
|--------|--------|----------|----------|
| User/Domain Recon | ✓ | ✓ | |
| Password Spraying | ✓ | ✓ | |
| LLMNR/NBT-NS Poisoning | ✓ | ✓ | ✓ |
| Kerberoasting | ✓ | ✓ | |
| AS-REPRoasting | ✓ | ✓ | |
| Pass-the-Hash | ✓ | ✓ | |
| Pass-the-Ticket | ✓ | ✓ | |
| Overpass-the-Hash | ✓ | ✓ | |
| Golden Ticket | ✓ | ✓ | |
| Silver Ticket | ✓ | ✓ | |
| Unconstrained Delegation | ✓ | ✓ | |
| Constrained Delegation | ✓ | ✓ | |
| DCSync | ✓ | ✓ | |
| DCShadow | ✓ | ✓ | |

### `Windows Attacks - LogPoint Detection Rules.md`
Production-ready LogPoint rules with alert thresholds and honeypot detection patterns, covering a broader attack surface.

| Attack |
|--------|
| Kerberoasting |
| AS-REPRoasting |
| GPP Passwords |
| GPO Permissions Abuse |
| Credentials in Shares |
| Credentials in Object Properties |
| DCSync |
| Golden Ticket |
| Kerberos Constrained Delegation |
| PrinterBug & NTLM Relaying |
| Coercing Attacks & Unconstrained Delegation |
| Object ACL Abuse |
| ESC1 — ADCS Misconfiguration |

## Notes

- LogPoint queries assume default Windows log sources only (no Sysmon, no SilkETW) unless stated
- Splunk queries use Sysmon and SilkETW where available
- Adjust field names, thresholds, and `norm_id` values to match your environment

## Author

[FlowHero](https://flowhero.github.io) — HackTheBox CDSA
