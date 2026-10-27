# Windows Attacks — LogPoint SIEM Detection Rules

> **Source log:** Windows Security Event Log (`norm_id=WinServer` or `source_name=Security`)
> All queries assume Windows Event Log forwarding to LogPoint is configured.
> Adjust `norm_id`, field names, and thresholds to match your environment.

---

## Table of Contents

- [[#Kerberoasting|Kerberoasting]]
- [[#AS-REProasting|AS-REProasting]]
- [[#GPP Passwords|GPP Passwords]]
- [[#GPO Permissions / GPO Files|GPO Permissions / GPO Files]]
- [[#Credentials in Shares|Credentials in Shares]]
- [[#Credentials in Object Properties|Credentials in Object Properties]]
- [[#DCSync|DCSync]]
- [[#Golden Ticket|Golden Ticket]]
- [[#Kerberos Constrained Delegation|Kerberos Constrained Delegation]]
- [[#PrinterBug & NTLM Relaying|PrinterBug & NTLM Relaying]]
- [[#Coercing Attacks & Unconstrained Delegation|Coercing Attacks & Unconstrained Delegation]]
- [[#Object ACL Abuse|Object ACL Abuse]]
- [[#ESC1 — ADCS Misconfiguration|ESC1 — ADCS Misconfiguration]]

---

## Kerberoasting

**Relevant Event ID:** `4769` — Kerberos Service Ticket Requested

### Rule 1 — RC4 Ticket Requested in AES Environment

Detects a TGS ticket using RC4 encryption (`0x17`), which is a strong indicator of a downgrade or a Kerberoasting attempt in an AES-enforced environment.

```
norm_id=WinServer event_id=4769 ticket_encryption_type="0x17"
| chart count() as count by src_ip, subject_account_name
| search count > 0
```

**Alert threshold:** Any single occurrence in an AES-only environment.

---

### Rule 2 — High-Volume TGS Requests from Single Source (Rubeus Bulk Dump)

Detects mass TGS requests within a short window — characteristic of Rubeus dumping all SPNs at once.

```
norm_id=WinServer event_id=4769
| timechart span=1m count() as ticket_count by src_ip
| search ticket_count > 10
```

**Alert threshold:** More than 10 TGS requests from the same source IP within 1 minute.

---

### Rule 3 — Honeypot SPN Triggered

Alert on any TGS request for the honeypot service account (e.g., `svc-iam`).

```
norm_id=WinServer event_id=4769 service_name="svc-iam"
| chart count() by src_ip, subject_account_name, service_name
```

**Alert threshold:** Any single occurrence.

---

## AS-REProasting

**Relevant Event ID:** `4768` — Kerberos TGT Requested

### Rule 1 — Pre-Authentication Disabled (Type 0)

Detects AS-REP requests sent without pre-authentication, which means the account has `Do not require Kerberos preauthentication` set.

```
norm_id=WinServer event_id=4768 pre_auth_type="0"
| chart count() by src_ip, target_user_name
```

**Alert threshold:** Any occurrence.

---

### Rule 2 — RC4 TGT in AS-REP

Rubeus defaults to requesting RC4 (`0x17`) tickets in AS-REProasting. Combine with pre-auth type 0 for high-fidelity alerts.

```
norm_id=WinServer event_id=4768 pre_auth_type="0" ticket_encryption_type="0x17"
| chart count() by src_ip, target_user_name
```

**Alert threshold:** Any occurrence.

---

### Rule 3 — Honeypot AS-REP Account Targeted

Alert on any TGT request for a honeypot account configured with pre-auth disabled (e.g., `svc-iam`).

```
norm_id=WinServer event_id=4768 target_user_name="svc-iam"
| chart count() by src_ip, target_user_name
```

**Alert threshold:** Any single occurrence.

---

## GPP Passwords

**Relevant Event IDs:** `4663` (file access), `4624` (logon success), `4625` (logon failure), `4768` (TGT request)

### Rule 1 — SYSVOL GPP XML File Accessed (Honeypot File)

Detects any read access to the honeypot Groups.xml file in SYSVOL. File auditing must be enabled on the file.

```
norm_id=WinServer event_id=4663 object_name="*\\SYSVOL\\*\\Policies\\*\\Groups.xml"
| chart count() by src_ip, subject_account_name, object_name
```

**Alert threshold:** Any occurrence outside of known admin maintenance windows.

---

### Rule 2 — Service Account Logon from Unexpected Source

Detects a successful logon for a monitored service account (e.g., `svc-iis`) originating from a workstation instead of a server. Adjust the IP subnet for your environment.

```
norm_id=WinServer event_id=4624 target_user_name="svc-iis"
| search NOT (src_ip="10.0.0.*")
| chart count() by src_ip, target_user_name, logon_type
```

---

### Rule 3 — GPP Honeypot Account Failed Logon (Wrong Password)

Detects failed logon attempts using the honeypot credential planted in a GPP XML file.

```
norm_id=WinServer event_id IN [4625, 4771, 4776] target_user_name="svc-iis"
| chart count() by src_ip, target_user_name, event_id
```

**Alert threshold:** Any single occurrence.

- `4625` — NTLM/interactive logon failure
- `4771` — Kerberos pre-auth failure (failure code `0x18` = wrong password)
- `4776` — NTLM credential validation failure (`0xC000006A` = bad password)

---

## GPO Permissions / GPO Files

**Relevant Event ID:** `5136` — Directory Service Object Modified

### Rule 1 — GPO Modified by Non-Privileged Account

Detects a GPO modification where the modifying account does not match the expected admin naming convention (e.g., accounts not starting with `admin`).

```
norm_id=WinServer event_id=5136 object_class="groupPolicyContainer"
| search NOT subject_account_name="admin*"
| chart count() by subject_account_name, object_dn
```

**Alert threshold:** Any occurrence.

---

### Rule 2 — Honeypot GPO Modified

Alert on any modification to the designated honeypot GPO. Replace the GUID below with your honeypot GPO's actual GUID.

```
norm_id=WinServer event_id=5136 object_dn="*{HONEYPOT-GPO-GUID}*"
| chart count() by subject_account_name, src_ip, object_dn
```

**Alert threshold:** Any single occurrence. Consider auto-disabling the offending account via response action.

---

## Credentials in Shares

**Relevant Event IDs:** `4624`, `4625`, `4768`, `4771`, `4776`

### Rule 1 — One-to-Many SMB Connections (Share Enumeration)

Detects a single workstation connecting to an abnormally large number of distinct hosts in a short window — characteristic of `Invoke-ShareFinder`.

```
norm_id=WinServer event_id=4624 logon_type="3"
| timechart span=1m dc(target_host) as unique_hosts by src_ip
| search unique_hosts > 20
```

**Alert threshold:** More than 20 unique hosts accessed via network logon from one source IP within 1 minute.

---

### Rule 2 — Honeypot Service Account Failed Logon (Credential Found in Share)

Same pattern as GPP honeypot. Alert on any failed authentication for the credential planted in a share script.

```
norm_id=WinServer event_id IN [4625, 4771, 4776] target_user_name="svc-iis"
| chart count() by src_ip, target_user_name, event_id
```

**Alert threshold:** Any single occurrence.

---

## Credentials in Object Properties

**Relevant Event IDs:** `4624`, `4625`, `4768`

### Rule 1 — Abnormal Logon for Admin/Service Account

Detects a logon for privileged or service accounts from an IP outside the expected administrative range.

```
norm_id=WinServer event_id=4624 target_user_name IN ["bonni", "svc-*", "admin*"]
| search NOT src_ip="10.0.1.*"
| chart count() by src_ip, target_user_name, logon_type
```

---

### Rule 2 — Honeypot Object Account Failed Authentication

Detects failed authentication for a service account whose Description field contains a fake password.

```
norm_id=WinServer event_id IN [4625, 4771, 4776] target_user_name="svc-iis"
| chart count() by src_ip, event_id, failure_reason
```

**Alert threshold:** Any single occurrence.

---

## DCSync

**Relevant Event ID:** `4662` — An Operation Was Performed on an Object

### Rule 1 — DCSync by Non-Domain-Controller Account

Detects replication operations (`Replicating Directory Changes` / `Replicating Directory Changes All`) performed by an account that is not a Domain Controller machine account (`$`).

```
norm_id=WinServer event_id=4662
  object_type="domainDNS"
  properties IN ["*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*", "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*"]
| search NOT subject_account_name="*$"
| chart count() by subject_account_name, src_ip, object_type
```

**Alert threshold:** Any occurrence. Whitelist accounts like `MSOL_*` (Azure AD Connect) if applicable.

---

### Rule 2 — DCSync Excluding Known Legitimate Sources

Refined version whitelisting known replication agents.

```
norm_id=WinServer event_id=4662
  object_type="domainDNS"
  properties IN ["*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*", "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*"]
| search NOT subject_account_name IN ["*$", "MSOL_*", "ADConnect"]
| chart count() by subject_account_name, src_ip
```

---

## Golden Ticket

**Relevant Event IDs:** `4624`, `4769`, `4675`

### Rule 1 — TGS Request Without Preceding TGT (Forged Ticket Indicator)

Detects a TGS service ticket request (`4769`) for a privileged account where no corresponding TGT request (`4768`) exists from the same source within a lookback window. This indicates a pre-forged ticket injected directly.

```
norm_id=WinServer event_id=4769 target_user_name="Administrator"
| join {
    norm_id=WinServer event_id=4768 target_user_name="Administrator"
  } src_ip
| search _joined_count=0
| chart count() by src_ip, target_user_name
```

> Note: Implement as a correlation rule with a 10-minute lookback on the 4768 side.

---

### Rule 2 — Privileged Account Logon from Unexpected Machine

Detects Administrator or other tier-0 accounts logging on from a non-PAW (Privileged Access Workstation) machine.

```
norm_id=WinServer event_id=4624
  target_user_name IN ["Administrator", "krbtgt"]
  logon_type IN ["2", "3", "10"]
| search NOT src_ip IN ["10.0.0.5", "10.0.0.6"]
| chart count() by src_ip, target_user_name, logon_type
```

Replace the IP list with your PAW subnet/IPs.

---

### Rule 3 — SID Filtering Triggered (Cross-Domain Golden Ticket)

Detects SID history filtering events, indicating an attempt to escalate from a child domain to a parent domain using a Golden Ticket.

```
norm_id=WinServer event_id=4675
| chart count() by subject_account_name, src_ip, target_user_name
```

**Alert threshold:** Any occurrence.

---

## Kerberos Constrained Delegation

**Relevant Event ID:** `4624` — Successful Logon

### Rule 1 — Privileged Logon via Delegated Service (Transited Services Populated)

Detects a logon event for a high-privileged account that includes a `Transited Services` field, indicating S4U delegation was used to impersonate the account.

```
norm_id=WinServer event_id=4624
  target_user_name="Administrator"
  transited_services!=""
| chart count() by src_ip, target_user_name, transited_services
```

**Alert threshold:** Any occurrence where `transited_services` contains a non-PAW service account.

---

### Rule 2 — High-Privilege Logon from Non-PAW (Delegation Abuse)

```
norm_id=WinServer event_id=4624
  target_user_name IN ["Administrator", "admin*"]
  logon_type="3"
| search NOT src_ip IN ["10.0.0.5", "10.0.0.6"]
| chart count() by src_ip, target_user_name, transited_services
```

---

## PrinterBug & NTLM Relaying

**Relevant Event IDs:** `4624`, `4662`, `7045` (new service installed — Print Spooler activity)

### Rule 1 — DC Authenticating Outbound to Non-DC Host (Coercion Indicator)

Detects a Domain Controller establishing a network logon to a host that is not another DC — a sign that coercion (PrinterBug/PetitPotam) forced the DC to authenticate out.

```
norm_id=WinServer event_id=4624
  logon_type="3"
  subject_account_name="*$"
| search NOT target_host IN ["DC1", "DC2", "dc1.eagle.local", "dc2.eagle.local"]
| chart count() by subject_account_name, target_host, src_ip
```

---

### Rule 2 — DCSync Immediately After Coercion Window

Correlate a DC outbound auth event followed by a DCSync `4662` event within a short time window. Build as a two-stage correlation rule:

**Stage 1 — Coercion detected:**
```
norm_id=WinServer event_id=4624 logon_type="3" subject_account_name="*$"
| search NOT target_host IN ["DC1", "DC2"]
| chart count() by subject_account_name, src_ip
```

**Stage 2 — DCSync follows within 5 minutes:**
```
norm_id=WinServer event_id=4662
  properties IN ["*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*", "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*"]
| search NOT subject_account_name="*$"
```

Alert when both stages trigger within a 5-minute window from the same or correlated source.

---

### Rule 3 — Print Spooler Service Running on Domain Controller

Detects if the Print Spooler service (`Spooler`) is active or started on a DC — a prerequisite for PrinterBug.

```
norm_id=WinServer event_id=7045 service_name="Spooler" host IN ["DC1", "DC2"]
| chart count() by host, service_name, service_account
```

---

## Coercing Attacks & Unconstrained Delegation

**Relevant Event IDs:** `4624`, `4768`

### Rule 1 — TGT Cached on Workstation (Unconstrained Delegation Machine Receives TGT)

Detects a Domain Controller TGT (`4768` for a machine account ending in `$`) being forwarded or used on a workstation configured for Unconstrained Delegation. Typically surfaces as a logon event on that workstation from a DC machine account.

```
norm_id=WinServer event_id=4624
  target_user_name="*$"
  logon_type="3"
  target_host IN ["WS001", "WS002"]
| search subject_account_name IN ["DC1$", "DC2$"]
| chart count() by subject_account_name, target_host, src_ip
```

---

### Rule 2 — Outbound SMB/RPC from DC Blocked (Firewall Log Correlation)

If firewall logging is forwarded to LogPoint, detect dropped outbound connections from DCs on ports 139/445.

```
norm_id=FirewallLog action="drop" src_host IN ["DC1", "DC2"] dst_port IN ["139", "445"]
| search NOT dst_host IN ["DC1", "DC2"]
| chart count() by src_host, dst_host, dst_port
```

This confirms that the mitigation firewall rule is working and the coercion attempt was blocked.

---

## Object ACL Abuse

**Relevant Event IDs:** `4738` (user account changed), `4742` (computer account changed), `4724` (password reset)

### Rule 1 — Non-Admin User Modifying Another User Account

Detects `4738` events where the modifying account does not follow the privileged admin naming convention.

```
norm_id=WinServer event_id=4738
| search NOT subject_account_name="admin*"
| chart count() by subject_account_name, target_account, src_ip
```

**Alert threshold:** Any occurrence where a non-admin modifies a privileged account.

---

### Rule 2 — Password Reset Performed via ACL Abuse

Detects Event `4724` (password reset) where the initiator is not an expected admin account — indicating an adversary used `ForceChangePassword` ACL rights.

```
norm_id=WinServer event_id=4724
| search NOT subject_account_name IN ["admin*", "Administrator"]
| chart count() by subject_account_name, target_account, src_ip
```

**Alert threshold:** Any occurrence.

---

### Rule 3 — Computer Account Modified by Non-Admin

Detects `4742` events (computer account changed) from unexpected accounts — could indicate resource-based constrained delegation abuse (`msDS-AllowedToActOnBehalfOfOtherIdentity` modified).

```
norm_id=WinServer event_id=4742
| search NOT subject_account_name IN ["admin*", "Administrator", "SYSTEM"]
| chart count() by subject_account_name, target_computer, src_ip
```

---

### Rule 4 — Honeypot User Account Modified

Alert on any `4738` event targeting the designated honeypot user account.

```
norm_id=WinServer event_id=4738 target_account="honeypot-user"
| chart count() by subject_account_name, src_ip, target_account
```

**Alert threshold:** Any single occurrence. Optionally auto-disable the subject account.

---

## ESC1 — ADCS Misconfiguration

**Relevant Event IDs:** `4887` (certificate issued), `4768` / `4624` (subsequent auth with issued cert)

### Rule 1 — Certificate Issued with Subject Alternative Name (SAN) Override

Detects certificate issuance events where a Subject Alternative Name (SAN) was supplied by the requester (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` template), which is the ESC1 prerequisite.

```
norm_id=WinServer event_id=4887
  certificate_template="UserCert"
| search requester_name!="" subject_alt_name!=""
| chart count() by requester_name, subject_alt_name, certificate_template
```

> Adjust `certificate_template` to match the vulnerable template name in your environment.

---

### Rule 2 — Certificate Requested for Privileged Account SAN

High-fidelity rule: alert when a certificate is issued with `Administrator` or another privileged account in the SAN, requested by a different (lower-privileged) user.

```
norm_id=WinServer event_id=4887
  subject_alt_name IN ["Administrator", "Domain Admins", "krbtgt"]
| search NOT requester_name="Administrator"
| chart count() by requester_name, subject_alt_name, certificate_template
```

**Alert threshold:** Any occurrence.

---

### Rule 3 — Smart Card / Certificate-Based Logon for Privileged Account from Unexpected Source

After ESC1 exploitation, the attacker authenticates using the forged certificate. Detect this via PKINIT logon from a non-PAW.

```
norm_id=WinServer event_id=4768
  target_user_name="Administrator"
  certificate_issuer!=""
| search NOT src_ip IN ["10.0.0.5", "10.0.0.6"]
| chart count() by src_ip, target_user_name, certificate_issuer
```

---

## Quick Reference: Event ID to Attack Mapping

| Event ID | Relevant Attack(s)                                         |
| -------- | ---------------------------------------------------------- |
| `4624`   | Golden Ticket, Constrained Delegation, Credentials in Shares, GPP |
| `4625`   | GPP Honeypot, Credentials in Shares/Properties Honeypot   |
| `4662`   | DCSync, NTLM Relay post-coercion                          |
| `4663`   | GPP XML file access (honeypot)                            |
| `4675`   | Golden Ticket cross-domain (SID filtering)                |
| `4724`   | Object ACL abuse (ForceChangePassword)                    |
| `4738`   | Object ACL abuse (SPN add, attribute change)              |
| `4742`   | Object ACL abuse (RBCD via computer object modification)  |
| `4768`   | AS-REProasting, Golden Ticket, ESC1 cert logon            |
| `4769`   | Kerberoasting, Golden Ticket (TGS without TGT)            |
| `4771`   | Failed Kerberos pre-auth (honeypot triggers)              |
| `4776`   | NTLM credential validation failure (honeypot triggers)    |
| `4887`   | ESC1 certificate issuance                                 |
| `5136`   | GPO modification (GPO abuse, honeypot GPO)                |
| `7045`   | Print Spooler service on DC (PrinterBug prerequisite)     |
