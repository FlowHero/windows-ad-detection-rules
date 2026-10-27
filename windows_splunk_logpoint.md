# Windows Attack Detection — Splunk & LogPoint Queries


- [[#1. User/Domain Recon|1. User/Domain Recon]]
	- [[#1. User/Domain Recon#Splunk|Splunk]]
	- [[#1. User/Domain Recon#LogPoint (default Windows logs only)|LogPoint (default Windows logs only)]]
- [[#2. Password Spraying|2. Password Spraying]]
	- [[#2. Password Spraying#Splunk|Splunk]]
	- [[#2. Password Spraying#LogPoint|LogPoint]]
- [[#3. LLMNR/NBT-NS Poisoning|3. LLMNR/NBT-NS Poisoning]]
	- [[#3. LLMNR/NBT-NS Poisoning#Splunk|Splunk]]
	- [[#3. LLMNR/NBT-NS Poisoning#LogPoint (default Windows logs only)|LogPoint (default Windows logs only)]]
	- [[#3. LLMNR/NBT-NS Poisoning#Suricata|Suricata]]
- [[#4. Kerberoasting|4. Kerberoasting]]
	- [[#4. Kerberoasting#Splunk|Splunk]]
	- [[#4. Kerberoasting#LogPoint (default Windows logs only)|LogPoint (default Windows logs only)]]
- [[#5. AS-REPRoasting|5. AS-REPRoasting]]
	- [[#5. AS-REPRoasting#Splunk|Splunk]]
	- [[#5. AS-REPRoasting#LogPoint (default Windows logs only)|LogPoint (default Windows logs only)]]
- [[#6. Pass-the-Hash|6. Pass-the-Hash]]
	- [[#6. Pass-the-Hash#Splunk|Splunk]]
	- [[#6. Pass-the-Hash#LogPoint (default Windows logs only)|LogPoint (default Windows logs only)]]
- [[#7. Pass-the-Ticket|7. Pass-the-Ticket]]
	- [[#7. Pass-the-Ticket#Splunk|Splunk]]
	- [[#7. Pass-the-Ticket#LogPoint (default Windows logs only)|LogPoint (default Windows logs only)]]
- [[#8. Overpass-the-Hash|8. Overpass-the-Hash]]
	- [[#8. Overpass-the-Hash#Splunk|Splunk]]
	- [[#8. Overpass-the-Hash#LogPoint (default Windows logs only)|LogPoint (default Windows logs only)]]
- [[#9. Golden Ticket|9. Golden Ticket]]
	- [[#9. Golden Ticket#Splunk|Splunk]]
	- [[#9. Golden Ticket#LogPoint (default Windows logs only)|LogPoint (default Windows logs only)]]
- [[#10. Silver Ticket|10. Silver Ticket]]
	- [[#10. Silver Ticket#Splunk|Splunk]]
	- [[#10. Silver Ticket#LogPoint (default Windows logs only)|LogPoint (default Windows logs only)]]
- [[#11. Unconstrained Delegation|11. Unconstrained Delegation]]
	- [[#11. Unconstrained Delegation#Splunk|Splunk]]
	- [[#11. Unconstrained Delegation#LogPoint (default Windows logs only)|LogPoint (default Windows logs only)]]
- [[#12. Constrained Delegation|12. Constrained Delegation]]
	- [[#12. Constrained Delegation#Splunk|Splunk]]
	- [[#12. Constrained Delegation#LogPoint (default Windows logs only)|LogPoint (default Windows logs only)]]
- [[#13. DCSync|13. DCSync]]
	- [[#13. DCSync#Splunk|Splunk]]
	- [[#13. DCSync#LogPoint (default Windows logs only)|LogPoint (default Windows logs only)]]
- [[#14. DCShadow|14. DCShadow]]
	- [[#14. DCShadow#Splunk|Splunk]]
	- [[#14. DCShadow#LogPoint (default Windows logs only)|LogPoint (default Windows logs only)]]


> **LogPoint note**: All LogPoint queries use **default Windows log sources only** — no Sysmon, no SilkETW.
> Available sources: `Security`, `Microsoft-Windows-PowerShell/Operational`, `System`, `Application`.
> Some detections require audit policies enabled:
> - **Process Creation (EID 4688)**: Audit Process Creation + "Include command line" GPO
> - **DS Access (EID 4662)**: Advanced Audit → DS Access → Audit Directory Service Access
> - **PowerShell Script Block (EID 4104)**: Enable Script Block Logging via GPO

---

## 1. User/Domain Recon

### Splunk

**Native executables (Sysmon EID 1):**
```sql
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| search process_name IN (arp.exe,chcp.com,ipconfig.exe,net.exe,net1.exe,nltest.exe,ping.exe,systeminfo.exe,whoami.exe)
  OR (process_name IN (cmd.exe,powershell.exe) AND process IN (*arp*,*chcp*,*ipconfig*,*net*,*net1*,*nltest*,*ping*,*systeminfo*,*whoami*))
| stats values(process) as process, min(_time) as _time by parent_process, parent_process_id, dest, user
| where mvcount(process) > 3
```

**BloodHound/SharpHound (SilkETW LDAP):**
```sql
index=main source="WinEventLog:SilkService-Log"
| spath input=Message
| rename XmlEventData.* as *
| table _time, ComputerName, ProcessName, ProcessId, DistinguishedName, SearchFilter
| sort 0 _time
| search SearchFilter="*(samAccountType=805306368)*"
| stats min(_time) as _time, max(_time) as maxTime, count, values(SearchFilter) as SearchFilter by ComputerName, ProcessName, ProcessId
| where count > 10
| convert ctime(maxTime)
```

### LogPoint (default Windows logs only)

**Native executables via EID 4688 (Process Creation — requires audit policy):**
```
norm_id=WindowsSecurity event_id=4688
label IN ["arp.exe", "whoami.exe", "net.exe", "net1.exe", "nltest.exe",
          "systeminfo.exe", "ipconfig.exe", "ping.exe", "chcp.com"]
| process dc(label) as tool_count, values(label) as tools, values(command) as commands
  by parent_label, user, host
| search tool_count > 3
| chart tool_count, tools by parent_label, user, host
```

**PowerShell-based recon via EID 4104 (Script Block Logging):**
```
norm_id=WindowsPowerShell event_id=4104
message IN ["*Get-ADUser*", "*Get-ADComputer*", "*Get-ADGroup*", "*Get-ADDomain*",
            "*net user*", "*net group*", "*nltest*", "*domain_trusts*"]
| table timestamp, host, user, message
| sort by timestamp
```

> Without Sysmon or SilkETW, LDAP-based recon (BloodHound) is not detectable through default Windows logs.

---

## 2. Password Spraying

### Splunk

```sql
index=main source="WinEventLog:Security" EventCode=4625
| bin span=15m _time
| stats values(user) as Users, dc(user) as dc_user by src, Source_Network_Address, dest, EventCode, Failure_Reason
```

### LogPoint

**Failed logons (EID 4625) — same source, many distinct users:**
```
norm_id=WindowsSecurity event_id=4625
| process dc(target_user) as distinct_users, values(target_user) as users,
  count() as total_attempts by src_host, host
| search distinct_users > 10
| chart distinct_users, total_attempts by src_host, host
```

**Kerberos pre-auth failures (EID 4771) — same source, many targets:**
```
norm_id=WindowsSecurity event_id=4771
| process dc(target_user) as distinct_users, count() as count by src_ip, host
| search distinct_users > 10
| chart distinct_users, count by src_ip, host
```

**NTLM failures (EID 4776) — wrong password from one source:**
```
norm_id=WindowsSecurity event_id=4776 result_code IN ["0xC000006A", "0xC0000064"]
| process dc(target_user) as distinct_users, count() as count by src_host, host
| search distinct_users > 10
| chart distinct_users, count by src_host, host
```

---

## 3. LLMNR/NBT-NS Poisoning

### Splunk

**Custom honeypot log (LLMNRDetection scheduled task):**
```sql
index=main SourceName=LLMNRDetection
| table _time, ComputerName, SourceName, Message
```

**DNS queries to non-existent hosts (Sysmon EID 22):**
```sql
index=main EventCode=22
| table _time, Computer, user, Image, QueryName, QueryResults
```

**Explicit logon to rogue share (EID 4648):**
```sql
index=main EventCode=4648
| table _time, EventCode, source, name, user, Target_Server_Name, Message
| sort 0 _time
```

### LogPoint (default Windows logs only)

**Explicit logon to rogue share (EID 4648) — only viable default-log signal:**
```
norm_id=WindowsSecurity event_id=4648
| table timestamp, host, user, target_user, target_server, target_info
| sort by timestamp
```

> Without Sysmon EID 22 or a custom honeypot source, LLMNR/NBT-NS poisoning cannot be reliably detected through default Windows logs alone. EID 4648 covers only the credential-capture follow-up, not the poisoning itself.

### Suricata

> These rules detect the poisoning at the **network layer** — the only place where the attack itself is actually visible.

```suricata
# ─────────────────────────────────────────────
# LLMNR Poisoning Response  (UDP/5355)
# ─────────────────────────────────────────────
# LLMNR header layout:
#   [0-1] Transaction ID
#   [2-3] Flags  →  0x8000 = QR=1 (response), no error
#   [4-5] QDCOUNT
#   [6-7] ANCOUNT  →  > 0 means the response carries an answer (attacker's IP)
#
alert udp any any -> any 5355 (
    msg:"LLMNR Poisoning - Response with Answer Detected (Potential Responder)";
    content:"|80 00|"; offset:2; depth:2;
    byte_test:2,>,0,6,big;
    threshold:type limit, track by_src, count 3, seconds 60;
    metadata:attack_target Client_Endpoint, mitre_technique T1557.001;
    sid:9000001; rev:1;
)

# ─────────────────────────────────────────────
# NBT-NS Poisoning Response  (UDP/137)
# ─────────────────────────────────────────────
# NBT-NS header layout (RFC 1002):
#   [0-1] Transaction ID
#   [2-3] Flags  →  0x8500 = QR=1, OPCODE=QUERY, AA=1, RD=1, RCODE=0
#                   (positive Name Query Response, claiming to be authoritative)
#   [6-7] ANCOUNT  →  > 0 confirms it carries an answer record
#
alert udp any 137 -> any any (
    msg:"NBT-NS Poisoning - Positive Name Query Response Detected (Potential Responder)";
    content:"|85 00|"; offset:2; depth:2;
    byte_test:2,>,0,6,big;
    threshold:type limit, track by_src, count 3, seconds 60;
    metadata:attack_target Client_Endpoint, mitre_technique T1557.001;
    sid:9000002; rev:1;
)

# ─────────────────────────────────────────────
# mDNS Poisoning Response  (UDP/5353)
# ─────────────────────────────────────────────
# mDNS uses the same header layout as DNS:
#   [2-3] Flags  →  0x8400 = QR=1 (response) + AA=1 (authoritative)
#                   standard mDNS response always sets AA
#   Destination 224.0.0.251 = mDNS multicast group
#   [6-7] ANCOUNT  →  > 0 confirms a poisoned answer is included
#
alert udp any 5353 -> 224.0.0.251 5353 (
    msg:"mDNS Poisoning - Multicast Response with Answer Detected (Potential Responder)";
    content:"|84 00|"; offset:2; depth:2;
    byte_test:2,>,0,6,big;
    threshold:type limit, track by_src, count 3, seconds 60;
    metadata:attack_target Client_Endpoint, mitre_technique T1557.001;
    sid:9000003; rev:1;
)
```

**Tuning tips:**
- `byte_test:2,>,0,6,big` — ensures `ANCOUNT > 0`, so only responses carrying an answer record fire (not bare queries)
- `threshold: limit, track by_src, count 3, seconds 60` — Responder answers everything indiscriminately, so it will trigger this repeatedly; throttle to avoid SIEM flood
- If LLMNR/NBT-NS is **disabled via GPO** (as it should be), remove the threshold entirely — any response at all is an immediate alert
- Whitelist known WINS servers on port 137 by adding `![$WINS_SERVERS]` to the source group of the NBT-NS rule

---

## 4. Kerberoasting

### Splunk

**TGS request + no subsequent logon (basic view):**
```sql
index=main source="WinEventLog:Security"
EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)
| dedup RecordNumber
| rex field=user "(?<username>[^@]+)"
| table _time, ComputerName, EventCode, username, Account_Name, src_ip,
        service_name, Ticket_Options, Ticket_Encryption_Type, Target_Server_Name
```

**LDAP SPN enumeration (SilkETW):**
```sql
index=main source="WinEventLog:SilkService-Log"
| spath input=Message
| rename XmlEventData.* as *
| table _time, ComputerName, ProcessName, DistinguishedName, SearchFilter
| search SearchFilter="*(&(samAccountType=805306368)(servicePrincipalName=*)*"
```

**TGS without logon — bin approach:**
```sql
index=main source="WinEventLog:Security"
EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)
| dedup RecordNumber
| rex field=user "(?<username>[^@]+)"
| bin span=2m _time
| search username!=*$
| stats values(EventCode) as Events, values(service_name) as service_name,
        values(Target_Server_Name) as Target_Server_Name by _time, username
| where !match(Events,"4648")
```

**TGS without logon — transaction approach:**
```sql
index=main source="WinEventLog:Security"
EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)
| dedup RecordNumber
| rex field=user "(?<username>[^@]+)"
| search username!=*$
| transaction username keepevicted=true maxspan=5s endswith=(EventCode=4648) startswith=(EventCode=4769)
| where closed_txn=0 AND EventCode=4769
| table _time, EventCode, service_name, username
```

### LogPoint (default Windows logs only)

**TGS requests with RC4 encryption (EID 4769) — RC4 is the Kerberoasting indicator:**
```sql
norm_id=WindowsSecurity event_id=4769
target_user!="*$" target_user!="krbtgt"
ticket_encryption_type="0x17"
| process count() as count, values(target_user) as services by user, src_ip, host
| chart count, services by user, src_ip, host
```

**TGS without subsequent logon — transaction approach (EID 4769 + 4648):**
```
norm_id=WindowsSecurity event_id IN [4769, 4648]
user!="*$"
| transaction user, host maxspan=5s keepevicted=true
  startswith="event_id=4769" endswith="event_id=4648"
| search evicted=true AND event_id=4769
| table timestamp, user, host, target_user, ticket_encryption_type
```

> RC4 encryption type `0x17` in EID 4769 is a strong Kerberoasting indicator as modern environments use AES (`0x12`/`0x11`). Without SilkETW, LDAP-based SPN enumeration is not visible.

---

## 5. AS-REPRoasting

### Splunk

**LDAP query for pre-auth disabled accounts (SilkETW):**
```sql
index=main source="WinEventLog:SilkService-Log"
| spath input=Message
| rename XmlEventData.* as *
| table _time, ComputerName, ProcessName, DistinguishedName, SearchFilter
| search SearchFilter="*(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)*"
```

**TGT requests with pre-auth disabled (EID 4768):**
```sql
index=main source="WinEventLog:Security" EventCode=4768 Pre_Authentication_Type=0
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip>[0-9\.]+)"
| table _time, src_ip, user, Pre_Authentication_Type, Ticket_Options, Ticket_Encryption_Type
```

### LogPoint (default Windows logs only)

**TGT with pre-auth disabled — EID 4768, PreAuthType=0:**
```
norm_id=WindowsSecurity event_id=4768 pre_auth_type=0
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip4>[0-9\.]+)" as src_ip4
| table timestamp, host, target_user, src_ip4, pre_auth_type, ticket_encryption_type
| sort by timestamp
```

---

## 6. Pass-the-Hash

### Splunk

**Basic — LogonType 9 + seclogo (EID 4624):**
```sql
index=main source="WinEventLog:Security" EventCode=4624
Logon_Type=9 Logon_Process=seclogo
| table _time, ComputerName, EventCode, user, Network_Account_Domain,
        Network_Account_Name, Logon_Type, Logon_Process
```

**Enhanced — correlated with LSASS memory access (Sysmon EID 10 + EID 4624):**
```sql
index=main
(source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
  TargetImage="C:\\Windows\\system32\\lsass.exe"
  SourceImage!="C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\*\\MsMpEng.exe")
OR
(source="WinEventLog:Security" EventCode=4624 Logon_Type=9 Logon_Process=seclogo)
| sort _time, RecordNumber
| transaction host maxspan=1m endswith=(EventCode=4624) startswith=(EventCode=10)
| stats count by _time, Computer, SourceImage, SourceProcessId,
        Network_Account_Domain, Network_Account_Name, Logon_Type, Logon_Process
| fields - count
```

### LogPoint (default Windows logs only)

**LogonType 9 + seclogo (EID 4624) — direct PtH fingerprint:**
```
norm_id=WindowsSecurity event_id=4624
logon_type=9 logon_process=seclogo
| table timestamp, host, user, target_user, target_domain, logon_type, logon_process, src_host
| sort by timestamp
```

**Correlate with failed logon attempts before PtH success:**
```
norm_id=WindowsSecurity event_id IN [4624, 4625]
logon_type=9
| process count() as count, dc(target_user) as accounts by src_host, host, logon_process
| search logon_process="seclogo"
| chart count, accounts by src_host, host
```

> Without Sysmon EID 10, LSASS memory access correlation is not possible. The `seclogo` + `LogonType=9` combination alone is the best available signal from default logs.

---

## 7. Pass-the-Ticket

### Splunk

**4769/4770 without prior 4768 from same source — transaction approach:**
```sql
index=main source="WinEventLog:Security" user!=*$
EventCode IN (4768,4769,4770)
| rex field=user "(?<username>[^@]+)"
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip_4>[0-9\.]+)"
| transaction username, src_ip_4 maxspan=10h keepevicted=true startswith=(EventCode=4768)
| where closed_txn=0
| search NOT user="*$@*"
| table _time, ComputerName, username, src_ip_4, service_name, category
```

### LogPoint (default Windows logs only)

**4769/4770 with no prior 4768 from same source:**
```
norm_id=WindowsSecurity event_id IN [4768, 4769, 4770]
user!="*$"
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip4>[0-9\.]+)" as src_ip4
| transaction user, src_ip4 maxspan=10h keepevicted=true startswith="event_id=4768"
| search evicted=true AND event_id IN [4769, 4770]
| search NOT user="*$@*"
| table timestamp, host, user, src_ip4, target_user, category
```

---

## 8. Overpass-the-Hash

### Splunk

**Rubeus path — non-lsass process connecting to port 88 (Sysmon EID 3 + EID 1):**
```sql
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(EventCode=3 dest_port=88 Image!=*lsass.exe) OR EventCode=1
| eventstats values(process) as process by process_id
| where EventCode=3
| stats count by _time, Computer, dest_ip, dest_port, Image, process
| fields - count
```

### LogPoint (default Windows logs only)

**Mimikatz path (same as PtH) — LogonType 9 + seclogo:**
```
norm_id=WindowsSecurity event_id=4624
logon_type=9 logon_process=seclogo
| table timestamp, host, user, target_user, target_domain, src_host, logon_process
```

**Rubeus path — anomalous TGT request (EID 4768) from unexpected host:**
```
norm_id=WindowsSecurity event_id=4768
result_code="0x0"
| process count() as tgt_requests by target_user, src_ip, host
| chart tgt_requests by target_user, src_ip, host
```

> Without Sysmon EID 3, detecting the Rubeus raw port-88 connection is not possible with default Windows logs. The best fallback is spotting `4768` requests from unexpected hosts or correlating with the PtH detection approach for the Mimikatz path.

---

## 9. Golden Ticket

### Splunk

**Same as Pass-the-Ticket (forged TGT is injected identically):**
```sql
index=main source="WinEventLog:Security" user!=*$
EventCode IN (4768,4769,4770)
| rex field=user "(?<username>[^@]+)"
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip_4>[0-9\.]+)"
| transaction username, src_ip_4 maxspan=10h keepevicted=true startswith=(EventCode=4768)
| where closed_txn=0
| search NOT user="*$@*"
| table _time, ComputerName, username, src_ip_4, service_name, category
```

### LogPoint (default Windows logs only)

**Same transaction logic as PtT:**
```
norm_id=WindowsSecurity event_id IN [4768, 4769, 4770]
user!="*$"
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip4>[0-9\.]+)" as src_ip4
| transaction user, src_ip4 maxspan=10h keepevicted=true startswith="event_id=4768"
| search evicted=true AND event_id IN [4769, 4770]
| table timestamp, host, user, src_ip4, target_user, category
```

**Additional — detect KRBTGT hash theft via DCSync (see DCSync section).**

---

## 10. Silver Ticket

### Splunk

**Step 1 — Build known-user baseline from EID 4720:**
```sql
index=main EventCode=4720
| stats min(_time) as _time, values(EventCode) as EventCode by user
| outputlookup users.csv
```

**Step 2 — Find logons from users NOT in baseline:**
```sql
index=main EventCode=4624
| stats min(_time) as firstTime, values(ComputerName) as ComputerName,
        values(EventCode) as EventCode by user
| eval last24h = relative_time(now(),"-24h@h")
| where firstTime > last24h
| convert ctime(firstTime)
| lookup users.csv user as user OUTPUT EventCode as Events
| where isnull(Events)
```

**Step 3 — Anomalous special-privilege logons (EID 4672):**
```sql
index=main EventCode=4672
| stats min(_time) as firstTime, values(ComputerName) as ComputerName by Account_Name
| eval last24h = relative_time(now(),"-24h@h")
| where firstTime > last24h
| table firstTime, ComputerName, Account_Name
| convert ctime(firstTime)
```

### LogPoint (default Windows logs only)

**Unknown users logging in (EID 4624 vs 4720 baseline):**
```
norm_id=WindowsSecurity event_id=4624
| process min(timestamp) as first_logon, values(host) as hosts by target_user
| eval since=relative_time(now(), "-24h")
| search first_logon > since
| lookup users_baseline.csv target_user OUTPUT created as known_user
| search isnull(known_user)
| table first_logon, target_user, hosts
| sort by first_logon
```

**Special privileges assigned at logon (EID 4672) — new accounts only:**
```
norm_id=WindowsSecurity event_id=4672
| process min(timestamp) as first_seen, values(host) as hosts by user
| eval since=relative_time(now(), "-24h")
| search first_seen > since
| table first_seen, user, hosts
| sort by first_seen
```

---

## 11. Unconstrained Delegation

### Splunk

**PowerShell discovery of TrustedForDelegation (EID 4104):**
```sql
index=main source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
Message="*TrustedForDelegation*" OR Message="*userAccountControl:1.2.840.113556.1.4.803:=524288*"
| table _time, ComputerName, EventCode, Message
```

### LogPoint (default Windows logs only)

**PowerShell script block querying TrustedForDelegation (EID 4104):**
```
norm_id=WindowsPowerShell event_id=4104
message IN ["*TrustedForDelegation*", "*userAccountControl:1.2.840.113556.1.4.803:=524288*"]
| table timestamp, host, user, message
| sort by timestamp
```

> Post-exploitation (TGT extraction and reuse) falls back to Pass-the-Ticket detection.

---

## 12. Constrained Delegation

### Splunk

**PowerShell discovery of msDS-AllowedToDelegateTo (EID 4104):**
```sql
index=main source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
Message="*msDS-AllowedToDelegateTo*"
| table _time, ComputerName, EventCode, Message
```

**Rubeus S4U — non-lsass process on port 88 (Sysmon EID 3 + EID 1):**
```sql
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| eventstats values(process) as process by process_id
| where EventCode=3 AND dest_port=88
| table _time, Computer, dest_ip, dest_port, Image, process
```

### LogPoint (default Windows logs only)

**PowerShell discovery (EID 4104):**
```
norm_id=WindowsPowerShell event_id=4104
message="*msDS-AllowedToDelegateTo*"
| table timestamp, host, user, message
| sort by timestamp
```

**S4U impersonation — anomalous TGS for privileged accounts from service accounts (EID 4769):**
```
norm_id=WindowsSecurity event_id=4769
user!="*$"
| process values(target_user) as services, count() as count by user, src_ip, host
| search count > 5
| chart count, services by user, src_ip, host
```

> Without Sysmon EID 3, the port-88 Rubeus connection detection is unavailable in default Windows logs.

---

## 13. DCSync

### Splunk

```sql
index=main EventCode=4662 Message="*Replicating Directory Changes*"
| rex field=Message "(?P<property>Replicating Directory Changes.*)"
| table _time, user, object_file_name, Object_Server, property
```

### LogPoint (default Windows logs only)

**DS-Replication-Get-Changes operation (EID 4662) by a non-DC account:**
```
norm_id=WindowsSecurity event_id=4662
properties IN ["*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*", "*Replicating Directory Changes*"]
| table timestamp, host, user, object_name, properties
| sort by timestamp
```

**Narrow to non-machine accounts (human user triggering replication = anomalous):**
```
norm_id=WindowsSecurity event_id=4662
properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*"
user!="*$"
| table timestamp, host, user, object_name, properties
| sort by timestamp
```

> Requires **DS Access auditing** enabled: Computer Configuration → Advanced Audit Policy → DS Access → Audit Directory Service Access. Disabled by default.

---

## 14. DCShadow

### Splunk

**GC SPN added to computer object (EID 4742):**
```sql
index=main EventCode=4742
| rex field=Message "(?P<gcspn>XX\/[a-zA-Z0-9\.\-\/]+)"
| table _time, ComputerName, Security_ID, Account_Name, user, gcspn
| search gcspn=*
```

### LogPoint (default Windows logs only)

**Computer account changed with new SPN (EID 4742):**
```
norm_id=WindowsSecurity event_id=4742
| rex field=message "(?P<gcspn>GC\/[a-zA-Z0-9\.\-\/]+)" as gcspn
| search gcspn=*
| table timestamp, host, user, target_user, gcspn
| sort by timestamp
```

**Broader — any SPN change on a non-DC computer (EID 4742):**
```
norm_id=WindowsSecurity event_id=4742
message="*ServicePrincipalNames*"
| table timestamp, host, user, target_user, message
| sort by timestamp
```


